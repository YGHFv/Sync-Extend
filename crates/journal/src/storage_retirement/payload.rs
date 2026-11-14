//! Durable pre-move and restoration requests for one exact retired storage object.
use super::{invalid, payload_schema};
use crate::{
    storage_inventory::reader::{add, preflight},
    Journal, Result,
};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, EntryId};

const KINDS: [&str; 4] = [
    "quarantine_requested",
    "quarantined",
    "restore_requested",
    "restored",
];
const EVENT_PEAK: u64 = 144;
type EventSql = (u64, String, String, u64);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRetirementPayloadReport {
    pub request_id: EntryId,
    pub recorded_steps: usize,
    pub state: String,
    pub content_fenced: bool,
    pub deletion_authorized: bool,
    pub backup_complete: bool,
}

fn fingerprint(
    request: &super::StorageRetirementAdmission,
    owner: &super::owner::StorageRetirementOwnerReceipt,
    step: u64,
    time: u64,
) -> Result<ContentId> {
    Ok(ContentId::hash(&serde_json::to_vec(&(
        "sync-extend.storage-retirement-payload-event.v1",
        &request.request_fingerprint,
        &owner.activation_id,
        &owner.tmp_key,
        &owner.owner_key,
        step,
        time,
    ))?))
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<StorageRetirementPayloadReport>> {
    let owners = super::owner::audit(connection)?;
    audit_with_owners(connection, &owners)
}

pub(super) fn audit_with_owners(
    connection: &Connection,
    owners: &[super::owner::StorageRetirementOwnerReceipt],
) -> Result<Vec<StorageRetirementPayloadReport>> {
    payload_schema::validate(connection)?;
    preflight(
        connection,
        payload_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let admissions = super::audit(connection)?;
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )
        .optional()?;
    let mut result = Vec::new();
    for owner in owners {
        let admission = admissions
            .iter()
            .find(|r| r.request.request_id == owner.request_id)
            .ok_or_else(invalid)?;
        let events: Vec<EventSql> = connection.prepare(
            "SELECT step,kind,event_hash,recorded_at_ms FROM main.storage_retirement_payload_events
             WHERE request_id=?1 ORDER BY step",
        )?.query_map([owner.request_id.as_str()],|r|Ok((crate::sql_u64(r, 0)?,r.get(1)?,r.get(2)?,crate::sql_u64(r, 3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut prior = owner.created_at_ms;
        if events.len() > 4 {
            return Err(invalid());
        }
        for (index, (step, kind, hash, time)) in events.iter().enumerate() {
            if *step != index as u64
                || kind != KINDS[index]
                || *time < prior
                || clock.is_none_or(|clock| *time > clock)
                || (index == 0 && *time >= admission.request.expires_at_ms)
                || hash != fingerprint(admission, owner, *step, *time)?.as_str()
            {
                return Err(invalid());
            }
            prior = *time;
        }
        result.push(StorageRetirementPayloadReport {
            request_id: owner.request_id.clone(),
            recorded_steps: events.len(),
            state: events
                .last()
                .map(|r| r.1.clone())
                .unwrap_or_else(|| "owner_created".into()),
            content_fenced: admission.content_fenced,
            deletion_authorized: false,
            backup_complete: false,
        });
    }
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.storage_retirement_payload_events p
         LEFT JOIN main.storage_retirement_owner_creations c USING(request_id)
         WHERE c.request_id IS NULL)",
        [],
        |r| r.get(0),
    )?;
    if orphan {
        return Err(invalid());
    }
    Ok(result)
}

pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    let mut result = TreeStorageCharge::default();
    let disposals = super::disposal::audit(connection)?;
    for owner in audit(connection)? {
        let disposed = disposals
            .iter()
            .find(|r| r.request_id == owner.request_id)
            .ok_or_else(invalid)?;
        let rows = if disposed.recorded_steps != 0 {
            0
        } else {
            4 - owner.recorded_steps as u64
        };
        result.rows = add(result.rows, rows)?;
        result.logical_bytes = add(
            result.logical_bytes,
            rows.checked_mul(EVENT_PEAK).ok_or_else(invalid)?,
        )?;
    }
    // Activation already owns an eventual receipt and must reserve all future
    // payload liabilities before the original CREATE, even after process death.
    let unresolved = super::owner::outstanding(connection)?.rows;
    result.rows = add(result.rows, unresolved.checked_mul(4).ok_or_else(invalid)?)?;
    result.logical_bytes = add(
        result.logical_bytes,
        unresolved.checked_mul(4 * EVENT_PEAK).ok_or_else(invalid)?,
    )?;
    Ok(result)
}

impl Journal {
    pub fn storage_retirement_payloads(&self) -> Result<Vec<StorageRetirementPayloadReport>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let result = audit(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}

#[cfg(windows)]
pub(super) mod windows {
    use super::*;
    use rusqlite::{params, Transaction, TransactionBehavior};
    use std::{
        io::{Read, Seek, SeekFrom},
        path::{Path, PathBuf},
    };
    use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory, LockedFile};

    struct Held {
        _directories: Vec<LockedDirectory>,
        _marker: GuardedReadFile,
        file: LockedFile,
        at_original: bool,
        original: PathBuf,
        quarantine: PathBuf,
    }
    fn present(path: &Path) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    fn inspect(
        config: &sync_extend_core_model::storage_node::StorageNodeConfig,
        admission: &super::super::StorageRetirementAdmission,
        owner: &super::super::owner::StorageRetirementOwnerReceipt,
    ) -> Result<Held> {
        let request = &admission.request;
        let cas = config.data_dir.join("cas");
        let tmp = cas.join("tmp");
        let shard = cas.join("objects").join(&request.content_id.as_str()[..2]);
        let mut directories = Vec::new();
        for (parent, expected) in [
            (&config.data_dir, &request.data_identity),
            (&cas, &request.cas_identity),
            (&cas.join("objects"), &request.objects_identity),
            (&shard, &request.shard_identity),
        ] {
            let held = LockedDirectory::open(parent)?;
            held.require_local_ntfs(parent)?;
            held.require_case_insensitive()?;
            if ContentId::hash(held.key()?.to_string().as_bytes()) != *expected {
                return Err(invalid());
            }
            directories.push(held);
        }
        for path in tmp.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let held = LockedDirectory::open(path)?;
            held.require_local_ntfs(path)?;
            held.require_case_insensitive()?;
            if path == tmp
                && format!("{:016x}:{:032x}", held.key()?.volume, held.key()?.id) != owner.tmp_key
            {
                return Err(invalid());
            }
            directories.push(held);
        }
        let marker = GuardedReadFile::open(&tmp.join(&owner.component))?;
        let key = marker.key()?;
        if format!("{:016x}:{:032x}", key.volume, key.id) != owner.owner_key {
            return Err(invalid());
        }
        marker.verify_single_link()?;
        let mut bytes = Vec::new();
        marker.reader().take(66).read_to_end(&mut bytes)?;
        if ContentId::hash(&bytes) != owner.marker_hash
            || bytes != format!("{}:{}", owner.request_id, owner.activation_id).as_bytes()
        {
            return Err(invalid());
        }
        let original = shard.join(request.content_id.as_str());
        let quarantine = tmp.join(format!("retirement-{}.object", owner.activation_id));
        let at_original = present(&original)?;
        if at_original == present(&quarantine)? {
            return Err(invalid());
        }
        let file = LockedFile::open(if at_original { &original } else { &quarantine })?;
        let key = file.key()?;
        if ContentId::hash(key.to_string().as_bytes()) != request.object_identity {
            return Err(invalid());
        }
        verify_payload(&file, request)?;
        Ok(Held {
            _directories: directories,
            _marker: marker,
            file,
            at_original,
            original,
            quarantine,
        })
    }
    pub(crate) fn verify_payload(
        file: &LockedFile,
        request: &sync_extend_core_model::storage_retirement::StorageRetirementRequest,
    ) -> Result<()> {
        let before = file.reader().metadata()?;
        let stamp = u64::try_from(
            before
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| invalid())?
                .as_nanos(),
        )
        .map_err(|_| invalid())?;
        if before.len() != u64::from(request.length) || stamp != request.modified_at_ns {
            return Err(invalid());
        }
        let mut reader = file.reader();
        reader.seek(SeekFrom::Start(0))?;
        let mut hash = blake3::Hasher::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total = add(total, n as u64)?;
            if total > u64::from(request.length) {
                return Err(invalid());
            }
            hash.update(&buffer[..n]);
        }
        let after = file.reader().metadata()?;
        if total != u64::from(request.length)
            || ContentId::from_hasher(&hash) != request.content_id
            || before.len() != after.len()
            || before.modified()? != after.modified()?
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn checkpoint(phase: &str) {
        #[cfg(feature = "fault-injection")]
        if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(phase) {
            eprintln!("SYNCEXTEND_CHECKPOINT:{phase}");
            while !std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
                .is_some_and(|p| Path::new(&p).is_file())
            {
                std::thread::park_timeout(std::time::Duration::from_millis(25));
            }
        }
        let _ = phase;
    }
    impl Journal {
        fn record_payload(
            &self,
            admission: &super::super::StorageRetirementAdmission,
            owner: &super::super::owner::StorageRetirementOwnerReceipt,
            scope: (
                &sync_extend_core_model::storage_node::StorageNodeConfig,
                &sync_extend_core_model::DeviceId,
            ),
            step: usize,
            time: u64,
        ) -> Result<()> {
            let (config, device) = scope;
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            super::super::scope(&tx, &admission.request, config, device)?;
            let limits = self.writer_capacity_limits(config.max_metadata_entries)?;
            let before = self
                .read_view()
                .audit_storage_receive_capacity(&config.space_id, limits)?;
            let report = audit(&tx)?
                .into_iter()
                .find(|r| r.request_id == owner.request_id)
                .ok_or_else(invalid)?;
            let clock: u64 = tx.query_row(
                "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
                [],
                |r| crate::sql_u64(r, 0),
            )?;
            if report.recorded_steps != step || step >= 4 || time < clock {
                return Err(invalid());
            }
            let hash = fingerprint(admission, owner, step as u64, time)?;
            tx.execute(
                "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
                [crate::sql_integer(time)?],
            )?;
            self.storage_retirement_payload_issue
                .issue(hash.to_string(), time, || {
                    tx.execute(
                        "INSERT INTO main.storage_retirement_payload_events VALUES(?1,?2,?3,?4,?5)",
                        params![
                            owner.request_id.as_str(),
                            step as i64,
                            KINDS[step],
                            hash.as_str(),
                            crate::sql_integer(time)?
                        ],
                    )?;
                    Ok(())
                })?;
            super::super::unchanged(
                &before,
                &self
                    .read_view()
                    .audit_storage_receive_capacity(&config.space_id, limits)?,
            )?;
            tx.commit()?;
            Ok(())
        }
        /// Exact pre-move then same-handle no-overwrite quarantine or restoration.
        /// Return reports remain fenced and never grant deletion or backup.
        pub fn move_storage_retirement_payload(
            &self,
            id: &EntryId,
            config: &sync_extend_core_model::storage_node::StorageNodeConfig,
            device: &sync_extend_core_model::DeviceId,
            restore: bool,
            now: impl Fn() -> Result<u64>,
        ) -> Result<StorageRetirementPayloadReport> {
            if !self.connection.is_autocommit() {
                return Err(invalid());
            }
            let mut cas = self.acquire_cas_coordination()?;
            cas.try_exclusive()?;
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let admission = super::super::audit(&tx)?
                .into_iter()
                .find(|r| r.request.request_id == *id)
                .ok_or_else(invalid)?;
            super::super::scope(&tx, &admission.request, config, device)?;
            let owner = super::super::owner::audit(&tx)?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)?;
            let report = audit(&tx)?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)?;
            tx.commit()?;
            if report.recorded_steps == 4 || (!restore && report.recorded_steps >= 2) {
                return Ok(report);
            }
            if restore && report.recorded_steps < 2 {
                return Err(invalid());
            }
            let held = inspect(config, &admission, &owner)?;
            if !restore {
                if report.recorded_steps == 0 {
                    if !held.at_original {
                        return Err(invalid());
                    }
                    self.record_payload(&admission, &owner, (config, device), 0, now()?)?;
                    checkpoint("storage_retirement_quarantine_requested");
                }
                if held.at_original {
                    let time = now()?;
                    let clock=self.connection.query_row(
                        "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",[],|r|crate::sql_u64(r, 0))?;
                    if time < clock || time >= admission.request.expires_at_ms {
                        return Err(invalid());
                    }
                    verify_payload(&held.file, &admission.request)?;
                    held.file.rename_no_replace(&held.quarantine)?;
                    checkpoint("storage_retirement_quarantine_moved");
                }
                if !held.file.matches_path(&held.quarantine)? || present(&held.original)? {
                    return Err(invalid());
                }
                verify_payload(&held.file, &admission.request)?;
                self.record_payload(&admission, &owner, (config, device), 1, now()?)?;
                checkpoint("storage_retirement_quarantined");
            } else {
                if report.recorded_steps == 2 {
                    if held.at_original {
                        return Err(invalid());
                    }
                    self.record_payload(&admission, &owner, (config, device), 2, now()?)?;
                    checkpoint("storage_retirement_restore_requested");
                }
                if !held.at_original {
                    let clock:u64=self.connection.query_row(
                        "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",[],|r|crate::sql_u64(r, 0))?;
                    if now()? < clock {
                        return Err(invalid());
                    }
                    verify_payload(&held.file, &admission.request)?;
                    held.file.rename_no_replace(&held.original)?;
                    checkpoint("storage_retirement_restore_moved");
                }
                if !held.file.matches_path(&held.original)? || present(&held.quarantine)? {
                    return Err(invalid());
                }
                verify_payload(&held.file, &admission.request)?;
                self.record_payload(&admission, &owner, (config, device), 3, now()?)?;
                checkpoint("storage_retirement_restored");
            }
            self.storage_retirement_payloads()?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)
        }
    }
}
