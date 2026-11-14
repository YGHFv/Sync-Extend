//! Durable pre-request, exact native close, absence, and original marker cleanup.
use super::{disposal_schema, invalid};
use crate::{
    storage_inventory::reader::{add, preflight},
    Journal, Result,
};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, EntryId};
const KINDS: [&str; 4] = [
    "delete_requested",
    "deleted",
    "marker_cleanup_requested",
    "closed",
];
const EVENT_PEAK: u64 = 144;
type SqlEvent = (u64, String, String, u64);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRetirementDisposalReport {
    pub request_id: EntryId,
    pub state: String,
    pub recorded_steps: usize,
    pub payload_absence_recorded: bool,
    pub marker_absence_recorded: bool,
    pub deletion_authorized: bool,
    pub backup_complete: bool,
}
fn hash(
    admission: &super::StorageRetirementAdmission,
    owner: &super::owner::StorageRetirementOwnerReceipt,
    step: u64,
    time: u64,
) -> Result<ContentId> {
    Ok(ContentId::hash(&serde_json::to_vec(&(
        "sync-extend.storage-retirement-disposal.v1",
        &admission.request_fingerprint,
        &owner.activation_id,
        &owner.owner_key,
        &owner.tmp_key,
        step,
        time,
    ))?))
}
pub(crate) fn audit(connection: &Connection) -> Result<Vec<StorageRetirementDisposalReport>> {
    let owners = super::owner::audit(connection)?;
    audit_with_owners(connection, &owners)
}
pub(super) fn audit_with_owners(
    connection: &Connection,
    owners: &[super::owner::StorageRetirementOwnerReceipt],
) -> Result<Vec<StorageRetirementDisposalReport>> {
    disposal_schema::validate(connection)?;
    preflight(
        connection,
        disposal_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let admissions = super::audit(connection)?;
    let payloads = super::payload::audit_with_owners(connection, owners)?;
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
        let payload = payloads
            .iter()
            .find(|r| r.request_id == owner.request_id)
            .ok_or_else(invalid)?;
        let events: Vec<SqlEvent> = connection
            .prepare(
                "SELECT step,kind,event_hash,recorded_at_ms
            FROM main.storage_retirement_disposal_events WHERE request_id=?1 ORDER BY step",
            )?
            .query_map([owner.request_id.as_str()], |r| {
                Ok((
                    crate::sql_u64(r, 0)?,
                    r.get(1)?,
                    r.get(2)?,
                    crate::sql_u64(r, 3)?,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        if events.len() > 4 || (!events.is_empty() && payload.recorded_steps != 2) {
            return Err(invalid());
        }
        let mut prior = if events.is_empty() {
            owner.created_at_ms
        } else {
            connection.query_row(
                "SELECT recorded_at_ms FROM main.storage_retirement_payload_events WHERE request_id=?1 AND step=1",
                [owner.request_id.as_str()], |r| crate::sql_u64(r, 0),
            )?
        };
        for (index, (step, kind, fingerprint, time)) in events.iter().enumerate() {
            if *step != index as u64
                || kind != KINDS[index]
                || *time < prior
                || clock.is_none_or(|c| *time > c)
                || (index == 0 && *time >= admission.request.expires_at_ms)
                || fingerprint != hash(admission, owner, *step, *time)?.as_str()
            {
                return Err(invalid());
            }
            prior = *time;
        }
        result.push(StorageRetirementDisposalReport {
            request_id: owner.request_id.clone(),
            recorded_steps: events.len(),
            state: events
                .last()
                .map(|r| r.1.clone())
                .unwrap_or_else(|| "not_requested".into()),
            payload_absence_recorded: events.len() >= 2,
            marker_absence_recorded: events.len() == 4,
            deletion_authorized: false,
            backup_complete: false,
        });
    }
    let orphan:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM main.storage_retirement_disposal_events e
        LEFT JOIN main.storage_retirement_owner_creations c USING(request_id) WHERE c.request_id IS NULL)",[],|r|r.get(0))?;
    if orphan {
        return Err(invalid());
    }
    Ok(result)
}
pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    let reports = audit(connection)?;
    let payloads = super::payload::audit(connection)?;
    let unresolved = super::owner::outstanding(connection)?.rows;
    let mut result = TreeStorageCharge {
        rows: unresolved.checked_mul(4).ok_or_else(invalid)?,
        logical_bytes: unresolved.checked_mul(4 * EVENT_PEAK).ok_or_else(invalid)?,
    };
    for report in reports {
        let payload = payloads
            .iter()
            .find(|r| r.request_id == report.request_id)
            .ok_or_else(invalid)?;
        let remaining = if payload.recorded_steps >= 3 {
            0
        } else {
            4 - report.recorded_steps as u64
        };
        result.rows = add(result.rows, remaining)?;
        result.logical_bytes = add(
            result.logical_bytes,
            remaining.checked_mul(EVENT_PEAK).ok_or_else(invalid)?,
        )?;
    }
    Ok(result)
}
impl Journal {
    pub fn storage_retirement_disposals(&self) -> Result<Vec<StorageRetirementDisposalReport>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let reports = audit(&tx)?;
        tx.commit()?;
        Ok(reports)
    }
}

#[cfg(windows)]
pub(super) mod windows {
    use super::*;
    use rusqlite::{params, Transaction, TransactionBehavior};
    use std::{
        io::Read,
        path::{Path, PathBuf},
    };
    use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory, LockedFile};
    pub(in crate::storage_retirement) struct Namespace {
        _directories: Vec<LockedDirectory>,
        pub(in crate::storage_retirement) original: PathBuf,
        pub(in crate::storage_retirement) quarantine: PathBuf,
        pub(in crate::storage_retirement) marker: PathBuf,
    }
    pub(in crate::storage_retirement) fn present(path: &Path) -> Result<bool> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    pub(in crate::storage_retirement) fn namespace(
        config: &sync_extend_core_model::storage_node::StorageNodeConfig,
        request: &sync_extend_core_model::storage_retirement::StorageRetirementRequest,
        owner: &super::super::owner::StorageRetirementOwnerReceipt,
    ) -> Result<Namespace> {
        let cas = config.data_dir.join("cas");
        let objects = cas.join("objects");
        let shard = objects.join(&request.content_id.as_str()[..2]);
        let tmp = cas.join("tmp");
        let mut directories = Vec::new();
        for path in shard.ancestors().chain(tmp.ancestors()) {
            let held = LockedDirectory::open(path)?;
            held.require_local_ntfs(path)?;
            held.require_case_insensitive()?;
            let expected = if path == config.data_dir {
                Some(&request.data_identity)
            } else if path == cas {
                Some(&request.cas_identity)
            } else if path == objects {
                Some(&request.objects_identity)
            } else if path == shard {
                Some(&request.shard_identity)
            } else {
                None
            };
            let key = held.key()?;
            if expected.is_some_and(|e| ContentId::hash(key.to_string().as_bytes()) != *e)
                || (path == tmp && format!("{:016x}:{:032x}", key.volume, key.id) != owner.tmp_key)
            {
                return Err(invalid());
            }
            directories.push(held);
        }
        Ok(Namespace {
            _directories: directories,
            original: shard.join(request.content_id.as_str()),
            quarantine: tmp.join(format!("retirement-{}.object", owner.activation_id)),
            marker: tmp.join(&owner.component),
        })
    }
    pub(in crate::storage_retirement) fn marker(
        path: &Path,
        owner: &super::super::owner::StorageRetirementOwnerReceipt,
    ) -> Result<GuardedReadFile> {
        let held = GuardedReadFile::open(path)?;
        let key = held.key()?;
        if format!("{:016x}:{:032x}", key.volume, key.id) != owner.owner_key {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        held.reader().take(66).read_to_end(&mut bytes)?;
        if bytes != format!("{}:{}", owner.request_id, owner.activation_id).as_bytes()
            || ContentId::hash(&bytes) != owner.marker_hash
        {
            return Err(invalid());
        }
        held.verify_single_link()?;
        Ok(held)
    }
    pub(in crate::storage_retirement) fn expected_payload(
        path: &Path,
        request: &sync_extend_core_model::storage_retirement::StorageRetirementRequest,
    ) -> Result<LockedFile> {
        let held = LockedFile::open(path)?;
        if ContentId::hash(held.key()?.to_string().as_bytes()) != request.object_identity {
            return Err(invalid());
        }
        super::super::payload::windows::verify_payload(&held, request)?;
        Ok(held)
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
        fn record_storage_disposal(
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
            let before = self.read_view().audit_storage_receive_capacity(
                &config.space_id,
                self.writer_capacity_limits(config.max_metadata_entries)?,
            )?;
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
            let fingerprint = hash(admission, owner, step as u64, time)?;
            tx.execute(
                "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
                [crate::sql_integer(time)?],
            )?;
            self.storage_retirement_disposal_issue.issue(fingerprint.to_string(),time,||{
                tx.execute("INSERT INTO main.storage_retirement_disposal_events VALUES(?1,?2,?3,?4,?5)",
                    params![owner.request_id.as_str(),step as i64,KINDS[step],fingerprint.as_str(),crate::sql_integer(time)?])?;Ok(())
            })?;
            super::super::unchanged(
                &before,
                &self.read_view().audit_storage_receive_capacity(
                    &config.space_id,
                    self.writer_capacity_limits(config.max_metadata_entries)?,
                )?,
            )?;
            tx.commit()?;
            Ok(())
        }
        /// Close only the exact single-link payload after durable deletion intent.
        /// Terminal replay performs no native opens and grants no new deletion.
        pub fn dispose_storage_retirement_payload(
            &self,
            id: &EntryId,
            config: &sync_extend_core_model::storage_node::StorageNodeConfig,
            device: &sync_extend_core_model::DeviceId,
            now: impl Fn() -> Result<u64>,
        ) -> Result<StorageRetirementDisposalReport> {
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
            if report.recorded_steps == 4 {
                return Ok(report);
            }
            let namespace = namespace(config, &admission.request, &owner)?;
            if report.recorded_steps < 2 {
                let _marker = marker(&namespace.marker, &owner)?;
                if present(&namespace.original)? {
                    let original = GuardedReadFile::open(&namespace.original)?;
                    if ContentId::hash(original.key()?.to_string().as_bytes())
                        == admission.request.object_identity
                    {
                        return Err(invalid());
                    }
                    if report.recorded_steps == 0 {
                        return Err(invalid());
                    }
                }
                if report.recorded_steps == 0 {
                    let payload = expected_payload(&namespace.quarantine, &admission.request)?;
                    self.record_storage_disposal(&admission, &owner, (config, device), 0, now()?)?;
                    checkpoint("storage_retirement_delete_requested");
                    let time = now()?;
                    let clock:u64=self.connection.query_row(
                        "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",[],|r|crate::sql_u64(r, 0))?;
                    if time < clock || time >= admission.request.expires_at_ms {
                        return Err(invalid());
                    }
                    payload.delete_on_close()?;
                    checkpoint("storage_retirement_delete_native_requested");
                    drop(payload);
                    checkpoint("storage_retirement_payload_closed");
                } else if present(&namespace.quarantine)? {
                    let payload = expected_payload(&namespace.quarantine, &admission.request)?;
                    let time = now()?;
                    let clock:u64=self.connection.query_row(
                        "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",[],|r|crate::sql_u64(r, 0))?;
                    if time < clock || time >= admission.request.expires_at_ms {
                        return Err(invalid());
                    }
                    payload.delete_on_close()?;
                    drop(payload);
                }
                if present(&namespace.quarantine)? {
                    return Err(invalid());
                }
                self.record_storage_disposal(&admission, &owner, (config, device), 1, now()?)?;
                checkpoint("storage_retirement_deleted");
            }
            let current = self
                .storage_retirement_disposals()?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)?;
            if current.recorded_steps == 2 {
                let _marker = marker(&namespace.marker, &owner)?;
                self.record_storage_disposal(&admission, &owner, (config, device), 2, now()?)?;
                checkpoint("storage_retirement_marker_cleanup_requested");
            }
            if present(&namespace.marker)? {
                let held = marker(&namespace.marker, &owner)?;
                drop(held);
                let marker = LockedFile::open(&namespace.marker)?;
                let key = marker.key()?;
                if format!("{:016x}:{:032x}", key.volume, key.id) != owner.owner_key {
                    return Err(invalid());
                }
                let clock: u64 = self.connection.query_row(
                    "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
                    [],
                    |r| crate::sql_u64(r, 0),
                )?;
                if now()? < clock {
                    return Err(invalid());
                }
                let mut bytes = Vec::new();
                marker.reader().take(66).read_to_end(&mut bytes)?;
                if bytes != format!("{}:{}", owner.request_id, owner.activation_id).as_bytes()
                    || ContentId::hash(&bytes) != owner.marker_hash
                    || !marker.matches_path(&namespace.marker)?
                {
                    return Err(invalid());
                }
                marker.delete_on_close()?;
                checkpoint("storage_retirement_marker_native_requested");
                drop(marker);
                checkpoint("storage_retirement_marker_closed");
            }
            if present(&namespace.marker)? {
                return Err(invalid());
            }
            self.record_storage_disposal(&admission, &owner, (config, device), 3, now()?)?;
            checkpoint("storage_retirement_disposal_terminal");
            self.storage_retirement_disposals()?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)
        }
    }
}
