//! Exact restored-owner cleanup and audited native terminal fence release.
use super::{invalid, terminal_schema};
use crate::{
    storage_inventory::reader::{add, preflight},
    Journal, Result,
};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, EntryId};
const PEAK: u64 = 144;
type SqlEvent = (u64, String, String, u64);
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRetirementTerminalReport {
    pub request_id: EntryId,
    pub state: String,
    pub recorded_steps: usize,
    pub marker_absence_recorded: bool,
    pub content_fenced: bool,
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
        "sync-extend.storage-retirement-restored-terminal.v1",
        &admission.request_fingerprint,
        &owner.activation_id,
        &owner.owner_key,
        &owner.tmp_key,
        step,
        time,
    ))?))
}
pub(crate) fn closed(connection: &Connection, id: &EntryId) -> Result<bool> {
    let owners = super::owner::audit(connection)?;
    let restored = audit_with_owners(connection, &owners)?;
    let deleted = super::disposal::audit_with_owners(connection, &owners)?;
    Ok(restored
        .iter()
        .any(|r| r.request_id == *id && r.marker_absence_recorded)
        || deleted
            .iter()
            .any(|r| r.request_id == *id && r.marker_absence_recorded))
}
/// Validate retained terminal history using already typed owners to avoid audit recursion.
pub(super) fn validate_releases(
    connection: &Connection,
    admissions: &[super::StorageRetirementAdmission],
    owners: &[super::owner::StorageRetirementOwnerReceipt],
) -> Result<()> {
    if !owners.iter().any(|owner| {
        admissions
            .iter()
            .any(|a| a.request.request_id == owner.request_id && !a.content_fenced)
    }) {
        return Ok(());
    }
    let restored = audit_with_owners(connection, owners)?;
    let deleted = super::disposal::audit_with_owners(connection, owners)?;
    for owner in owners {
        let admission = admissions
            .iter()
            .find(|a| a.request.request_id == owner.request_id)
            .ok_or_else(invalid)?;
        if let Some(cancelled) = admission.cancelled_at_ms {
            let table = if restored
                .iter()
                .any(|r| r.request_id == owner.request_id && r.marker_absence_recorded)
            {
                "storage_retirement_terminal_events"
            } else if deleted
                .iter()
                .any(|r| r.request_id == owner.request_id && r.marker_absence_recorded)
            {
                "storage_retirement_disposal_events"
            } else {
                return Err(invalid());
            };
            let terminal_time: u64 = connection.query_row(
                &format!("SELECT max(recorded_at_ms) FROM main.{table} WHERE request_id=?1"),
                [owner.request_id.as_str()],
                |r| crate::sql_u64(r, 0),
            )?;
            if terminal_time > cancelled {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
pub(crate) fn audit(connection: &Connection) -> Result<Vec<StorageRetirementTerminalReport>> {
    let owners = super::owner::audit(connection)?;
    audit_with_owners(connection, &owners)
}
fn audit_with_owners(
    connection: &Connection,
    owners: &[super::owner::StorageRetirementOwnerReceipt],
) -> Result<Vec<StorageRetirementTerminalReport>> {
    terminal_schema::validate(connection)?;
    preflight(
        connection,
        terminal_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let admissions = super::audit(connection)?;
    let payloads = super::payload::audit_with_owners(connection, owners)?;
    let disposals = super::disposal::audit_with_owners(connection, owners)?;
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )
        .optional()?;
    let mut reports = Vec::new();
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
            FROM main.storage_retirement_terminal_events WHERE request_id=?1 ORDER BY step",
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
        let disposal = disposals
            .iter()
            .find(|r| r.request_id == owner.request_id)
            .ok_or_else(invalid)?;
        if events.len() > 2
            || (!events.is_empty() && (payload.recorded_steps != 4 || disposal.recorded_steps != 0))
        {
            return Err(invalid());
        }
        let mut prior = if events.is_empty() {
            owner.created_at_ms
        } else {
            connection.query_row(
                "SELECT recorded_at_ms FROM main.storage_retirement_payload_events
                WHERE request_id=?1 AND step=3",
                [owner.request_id.as_str()],
                |r| crate::sql_u64(r, 0),
            )?
        };
        for (index, (step, kind, fingerprint, time)) in events.iter().enumerate() {
            if *step != index as u64
                || kind != ["restored_cleanup_requested", "restored_closed"][index]
                || *time < prior
                || clock.is_none_or(|c| *time > c)
                || fingerprint != hash(admission, owner, *step, *time)?.as_str()
            {
                return Err(invalid());
            }
            prior = *time;
        }
        reports.push(StorageRetirementTerminalReport {
            request_id: owner.request_id.clone(),
            state: events
                .last()
                .map(|r| r.1.clone())
                .unwrap_or_else(|| "not_requested".into()),
            recorded_steps: events.len(),
            marker_absence_recorded: events.len() == 2,
            content_fenced: admission.content_fenced,
            deletion_authorized: false,
            backup_complete: false,
        });
    }
    let orphan:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM main.storage_retirement_terminal_events e
        LEFT JOIN main.storage_retirement_owner_creations c USING(request_id) WHERE c.request_id IS NULL)",[],|r|r.get(0))?;
    if orphan {
        return Err(invalid());
    }
    Ok(reports)
}
pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    let reports = audit(connection)?;
    let disposals = super::disposal::audit(connection)?;
    let unresolved = super::owner::outstanding(connection)?.rows;
    let mut result = TreeStorageCharge {
        rows: unresolved.checked_mul(2).ok_or_else(invalid)?,
        logical_bytes: unresolved.checked_mul(2 * PEAK).ok_or_else(invalid)?,
    };
    for report in reports {
        let disposed = disposals
            .iter()
            .find(|r| r.request_id == report.request_id)
            .ok_or_else(invalid)?;
        let remaining = if disposed.recorded_steps != 0 {
            0
        } else {
            2 - report.recorded_steps as u64
        };
        result.rows = add(result.rows, remaining)?;
        result.logical_bytes = add(
            result.logical_bytes,
            remaining.checked_mul(PEAK).ok_or_else(invalid)?,
        )?;
    }
    Ok(result)
}
impl Journal {
    pub fn storage_retirement_terminals(&self) -> Result<Vec<StorageRetirementTerminalReport>> {
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
pub(super) fn checkpoint(phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{phase}");
        while !std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
            .is_some_and(|p| std::path::Path::new(&p).is_file())
        {
            std::thread::park_timeout(std::time::Duration::from_millis(25));
        }
    }
    let _ = phase;
}

#[cfg(windows)]
mod windows {
    use super::*;
    use rusqlite::{params, Transaction, TransactionBehavior};
    use std::io::Read;
    use sync_extend_platform_fs::LockedFile;
    impl Journal {
        fn record_storage_restored_terminal(
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
            let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
            let before = self
                .read_view()
                .audit_storage_receive_capacity(&config.space_id, bounds)?;
            let report = audit(&tx)?
                .into_iter()
                .find(|r| r.request_id == owner.request_id)
                .ok_or_else(invalid)?;
            let clock: u64 = tx.query_row(
                "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
                [],
                |r| crate::sql_u64(r, 0),
            )?;
            if report.recorded_steps != step || step > 1 || time < clock {
                return Err(invalid());
            }
            let fingerprint = hash(admission, owner, step as u64, time)?;
            tx.execute(
                "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
                [crate::sql_integer(time)?],
            )?;
            self.storage_retirement_terminal_issue.issue(fingerprint.to_string(),time,||{
                tx.execute("INSERT INTO main.storage_retirement_terminal_events VALUES(?1,?2,?3,?4,?5)",
                    params![owner.request_id.as_str(),step as i64,["restored_cleanup_requested","restored_closed"][step],
                        fingerprint.as_str(),crate::sql_integer(time)?])?;Ok(())
            })?;
            super::super::unchanged(
                &before,
                &self
                    .read_view()
                    .audit_storage_receive_capacity(&config.space_id, bounds)?,
            )?;
            tx.commit()?;
            Ok(())
        }
        /// Clean only the exact original marker after durable original restoration.
        /// The returned metadata does not itself release the fence.
        pub fn close_restored_storage_retirement(
            &self,
            id: &EntryId,
            config: &sync_extend_core_model::storage_node::StorageNodeConfig,
            device: &sync_extend_core_model::DeviceId,
            now: impl Fn() -> Result<u64>,
        ) -> Result<StorageRetirementTerminalReport> {
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
            let payload = super::super::payload::audit(&tx)?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)?;
            tx.commit()?;
            if report.recorded_steps == 2 {
                return Ok(report);
            }
            if payload.recorded_steps != 4 {
                return Err(invalid());
            }
            let namespace =
                super::super::disposal::windows::namespace(config, &admission.request, &owner)?;
            let original = super::super::disposal::windows::expected_payload(
                &namespace.original,
                &admission.request,
            )?;
            if super::super::disposal::windows::present(&namespace.quarantine)? {
                return Err(invalid());
            }
            if report.recorded_steps == 0 {
                let held = super::super::disposal::windows::marker(&namespace.marker, &owner)?;
                self.record_storage_restored_terminal(
                    &admission,
                    &owner,
                    (config, device),
                    0,
                    now()?,
                )?;
                drop(held);
                checkpoint("storage_retirement_restored_cleanup_requested");
            }
            if super::super::disposal::windows::present(&namespace.marker)? {
                let held = LockedFile::open(&namespace.marker)?;
                let key = held.key()?;
                let mut bytes = Vec::new();
                held.reader().take(66).read_to_end(&mut bytes)?;
                let clock: u64 = self.connection.query_row(
                    "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
                    [],
                    |r| crate::sql_u64(r, 0),
                )?;
                if format!("{:016x}:{:032x}", key.volume, key.id) != owner.owner_key
                    || bytes != format!("{}:{}", owner.request_id, owner.activation_id).as_bytes()
                    || ContentId::hash(&bytes) != owner.marker_hash
                    || now()? < clock
                    || !held.matches_path(&namespace.marker)?
                {
                    return Err(invalid());
                }
                held.delete_on_close()?;
                checkpoint("storage_retirement_restored_marker_native_requested");
                drop(held);
                checkpoint("storage_retirement_restored_marker_closed");
            }
            if super::super::disposal::windows::present(&namespace.marker)? {
                return Err(invalid());
            }
            super::super::payload::windows::verify_payload(&original, &admission.request)?;
            if !original.matches_path(&namespace.original)? {
                return Err(invalid());
            }
            self.record_storage_restored_terminal(&admission, &owner, (config, device), 1, now()?)?;
            checkpoint("storage_retirement_restored_terminal");
            self.storage_retirement_terminals()?
                .into_iter()
                .find(|r| r.request_id == *id)
                .ok_or_else(invalid)
        }
    }
}
