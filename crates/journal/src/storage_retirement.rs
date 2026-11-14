//! Worktree-free durable content fences, never quarantine or deletion authority.
use crate::{
    storage_capacity::CapacitySnapshot,
    storage_inventory::reader::{add, preflight},
    CasAccessGuard, Journal, JournalError, Result,
};
use rusqlite::{
    params, types::Value, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::Serialize;
use sync_extend_core_model::{
    storage_node::StorageNodeConfig, storage_retirement::StorageRetirementRequest,
    tree_storage_capacity::TreeStorageCharge, Change, ContentId, DeviceId, EntryId,
};

pub(crate) mod disposal;
pub(crate) mod disposal_schema;
pub(crate) mod gate;
pub(crate) mod owner;
pub(crate) mod owner_schema;
pub(crate) mod payload;
pub(crate) mod payload_schema;
pub(crate) mod schema;
pub(crate) mod terminal;
pub(crate) mod terminal_schema;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRetirementAdmission {
    pub request: StorageRetirementRequest,
    pub request_fingerprint: ContentId,
    pub admitted_at_ms: u64,
    pub cancelled_at_ms: Option<u64>,
    pub content_fenced: bool,
    pub physical_disposal_enabled: bool,
    pub deletion_authorized: bool,
    pub backup_complete: bool,
}

fn invalid() -> JournalError {
    JournalError::Invariant("exact storage retirement durable fence")
}

fn scope(
    connection: &Connection,
    request: &StorageRetirementRequest,
    config: &StorageNodeConfig,
    device: &DeviceId,
) -> Result<()> {
    request.validate(config, device)?;
    let identity: Vec<(String, String)> = connection
        .prepare("SELECT key,value FROM main.local_state ORDER BY key")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if identity
        != [
            ("device_id".into(), device.to_string()),
            ("space_id".into(), config.space_id.to_string()),
            ("storage_role".into(), "storage-v1".into()),
        ]
    {
        return Err(invalid());
    }
    let owner = request.original_owner_id.as_str();
    let pages = crate::storage_page_handoff::audit(connection)?;
    let snapshots = crate::storage_snapshot_handoff::audit(connection)?;
    let page = pages.iter().find(|p| {
        p.policy.storage_id == request.storage_id && &p.policy.storage_id.as_str()[..32] == owner
    });
    let snapshot = snapshots.iter().find(|p| {
        p.policy.storage_id == request.storage_id && &p.policy.storage_id.as_str()[..32] == owner
    });
    if page.is_some() == snapshot.is_some() {
        return Err(invalid());
    }
    let (fingerprint, chunks) = if let Some(page) = page {
        page.clone()
            .verify_current(config, &page.retained.receiver)
            .map_err(|_| invalid())?;
        if page.retained.receiver.device_id != *device {
            return Err(invalid());
        }
        (
            ContentId::hash(&serde_json::to_vec(&page.retained.signed_page)?),
            page.retained
                .signed_page
                .page
                .operations
                .iter()
                .filter_map(|signed| {
                    if let Change::Put { entry } = &signed.operation.payload.change {
                        entry.content.as_ref()
                    } else {
                        None
                    }
                })
                .flat_map(|file| file.chunks.iter())
                .cloned()
                .collect::<Vec<_>>(),
        )
    } else {
        let snapshot = snapshot.ok_or_else(invalid)?;
        snapshot
            .clone()
            .verify_current(config, &snapshot.retained.receiver)
            .map_err(|_| invalid())?;
        if snapshot.retained.receiver.device_id != *device {
            return Err(invalid());
        }
        (
            ContentId::hash(&serde_json::to_vec(&snapshot.retained.signed_report)?),
            snapshot
                .retained
                .signed_report
                .report
                .manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .flat_map(|file| file.chunks.iter())
                .cloned()
                .collect(),
        )
    };
    if fingerprint != request.original_metadata_hash
        || !chunks
            .iter()
            .any(|chunk| chunk.content_id == request.content_id && chunk.length == request.length)
        || chunks
            .iter()
            .any(|chunk| chunk.content_id == request.content_id && chunk.length != request.length)
    {
        return Err(invalid());
    }
    Ok(())
}

fn values(
    request: &StorageRetirementRequest,
    config: &StorageNodeConfig,
    device: &DeviceId,
    time: u64,
) -> Result<Vec<Value>> {
    request.validate(config, device)?;
    if time < request.grace_until_ms || time >= request.expires_at_ms {
        return Err(invalid());
    }
    let json = serde_json::to_string(request)?;
    let config_json = serde_json::to_string(config)?;
    if json.len() > 16384 || config_json.len() > crate::MAX_OPERATION_BYTES {
        return Err(invalid());
    }
    Ok(vec![
        Value::Text(request.request_id.to_string()),
        Value::Text(config.space_id.to_string()),
        Value::Text(request.storage_id.to_string()),
        Value::Text(request.original_owner_id.to_string()),
        Value::Text(device.to_string()),
        Value::Text(request.storage_policy.to_string()),
        Value::Text(request.content_id.to_string()),
        Value::Text(request.original_metadata_hash.to_string()),
        Value::Text(request.fingerprint(config, device)?.to_string()),
        Value::Integer(crate::sql_integer(request.requested_at_ms)?),
        Value::Integer(crate::sql_integer(request.grace_until_ms)?),
        Value::Integer(crate::sql_integer(request.expires_at_ms)?),
        Value::Integer(crate::sql_integer(time)?),
        Value::Text(json),
        Value::Text(config_json),
    ])
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<StorageRetirementAdmission>> {
    schema::validate(connection)?;
    preflight(
        connection,
        schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )
        .optional()?;
    let stored = connection
        .prepare(
            "SELECT request_id,space_id,storage_id,owner_id,device_id,policy_hash,content_id,
         metadata_hash,request_hash,requested_at_ms,grace_until_ms,expires_at_ms,
         admitted_at_ms,request,config FROM main.storage_retirement_requests ORDER BY request_id",
        )?
        .query_map([], |r| {
            (0..15)
                .map(|index| r.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    let mut active = std::collections::BTreeSet::new();
    for row in stored {
        let (Value::Text(json), Value::Text(config)) = (&row[13], &row[14]) else {
            return Err(invalid());
        };
        let request: StorageRetirementRequest = serde_json::from_str(json)?;
        let config: StorageNodeConfig = serde_json::from_str(config)?;
        let device = request.storage_device.clone();
        let Value::Integer(time) = row[12] else {
            return Err(invalid());
        };
        let time = u64::try_from(time).map_err(|_| invalid())?;
        if values(&request, &config, &device, time)? != row
            || clock.is_none_or(|clock| clock < time)
        {
            return Err(invalid());
        }
        scope(connection, &request, &config, &device)?;
        let cancelled: Option<u64> = connection.query_row(
            "SELECT cancelled_at_ms FROM main.storage_retirement_cancellations WHERE request_id=?1",
            [request.request_id.as_str()], |r| crate::sql_u64(r, 0),
        ).optional()?;
        if cancelled.is_some_and(|cancelled| {
            cancelled < time || clock.is_none_or(|clock| cancelled > clock)
        }) {
            return Err(invalid());
        }
        if cancelled.is_none() && !active.insert(request.content_id.clone()) {
            return Err(invalid());
        }
        if cancelled.is_none() {
            let pinned: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.reference_reservation_objects WHERE content_id=?1)
                 OR EXISTS(SELECT 1 FROM main.snapshot_objects WHERE content_id=?1)
                 OR EXISTS(SELECT 1 FROM main.publication_objects WHERE content_id=?1)
                 OR EXISTS(SELECT 1 FROM main.mutation_objects WHERE content_id=?1)
                 OR EXISTS(SELECT 1 FROM main.read_lease_objects WHERE content_id=?1)",
                [request.content_id.as_str()], |r| r.get(0),
            )?;
            if pinned {
                return Err(invalid());
            }
        }
        result.push(StorageRetirementAdmission {
            request_fingerprint: request.fingerprint(&config, &device)?,
            request,
            admitted_at_ms: time,
            cancelled_at_ms: cancelled,
            content_fenced: cancelled.is_none(),
            physical_disposal_enabled: false,
            deletion_authorized: false,
            backup_complete: false,
        });
    }
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.storage_retirement_cancellations c
         LEFT JOIN main.storage_retirement_requests r USING(request_id) WHERE r.request_id IS NULL)",
        [], |r| r.get(0),
    )?;
    if orphan {
        return Err(invalid());
    }
    Ok(result)
}

pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    let count = audit(connection)?
        .iter()
        .filter(|row| row.content_fenced)
        .count() as u64;
    Ok(TreeStorageCharge {
        rows: count,
        // Exact cancellation row: request ID UTF8=32 and timestamp INTEGER=8.
        logical_bytes: count.checked_mul(40).ok_or_else(invalid)?,
    })
}

fn unchanged(before: &CapacitySnapshot, after: &CapacitySnapshot) -> Result<()> {
    let original = |snapshot: &CapacitySnapshot| {
        snapshot
            .rows
            .iter()
            .filter(|row| !row.table().starts_with("storage_retirement_"))
            .map(|row| {
                (
                    row.table().to_owned(),
                    row.primary_key().to_vec(),
                    row.fingerprint().clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    if original(before) != original(after)
        || !after.report.within_accounted_limits()
        || !after.report.coverage_gaps().is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

impl Journal {
    pub fn storage_retirement_admissions(&self) -> Result<Vec<StorageRetirementAdmission>> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let rows = audit(&tx)?;
        tx.commit()?;
        Ok(rows)
    }

    /// Fence admission only. The callback establishes physical observations;
    /// neither its result nor the returned guard is a native effect grant.
    pub fn with_storage_retirement_admission<T, E>(
        &self,
        request: &StorageRetirementRequest,
        config: &StorageNodeConfig,
        device: &DeviceId,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, StorageRetirementAdmission), E>
    where
        E: From<JournalError>,
    {
        request
            .validate(config, device)
            .map_err(JournalError::from)?;
        if !self.connection.is_autocommit() {
            return Err(invalid().into());
        }
        let fingerprint = request
            .fingerprint(config, device)
            .map_err(JournalError::from)?;
        let replay =
            |rows: Vec<StorageRetirementAdmission>| -> Result<Option<StorageRetirementAdmission>> {
                let old = rows
                    .into_iter()
                    .find(|row| row.request.request_id == request.request_id);
                if old.as_ref().is_some_and(|old| {
                    old.request != *request || old.request_fingerprint != fingerprint
                }) {
                    return Err(invalid());
                }
                Ok(old)
            };
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(JournalError::from)?;
            scope(&tx, request, config, device)?;
            if let Some(old) = replay(audit(&tx)?)? {
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, old));
            }
        }
        // Exclusive CAS precedes even the first writer snapshot.
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        scope(&tx, request, config, device)?;
        if let Some(old) = replay(audit(&tx)?)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
        let before = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        if !before.report.coverage_gaps().is_empty()
            || !before.report.within_accounted_limits()
            || self.gc_protected(&request.content_id)?
        {
            return Err(invalid().into());
        }
        self.require_cas_access(&request.content_id)?;
        let held = inspect()?;
        let time = now()?;
        let issued = values(request, config, device, time)?;
        let old_clock: Option<u64> = tx
            .query_row(
                "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
                [],
                |r| crate::sql_u64(r, 0),
            )
            .optional()
            .map_err(JournalError::from)?;
        if old_clock.is_some_and(|old| time < old) {
            return Err(invalid().into());
        }
        let width = issued.iter().try_fold(0u64, |sum, value| {
            add(
                sum,
                match value {
                    Value::Text(text) => text.len() as u64,
                    Value::Integer(_) => 8,
                    _ => 0,
                },
            )
        })?;
        if add(
            before.report.accounted_total().rows,
            2 + u64::from(old_clock.is_none()),
        )? > bounds.max_rows
            || add(before.report.accounted_total().logical_bytes, width + 40)?
                > bounds.max_logical_bytes
        {
            return Err(invalid().into());
        }
        if old_clock.is_some() {
            tx.execute(
                "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
                [crate::sql_integer(time)?],
            )
            .map_err(JournalError::from)?;
        } else {
            tx.execute(
                "INSERT INTO main.storage_retirement_clock VALUES(1,?1)",
                [crate::sql_integer(time)?],
            )
            .map_err(JournalError::from)?;
        }
        self.storage_retirement_issuance.issue(
            request
                .fingerprint(config, device)
                .map_err(JournalError::from)?
                .to_string(),
            time,
            || {
                tx.execute(
                    "INSERT INTO main.storage_retirement_requests VALUES
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                    rusqlite::params_from_iter(issued.iter()),
                )?;
                Ok(())
            },
        )?;
        let after = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        unchanged(&before, &after)?;
        let result = audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == request.request_id)
            .ok_or_else(invalid)?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), result))
    }

    /// Cancel only a fence that has never activated a physical owner.
    pub fn cancel_storage_retirement(
        &self,
        request_id: &EntryId,
        config: &StorageNodeConfig,
        device: &DeviceId,
        time: u64,
    ) -> Result<StorageRetirementAdmission> {
        self.finish_storage_retirement_fence(request_id, config, device, time, false)
    }

    /// Release only an owner whose exact native terminal history is fully audited.
    pub fn release_storage_retirement_terminal(
        &self,
        request_id: &EntryId,
        config: &StorageNodeConfig,
        device: &DeviceId,
        time: u64,
    ) -> Result<StorageRetirementAdmission> {
        self.finish_storage_retirement_fence(request_id, config, device, time, true)
    }

    fn finish_storage_retirement_fence(
        &self,
        request_id: &EntryId,
        config: &StorageNodeConfig,
        device: &DeviceId,
        time: u64,
        terminal_release: bool,
    ) -> Result<StorageRetirementAdmission> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let old = audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == *request_id)
            .ok_or_else(invalid)?;
        scope(&tx, &old.request, config, device)?;
        owner::audit(&tx)?;
        let activated: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.storage_retirement_owner_activations WHERE request_id=?1)",
            [request_id.as_str()], |r| r.get(0),
        )?;
        if terminal_release {
            if !activated || !terminal::closed(&tx, request_id)? {
                return Err(invalid());
            }
        } else if activated {
            return Err(invalid());
        }
        if old.cancelled_at_ms.is_some() {
            tx.commit()?;
            return Ok(old);
        }
        let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
        let before = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        let clock: u64 = tx.query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )?;
        if time < clock {
            return Err(invalid());
        }
        tx.execute(
            "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
            [crate::sql_integer(time)?],
        )?;
        self.storage_retirement_cancellation
            .issue(request_id.to_string(), time, || {
                tx.execute(
                    "INSERT INTO main.storage_retirement_cancellations VALUES(?1,?2)",
                    params![request_id.as_str(), crate::sql_integer(time)?],
                )?;
                Ok(())
            })?;
        let after = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        unchanged(&before, &after)?;
        let result = audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == *request_id)
            .ok_or_else(invalid)?;
        #[cfg(windows)]
        if terminal_release {
            terminal::checkpoint("storage_retirement_release_before_commit");
        }
        tx.commit()?;
        #[cfg(windows)]
        if terminal_release {
            terminal::checkpoint("storage_retirement_released");
        }
        Ok(result)
    }
}
