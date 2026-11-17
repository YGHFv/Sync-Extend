//! Durable ordinary history liability. No restart issuer or native authority.
use crate::{Journal, JournalError, Result};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    persisted_rename::RenameObservationMap, tree_storage_capacity::TreeStorageCharge, EntryId,
    Manifest, Operation, PortablePath, SnapshotId,
};

pub(crate) const KEY: &str = "original.local-history.reservation.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stored {
    version: u32,
    attempt: EntryId,
    baseline: Manifest,
    planned: Manifest,
    operations: Vec<Operation>,
    timestamp: u64,
    original_device: sync_extend_core_model::DeviceId,
    original_worktree_digest: sync_extend_core_model::ContentId,
    observations: RenameObservationMap,
    future_path: PortablePath,
    native_footprint: OriginalNativeCreateFootprint,
}

/// Private construction only after the original reservation transaction commits.
/// The persisted row by itself cannot be adopted into this live token.
pub struct OriginalLocalHistoryReservation {
    exact_json: String,
    attempt: EntryId,
    issuer: std::sync::Arc<()>,
    original_issued_phases: std::sync::Mutex<Vec<String>>,
}

impl OriginalLocalHistoryReservation {
    pub fn attempt(&self) -> &EntryId {
        &self.attempt
    }
    pub fn exact_json(&self) -> &str {
        &self.exact_json
    }
}

impl Stored {
    fn validate(&self, max: usize) -> Result<()> {
        self.baseline.validate()?;
        self.planned.validate()?;
        self.observations.validate(&self.planned, max)?;
        crate::sql_integer(self.timestamp)?;
        if self.version != 1
            || self.operations.len() != 1
            || self.baseline.space_id != self.planned.space_id
        {
            return Err(JournalError::Invariant(
                "original history reservation scope",
            ));
        }
        self.operations[0].validate()?;
        self.native_footprint.validate(self)?;
        if self.operations[0].payload.origin_device_id != self.original_device {
            return Err(JournalError::Invariant(
                "original reserved device differs from full operation",
            ));
        }
        let entry = self
            .planned
            .entries
            .values()
            .find(|entry| entry.path == self.future_path)
            .ok_or(JournalError::Invariant(
                "reserved original target entry required",
            ))?;
        let operation = &self.operations[0];
        if operation.payload.space_id != self.planned.space_id
            || operation.payload.created_at_ms != self.timestamp
            || operation.payload.change
                != (sync_extend_core_model::Change::Put {
                    entry: entry.clone(),
                })
            || self.baseline.entries.contains_key(&entry.entry_id)
            || self
                .baseline
                .entries
                .values()
                .any(|old| old.path.collision_key() == self.future_path.collision_key())
            || self.planned.entries.len() != self.baseline.entries.len() + 1
            || self
                .baseline
                .entries
                .iter()
                .any(|(id, old)| self.planned.entries.get(id) != Some(old))
        {
            return Err(JournalError::Invariant(
                "reserved original complete CREATE plan",
            ));
        }
        let mut vector = self.baseline.version_vector.clone();
        if operation.payload.causal != vector
            || operation.payload.origin_seq
                != vector
                    .get(&operation.payload.origin_device_id)
                    .checked_add(1)
                    .ok_or(JournalError::Invariant("reservation sequence overflow"))?
        {
            return Err(JournalError::Invariant(
                "reserved original causal continuation",
            ));
        }
        vector.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        if vector != self.planned.version_vector
            || self.baseline.tombstones != self.planned.tombstones
        {
            return Err(JournalError::Invariant(
                "reserved original version or tombstone changed",
            ));
        }
        Ok(())
    }

    fn charge(&self) -> Result<TreeStorageCharge> {
        let mut protected_objects = std::collections::BTreeMap::new();
        for content in self
            .planned
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &content.chunks {
                if protected_objects
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|old| old != chunk.length)
                {
                    return Err(JournalError::Invariant(
                        "reserved conflicting content lengths",
                    ));
                }
            }
        }
        let completion = crate::PublicationCompletion {
            baseline: self.baseline.clone(),
            manifest: self.planned.clone(),
            operations: self.operations.clone(),
            timestamp_ms: self.timestamp,
            protected_objects,
        };
        let mut charge = completion.charge()?;
        let observations = crate::rename_observation::serialize_observation(&self.observations)?;
        charge.rows = charge
            .rows
            .checked_add(2)
            .ok_or(JournalError::Invariant("reservation row overflow"))?;
        charge.logical_bytes = charge
            .logical_bytes
            .checked_add(observations.len() as u64 + 160 + 4096)
            .ok_or(JournalError::Invariant("reservation byte overflow"))?;
        Ok(charge)
    }
}

pub(crate) fn persisted_charge(json: &str, max: usize) -> Result<TreeStorageCharge> {
    if json.len() > crate::MAX_OPERATION_BYTES {
        return Err(JournalError::Invariant(
            "reserved original history byte bound",
        ));
    }
    let stored: Stored = serde_json::from_str(json)?;
    stored.validate(max)?;
    if serde_json::to_string(&stored)? != json {
        return Err(JournalError::Invariant("reserved original canonical bytes"));
    }
    stored.charge()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn consume(
    tx: &Transaction<'_>,
    issuer: &std::sync::Arc<()>,
    reservation: &OriginalLocalHistoryReservation,
    baseline: Option<&SnapshotId>,
    manifest: &Manifest,
    operations: &[Operation],
    timestamp: u64,
    observations: Option<(&RenameObservationMap, usize)>,
) -> Result<OriginalNativePhaseChain> {
    if !std::sync::Arc::ptr_eq(issuer, &reservation.issuer) {
        return Err(JournalError::Invariant(
            "reservation requires exact original live Journal issuer",
        ));
    }
    liability::verify_pending_connection(tx, &reservation.exact_json)?;
    let stored: Stored = serde_json::from_str(&reservation.exact_json)?;
    let (actual, max) =
        observations.ok_or(JournalError::Invariant("reserved complete observations"))?;
    stored.validate(max)?;
    actual.validate(manifest, max)?;
    let mut normalized = actual.clone();
    let planned = stored
        .observations
        .entries
        .iter()
        .find(|record| record.observed.path == stored.future_path)
        .ok_or(JournalError::Invariant(
            "reserved future observation missing",
        ))?;
    let current = normalized
        .entries
        .iter_mut()
        .find(|record| record.entry_id == planned.entry_id)
        .ok_or(JournalError::Invariant(
            "actual original target observation missing",
        ))?;
    // Only the future inode hash changes. Every prior identity and every target
    // field, path, content, link flag, root and epoch must remain byte exact.
    current.observed.physical_identity = planned.observed.physical_identity.clone();
    if stored.attempt != reservation.attempt
        || baseline != Some(&stored.baseline.root()?)
        || stored.planned != *manifest
        || stored.operations != operations
        || stored.timestamp != timestamp
        || normalized != stored.observations
    {
        return Err(JournalError::Invariant("reserved original history changed"));
    }
    let original_phase_chain = phase_chain::complete(tx, reservation, actual)?;
    let removed = tx.execute(
        "DELETE FROM local_state WHERE key=?1 AND value=?2",
        params![KEY, reservation.exact_json],
    )?;
    if removed != 1 {
        return Err(JournalError::Invariant(
            "live original reservation absent or changed",
        ));
    }
    Ok(original_phase_chain)
}

impl Journal {
    /// Persist the full immutable plan and its independent future row/byte
    /// charge before target effects. Existing rows cannot issue a new token.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_original_local_history(
        &mut self,
        baseline: &Manifest,
        planned: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        observations: &RenameObservationMap,
        future_path: &PortablePath,
        max: usize,
    ) -> Result<OriginalLocalHistoryReservation> {
        let _original_cas_coordination = self.acquire_cas_coordination()?;
        let bounds = self.writer_capacity_limits(max)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let original_device: String = tx.query_row(
            "SELECT value FROM local_state WHERE key='device_id'",
            [],
            |row| row.get(0),
        )?;
        let original_worktree: String = tx.query_row(
            "SELECT value FROM local_state WHERE key='worktree'",
            [],
            |row| row.get(0),
        )?;
        if original_worktree.is_empty() || original_worktree.len() > crate::MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant(
                "original reserved worktree path bound",
            ));
        }
        let stored = Stored {
            version: 1,
            attempt: EntryId::random()?,
            baseline: baseline.clone(),
            planned: planned.clone(),
            operations: operations.to_vec(),
            timestamp,
            original_device: original_device.parse()?,
            original_worktree_digest: sync_extend_core_model::ContentId::hash(
                original_worktree.as_bytes(),
            ),
            observations: observations.clone(),
            future_path: future_path.clone(),
            native_footprint: OriginalNativeCreateFootprint::plan(planned, future_path)?,
        };
        stored.validate(max)?;
        let exact_json = serde_json::to_string(&stored)?;
        persisted_charge(&exact_json, max)?;
        let snapshot_json = serde_json::to_string(planned)?;
        let operation_json = operations
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let observation_bytes = crate::rename_observation::serialize_observation(observations)?;
        let observation_json = std::str::from_utf8(&observation_bytes)
            .map_err(|_| JournalError::Invariant("reserved observation encoding"))?;
        let existing: Option<String> = tx
            .query_row("SELECT value FROM local_state WHERE key=?1", [KEY], |row| {
                row.get(0)
            })
            .optional()?;
        if existing.is_some() {
            return Err(JournalError::Invariant(
                "existing reservation cannot be adopted",
            ));
        }
        let before = self
            .read_view()
            .audit_local_commit_capacity(&planned.space_id, bounds)?;
        verify_original_capacity_context(&exact_json, &before.rows)?;

        crate::storage_policy::local_commit::project(
            &before,
            crate::storage_policy::local_commit::Input {
                expected_root: Some(&baseline.root()?),
                manifest: planned,
                operations,
                operation_json: &operation_json,
                snapshot_json: &snapshot_json,
                timestamp,
                observation_json: Some(observation_json),
            },
        )?;
        for content in stored
            .planned
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &content.chunks {
                self.require_cas_access(&chunk.content_id)?;
            }
        }
        let marked_ids = stored
            .planned
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| content.chunks.iter().map(|chunk| chunk.content_id.as_str()))
            .collect::<std::collections::BTreeSet<_>>();
        let mut mark_query = tx.prepare_cached(
            "SELECT content_id FROM gc_marks m WHERE NOT EXISTS(SELECT 1 FROM gc_cancellations c WHERE c.mark_id=m.mark_id) AND NOT EXISTS(SELECT 1 FROM gc_invalidations i WHERE i.mark_id=m.mark_id)",
        )?;
        let marked = mark_query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if marked.iter().any(|id| marked_ids.contains(id.as_str())) {
            return Err(JournalError::Invariant(
                "planned original content already marked for GC",
            ));
        }
        drop(mark_query);
        tx.execute(
            "INSERT INTO local_state VALUES (?1,?2)",
            params![KEY, exact_json],
        )?;
        liability::insert(&tx, &exact_json)?;
        phase_chain::insert(&tx, &exact_json)?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&planned.space_id, bounds)?;
        if !after.report.within_accounted_limits()
            || after.rows.len() != before.rows.len() + 3
            || before.rows.iter().any(|row| {
                !after.rows.iter().any(|other| {
                    row.table() == other.table()
                        && row.primary_key() == other.primary_key()
                        && row.columns() == other.columns()
                })
            })
        {
            return Err(JournalError::Invariant(
                "original reservation exact row receipt",
            ));
        }
        tx.commit()?;
        Ok(OriginalLocalHistoryReservation {
            exact_json,
            attempt: stored.attempt,
            original_issued_phases: std::sync::Mutex::new(Vec::with_capacity(4)),
            issuer: self.original_local_history_issuer.clone(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_original_reserved_history(
        &mut self,
        reservation: OriginalLocalHistoryReservation,
        baseline: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
        observations: &RenameObservationMap,
        max: usize,
    ) -> Result<OriginalReservedHistoryCommitReceipt> {
        let (history, original_phase_chain) = self.commit_local_reserved_receipted(
            baseline,
            manifest,
            operations,
            timestamp,
            Some((observations, max)),
            Some(&reservation),
        )?;
        Ok(OriginalReservedHistoryCommitReceipt::issued(
            history,
            reservation,
            original_phase_chain.ok_or(JournalError::Invariant(
                "original commit complete phase receipt absent",
            ))?,
        ))
    }
}

mod reserved_receipt;
pub use reserved_receipt::OriginalReservedHistoryCommitReceipt;

pub(crate) fn verify_original_capacity_context(
    json: &str,
    rows: &[crate::JournalStoredRow],
) -> Result<()> {
    let stored: Stored = serde_json::from_str(json)?;
    if rows
        .iter()
        .any(|row| row.table() == "local_state" && row.primary_key() == [KEY.to_owned()])
    {
        liability::verify_pending_rows(json, rows)?;
    }
    stored.validate(sync_extend_core_model::limits::MAX_ENTRIES)?;
    fn field<'a>(row: &'a crate::JournalStoredRow, name: &str) -> Result<&'a str> {
        match row
            .columns()
            .iter()
            .find(|column| column.name == name)
            .map(|column| &column.value)
        {
            Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value),
            _ => Err(JournalError::Invariant(
                "original reservation context text required",
            )),
        }
    }
    let state = |key: &str| -> Result<&str> {
        let row = rows
            .iter()
            .find(|row| row.table() == "local_state" && row.primary_key() == [key.to_owned()])
            .ok_or(JournalError::Invariant(
                "original reservation identity row missing",
            ))?;
        field(row, "value")
    };
    let space = state("space_id")?;
    let device = state("device_id")?;
    let worktree = state("worktree")?;
    let baseline = stored.baseline.root()?;
    let current = rows
        .iter()
        .find(|row| row.table() == "current_manifests" && row.primary_key() == [space.to_owned()])
        .ok_or(JournalError::Invariant(
            "original reservation current row missing",
        ))?;
    let prior = rows
        .iter()
        .find(|row| row.table() == "rename_observations" && row.primary_key() == [space.to_owned()])
        .ok_or(JournalError::Invariant(
            "original reservation prior observation missing",
        ))?;
    let prior_observations: RenameObservationMap =
        serde_json::from_str(field(prior, "observation")?)?;
    prior_observations.validate(
        &stored.baseline,
        sync_extend_core_model::limits::MAX_ENTRIES,
    )?;
    if space != stored.baseline.space_id.as_str()
        || stored
            .operations
            .iter()
            .any(|operation| operation.payload.origin_device_id.as_str() != device)
        || worktree.is_empty()
        || stored.original_device.as_str() != device
        || stored.original_worktree_digest
            != sync_extend_core_model::ContentId::hash(worktree.as_bytes())
        || field(current, "snapshot_id")? != baseline.as_str()
        || prior_observations.scope.local_root_identity
            != stored.observations.scope.local_root_identity
        || prior_observations.scope.platform_epoch != stored.observations.scope.platform_epoch
        || prior_observations.entries.iter().any(|original| {
            !stored
                .observations
                .entries
                .iter()
                .any(|planned| planned == original)
        })
    {
        return Err(JournalError::Invariant(
            "original reservation foreign space device baseline or observations",
        ));
    }
    Ok(())
}

pub(crate) fn original_reserved_content(
    connection: &rusqlite::Connection,
) -> Result<std::collections::BTreeSet<sync_extend_core_model::ContentId>> {
    let _original_content_snapshot = if connection.is_autocommit() {
        Some(Transaction::new_unchecked(
            connection,
            TransactionBehavior::Deferred,
        )?)
    } else {
        None
    };
    let bytes: Option<String> = connection
        .query_row("SELECT value FROM local_state WHERE key=?1", [KEY], |row| {
            row.get(0)
        })
        .optional()?;
    validate_cancellation_connection(connection)?;
    validate_native_phase_connection(connection)?;
    let mut result = liability::protected_content(connection)?;
    if let Some(json) = bytes {
        liability::verify_pending_connection(connection, &json)?;
        persisted_charge(&json, sync_extend_core_model::limits::MAX_ENTRIES)?;
        let stored: Stored = serde_json::from_str(&json)?;
        for entry in stored.planned.entries.values() {
            if let Some(content) = &entry.content {
                for chunk in &content.chunks {
                    result.insert(chunk.content_id.clone());
                }
            }
        }
    }
    Ok(result)
}

pub(crate) fn original_reservation_legacy_charge(
    connection: &rusqlite::Connection,
) -> Result<TreeStorageCharge> {
    let json: Option<String> = connection
        .query_row("SELECT value FROM local_state WHERE key=?1", [KEY], |row| {
            row.get(0)
        })
        .optional()?;
    let mut terminal = validate_cancellation_connection(connection)?;
    let native = liability::legacy_charge(connection)?;
    terminal.rows = terminal
        .rows
        .checked_add(native.rows)
        .ok_or(JournalError::Invariant(
            "original native terminal legacy rows overflow",
        ))?;
    terminal.logical_bytes = terminal
        .logical_bytes
        .checked_add(native.logical_bytes)
        .ok_or(JournalError::Invariant(
            "original native terminal legacy bytes overflow",
        ))?;
    if let Some(json) = json {
        let mut charge = persisted_charge(&json, sync_extend_core_model::limits::MAX_ENTRIES)?;
        charge.rows = charge
            .rows
            .checked_add(1)
            .ok_or(JournalError::Invariant("legacy reservation row overflow"))?;
        charge.logical_bytes = charge
            .logical_bytes
            .checked_add(KEY.len() as u64 + json.len() as u64)
            .ok_or(JournalError::Invariant("legacy reservation byte overflow"))?;
        charge.rows = charge
            .rows
            .checked_add(terminal.rows)
            .ok_or(JournalError::Invariant(
                "original history total terminal rows overflow",
            ))?;
        charge.logical_bytes = charge
            .logical_bytes
            .checked_add(terminal.logical_bytes)
            .ok_or(JournalError::Invariant(
                "original history total terminal bytes overflow",
            ))?;
        Ok(charge)
    } else {
        Ok(terminal)
    }
}

mod cancel;
pub use cancel::OriginalHistoryCancellationReceipt;
#[allow(unused_imports)]
pub(crate) use cancel::{
    validate_connection as validate_cancellation_connection,
    validate_rows as validate_cancellation_rows,
};

mod diagnostics;
pub use diagnostics::OriginalLocalHistoryAttemptDiagnostic;

mod footprint;
pub use footprint::OriginalNativeCreateFootprint;

mod liability;
#[allow(unused_imports)]
pub(crate) use liability::validate_rows as validate_native_liability_rows;

#[allow(unused_imports)]
pub(crate) use liability::legacy_charge as validate_native_liability_connection;

#[cfg(target_os = "linux")]
mod phases;
#[cfg(target_os = "linux")]
pub use phases::OriginalNativePhaseObservationReceipt;

mod phase_evidence;
#[allow(unused_imports)]
pub(crate) use phase_evidence::{
    validate_connection as validate_native_phase_connection,
    validate_rows as validate_native_phase_rows,
};

mod phase_chain;
pub use phase_chain::OriginalNativePhaseChain;

mod commit;

pub(crate) use diagnostics::audit_recovered_attempt_rows;
