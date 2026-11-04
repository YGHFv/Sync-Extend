use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    limits,
    tree_restore::{
        plan_tree_restore, TreeRestoreLimits, TreeRestorePlan, TreeRestoreScope, TreeRestoreStep,
    },
    ContentId, EntryId, Manifest, SpaceId,
};

const TERMINAL_BYTES: u64 = 4096;
const STEP_RESERVE_BYTES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestorePreparationIntent {
    pub transaction_id: EntryId,
    pub scope: TreeRestoreScope,
    pub limits: TreeRestoreLimits,
    pub prepared_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestorePreparation {
    pub intent: TreeRestorePreparationIntent,
    pub steps: Vec<TreeRestoreStep>,
    pub state: &'static str,
    pub cancelled_at_ms: Option<u64>,
    pub reserved_rows: u64,
    pub reserved_metadata_bytes: u64,
    pub target_logical_bytes: u64,
    pub retained_and_staging_bytes: u64,
    pub exact_input_pins_verified: bool,
    pub writer_gate_held: bool,
    pub content_hashes_verified: bool,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub executor_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
    pub remote_backup_complete: bool,
    pub history_reservation: Option<crate::TreeRestoreHistoryReservation>,
    pub native_reservation: Option<crate::TreeRestoreNativeReservation>,
    pub execution_description: Option<crate::TreeExecutionDescriptionAudit>,
    pub execution_records: Option<crate::TreeExecutionRecordsAudit>,
    pub original_pins: Option<crate::TreeOriginalPinsAudit>,
    pub owner_description: Option<crate::TreeOwnerDescriptionAudit>,
}

struct PreparedPlan {
    plan: TreeRestorePlan,
    chunks: BTreeMap<ContentId, u32>,
    json: String,
    steps: Vec<String>,
    input_inventory: usize,
    reserved_rows: u64,
    reserved_bytes: u64,
}

impl TreeRestorePreparationIntent {
    fn validate_bounds(&self, max: usize) -> Result<()> {
        sql_integer(self.prepared_at_ms)?;
        if max == 0
            || max > limits::MAX_ENTRIES
            || self.limits.max_entries > limits::MAX_ENTRIES
            || self.limits.max_steps > limits::MAX_ENTRIES
            || self.limits.max_chunk_visits > limits::MAX_CHUNKS
            || self.limits.max_plan_bytes > MAX_OPERATION_BYTES as u64
        {
            return Err(JournalError::Invariant("tree restore preparation bounds"));
        }
        sql_integer(self.limits.max_target_bytes)?;
        sql_integer(self.limits.max_retained_and_staging_bytes)?;
        Ok(())
    }

    fn plan(&self, connection: &Connection, max: usize, active: bool) -> Result<PreparedPlan> {
        self.validate_bounds(max)?;
        let baseline = audit_snapshot(
            connection,
            &self.scope.space_id,
            &self.scope.baseline_snapshot,
        )?;
        let target = audit_snapshot(
            connection,
            &self.scope.space_id,
            &self.scope.target_snapshot,
        )?;
        if baseline.state != "materialized"
            || target.state != "materialized"
            || baseline.created_at_ms > self.prepared_at_ms
            || target.created_at_ms > self.prepared_at_ms
        {
            return Err(JournalError::Invariant(
                "tree restore retained input mismatch",
            ));
        }
        if active {
            for root in [&self.scope.baseline_snapshot, &self.scope.target_snapshot] {
                crate::snapshot_pruning::require_unpruned(connection, root)?;
            }
            let current: Option<String> = connection
                .query_row(
                    "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
                    [self.scope.space_id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if current.as_deref() != Some(self.scope.baseline_snapshot.as_str()) {
                return Err(JournalError::Invariant("tree restore baseline changed"));
            }
        }
        let plan = plan_tree_restore(
            &self.scope,
            &baseline.manifest,
            &target.manifest,
            self.limits,
        )?;
        let mut input_inventory = 0usize;
        for manifest in [&baseline.manifest, &target.manifest] {
            input_inventory = input_inventory
                .checked_add(manifest.entries.len())
                .and_then(|n| n.checked_add(manifest.tombstones.len()))
                .ok_or(JournalError::Invariant(
                    "tree restore input inventory overflow",
                ))?;
            for file in manifest.entries.values().filter_map(|e| e.content.as_ref()) {
                input_inventory = input_inventory.checked_add(file.chunks.len()).ok_or(
                    JournalError::Invariant("tree restore input inventory overflow"),
                )?;
            }
        }
        if input_inventory > max {
            return Err(JournalError::Invariant(
                "tree restore input inventory limit",
            ));
        }
        let chunks = input_chunks([&baseline.manifest, &target.manifest]);
        let json = serde_json::to_string(self)?;
        let mut encoded_bytes = json.len() as u64;
        let mut steps = Vec::new();
        for step in plan.steps() {
            let json = serde_json::to_string(step)?;
            if json.len() > MAX_OPERATION_BYTES {
                return Err(JournalError::Invariant("tree restore step byte limit"));
            }
            encoded_bytes = encoded_bytes
                .checked_add(json.len() as u64)
                .ok_or(JournalError::Invariant("tree restore metadata overflow"))?;
            steps.push(json);
        }
        let reserved_bytes = encoded_bytes
            .checked_add(TERMINAL_BYTES + STEP_RESERVE_BYTES * steps.len() as u64)
            .and_then(|n| n.checked_add(128 * chunks.len() as u64))
            .ok_or(JournalError::Invariant("tree restore metadata overflow"))?
            .max(plan.conservative_plan_bytes());
        let reserved_rows = 2 + 3 * steps.len() as u64 + chunks.len() as u64;
        if json.len() > MAX_OPERATION_BYTES
            || reserved_bytes > self.limits.max_plan_bytes
            || reserved_rows > max as u64
            || reserved_bytes > max as u64 * 1024
        {
            return Err(JournalError::Invariant(
                "tree restore journal reservation limit",
            ));
        }
        Ok(PreparedPlan {
            plan,
            chunks,
            json,
            steps,
            input_inventory,
            reserved_rows,
            reserved_bytes,
        })
    }
}

fn input_chunks(manifests: [&Manifest; 2]) -> BTreeMap<ContentId, u32> {
    manifests
        .into_iter()
        .flat_map(|m| m.entries.values())
        .filter_map(|e| e.content.as_ref())
        .flat_map(|f| &f.chunks)
        .map(|c| (c.content_id.clone(), c.length))
        .collect()
}

impl Journal {
    /// Metadata-only preparation audit; no CAS bytes or native tree are certified.
    pub fn tree_restore_preparations(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Vec<TreeRestorePreparation>> {
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let audits = self.audit_tree_restore_preparations(space, max)?;
            tx.commit()?;
            return Ok(audits);
        }
        self.audit_tree_restore_preparations(space, max)
    }

    fn audit_tree_restore_preparations(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Vec<TreeRestorePreparation>> {
        if max == 0 || max > limits::MAX_ENTRIES {
            return Err(JournalError::Invariant(
                "tree restore audit inventory limit",
            ));
        }
        self.check_storage_metadata_limit(max)?;
        if self.state("space_id")?.as_deref() != Some(space.as_str()) {
            return Err(JournalError::Invariant("tree restore space mismatch"));
        }
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM tree_restore_steps s
                LEFT JOIN tree_restore_preparations p USING(transaction_id) WHERE p.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_objects o
                LEFT JOIN tree_restore_preparations p USING(transaction_id) WHERE p.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_cancellations c
                LEFT JOIN tree_restore_preparations p USING(transaction_id) WHERE p.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_histories h
                LEFT JOIN tree_restore_preparations p USING(transaction_id) WHERE p.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_native_reservations n
                LEFT JOIN tree_restore_preparations p USING(transaction_id)
                LEFT JOIN tree_restore_histories h USING(transaction_id)
                WHERE p.transaction_id IS NULL OR h.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_execution_intents e
                LEFT JOIN tree_restore_preparations p USING(transaction_id)
                LEFT JOIN tree_restore_histories h USING(transaction_id)
                LEFT JOIN tree_restore_native_reservations n USING(transaction_id)
                WHERE p.transaction_id IS NULL OR h.transaction_id IS NULL OR n.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents s
                LEFT JOIN tree_restore_execution_intents e USING(transaction_id)
                WHERE e.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_execution_records r
                LEFT JOIN tree_restore_execution_step_intents s
                    ON s.transaction_id=r.transaction_id AND s.step_index=r.step_index
                WHERE s.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_original_reservations h
                LEFT JOIN tree_restore_execution_intents c USING(transaction_id)
                WHERE c.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_original_owners o
                LEFT JOIN tree_restore_original_reservations h USING(transaction_id)
                LEFT JOIN tree_restore_execution_step_intents s
                    ON s.transaction_id=o.transaction_id AND s.step_index=o.step_index
                WHERE h.transaction_id IS NULL OR s.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_original_objects p
                LEFT JOIN tree_restore_original_owners o
                    ON o.transaction_id=p.transaction_id AND o.step_index=p.step_index
                WHERE o.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_owner_intents o
                LEFT JOIN tree_restore_original_reservations h USING(transaction_id)
                WHERE h.transaction_id IS NULL)
             OR EXISTS(SELECT 1 FROM tree_restore_owner_records r
                LEFT JOIN tree_restore_owner_intents o USING(transaction_id)
                WHERE o.transaction_id IS NULL)",
            [],
            |r| r.get(0),
        )?;
        if orphan {
            return Err(JournalError::Invariant("orphan tree restore metadata"));
        }
        crate::tree_restore_execution_intent::audit_generation_inventory(&self.connection, max)?;
        let (native_rows, native_bindings): (i64, i64) = self.connection.query_row(
            "SELECT count(*),coalesce(sum(binding_count),0) FROM tree_restore_native_reservations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if native_rows < 0
            || native_bindings < 0
            || native_rows as u64 > max as u64
            || native_bindings as u64 > max as u64
        {
            return Err(JournalError::Invariant(
                "tree native aggregate inventory limit",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT CASE WHEN length(CAST(transaction_id AS BLOB))=32 THEN transaction_id ELSE '' END,
                CASE WHEN length(CAST(space_id AS BLOB))=32 THEN space_id ELSE '' END,
                CASE WHEN length(CAST(baseline_root AS BLOB))=64 THEN baseline_root ELSE '' END,
                CASE WHEN length(CAST(target_root AS BLOB))=64 THEN target_root ELSE '' END,
                CASE WHEN length(CAST(intent AS BLOB))<=16777216 THEN intent ELSE '' END,
                CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END,
                prepared_at_ms,step_count,reserved_rows,reserved_bytes
             FROM tree_restore_preparations ORDER BY transaction_id",
        )?;
        let mut rows = statement.query([])?;
        let mut audits = Vec::new();
        let mut active_count = 0;
        let mut inventory = 0usize;
        let mut lengths = BTreeMap::new();
        let mut actual_native_bindings = 0usize;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let json: String = row.get(4)?;
            let hash: String = row.get(5)?;
            let intent: TreeRestorePreparationIntent = serde_json::from_str(&json)?;
            if intent.transaction_id.as_str() != id
                || intent.scope.space_id != *space
                || intent.scope.space_id.as_str() != row.get::<_, String>(1)?
                || intent.scope.baseline_snapshot.as_str() != row.get::<_, String>(2)?
                || intent.scope.target_snapshot.as_str() != row.get::<_, String>(3)?
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || sql_integer(intent.prepared_at_ms)? != row.get::<_, i64>(6)?
            {
                return Err(JournalError::Invariant(
                    "tree restore preparation integrity mismatch",
                ));
            }
            let terminal: Option<(String, i64)> = self.connection.query_row(
                "SELECT CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END,
                    cancelled_at_ms FROM tree_restore_cancellations WHERE transaction_id=?1",
                [&id], |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            let cancelled_at_ms = terminal
                .map(|(terminal_hash, time)| {
                    let time = u64::try_from(time)
                        .map_err(|_| JournalError::Invariant("tree restore cancellation time"))?;
                    if terminal_hash != hash || time < intent.prepared_at_ms {
                        return Err(JournalError::Invariant(
                            "tree restore cancellation mismatch",
                        ));
                    }
                    Ok(time)
                })
                .transpose()?;
            let active = cancelled_at_ms.is_none();
            let prepared = intent.plan(&self.connection, max, active)?;
            if prepared.json != json
                || sql_integer(prepared.steps.len() as u64)? != row.get::<_, i64>(7)?
                || sql_integer(prepared.reserved_rows)? != row.get::<_, i64>(8)?
                || sql_integer(prepared.reserved_bytes)? != row.get::<_, i64>(9)?
            {
                return Err(JournalError::Invariant(
                    "tree restore plan reservation mismatch",
                ));
            }
            inventory =
                inventory
                    .checked_add(prepared.input_inventory)
                    .ok_or(JournalError::Invariant(
                        "tree restore aggregate inventory overflow",
                    ))?;
            if inventory > max {
                return Err(JournalError::Invariant(
                    "tree restore aggregate input inventory limit",
                ));
            }
            let mut steps = self.connection.prepare(
                "SELECT step_index,CASE WHEN length(CAST(step AS BLOB))<=16777216 THEN step ELSE '' END,
                    CASE WHEN length(CAST(step_hash AS BLOB))=64 THEN step_hash ELSE '' END
                 FROM tree_restore_steps WHERE transaction_id=?1 ORDER BY step_index",
            )?;
            let mut stored = steps.query([&id])?;
            for (index, expected) in prepared.steps.iter().enumerate() {
                let row = stored
                    .next()?
                    .ok_or(JournalError::Invariant("tree restore step missing"))?;
                let step: String = row.get(1)?;
                if sql_integer(index as u64)? != row.get::<_, i64>(0)?
                    || *expected != step
                    || ContentId::hash(step.as_bytes()).as_str() != row.get::<_, String>(2)?
                {
                    return Err(JournalError::Invariant("tree restore exact step mismatch"));
                }
            }
            if stored.next()?.is_some() {
                return Err(JournalError::Invariant("extra tree restore step"));
            }
            let mut pins = self.connection.prepare(
                "SELECT CASE WHEN length(CAST(content_id AS BLOB))=64 THEN content_id ELSE '' END,
                    length FROM tree_restore_objects WHERE transaction_id=?1 ORDER BY content_id",
            )?;
            let mut pins = pins.query([&id])?;
            if active {
                for (chunk, length) in &prepared.chunks {
                    let row = pins
                        .next()?
                        .ok_or(JournalError::Invariant("tree restore pin missing"))?;
                    if row.get::<_, String>(0)? != chunk.as_str()
                        || row.get::<_, i64>(1)? != i64::from(*length)
                    {
                        return Err(JournalError::Invariant("tree restore exact pin mismatch"));
                    }
                    self.require_cas_access(chunk)?;
                    if lengths
                        .insert(chunk.clone(), *length)
                        .is_some_and(|old| old != *length)
                    {
                        return Err(JournalError::Invariant(
                            "tree restore chunk length mismatch",
                        ));
                    }
                }
                active_count += 1;
            }
            if pins.next()?.is_some() {
                return Err(JournalError::Invariant("extra tree restore pin"));
            }
            let history_reservation = crate::tree_restore_history::audit_history(
                &self.connection,
                &intent,
                &prepared.plan,
                cancelled_at_ms,
                max,
            )?;
            // Cancelled descriptions depend on immutable metadata, not retained content.
            let baseline =
                audit_snapshot(&self.connection, space, &intent.scope.baseline_snapshot)?.manifest;
            let native_reservation = crate::tree_restore_native_identity::audit_native(
                &self.connection,
                &intent,
                history_reservation.as_ref(),
                &prepared.plan,
                &baseline,
                cancelled_at_ms,
                max,
            )?;
            let target =
                audit_snapshot(&self.connection, space, &intent.scope.target_snapshot)?.manifest;
            let execution_description = crate::tree_restore_execution_intent::audit_description(
                &self.connection,
                &intent,
                history_reservation.as_ref(),
                native_reservation.as_ref(),
                &baseline,
                &target,
                cancelled_at_ms,
                max,
            )?;
            let execution_records = crate::tree_execution_records::audit_records(
                &self.connection,
                &intent,
                history_reservation.as_ref(),
                native_reservation.as_ref(),
                execution_description.as_ref(),
                &baseline,
                &target,
                cancelled_at_ms,
                max,
            )?;
            let original_pins = crate::tree_original_pins::audit_originals(
                self,
                &intent,
                history_reservation.as_ref(),
                native_reservation.as_ref(),
                execution_description.as_ref(),
                &baseline,
                &target,
                cancelled_at_ms,
                max,
            )?;
            let owner_description = crate::tree_owner_description::audit_owner(
                &self.connection,
                &intent,
                history_reservation.as_ref(),
                native_reservation.as_ref(),
                execution_description.as_ref(),
                original_pins.as_ref(),
                &baseline,
                &target,
                cancelled_at_ms,
                max,
            )?;
            if let Some(native) = &native_reservation {
                actual_native_bindings = actual_native_bindings
                    .checked_add(native.binding_count)
                    .filter(|n| *n <= max)
                    .ok_or(JournalError::Invariant(
                        "tree native actual aggregate limit",
                    ))?;
            }
            audits.push(TreeRestorePreparation {
                intent,
                steps: prepared.plan.steps().to_vec(),
                state: if active { "prepared" } else { "cancelled" },
                cancelled_at_ms,
                reserved_rows: prepared.reserved_rows,
                reserved_metadata_bytes: prepared.reserved_bytes,
                target_logical_bytes: prepared.plan.target_logical_bytes(),
                retained_and_staging_bytes: prepared.plan.retained_and_staging_bytes(),
                exact_input_pins_verified: active,
                writer_gate_held: active,
                content_hashes_verified: false,
                native_tree_verified: false,
                execution_admission_available: false,
                executor_available: false,
                final_handoff_capacity_verified: false,
                tree_atomic: false,
                remote_backup_complete: false,
                history_reservation,
                native_reservation,
                execution_description,
                execution_records,
                original_pins,
                owner_description,
            });
        }
        if actual_native_bindings as u64 != native_bindings as u64 {
            return Err(JournalError::Invariant(
                "tree native aggregate counter mismatch",
            ));
        }
        if active_count > 1 {
            return Err(JournalError::Invariant("multiple tree restore writers"));
        }
        if active_count != 0 {
            require_no_ordinary_writer(&self.connection, space)?;
        }
        Ok(audits)
    }

    pub fn require_no_tree_restore(&self, space: &SpaceId, max: usize) -> Result<()> {
        let any: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM tree_restore_preparations)
             OR EXISTS(SELECT 1 FROM tree_restore_steps)
             OR EXISTS(SELECT 1 FROM tree_restore_objects)
             OR EXISTS(SELECT 1 FROM tree_restore_cancellations)
             OR EXISTS(SELECT 1 FROM tree_restore_histories)
             OR EXISTS(SELECT 1 FROM tree_restore_native_reservations)
             OR EXISTS(SELECT 1 FROM tree_restore_execution_intents)
             OR EXISTS(SELECT 1 FROM tree_restore_execution_step_intents)
             OR EXISTS(SELECT 1 FROM tree_restore_execution_records)
             OR EXISTS(SELECT 1 FROM tree_restore_original_reservations)
             OR EXISTS(SELECT 1 FROM tree_restore_original_owners)
             OR EXISTS(SELECT 1 FROM tree_restore_original_objects)
             OR EXISTS(SELECT 1 FROM tree_restore_owner_intents)
             OR EXISTS(SELECT 1 FROM tree_restore_owner_records)",
            [],
            |r| r.get(0),
        )?;
        if !any {
            return Ok(());
        }
        if self
            .tree_restore_preparations(space, max)?
            .iter()
            .any(|p| p.writer_gate_held)
        {
            return Err(JournalError::Invariant(
                "prepared tree restore owns writer gate",
            ));
        }
        Ok(())
    }

    /// Reserve exact immutable inputs before any future native admission exists.
    /// The callback is read-only, not an executor; it and the CAS guard span commit.
    pub fn with_tree_restore_preparation<T, E>(
        &self,
        intent: &TreeRestorePreparationIntent,
        max: usize,
        inspect: impl FnOnce(&TreeRestorePreparationIntent) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeRestorePreparation), E>
    where
        E: From<JournalError>,
    {
        intent.validate_bounds(max)?;
        let find = || {
            Ok::<_, JournalError>(
                self.tree_restore_preparations(&intent.scope.space_id, max)?
                    .into_iter()
                    .find(|p| p.intent.transaction_id == intent.transaction_id),
            )
        };
        let replay = |old: TreeRestorePreparation| {
            if old.intent != *intent {
                Err(JournalError::Invariant(
                    "tree restore transaction ID collision",
                ))
            } else {
                Ok((None, old))
            }
        };
        if let Some(old) = find()? {
            return replay(old).map_err(E::from);
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&intent.scope.space_id, max)?;
        if let Some(old) = find()? {
            let result = replay(old)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok(result);
        }
        self.require_no_tree_restore(&intent.scope.space_id, max)?;
        require_no_ordinary_writer(&tx, &intent.scope.space_id)?;
        let prepared = intent.plan(&tx, max, true)?;
        for id in prepared.chunks.keys() {
            self.require_cas_access(id)?;
        }
        check_storage_metadata_limit(&tx, max, prepared.reserved_rows, prepared.reserved_bytes)?;
        tx.execute(
            "INSERT INTO tree_restore_preparations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                intent.transaction_id.as_str(),
                intent.scope.space_id.as_str(),
                intent.scope.baseline_snapshot.as_str(),
                intent.scope.target_snapshot.as_str(),
                prepared.json,
                ContentId::hash(prepared.json.as_bytes()).as_str(),
                sql_integer(intent.prepared_at_ms)?,
                sql_integer(prepared.steps.len() as u64)?,
                sql_integer(prepared.reserved_rows)?,
                sql_integer(prepared.reserved_bytes)?,
            ],
        )
        .map_err(JournalError::from)?;
        for (index, step) in prepared.steps.iter().enumerate() {
            tx.execute(
                "INSERT INTO tree_restore_steps VALUES (?1,?2,?3,?4)",
                params![
                    intent.transaction_id.as_str(),
                    sql_integer(index as u64)?,
                    step,
                    ContentId::hash(step.as_bytes()).as_str()
                ],
            )
            .map_err(JournalError::from)?;
        }
        for (id, length) in &prepared.chunks {
            tx.execute(
                "INSERT INTO tree_restore_objects VALUES (?1,?2,?3)",
                params![intent.transaction_id.as_str(), id.as_str(), length],
            )
            .map_err(JournalError::from)?;
        }
        self.audit_gc_owners(&intent.scope.space_id, max)?;
        let held = inspect(intent)?;
        self.audit_gc_owners(&intent.scope.space_id, max)?;
        let audit = find()?.ok_or(JournalError::Invariant(
            "tree restore preparation disappeared",
        ))?;
        if audit.intent != *intent || !audit.writer_gate_held {
            return Err(JournalError::Invariant(
                "tree restore preparation changed during inspection",
            )
            .into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }

    /// Only prepared metadata exists in this slice; cancellation admits no native action.
    pub fn cancel_tree_restore_preparation(
        &self,
        space: &SpaceId,
        id: &EntryId,
        cancelled_at_ms: u64,
        max: usize,
    ) -> Result<TreeRestorePreparation> {
        let find = || {
            self.tree_restore_preparations(space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == *id)
                .ok_or(JournalError::Invariant("unknown tree restore preparation"))
        };
        let old = find()?;
        if old.cancelled_at_ms.is_some() {
            return Ok(old);
        }
        sql_integer(cancelled_at_ms)?;
        if cancelled_at_ms < old.intent.prepared_at_ms {
            return Err(JournalError::Invariant(
                "tree restore cancellation precedes preparation",
            ));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_gc_owners(space, max)?;
        let old = find()?;
        if old.cancelled_at_ms.is_some() {
            tx.commit()?;
            return Ok(old);
        }
        let json = serde_json::to_string(&old.intent)?;
        tx.execute(
            "INSERT INTO tree_restore_cancellations VALUES (?1,?2,?3)",
            params![
                id.as_str(),
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(cancelled_at_ms)?
            ],
        )?;
        tx.execute(
            "DELETE FROM tree_restore_original_objects WHERE transaction_id=?1",
            [id.as_str()],
        )?;
        tx.execute(
            "DELETE FROM tree_restore_objects WHERE transaction_id=?1",
            [id.as_str()],
        )?;
        self.audit_gc_owners(space, max)?;
        let audit = find()?;
        tx.commit()?;
        Ok(audit)
    }
}

fn require_no_ordinary_writer(connection: &Connection, space: &SpaceId) -> Result<()> {
    let busy: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM publications WHERE space_id=?1 AND (state!='committed' OR cleaned=0))
         OR EXISTS(SELECT 1 FROM mutations WHERE space_id=?1
            AND state IN ('prepared','executing','quarantined','moved','replaced'))
         OR EXISTS(SELECT 1 FROM cleanup_plans WHERE space_id=?1 AND state='executing')",
        [space.as_str()], |r| r.get(0),
    )?;
    if busy {
        return Err(JournalError::Invariant(
            "ordinary writer blocks tree restore preparation",
        ));
    }
    Ok(())
}
