use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeRestorePreparationIntent, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{
    tree_restore::{plan_tree_restore, TreeRestorePlan},
    tree_restore_history::{
        encode_history_record, plan_tree_restore_history, TreeRestoreHistoryFootprint,
        TreeRestoreHistoryInput, TreeRestoreHistoryPlan,
    },
    Change, ContentId, EntryId, Manifest, Operation, SnapshotId, VersionVector,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreHistoryIntent {
    pub transaction_id: EntryId,
    pub preparation_hash: ContentId,
    pub history: TreeRestoreHistoryInput,
}

/// Immutable capacity projection, not allocated log sequences or execution authority.
/// A cancelled preparation can share this projection with a later, distinct owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreHistoryReservation {
    pub accounting: &'static str,
    pub intent: TreeRestoreHistoryIntent,
    pub projection_hash: ContentId,
    pub final_snapshot_id: SnapshotId,
    pub first_seq: u64,
    pub last_seq: u64,
    pub history_footprint: TreeRestoreHistoryFootprint,
    pub reserved_rows: u64,
    pub reserved_metadata_bytes: u64,
    pub history_component_capacity_verified: bool,
    pub final_handoff_capacity_verified: bool,
    pub execution_admission_available: bool,
    pub native_tree_verified: bool,
    pub tree_atomic: bool,
}

struct Projection {
    plan: TreeRestoreHistoryPlan,
    json: String,
    audit: TreeRestoreHistoryReservation,
}

fn project(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    tree: &TreeRestorePlan,
    intent: &TreeRestoreHistoryIntent,
    max: usize,
) -> Result<Projection> {
    if intent.transaction_id != preparation.transaction_id
        || intent.preparation_hash != ContentId::hash(&serde_json::to_vec(preparation)?)
        || intent.history.created_at_ms < preparation.prepared_at_ms
        || intent.history.limits.max_rows > max as u64
    {
        return Err(JournalError::Invariant(
            "tree history preparation binding mismatch",
        ));
    }
    let baseline = audit_snapshot(
        connection,
        &preparation.scope.space_id,
        &preparation.scope.baseline_snapshot,
    )?;
    let target = audit_snapshot(
        connection,
        &preparation.scope.space_id,
        &preparation.scope.target_snapshot,
    )?;
    let plan =
        plan_tree_restore_history(tree, &baseline.manifest, &target.manifest, &intent.history)?;
    let json = String::from_utf8(encode_history_record(intent, MAX_OPERATION_BYTES as u64)?)
        .map_err(|_| JournalError::Invariant("tree history encoding"))?;
    let reserved_rows = plan.footprint().row_writes + 1;
    // Exact intent row: six identifiers and five SQLite integer fields.
    let reserved_metadata_bytes = plan
        .footprint()
        .metadata_bytes
        .checked_add(json.len() as u64 + 392)
        .ok_or(JournalError::Invariant("tree history reservation overflow"))?;
    if reserved_rows > max as u64 || reserved_metadata_bytes > max as u64 * 1024 {
        return Err(JournalError::Invariant("tree history reservation budget"));
    }
    let audit = TreeRestoreHistoryReservation {
        accounting: "logical_history_row_values_not_sqlite_allocation_or_complete_handoff",
        intent: intent.clone(),
        projection_hash: plan.fingerprint().clone(),
        final_snapshot_id: plan.snapshot_id().clone(),
        first_seq: plan.operations()[0].payload.origin_seq,
        last_seq: plan
            .operations()
            .last()
            .expect("nonempty checked")
            .payload
            .origin_seq,
        history_footprint: plan.footprint().clone(),
        reserved_rows,
        reserved_metadata_bytes,
        history_component_capacity_verified: true,
        final_handoff_capacity_verified: false,
        execution_admission_available: false,
        native_tree_verified: false,
        tree_atomic: false,
    };
    Ok(Projection { plan, json, audit })
}

/// Revalidate actual causal metadata and ALL historical entry IDs under the gate.
fn audit_history_inputs(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    projection: &Projection,
    max: usize,
) -> Result<()> {
    let intent = &projection.audit.intent;
    let space = &preparation.scope.space_id;
    let baseline =
        audit_snapshot(connection, space, &preparation.scope.baseline_snapshot)?.manifest;
    let device: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(value AS BLOB))=64 THEN value ELSE '' END
             FROM local_state WHERE key='device_id'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if device.as_deref() != Some(intent.history.origin_device_id.as_str()) {
        return Err(JournalError::Invariant("tree history origin is not local"));
    }
    let mut cursors = VersionVector::default();
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(CAST(space_id AS BLOB))=32 THEN space_id ELSE '' END,
            CASE WHEN length(CAST(device_id AS BLOB))=64 THEN device_id ELSE '' END,
            contiguous_seq FROM receive_cursors ORDER BY device_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let stored_space: String = row.get(0)?;
        let device: String = row.get(1)?;
        let seq: i64 = row.get(2)?;
        if stored_space != space.as_str() || seq <= 0 || cursors.0.len() >= 1024 {
            return Err(JournalError::Invariant("tree history cursor mismatch"));
        }
        if cursors.0.insert(device.parse()?, seq as u64).is_some() {
            return Err(JournalError::Invariant("duplicate tree history cursor"));
        }
    }
    if cursors != baseline.version_vector {
        return Err(JournalError::Invariant(
            "tree history baseline cursor mismatch",
        ));
    }
    let fresh: BTreeSet<_> = intent.history.fresh_entry_ids.values().collect();
    let mut seen = VersionVector::default();
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(CAST(op_id AS BLOB))=64 THEN op_id ELSE '' END,
            CASE WHEN length(CAST(space_id AS BLOB))=32 THEN space_id ELSE '' END,
            CASE WHEN length(CAST(origin_device_id AS BLOB))=64 THEN origin_device_id ELSE '' END,origin_seq,
            CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 16777216
                THEN payload ELSE '' END,state
         FROM operations ORDER BY origin_device_id,origin_seq",
    )?;
    let mut rows = statement.query([])?;
    let mut inventory = 0usize;
    let mut seen_ops = BTreeSet::new();
    while let Some(row) = rows.next()? {
        inventory += 1;
        if inventory > max {
            return Err(JournalError::Invariant("tree history operation inventory"));
        }
        let json: String = row.get(4)?;
        let op: Operation = serde_json::from_str(&json)?;
        op.validate()?;
        let p = &op.payload;
        if p.space_id != *space
            || p.space_id.as_str() != row.get::<_, String>(1)?
            || op.op_id.as_str() != row.get::<_, String>(0)?
            || p.origin_device_id.as_str() != row.get::<_, String>(2)?
            || sql_integer(p.origin_seq)? != row.get::<_, i64>(3)?
            || row.get::<_, String>(5)? != "materialized"
            || p.origin_seq != seen.get(&p.origin_device_id) + 1
            || p.origin_seq > baseline.version_vector.get(&p.origin_device_id)
            || !baseline.version_vector.dominates(&p.causal)
            || p.created_at_ms > intent.history.created_at_ms
            || !seen_ops.insert(op.op_id.clone())
        {
            return Err(JournalError::Invariant("tree history operation mismatch"));
        }
        let id = match &p.change {
            Change::Put { entry } => &entry.entry_id,
            Change::Delete { entry_id } | Change::Rename { entry_id, .. } => entry_id,
        };
        if fresh.contains(id) {
            return Err(JournalError::Invariant(
                "tree history logical ID already used",
            ));
        }
        seen.observe(p.origin_device_id.clone(), p.origin_seq);
    }
    if seen != baseline.version_vector {
        return Err(JournalError::Invariant("tree history operation gap"));
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(CAST(snapshot_id AS BLOB))=64 THEN snapshot_id ELSE '' END,
            CASE WHEN length(CAST(space_id AS BLOB))=32 THEN space_id ELSE '' END,
            CASE WHEN length(CAST(manifest AS BLOB)) BETWEEN 1 AND 16777216
                THEN manifest ELSE '' END FROM snapshots ORDER BY snapshot_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let json: String = row.get(2)?;
        let manifest: Manifest = serde_json::from_str(&json)?;
        inventory = inventory
            .checked_add(1 + manifest.entries.len() + manifest.tombstones.len())
            .ok_or(JournalError::Invariant("tree history input overflow"))?;
        for file in manifest.entries.values().filter_map(|e| e.content.as_ref()) {
            inventory = inventory
                .checked_add(file.chunks.len())
                .ok_or(JournalError::Invariant("tree history input overflow"))?;
        }
        if inventory > max
            || manifest.space_id != *space
            || manifest.space_id.as_str() != row.get::<_, String>(1)?
            || manifest.root()?.as_str() != row.get::<_, String>(0)?
            || manifest.root()? == *projection.plan.snapshot_id()
            || manifest
                .entries
                .keys()
                .chain(manifest.tombstones.keys())
                .any(|id| fresh.contains(id))
        {
            return Err(JournalError::Invariant(
                "tree history snapshot or fresh ID mismatch",
            ));
        }
    }
    Ok(())
}

pub(crate) fn audit_history(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    tree: &TreeRestorePlan,
    cancelled_at_ms: Option<u64>,
    max: usize,
) -> Result<Option<TreeRestoreHistoryReservation>> {
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(CAST(preparation_hash AS BLOB))=64 THEN preparation_hash ELSE '' END,
            CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216 THEN intent ELSE '' END,
            CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END,
            CASE WHEN length(CAST(projection_hash AS BLOB))=64 THEN projection_hash ELSE '' END,
            CASE WHEN length(CAST(final_snapshot_id AS BLOB))=64 THEN final_snapshot_id ELSE '' END,
            CASE WHEN length(CAST(origin_device_id AS BLOB))=64 THEN origin_device_id ELSE '' END,created_at_ms,
            first_seq,last_seq,reserved_rows,reserved_bytes
         FROM tree_restore_histories WHERE transaction_id=?1",
    )?;
    let mut rows = statement.query([preparation.transaction_id.as_str()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let json: String = row.get(1)?;
    let intent: TreeRestoreHistoryIntent = serde_json::from_str(&json)?;
    let projected = project(connection, preparation, tree, &intent, max)?;
    let a = &projected.audit;
    if projected.json != json
        || intent.preparation_hash.as_str() != row.get::<_, String>(0)?
        || ContentId::hash(json.as_bytes()).as_str() != row.get::<_, String>(2)?
        || a.projection_hash.as_str() != row.get::<_, String>(3)?
        || a.final_snapshot_id.as_str() != row.get::<_, String>(4)?
        || intent.history.origin_device_id.as_str() != row.get::<_, String>(5)?
        || sql_integer(intent.history.created_at_ms)? != row.get::<_, i64>(6)?
        || sql_integer(a.first_seq)? != row.get::<_, i64>(7)?
        || sql_integer(a.last_seq)? != row.get::<_, i64>(8)?
        || sql_integer(a.reserved_rows)? != row.get::<_, i64>(9)?
        || sql_integer(a.reserved_metadata_bytes)? != row.get::<_, i64>(10)?
        || cancelled_at_ms.is_some_and(|t| t < intent.history.created_at_ms)
    {
        return Err(JournalError::Invariant(
            "tree history immutable projection mismatch",
        ));
    }
    if cancelled_at_ms.is_none() {
        audit_history_inputs(connection, preparation, &projected, max)?;
    }
    Ok(Some(projected.audit))
}

impl Journal {
    /// Reserve only NEW history metadata capacity; the callback cannot admit a step.
    /// Exact replay is metadata-only and never invokes the callback or changes pins.
    pub fn with_tree_restore_history<T, E>(
        &self,
        intent: &TreeRestoreHistoryIntent,
        max: usize,
        inspect: impl FnOnce(&TreeRestoreHistoryPlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeRestoreHistoryReservation), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree history space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == intent.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree history preparation"))
        };
        let replay = |old: TreeRestoreHistoryReservation| {
            if old.intent != *intent {
                Err(JournalError::Invariant("tree history intent collision"))
            } else {
                Ok((None, old))
            }
        };
        let preparation = find()?;
        if let Some(old) = preparation.history_reservation {
            return replay(old).map_err(E::from);
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("cancelled tree history preparation").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let preparation = find()?;
        if let Some(old) = preparation.history_reservation {
            let result = replay(old)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok(result);
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("tree history preparation cancelled").into());
        }
        let baseline = self.snapshot(&space, &preparation.intent.scope.baseline_snapshot)?;
        let target = self.snapshot(&space, &preparation.intent.scope.target_snapshot)?;
        let tree = plan_tree_restore(
            &preparation.intent.scope,
            &baseline,
            &target,
            preparation.intent.limits,
        )
        .map_err(JournalError::from)?;
        let projected = project(&tx, &preparation.intent, &tree, intent, max)?;
        audit_history_inputs(&tx, &preparation.intent, &projected, max)?;
        let a = &projected.audit;
        check_storage_metadata_limit(&tx, max, a.reserved_rows, a.reserved_metadata_bytes)?;
        tx.execute(
            "INSERT INTO tree_restore_histories VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                intent.transaction_id.as_str(),
                intent.preparation_hash.as_str(),
                projected.json,
                ContentId::hash(projected.json.as_bytes()).as_str(),
                a.projection_hash.as_str(),
                a.final_snapshot_id.as_str(),
                intent.history.origin_device_id.as_str(),
                sql_integer(intent.history.created_at_ms)?,
                sql_integer(a.first_seq)?,
                sql_integer(a.last_seq)?,
                sql_integer(a.reserved_rows)?,
                sql_integer(a.reserved_metadata_bytes)?,
            ],
        )
        .map_err(JournalError::from)?;
        let held = inspect(&projected.plan)?;
        self.audit_gc_owners(&space, max)?;
        let audit = find()?.history_reservation.ok_or(JournalError::Invariant(
            "tree history reservation disappeared",
        ))?;
        if audit != projected.audit {
            return Err(JournalError::Invariant("tree history changed during inspection").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }
}
