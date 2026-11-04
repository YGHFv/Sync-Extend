//! Immutable descriptions, not native admission or complete execution capacity.
use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, Journal, JournalError, Result,
    TreeRestoreHistoryReservation, TreeRestoreNativeReservation, TreeRestorePreparationIntent,
    MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use std::collections::BTreeSet;
use sync_extend_core_model::{
    limits,
    tree_restore::plan_tree_restore,
    tree_restore_execution_intent::{
        plan_tree_execution_intent, TreeExecutionIntent, TreeExecutionIntentInput,
        TreeExecutionIntentPlan,
    },
    tree_restore_history::{encode_history_record, plan_tree_restore_history},
    tree_restore_identity::plan_tree_restore_identities,
    Change, ContentId, EntryId, Manifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeExecutionDescriptionAudit {
    pub accounting: &'static str,
    pub intent: TreeExecutionIntent,
    pub intent_hash: ContentId,
    pub fingerprint: ContentId,
    pub step_count: usize,
    pub reserved_rows: u64,
    pub reserved_metadata_bytes: u64,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

pub(crate) struct Projection {
    pub(crate) plan: TreeExecutionIntentPlan,
    pub(crate) identity: sync_extend_core_model::tree_restore_identity::TreeIdentityPlan,
    json: String,
    steps: Vec<String>,
    audit: TreeExecutionDescriptionAudit,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn project(
    preparation: &TreeRestorePreparationIntent,
    history: &TreeRestoreHistoryReservation,
    native: &TreeRestoreNativeReservation,
    baseline: &Manifest,
    target: &Manifest,
    input: &TreeExecutionIntentInput,
    max: usize,
) -> Result<Projection> {
    if max == 0
        || max > limits::MAX_ENTRIES
        || preparation.transaction_id != input.transaction_id
        || input.preparation_hash != ContentId::hash(&serde_json::to_vec(preparation)?)
        || input.history_intent_hash != ContentId::hash(&serde_json::to_vec(&history.intent)?)
        || input.native_intent_hash != ContentId::hash(&serde_json::to_vec(&native.intent)?)
        || input.created_at_ms < native.intent.request.captured_at_ms
        || input.history_projection_hash != history.projection_hash
        || input.native_identity_fingerprint != native.identity_fingerprint
        || input.limits.max_steps > max
        || input.limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
    {
        return Err(JournalError::Invariant(
            "execution exact description binding",
        ));
    }
    sql_integer(input.created_at_ms)?;
    let tree = plan_tree_restore(&preparation.scope, baseline, target, preparation.limits)?;
    let history_plan = plan_tree_restore_history(&tree, baseline, target, &history.intent.history)?;
    let identity = plan_tree_restore_identities(
        &tree,
        baseline,
        &input.transaction_id,
        &input.preparation_hash,
        &native.intent.inventory,
        native.intent.request.limits,
    )?;
    let plan = plan_tree_execution_intent(
        &tree,
        baseline,
        target,
        &history_plan,
        &history.intent.history,
        &identity,
        input,
    )?;
    let json = String::from_utf8(encode_history_record(
        plan.intent(),
        input.limits.max_encoded_bytes,
    )?)
    .map_err(|_| JournalError::Invariant("execution description encoding"))?;
    // Coordinator: two 32-byte IDs, six 64-byte hashes, four 8-byte integers.
    let mut bytes = (json.len() as u64)
        .checked_add(480)
        .ok_or(JournalError::Invariant(
            "execution description byte overflow",
        ))?;
    let mut steps = Vec::new();
    for step in &plan.intent().steps {
        let encoded = encode_history_record(step, MAX_OPERATION_BYTES as u64)?;
        // Step: three 32-byte IDs, one 64-byte hash and one 8-byte index.
        bytes = bytes
            .checked_add(encoded.len() as u64)
            .and_then(|n| n.checked_add(168))
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant("execution description byte budget"))?;
        steps.push(
            String::from_utf8(encoded)
                .map_err(|_| JournalError::Invariant("execution step description encoding"))?,
        );
    }
    let reserved_rows = 1 + steps.len() as u64;
    if reserved_rows > max as u64 || bytes > max as u64 * 1024 {
        return Err(JournalError::Invariant(
            "execution description row/value budget",
        ));
    }
    let audit = TreeExecutionDescriptionAudit {
        accounting: "logical_exact_description_values_not_execution_terminal_or_sqlite_capacity",
        intent: plan.intent().clone(),
        intent_hash: ContentId::hash(json.as_bytes()),
        fingerprint: plan.fingerprint().clone(),
        step_count: steps.len(),
        reserved_rows,
        reserved_metadata_bytes: bytes,
        native_tree_verified: false,
        execution_admission_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    };
    Ok(Projection {
        plan,
        identity,
        json,
        steps,
        audit,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_description(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    history: Option<&TreeRestoreHistoryReservation>,
    native: Option<&TreeRestoreNativeReservation>,
    baseline: &Manifest,
    target: &Manifest,
    cancelled: Option<u64>,
    max: usize,
) -> Result<Option<TreeExecutionDescriptionAudit>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216
            THEN intent ELSE '' END FROM tree_restore_execution_intents WHERE transaction_id=?1",
            [preparation.transaction_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let stored: TreeExecutionIntent = serde_json::from_str(&json)?;
    let projection = project(
        preparation,
        history.ok_or(JournalError::Invariant(
            "execution description history missing",
        ))?,
        native.ok_or(JournalError::Invariant(
            "execution description native missing",
        ))?,
        baseline,
        target,
        &stored.input,
        max,
    )?;
    let a = &projection.audit;
    let i = &stored.input;
    let exact: bool = connection.query_row(
        "SELECT preparation_hash=?2 AND history_intent_hash=?3 AND native_intent_hash=?4
            AND history_projection_hash=?5 AND native_identity_fingerprint=?6 AND execution_id=?7
            AND intent=?8 AND intent_hash=?9 AND created_at_ms=?10 AND step_count=?11
            AND reserved_rows=?12 AND reserved_bytes=?13
         FROM tree_restore_execution_intents WHERE transaction_id=?1",
        params![
            i.transaction_id.as_str(),
            i.preparation_hash.as_str(),
            i.history_intent_hash.as_str(),
            i.native_intent_hash.as_str(),
            i.history_projection_hash.as_str(),
            i.native_identity_fingerprint.as_str(),
            i.execution_id.as_str(),
            projection.json,
            a.intent_hash.as_str(),
            sql_integer(i.created_at_ms)?,
            sql_integer(a.step_count as u64)?,
            sql_integer(a.reserved_rows)?,
            sql_integer(a.reserved_metadata_bytes)?
        ],
        |r| r.get(0),
    )?;
    if !exact || stored != a.intent || cancelled.is_some_and(|t| t < i.created_at_ms) {
        return Err(JournalError::Invariant(
            "execution description immutable mismatch",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT step_index,execution_id,coordinator_execution_id,
            CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216 THEN intent ELSE '' END,
            intent_hash FROM tree_restore_execution_step_intents WHERE transaction_id=?1 ORDER BY step_index")?;
    let mut rows = statement.query([i.transaction_id.as_str()])?;
    for (index, encoded) in projection.steps.iter().enumerate() {
        let row = rows.next()?.ok_or(JournalError::Invariant(
            "execution step description missing",
        ))?;
        if row.get::<_, i64>(0)? != sql_integer(index as u64)?
            || row.get::<_, String>(1)? != i.step_execution_ids[&index].as_str()
            || row.get::<_, String>(2)? != i.execution_id.as_str()
            || row.get::<_, String>(3)? != *encoded
            || row.get::<_, String>(4)? != ContentId::hash(encoded.as_bytes()).as_str()
        {
            return Err(JournalError::Invariant(
                "execution exact step description mismatch",
            ));
        }
    }
    if rows.next()?.is_some() {
        return Err(JournalError::Invariant("extra execution step description"));
    }
    Ok(Some(projection.audit))
}

fn audit_generations(
    connection: &Connection,
    input: &TreeExecutionIntentInput,
    max: usize,
) -> Result<()> {
    let ids: BTreeSet<_> = [&input.execution_id]
        .into_iter()
        .chain(input.step_execution_ids.values())
        .collect();
    let mut statement = connection.prepare(
        "SELECT execution_id FROM tree_restore_execution_intents
         UNION ALL SELECT execution_id FROM tree_restore_execution_step_intents
         UNION ALL SELECT transaction_id FROM tree_restore_preparations",
    )?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        let id: EntryId = row.get::<_, String>(0)?.parse()?;
        if count > max || ids.contains(&id) {
            return Err(JournalError::Invariant(
                "execution historical generation collision",
            ));
        }
    }
    audit_logical_generations(connection, &ids, max)
}

fn audit_logical_generations(
    connection: &Connection,
    ids: &BTreeSet<&EntryId>,
    max: usize,
) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(CAST(manifest AS BLOB)) BETWEEN 1 AND 16777216 THEN manifest ELSE '' END FROM snapshots")?;
    let mut rows = statement.query([])?;
    let mut visited = 0usize;
    while let Some(row) = rows.next()? {
        let manifest: Manifest = serde_json::from_str(&row.get::<_, String>(0)?)?;
        manifest.validate()?;
        visited = visited
            .checked_add(manifest.entries.len() + manifest.tombstones.len() + 1)
            .filter(|n| *n <= max)
            .ok_or(JournalError::Invariant("execution historical ID inventory"))?;
        if manifest
            .entries
            .keys()
            .chain(manifest.tombstones.keys())
            .any(|id| ids.contains(id))
        {
            return Err(JournalError::Invariant(
                "execution historical logical ID collision",
            ));
        }
    }
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(CAST(payload AS BLOB)) BETWEEN 1 AND 16777216 THEN payload ELSE '' END FROM operations")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        visited = visited
            .checked_add(1)
            .filter(|n| *n <= max)
            .ok_or(JournalError::Invariant("execution operation inventory"))?;
        let op: sync_extend_core_model::Operation =
            serde_json::from_str(&row.get::<_, String>(0)?)?;
        op.validate()?;
        let id = match &op.payload.change {
            Change::Put { entry } => &entry.entry_id,
            Change::Delete { entry_id } | Change::Rename { entry_id, .. } => entry_id,
        };
        if ids.contains(id) {
            return Err(JournalError::Invariant("execution operation ID collision"));
        }
    }
    Ok(())
}

pub(crate) fn audit_generation_inventory(connection: &Connection, max: usize) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT execution_id FROM tree_restore_execution_intents
         UNION ALL SELECT execution_id FROM tree_restore_execution_step_intents",
    )?;
    let mut rows = statement.query([])?;
    let mut ids = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let id: EntryId = row.get::<_, String>(0)?.parse()?;
        let is_transaction: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM tree_restore_preparations WHERE transaction_id=?1)",
            [id.as_str()],
            |r| r.get(0),
        )?;
        if ids.len() >= max || is_transaction || !ids.insert(id) {
            return Err(JournalError::Invariant(
                "execution description generation inventory",
            ));
        }
    }
    audit_logical_generations(connection, &ids.iter().collect(), max)
}

impl Journal {
    /// Persist descriptions only. Replay skips CAS and callbacks, never renews authority.
    pub fn with_tree_execution_description<T, E>(
        &self,
        input: &TreeExecutionIntentInput,
        max: usize,
        inspect: impl FnOnce(&TreeExecutionIntentPlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeExecutionDescriptionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("execution space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == input.transaction_id)
                .ok_or(JournalError::Invariant(
                    "unknown execution description owner",
                ))
        };
        let replay = |old: TreeExecutionDescriptionAudit| {
            if old.intent.input != *input {
                Err(JournalError::Invariant("execution description collision"))
            } else {
                Ok((None, old))
            }
        };
        let p = find()?;
        if let Some(old) = p.execution_description {
            return replay(old).map_err(E::from);
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("cancelled execution description owner").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let p = find()?;
        if let Some(old) = p.execution_description {
            let result = replay(old)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok(result);
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("execution description owner cancelled").into());
        }
        let baseline = self.snapshot(&space, &p.intent.scope.baseline_snapshot)?;
        let target = self.snapshot(&space, &p.intent.scope.target_snapshot)?;
        let projection = project(
            &p.intent,
            p.history_reservation
                .as_ref()
                .ok_or(JournalError::Invariant("execution history missing"))?,
            p.native_reservation
                .as_ref()
                .ok_or(JournalError::Invariant("execution native missing"))?,
            &baseline,
            &target,
            input,
            max,
        )?;
        audit_generations(&tx, input, max)?;
        let a = &projection.audit;
        check_storage_metadata_limit(&tx, max, a.reserved_rows, a.reserved_metadata_bytes)?;
        tx.execute("INSERT INTO tree_restore_execution_intents VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![input.transaction_id.as_str(),input.preparation_hash.as_str(),input.history_intent_hash.as_str(),
                input.native_intent_hash.as_str(),input.history_projection_hash.as_str(),input.native_identity_fingerprint.as_str(),
                input.execution_id.as_str(),projection.json,a.intent_hash.as_str(),sql_integer(input.created_at_ms)?,
                sql_integer(a.step_count as u64)?,sql_integer(a.reserved_rows)?,sql_integer(a.reserved_metadata_bytes)?]).map_err(JournalError::from)?;
        for (index, json) in projection.steps.iter().enumerate() {
            tx.execute(
                "INSERT INTO tree_restore_execution_step_intents VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    input.transaction_id.as_str(),
                    sql_integer(index as u64)?,
                    input.step_execution_ids[&index].as_str(),
                    input.execution_id.as_str(),
                    json,
                    ContentId::hash(json.as_bytes()).as_str()
                ],
            )
            .map_err(JournalError::from)?;
        }
        let held = inspect(&projection.plan)?;
        self.audit_gc_owners(&space, max)?;
        let final_audit = find()?
            .execution_description
            .ok_or(JournalError::Invariant("execution description disappeared"))?;
        if final_audit != projection.audit {
            return Err(
                JournalError::Invariant("execution description changed during inspection").into(),
            );
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), final_audit))
    }
}
