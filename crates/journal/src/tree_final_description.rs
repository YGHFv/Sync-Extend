//! Immutable final candidate descriptions, never native evidence or final commit.
use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeRestorePreparation, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    tree_execution_records::{audit_tree_execution_records, TreeExecutionRecordLimits},
    tree_final_description::{
        plan_tree_final_description, TreeFinalInput, TreeFinalIntent, TreeFinalLimits,
        TreeFinalPlan,
    },
    tree_original_reference::plan_tree_original_references,
    tree_owner_marker::{
        audit_tree_owner_records, plan_tree_owner, TreeOwnerLimits, TreeOwnerRecordLimits,
    },
    tree_restore::plan_tree_restore,
    tree_restore_history::{encode_history_record, plan_tree_restore_history},
    ContentId,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalDescriptionRequest {
    pub input: TreeFinalInput,
    pub limits: TreeFinalLimits,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeFinalDescriptionAudit {
    pub request: TreeFinalDescriptionRequest,
    pub intent: TreeFinalIntent,
    pub intent_hash: ContentId,
    pub metadata_bytes: u64,
    pub description_rows: u64,
    pub input_encoded_bytes: u64,
    pub peak_native_entries: usize,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub original_reference_release_available: bool,
    pub history_commit_available: bool,
    pub tree_atomic: bool,
}

pub(crate) fn project(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeFinalDescriptionRequest,
    max: usize,
) -> Result<TreeFinalPlan> {
    let input = &request.input;
    if request.limits.max_steps > max
        || request.limits.max_entries > max
        || request.limits.max_records > max
        || request.limits.max_reference_rows > max
    {
        return Err(JournalError::Invariant(
            "tree final description inventory bounds",
        ));
    }
    let history = p
        .history_reservation
        .as_ref()
        .ok_or(JournalError::Invariant("tree final history missing"))?;
    let native = p
        .native_reservation
        .as_ref()
        .ok_or(JournalError::Invariant("tree final native missing"))?;
    let execution = p
        .execution_description
        .as_ref()
        .ok_or(JournalError::Invariant("tree final execution missing"))?;
    let original = p.original_pins.as_ref().ok_or(JournalError::Invariant(
        "tree final original reservation missing",
    ))?;
    let owner = p
        .owner_description
        .as_ref()
        .ok_or(JournalError::Invariant("tree final owner missing"))?;
    let records = p.execution_records.as_ref().ok_or(JournalError::Invariant(
        "tree final step descriptions missing",
    ))?;
    if input.execution_intent_hash != execution.intent_hash
        || input.original_request_hash != ContentId::hash(&serde_json::to_vec(&original.request)?)
        || input.original_closure_hash != original.fingerprint
        || input.owner_intent_hash != owner.intent_hash
        || input.owner_records_hash != owner.fingerprint
        || input.step_records_hash != records.fingerprint
        || input.history_projection_hash != history.projection_hash
        || input.described_at_ms < original.request.reserved_at_ms
    {
        return Err(JournalError::Invariant(
            "tree final actual prerequisite binding",
        ));
    }
    let baseline = audit_snapshot(
        connection,
        &p.intent.scope.space_id,
        &p.intent.scope.baseline_snapshot,
    )?
    .manifest;
    let target = audit_snapshot(
        connection,
        &p.intent.scope.space_id,
        &p.intent.scope.target_snapshot,
    )?
    .manifest;
    let execution = crate::tree_restore_execution_intent::project(
        &p.intent,
        history,
        native,
        &baseline,
        &target,
        &execution.intent.input,
        max,
    )?;
    let tree = plan_tree_restore(&p.intent.scope, &baseline, &target, p.intent.limits)?;
    let history = plan_tree_restore_history(&tree, &baseline, &target, &history.intent.history)?;
    let originals = plan_tree_original_references(
        &execution.plan,
        &execution.identity,
        original.request.limits,
    )?;
    if originals.intents() != &original.originals
        || originals.fingerprint() != &original.fingerprint
    {
        return Err(JournalError::Invariant(
            "tree final actual originals mismatch",
        ));
    }
    let owner_plan = plan_tree_owner(
        &execution.plan,
        &execution.identity,
        &originals,
        &owner.intent.input,
        TreeOwnerLimits {
            max_steps: max,
            max_encoded_bytes: MAX_OPERATION_BYTES as u64,
        },
    )?;
    let owner_records = audit_tree_owner_records(
        &owner_plan,
        &owner.records,
        TreeOwnerRecordLimits {
            max_records: 8,
            max_encoded_bytes: MAX_OPERATION_BYTES as u64,
        },
    )?;
    let steps = audit_tree_execution_records(
        &execution.plan,
        &execution.identity,
        &records.records,
        TreeExecutionRecordLimits {
            max_records: max,
            max_encoded_bytes: MAX_OPERATION_BYTES as u64,
        },
    )?;
    Ok(plan_tree_final_description(
        &execution.plan,
        &execution.identity,
        &history,
        &originals,
        &owner_plan,
        &owner_records,
        &steps,
        input,
        request.limits,
    )?)
}
fn report(
    request: &TreeFinalDescriptionRequest,
    plan: &TreeFinalPlan,
    bytes: u64,
) -> TreeFinalDescriptionAudit {
    TreeFinalDescriptionAudit {
        request: request.clone(),
        intent: plan.intent().clone(),
        intent_hash: plan.intent_hash().clone(),
        metadata_bytes: bytes,
        description_rows: 1 + plan.intent().retained_originals.len() as u64,
        input_encoded_bytes: plan.input_encoded_bytes(),
        peak_native_entries: plan.peak_native_entries(),
        native_tree_verified: false,
        execution_admission_available: false,
        final_handoff_capacity_verified: false,
        original_reference_release_available: false,
        history_commit_available: false,
        tree_atomic: false,
    }
}
fn bytes(request: &TreeFinalDescriptionRequest, plan: &TreeFinalPlan) -> Result<u64> {
    let mut bytes = encode_history_record(request, MAX_OPERATION_BYTES as u64)?.len() as u64
        + plan.encoded_bytes()
        + 696;
    for description in plan.intent().retained_originals.values() {
        bytes = bytes
            .checked_add(
                encode_history_record(description, MAX_OPERATION_BYTES as u64)?.len() as u64 + 488,
            )
            .ok_or(JournalError::Invariant(
                "tree final description byte overflow",
            ))?;
    }
    Ok(bytes)
}

pub(crate) fn audit_final(
    connection: &Connection,
    p: &TreeRestorePreparation,
    max: usize,
) -> Result<Option<TreeFinalDescriptionAudit>> {
    let transaction = p.intent.transaction_id.as_str();
    let json:Option<String>=connection.query_row(
        "SELECT CASE WHEN length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216 THEN request ELSE '' END
         FROM tree_restore_final_descriptions WHERE transaction_id=?1",
        [transaction],|r|r.get(0)).optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let request: TreeFinalDescriptionRequest = serde_json::from_str(&json)?;
    let plan = project(connection, p, &request, max)?;
    let input = &request.input;
    let intent = plan.intent();
    let original_count = intent.retained_originals.len() as u64;
    let refs = intent.retained_originals.values().try_fold(0u64, |n, r| {
        n.checked_add(r.references.len() as u64)
            .ok_or(JournalError::Invariant("tree final refs overflow"))
    })?;
    let exact:bool=connection.query_row(
        "SELECT coordinator_execution_id=?2 AND execution_intent_hash=?3 AND original_request_hash=?4
         AND original_closure_hash=?5 AND owner_intent_hash=?6 AND owner_records_hash=?7
         AND step_records_hash=?8 AND history_projection_hash=?9 AND final_snapshot_id=?10
         AND intent_hash=?11 AND described_at_ms=?12 AND step_count=?13 AND final_entry_count=?14
         AND original_count=?15 AND reference_row_count=?16 AND input_encoded_bytes=?17
         AND peak_native_entries=?18 AND request=?19 AND intent=?20
         FROM tree_restore_final_descriptions WHERE transaction_id=?1",
        params![transaction,input.coordinator_execution_id.as_str(),input.execution_intent_hash.as_str(),
            input.original_request_hash.as_str(),input.original_closure_hash.as_str(),input.owner_intent_hash.as_str(),
            input.owner_records_hash.as_str(),input.step_records_hash.as_str(),input.history_projection_hash.as_str(),
            intent.final_snapshot_id.as_str(),plan.intent_hash().as_str(),sql_integer(input.described_at_ms)?,
            sql_integer(intent.new_operation_ids.len() as u64)?,sql_integer(intent.final_native_entries.len() as u64)?,
            sql_integer(original_count)?,sql_integer(refs)?,sql_integer(plan.input_encoded_bytes())?,
            sql_integer(plan.peak_native_entries() as u64)?,serde_json::to_string(&request)?,serde_json::to_string(intent)?],
        |r|r.get(0))?;
    if !exact || p.cancelled_at_ms.is_some_and(|t| t < input.described_at_ms) {
        return Err(JournalError::Invariant("tree final exact header mismatch"));
    }
    let mut statement=connection.prepare(
        "SELECT step_index,coordinator_execution_id,step_execution_id,original_intent_hash,
         final_intent_hash,step_terminal_hash,new_operation_id,final_snapshot_id,
         CASE WHEN length(CAST(description AS BLOB)) BETWEEN 1 AND 16777216 THEN description ELSE '' END,
         description_hash FROM tree_restore_retained_descriptions WHERE transaction_id=?1 ORDER BY step_index")?;
    let mut rows = statement.query([transaction])?;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .filter(|n| *n <= max)
            .ok_or(JournalError::Invariant("tree final retained inventory"))?;
        let index: i64 = row.get(0)?;
        let index = usize::try_from(index)
            .map_err(|_| JournalError::Invariant("tree final retained index"))?;
        let expected = intent
            .retained_originals
            .get(&index)
            .ok_or(JournalError::Invariant(
                "tree final unexpected retained description",
            ))?;
        let json = serde_json::to_string(expected)?;
        if expected.original.coordinator_execution_id.as_str() != row.get::<_, String>(1)?
            || expected.original.step_execution_id.as_str() != row.get::<_, String>(2)?
            || ContentId::hash(&serde_json::to_vec(&expected.original)?).as_str()
                != row.get::<_, String>(3)?
            || plan.intent_hash().as_str() != row.get::<_, String>(4)?
            || expected.step_terminal_hash.as_str() != row.get::<_, String>(5)?
            || expected.new_operation_id.as_str() != row.get::<_, String>(6)?
            || expected.final_snapshot_id.as_str() != row.get::<_, String>(7)?
            || json != row.get::<_, String>(8)?
            || ContentId::hash(json.as_bytes()).as_str() != row.get::<_, String>(9)?
        {
            return Err(JournalError::Invariant(
                "tree final retained exact mismatch",
            ));
        }
    }
    if count != intent.retained_originals.len() {
        return Err(JournalError::Invariant(
            "tree final retained description missing",
        ));
    }
    let metadata_bytes = bytes(&request, &plan)?;
    if metadata_bytes > max as u64 * 1024 || 1 + plan.intent().retained_originals.len() > max {
        return Err(JournalError::Invariant(
            "tree final description byte/row inventory",
        ));
    }
    Ok(Some(report(&request, &plan, metadata_bytes)))
}

impl Journal {
    /// Persist a complete descriptive candidate only. No native or history authority.
    pub fn with_tree_final_description<T, E>(
        &self,
        request: &TreeFinalDescriptionRequest,
        max: usize,
        inspect: impl FnOnce(&TreeFinalPlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeFinalDescriptionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree final space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.input.transaction_id)
                .ok_or(JournalError::Invariant("tree final owner unknown"))
        };
        let replay = |a: &TreeFinalDescriptionAudit| -> Result<()> {
            if a.request != *request {
                return Err(JournalError::Invariant("tree final request collision"));
            }
            Ok(())
        };
        let p = find()?;
        if let Some(prior) = p.final_description {
            replay(&prior)?;
            return Ok((None, prior));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("tree final owner cancelled").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let p = find()?;
        if let Some(prior) = p.final_description {
            replay(&prior)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, prior));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("tree final owner cancelled").into());
        }
        let plan = project(&tx, &p, request, max)?;
        let metadata_bytes = bytes(request, &plan)?;
        let description_rows = 1 + plan.intent().retained_originals.len() as u64;
        check_storage_metadata_limit(&tx, max, description_rows, metadata_bytes)?;
        let expected = report(request, &plan, metadata_bytes);
        let input = &request.input;
        let intent = plan.intent();
        let refs = intent
            .retained_originals
            .values()
            .map(|r| r.references.len() as u64)
            .sum::<u64>();
        tx.execute(
            "INSERT INTO tree_restore_final_descriptions VALUES
            (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
            params![
                input.transaction_id.as_str(),
                input.coordinator_execution_id.as_str(),
                input.execution_intent_hash.as_str(),
                input.original_request_hash.as_str(),
                input.original_closure_hash.as_str(),
                input.owner_intent_hash.as_str(),
                input.owner_records_hash.as_str(),
                input.step_records_hash.as_str(),
                input.history_projection_hash.as_str(),
                intent.final_snapshot_id.as_str(),
                plan.intent_hash().as_str(),
                sql_integer(input.described_at_ms)?,
                sql_integer(intent.new_operation_ids.len() as u64)?,
                sql_integer(intent.final_native_entries.len() as u64)?,
                sql_integer(intent.retained_originals.len() as u64)?,
                sql_integer(refs)?,
                sql_integer(plan.input_encoded_bytes())?,
                sql_integer(plan.peak_native_entries() as u64)?,
                serde_json::to_string(request).map_err(JournalError::from)?,
                serde_json::to_string(intent).map_err(JournalError::from)?
            ],
        )
        .map_err(JournalError::from)?;
        for (index, r) in &intent.retained_originals {
            let json = serde_json::to_string(r).map_err(JournalError::from)?;
            tx.execute("INSERT INTO tree_restore_retained_descriptions VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![input.transaction_id.as_str(),r.original.coordinator_execution_id.as_str(),r.original.step_execution_id.as_str(),
                    sql_integer(*index as u64)?,ContentId::hash(&serde_json::to_vec(&r.original).map_err(JournalError::from)?).as_str(),plan.intent_hash().as_str(),
                    r.step_terminal_hash.as_str(),r.new_operation_id.as_str(),r.final_snapshot_id.as_str(),json,
                    ContentId::hash(json.as_bytes()).as_str()]).map_err(JournalError::from)?;
        }
        let held = inspect(&plan)?;
        self.audit_gc_owners(&space, max)?;
        let audit = find()?.final_description.ok_or(JournalError::Invariant(
            "tree final description disappeared",
        ))?;
        if audit != expected {
            return Err(JournalError::Invariant("tree final changed during inspection").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }
}
