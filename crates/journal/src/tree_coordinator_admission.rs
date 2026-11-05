//! Durable irreversible cancellation fence, never native execution permission.
use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeRestorePreparation, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{
    limits,
    tree_coordinator_lifecycle::{
        plan_tree_coordinator_admission, TreeCoordinatorAdmissionInput,
        TreeCoordinatorAdmissionPlan, TreeCoordinatorContext, TreeCoordinatorLimits,
    },
    tree_original_reference::plan_tree_original_references,
    tree_owner_marker::{plan_tree_owner, TreeOwnerLimits},
    tree_restore::{plan_tree_restore, TreeRestorePlan},
    tree_restore_history::{encode_history_record, plan_tree_restore_history},
    tree_restore_identity::TreeIdentityPlan,
    ContentId, EntryId, Manifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeCoordinatorAdmissionRequest {
    pub input: TreeCoordinatorAdmissionInput,
    pub limits: TreeCoordinatorLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeCoordinatorAdmissionAudit {
    pub request: TreeCoordinatorAdmissionRequest,
    pub intent_hash: ContentId,
    pub request_hash: ContentId,
    pub metadata_bytes: u64,
    pub irreversible_cancellation_fence_held: bool,
    pub native_action_available: bool,
    pub history_commit_available: bool,
    pub input_reference_release_available: bool,
    pub original_reference_release_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

pub struct TreeCoordinatorAdmissionInspection {
    plan: TreeCoordinatorAdmissionPlan,
    identity: TreeIdentityPlan,
    preparation: crate::TreeRestorePreparationIntent,
    tree: TreeRestorePlan,
    baseline: Manifest,
    target: Manifest,
    execution: sync_extend_core_model::tree_restore_execution_intent::TreeExecutionIntentPlan,
    history: sync_extend_core_model::tree_restore_history::TreeRestoreHistoryPlan,
    history_input: sync_extend_core_model::tree_restore_history::TreeRestoreHistoryInput,
    originals: sync_extend_core_model::tree_original_reference::TreeOriginalReferencePlan,
    owner: sync_extend_core_model::tree_owner_marker::TreeOwnerPlan,
}
impl TreeCoordinatorAdmissionInspection {
    pub fn plan(&self) -> &TreeCoordinatorAdmissionPlan {
        &self.plan
    }
    pub fn identity(&self) -> &TreeIdentityPlan {
        &self.identity
    }
    pub fn preparation(&self) -> &crate::TreeRestorePreparationIntent {
        &self.preparation
    }
    pub fn tree(&self) -> &TreeRestorePlan {
        &self.tree
    }
    pub fn baseline(&self) -> &Manifest {
        &self.baseline
    }
    pub fn target(&self) -> &Manifest {
        &self.target
    }
    pub(crate) fn context(&self) -> TreeCoordinatorContext<'_> {
        TreeCoordinatorContext {
            execution: &self.execution,
            identity: &self.identity,
            history: &self.history,
            history_input: &self.history_input,
            originals: &self.originals,
            owner: &self.owner,
            baseline: &self.baseline,
            target: &self.target,
        }
    }
}

pub(crate) fn project(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeCoordinatorAdmissionRequest,
    max: usize,
) -> Result<TreeCoordinatorAdmissionInspection> {
    if max == 0
        || max > limits::MAX_ENTRIES
        || request.limits.max_steps > max
        || request.limits.max_owners > max
        || request.limits.max_reference_rows > max
        || request.limits.max_input_bytes > MAX_OPERATION_BYTES as u64
        || request.limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
        || !p.writer_gate_held
        || p.cancelled_at_ms.is_some()
    {
        return Err(JournalError::Invariant(
            "tree admission limits or cancelled",
        ));
    }
    let execution = p
        .execution_description
        .as_ref()
        .ok_or(JournalError::Invariant("tree admission execution missing"))?;
    let history = p
        .history_reservation
        .as_ref()
        .ok_or(JournalError::Invariant("tree admission history missing"))?;
    let native = p
        .native_reservation
        .as_ref()
        .ok_or(JournalError::Invariant("tree admission native missing"))?;
    let originals = p.original_pins.as_ref().ok_or(JournalError::Invariant(
        "tree admission original references missing",
    ))?;
    let owner = p.owner_description.as_ref().ok_or(JournalError::Invariant(
        "tree admission owner intent missing",
    ))?;
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
    let history_plan =
        plan_tree_restore_history(&tree, &baseline, &target, &history.intent.history)?;
    let original_plan = plan_tree_original_references(
        &execution.plan,
        &execution.identity,
        originals.request.limits,
    )?;
    if originals.request.reserved_at_ms > request.input.admitted_at_ms
        || request.input.original_request_hash
            != ContentId::hash(&serde_json::to_vec(&originals.request)?)
        || original_plan.intents() != &originals.originals
        || original_plan.fingerprint() != &originals.fingerprint
        || !originals.exact_original_pins_verified
        || originals.active_reference_count != original_plan.reference_rows()
        || owner
            .records
            .iter()
            .any(|r| r.recorded_at_ms < request.input.admitted_at_ms)
        || p.execution_records.as_ref().is_some_and(|a| {
            a.records
                .values()
                .flatten()
                .any(|r| r.recorded_at_ms < request.input.admitted_at_ms)
        })
    {
        return Err(JournalError::Invariant(
            "tree admission actual original scope or effect order",
        ));
    }
    let owner_plan = plan_tree_owner(
        &execution.plan,
        &execution.identity,
        &original_plan,
        &owner.intent.input,
        TreeOwnerLimits {
            max_steps: max,
            max_encoded_bytes: MAX_OPERATION_BYTES as u64,
        },
    )?;
    if owner_plan.intent_hash() != &owner.intent_hash {
        return Err(JournalError::Invariant("tree admission actual owner hash"));
    }
    let context = TreeCoordinatorContext {
        execution: &execution.plan,
        identity: &execution.identity,
        history: &history_plan,
        history_input: &history.intent.history,
        originals: &original_plan,
        owner: &owner_plan,
        baseline: &baseline,
        target: &target,
    };
    let plan = plan_tree_coordinator_admission(&context, &request.input, request.limits)?;
    Ok(TreeCoordinatorAdmissionInspection {
        plan,
        identity: execution.identity,
        preparation: p.intent.clone(),
        tree,
        baseline,
        target,
        execution: execution.plan,
        history: history_plan,
        history_input: history.intent.history.clone(),
        originals: original_plan,
        owner: owner_plan,
    })
}

fn report(
    request: &TreeCoordinatorAdmissionRequest,
    plan: &TreeCoordinatorAdmissionPlan,
) -> Result<TreeCoordinatorAdmissionAudit> {
    let json = encode_history_record(request, MAX_OPERATION_BYTES as u64)?;
    // Three 32-byte IDs, seven 64-byte hashes and one logical 8-byte integer.
    let metadata_bytes = json.len() as u64 + 552;
    Ok(TreeCoordinatorAdmissionAudit {
        request: request.clone(),
        intent_hash: plan.intent_hash().clone(),
        request_hash: ContentId::hash(&json),
        metadata_bytes,
        irreversible_cancellation_fence_held: true,
        native_action_available: false,
        history_commit_available: false,
        input_reference_release_available: false,
        original_reference_release_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    })
}

pub(crate) fn audit(
    connection: &Connection,
    p: &TreeRestorePreparation,
    max: usize,
) -> Result<Option<TreeCoordinatorAdmissionAudit>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216
         THEN request ELSE '' END FROM tree_restore_coordinator_admissions WHERE transaction_id=?1",
            [p.intent.transaction_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let request: TreeCoordinatorAdmissionRequest = serde_json::from_str(&json)?;
    let projection = project(connection, p, &request, max)?;
    let expected = report(&request, &projection.plan)?;
    let i = &request.input;
    let exact: bool = connection.query_row(
        "SELECT coordinator_execution_id=?2 AND admission_id=?3 AND preparation_hash=?4
         AND execution_intent_hash=?5 AND original_request_hash=?6 AND original_closure_hash=?7
         AND owner_intent_hash=?8 AND intent_hash=?9 AND request_hash=?10 AND request=?11
         AND admitted_at_ms=?12 FROM tree_restore_coordinator_admissions WHERE transaction_id=?1",
        params![
            i.transaction_id.as_str(),
            i.coordinator_execution_id.as_str(),
            i.admission_id.as_str(),
            i.preparation_hash.as_str(),
            i.execution_intent_hash.as_str(),
            i.original_request_hash.as_str(),
            i.original_closure_hash.as_str(),
            i.owner_intent_hash.as_str(),
            expected.intent_hash.as_str(),
            expected.request_hash.as_str(),
            serde_json::to_string(&request)?,
            sql_integer(i.admitted_at_ms)?
        ],
        |r| r.get(0),
    )?;
    if !exact || json != serde_json::to_string(&request)? {
        return Err(JournalError::Invariant(
            "tree admission immutable exact binding",
        ));
    }
    Ok(Some(expected))
}

pub(crate) fn audit_generations(connection: &Connection, max: usize) -> Result<()> {
    let mut statement =
        connection.prepare("SELECT admission_id FROM tree_restore_coordinator_admissions")?;
    let mut ids = BTreeSet::new();
    for row in statement.query_map([], |r| r.get::<_, String>(0))? {
        let id: EntryId = row?.parse()?;
        if ids.len() >= max || !ids.insert(id) {
            return Err(JournalError::Invariant(
                "tree admission generation inventory",
            ));
        }
    }
    crate::tree_disposition_generations::audit_names(connection, &ids.iter().collect(), max)?;
    for id in &ids {
        let collision: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM tree_restore_disposition_intents WHERE disposition_id=?1)",
            [id.as_str()],
            |r| r.get(0),
        )?;
        if collision {
            return Err(JournalError::Invariant(
                "tree admission disposition generation alias",
            ));
        }
    }
    Ok(())
}

impl Journal {
    /// Persists only an irreversible fence. The inspection cannot grant native actions.
    pub fn with_tree_coordinator_admission<T, E>(
        &self,
        request: &TreeCoordinatorAdmissionRequest,
        max: usize,
        inspect: impl FnOnce(&TreeCoordinatorAdmissionInspection) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeCoordinatorAdmissionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree admission space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.input.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree admission owner"))
        };
        let replay = |p: &TreeRestorePreparation| -> Result<Option<TreeCoordinatorAdmissionAudit>> {
            if let Some(old) = &p.coordinator_admission {
                if old.request != *request {
                    return Err(JournalError::Invariant("tree admission request collision"));
                }
                return Ok(Some(old.clone()));
            }
            Ok(None)
        };
        let p = find()?;
        if let Some(old) = replay(&p)? {
            return Ok((None, old));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("cancelled tree admission").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let p = find()?;
        if let Some(old) = replay(&p)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let projection = project(&tx, &p, request, max)?;
        if p.owner_description
            .as_ref()
            .is_some_and(|o| !o.records.is_empty())
            || p.execution_records
                .as_ref()
                .is_some_and(|s| !s.records.is_empty())
            || p.final_description.is_some()
            || p.disposition_description.is_some()
        {
            return Err(JournalError::Invariant(
                "tree admission must precede every action description",
            )
            .into());
        }
        let expected = report(request, &projection.plan)?;
        let id = &request.input.admission_id;
        crate::tree_disposition_generations::audit_names(&tx, &BTreeSet::from([id]), max)?;
        check_storage_metadata_limit(&tx, max, 1, expected.metadata_bytes)?;
        let i = &request.input;
        tx.execute(
            "INSERT INTO tree_restore_coordinator_admissions VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![i.transaction_id.as_str(),i.coordinator_execution_id.as_str(),i.admission_id.as_str(),
                i.preparation_hash.as_str(),i.execution_intent_hash.as_str(),i.original_request_hash.as_str(),
                i.original_closure_hash.as_str(),i.owner_intent_hash.as_str(),expected.intent_hash.as_str(),
                expected.request_hash.as_str(),serde_json::to_string(request).map_err(JournalError::from)?,
                sql_integer(i.admitted_at_ms)?],
        ).map_err(JournalError::from)?;
        if find()?.coordinator_admission.as_ref() != Some(&expected) {
            return Err(JournalError::Invariant("tree admission changed before inspection").into());
        }
        let held = inspect(&projection)?;
        self.audit_gc_owners(&space, max)?;
        let actual = find()?
            .coordinator_admission
            .ok_or(JournalError::Invariant("tree admission disappeared"))?;
        if actual != expected {
            return Err(JournalError::Invariant("tree admission changed during inspection").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), actual))
    }
}
