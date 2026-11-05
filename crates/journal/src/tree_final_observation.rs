//! Fresh final metadata window; only the platform adapter observes native layout.
use crate::{CasAccessGuard, Journal, JournalError, Result, TreeRestorePreparation};
use rusqlite::{Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    limits,
    tree_final_description::{
        plan_tree_final_description, TreeFinalInput, TreeFinalLimits, TreeFinalPlan,
    },
    tree_final_transaction::{
        plan_tree_final_transaction, TreeFinalTransactionInput, TreeFinalTransactionLimits,
        TreeFinalTransactionPlan,
    },
    tree_native_protocol::{audit_tree_native_protocol_records, plan_tree_native_protocol},
    tree_owner_marker::TreeOwnerPlan,
    tree_restore_history::encode_history_record,
    tree_restore_identity::TreeNativeEntry,
    Manifest, PortablePath,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeFinalObservationRequest {
    pub input: TreeFinalTransactionInput,
    pub limits: TreeFinalTransactionLimits,
    pub max_native_handles: usize,
}

pub struct TreeFinalObservationInspection {
    projection: crate::TreeCoordinatorAdmissionInspection,
    transaction: TreeFinalTransactionPlan,
    final_layout: TreeFinalPlan,
    owner_directory: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
    owner_marker: sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
}
impl TreeFinalObservationInspection {
    pub fn transaction(&self) -> &TreeFinalTransactionPlan {
        &self.transaction
    }
    pub fn identity(&self) -> &sync_extend_core_model::tree_restore_identity::TreeIdentityPlan {
        self.projection.identity()
    }
    pub fn baseline(&self) -> &Manifest {
        self.projection.baseline()
    }
    pub fn target(&self) -> &Manifest {
        self.projection.target()
    }
    pub fn final_manifest(&self) -> &Manifest {
        self.projection.context().history.manifest()
    }
    pub fn owner(&self) -> &TreeOwnerPlan {
        self.projection.context().owner
    }
    pub fn final_entries(&self) -> &BTreeMap<PortablePath, TreeNativeEntry> {
        &self.final_layout.intent().final_native_entries
    }
    pub fn owner_native_identities(
        &self,
    ) -> (
        &sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
        &sync_extend_core_model::tree_restore_identity::TreeNativeIdentity,
    ) {
        (&self.owner_directory, &self.owner_marker)
    }
}

fn project(
    journal: &Journal,
    p: &TreeRestorePreparation,
    request: &TreeFinalObservationRequest,
    max: usize,
) -> Result<TreeFinalObservationInspection> {
    let admission = p
        .coordinator_admission
        .as_ref()
        .ok_or(JournalError::Invariant(
            "final observation actual admission missing",
        ))?;
    let stored = p
        .native_protocol_description
        .as_ref()
        .ok_or(JournalError::Invariant(
            "final observation actual protocol missing",
        ))?;
    let binding = &stored.request.input.admission;
    if binding.input != admission.request.input
        || binding.limits != admission.request.limits
        || binding.intent_hash != admission.intent_hash
        || binding.request_hash != admission.request_hash
        || request.input.prior_observation
            != journal.rename_observation(&p.intent.scope.space_id, max)?
    {
        return Err(JournalError::Invariant(
            "final observation actual request binding",
        ));
    }
    let projection = crate::tree_coordinator_admission::project(
        &journal.connection,
        p,
        &admission.request,
        max,
    )?;
    let context = projection.context();
    let protocol =
        plan_tree_native_protocol(&context, &stored.request.input, stored.request.limits)?;
    let audit = audit_tree_native_protocol_records(
        &context,
        &protocol,
        &stored.records,
        stored.request.limits,
    )?;
    if stored.protocol_hash != *protocol.intent_hash() || stored.fingerprint != *audit.fingerprint()
    {
        return Err(JournalError::Invariant(
            "final observation actual protocol mismatch",
        ));
    }
    let transaction =
        plan_tree_final_transaction(&context, &protocol, &audit, &request.input, request.limits)?;
    let binding = &admission.request.input;
    let final_layout = plan_tree_final_description(
        context.execution,
        context.identity,
        context.history,
        context.originals,
        context.owner,
        audit.owner(),
        audit.steps(),
        &TreeFinalInput {
            transaction_id: binding.transaction_id.clone(),
            coordinator_execution_id: binding.coordinator_execution_id.clone(),
            execution_intent_hash: binding.execution_intent_hash.clone(),
            original_request_hash: binding.original_request_hash.clone(),
            original_closure_hash: binding.original_closure_hash.clone(),
            owner_intent_hash: binding.owner_intent_hash.clone(),
            owner_records_hash: audit.owner().fingerprint().clone(),
            step_records_hash: audit.steps().fingerprint().clone(),
            history_projection_hash: context.history.fingerprint().clone(),
            described_at_ms: request.input.described_at_ms,
        },
        TreeFinalLimits {
            max_steps: max,
            max_entries: max,
            max_records: request.limits.max_records,
            max_reference_rows: request.limits.max_reference_rows,
            max_input_bytes: request.limits.max_input_bytes,
            max_encoded_bytes: request.limits.max_encoded_bytes,
        },
    )?;
    if final_layout.intent_hash() != &transaction.intent().final_description_hash {
        return Err(JournalError::Invariant(
            "final observation exact native layout mismatch",
        ));
    }
    // This is transient freshness, not a durable allocation of the finalization ID.
    let id = &request.input.finalization_id;
    crate::tree_disposition_generations::audit_names(
        &journal.connection,
        &std::collections::BTreeSet::from([id]),
        max,
    )?;
    let collision: bool = journal.connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM tree_restore_coordinator_admissions WHERE admission_id=?1)
        OR EXISTS(SELECT 1 FROM tree_restore_disposition_intents WHERE disposition_id=?1)",
        [id.as_str()],
        |r| r.get(0),
    )?;
    if collision {
        return Err(JournalError::Invariant(
            "final observation historical generation collision",
        ));
    }
    encode_history_record(
        &(
            transaction.intent(),
            transaction.rows(),
            final_layout.intent(),
        ),
        request.limits.max_encoded_bytes,
    )?;
    let owner_directory = audit
        .owner()
        .directory()
        .ok_or(JournalError::Invariant(
            "final observation owner directory missing",
        ))?
        .clone();
    let owner_marker = audit
        .owner()
        .marker()
        .ok_or(JournalError::Invariant(
            "final observation owner marker missing",
        ))?
        .clone();
    Ok(TreeFinalObservationInspection {
        projection,
        transaction,
        final_layout,
        owner_directory,
        owner_marker,
    })
}

impl Journal {
    /// Hold shared CAS before the SQLite window and keep platform inspection
    /// values through final all-owner and native rechecks. No rows are written.
    pub fn with_tree_final_observation<T, E>(
        &self,
        request: &TreeFinalObservationRequest,
        max: usize,
        inspect: impl FnOnce(&TreeFinalObservationInspection) -> std::result::Result<T, E>,
        recheck: impl FnOnce(&T, &TreeFinalObservationInspection) -> std::result::Result<(), E>,
    ) -> std::result::Result<(CasAccessGuard, T), E>
    where
        E: From<JournalError>,
    {
        if max == 0
            || max > limits::MAX_ENTRIES
            || request.max_native_handles == 0
            || request.max_native_handles > max
            || request.limits.max_rows > max as u64
            || request.limits.max_records > max
            || request.limits.max_reference_rows > max
            || request.limits.max_input_bytes > crate::MAX_OPERATION_BYTES as u64
            || request.limits.max_encoded_bytes > crate::MAX_OPERATION_BYTES as u64
            || request.limits.max_logical_bytes > crate::MAX_OPERATION_BYTES as u64
        {
            return Err(JournalError::Invariant("final observation inventory bounds").into());
        }
        encode_history_record(request, request.limits.max_input_bytes)
            .map_err(JournalError::from)?;
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("final observation space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.input.transaction_id)
                .ok_or(JournalError::Invariant("final observation owner missing"))
        };
        let p = find()?;
        let expected = project(self, &p, request, max)?;
        let held = inspect(&expected)?;
        self.audit_gc_owners(&space, max)?;
        if find()? != p {
            return Err(JournalError::Invariant("final observation metadata changed").into());
        }
        let actual = project(self, &p, request, max)?;
        if actual.transaction != expected.transaction
            || actual.final_layout != expected.final_layout
        {
            return Err(
                JournalError::Invariant("final observation final projection changed").into(),
            );
        }
        recheck(&held, &actual)?;
        tx.commit().map_err(JournalError::from)?;
        Ok((coordination, held))
    }
}
