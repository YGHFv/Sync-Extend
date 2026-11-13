//! Explicit TREE workflow joins the existing preparatory and native gates.
//! No step is authorized by a serialized preview or a reopened pathname.
use crate::{now_ms, LocalSpace, ReconcileError, Result};
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use sync_extend_core_model::{
    tree_coordinator_lifecycle::TreeCoordinatorAdmissionInput, tree_owner_marker::TreeOwnerInput,
    tree_restore_execution_intent::TreeExecutionIntentInput,
};
use sync_extend_core_model::{
    tree_coordinator_lifecycle::TreeCoordinatorLimits,
    tree_native_action_layout::TreeNativeActionLayoutLimits,
    tree_native_future_obligations::TreeNativeFutureLimits,
    tree_original_reference::TreeOriginalReferenceLimits,
    tree_restore::{plan_tree_restore, TreeRestoreAction, TreeRestoreLimits, TreeRestoreScope},
    tree_restore_execution_intent::TreeExecutionIntentLimits,
    tree_restore_history::{TreeRestoreHistoryInput, TreeRestoreHistoryLimits},
    tree_restore_identity::TreeIdentityLimits,
    ContentId, EntryId, SnapshotId,
};
#[cfg(windows)]
use sync_extend_journal::{
    TreeCoordinatorAdmissionRequest, TreeNativeFutureAdmissionRequest, TreeNativePrewriteRequest,
    TreeOriginalPinRequest, TreeRestoreNativeRequest,
};
use sync_extend_journal::{
    TreeRestoreHistoryIntent, TreeRestoreInventoryLimits, TreeRestorePreparation,
    TreeRestorePreparationIntent,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreBudgets {
    pub plan: TreeRestoreLimits,
    pub history: TreeRestoreHistoryLimits,
    pub identity: TreeIdentityLimits,
    pub execution: TreeExecutionIntentLimits,
    pub originals: TreeOriginalReferenceLimits,
    pub coordinator: TreeCoordinatorLimits,
    pub actions: TreeNativeActionLayoutLimits,
    pub future: TreeNativeFutureLimits,
    pub inventory: TreeRestoreInventoryLimits,
}

impl TreeRestoreBudgets {
    fn verify_persisted(&self, preparation: &TreeRestorePreparation) -> Result<()> {
        let differs = preparation.intent.limits != self.plan
            || preparation
                .history_reservation
                .as_ref()
                .is_some_and(|history| history.intent.history.limits != self.history)
            || preparation
                .native_reservation
                .as_ref()
                .is_some_and(|native| native.intent.request.limits != self.identity)
            || preparation
                .execution_description
                .as_ref()
                .is_some_and(|execution| execution.intent.input.limits != self.execution)
            || preparation
                .original_pins
                .as_ref()
                .is_some_and(|pins| pins.request.limits != self.originals)
            || preparation
                .coordinator_admission
                .as_ref()
                .is_some_and(|admission| admission.request.limits != self.coordinator)
            || preparation.native_storage.as_ref().is_some_and(|storage| {
                storage.request().layout_limits != self.actions
                    || storage.request().inventory_limits != self.inventory
            })
            || preparation
                .native_future_admission
                .as_ref()
                .is_some_and(|future| {
                    future.request().layout_limits != self.future
                        || future.request().inventory_limits != self.inventory
                });
        if differs {
            return Err(ReconcileError::Invariant(
                "TREE persisted pipeline budgets differ",
            ));
        }
        Ok(())
    }
}

impl LocalSpace {
    pub fn tree_restore_transactions(&self) -> Result<Vec<TreeRestorePreparation>> {
        self.verify_root()?;
        Ok(self
            .journal
            .tree_restore_preparations(&self.space_id, self.limits.max_storage_entries)?)
    }

    /// Persist only conservative preparation/history projections. Actual
    /// admission and irreversible native execution require separate calls.
    pub fn prepare_tree_restore_pipeline(
        &mut self,
        expected: &SnapshotId,
        target: &SnapshotId,
        transaction: EntryId,
        budgets: &TreeRestoreBudgets,
    ) -> Result<TreeRestorePreparation> {
        self.verify_root()?;
        let existing = self
            .tree_restore_transactions()?
            .into_iter()
            .find(|preparation| preparation.intent.transaction_id == transaction);
        if existing.is_none() {
            self.require_no_mutation()?;
        }
        if self
            .manifest()?
            .as_ref()
            .map(|manifest| manifest.root())
            .transpose()?
            .as_ref()
            != Some(expected)
        {
            return Err(ReconcileError::Invariant(
                "TREE requested baseline is no longer current",
            ));
        }
        let baseline = self.journal.retained_snapshot(&self.space_id, expected)?;
        let historical = self.journal.retained_snapshot(&self.space_id, target)?;
        let preparation = if let Some(existing) = existing {
            budgets.verify_persisted(&existing)?;
            if existing.intent.scope.baseline_snapshot != *expected
                || existing.intent.scope.target_snapshot != *target
                || !existing.writer_gate_held
            {
                return Err(ReconcileError::Invariant(
                    "TREE preparation scope/budget/state differs",
                ));
            }
            if let Some(history) = &existing.history_reservation {
                if history.intent.history.limits != budgets.history {
                    return Err(ReconcileError::Invariant(
                        "TREE projected history budgets differ",
                    ));
                }
                return Ok(existing);
            }
            existing.intent
        } else {
            TreeRestorePreparationIntent {
                transaction_id: transaction.clone(),
                scope: TreeRestoreScope {
                    format_version: 1,
                    space_id: self.space_id.clone(),
                    baseline_snapshot: expected.clone(),
                    target_snapshot: target.clone(),
                },
                limits: budgets.plan,
                prepared_at_ms: now_ms()?,
            }
        };
        let plan = plan_tree_restore(
            &preparation.scope,
            &baseline.manifest,
            &historical.manifest,
            budgets.plan,
        )?;
        if plan.steps().is_empty() {
            return Err(ReconcileError::Invariant(
                "TREE target has no planned changes",
            ));
        }
        let native = self.stable_scan()?;
        if native.len() != baseline.manifest.entries.len()
            || baseline.manifest.entries.values().any(|entry| {
                native
                    .get(&entry.path)
                    .is_none_or(|seen| seen.kind != entry.kind || seen.content != entry.content)
            })
        {
            return Err(ReconcileError::Unstable);
        }
        for manifest in [&baseline.manifest, &historical.manifest] {
            for content in manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
            {
                self.check_publication_limits(content)?;
                self.cas.verify(content)?;
            }
        }
        let (held, _) = self.journal.with_tree_restore_preparation(
            &preparation,
            self.limits.max_storage_entries,
            |_| Ok::<_, ReconcileError>(()),
        )?;
        drop(held);
        let fresh_entry_ids = plan
            .steps()
            .iter()
            .filter(|step| {
                matches!(
                    step.action,
                    TreeRestoreAction::CreateDirectory | TreeRestoreAction::PublishNewFile
                )
            })
            .map(|step| Ok((step.index, EntryId::random()?)))
            .collect::<Result<_>>()?;
        let history = TreeRestoreHistoryIntent {
            transaction_id: transaction,
            preparation_hash: ContentId::hash(&serde_json::to_vec(&preparation)?),
            history: TreeRestoreHistoryInput {
                format_version: 1,
                origin_device_id: self.device_id.clone(),
                created_at_ms: preparation.prepared_at_ms,
                fresh_entry_ids,
                limits: budgets.history,
            },
        };
        let (held, _) = self.journal.with_tree_restore_history(
            &history,
            self.limits.max_storage_entries,
            |_| Ok::<_, ReconcileError>(()),
        )?;
        drop(held);
        self.tree_restore_transactions()?
            .into_iter()
            .find(|preparation| preparation.intent.transaction_id == history.transaction_id)
            .ok_or(ReconcileError::Invariant(
                "TREE prepared pipeline disappeared",
            ))
    }

    /// Continue preparatory metadata for the same exact lineage. Resuming an
    /// interrupted prefix reuses persisted IDs, never creates a second owner.
    #[cfg(windows)]
    pub fn admit_tree_restore_pipeline(
        &self,
        transaction: &EntryId,
        budgets: &TreeRestoreBudgets,
    ) -> Result<TreeRestorePreparation> {
        let find = || {
            self.tree_restore_transactions()?
                .into_iter()
                .find(|preparation| &preparation.intent.transaction_id == transaction)
                .ok_or(ReconcileError::Invariant(
                    "TREE requested preparation missing",
                ))
        };
        let mut preparation = find()?;
        budgets.verify_persisted(&preparation)?;
        self.verify_tree_owner_policy(transaction)?;
        if !preparation.writer_gate_held {
            return Err(ReconcileError::Invariant(
                "TREE cancelled preparation cannot be admitted",
            ));
        }
        if preparation.native_future_admission.is_some() {
            return Ok(preparation);
        }
        let history = preparation
            .history_reservation
            .as_ref()
            .ok_or(ReconcileError::Invariant("TREE projected history absent"))?;
        let native_request = match &preparation.native_reservation {
            Some(native) => native.intent.request.clone(),
            None => TreeRestoreNativeRequest {
                transaction_id: transaction.clone(),
                preparation_hash: history.intent.preparation_hash.clone(),
                history_intent_hash: ContentId::hash(&serde_json::to_vec(&history.intent)?),
                history_projection_hash: history.projection_hash.clone(),
                captured_at_ms: now_ms()?.max(history.intent.history.created_at_ms),
                limits: budgets.identity,
            },
        };
        let native = self.reserve_tree_restore_native_identity(&native_request)?;
        preparation = find()?;
        let input = match &preparation.execution_description {
            Some(execution) => execution.intent.input.clone(),
            None => TreeExecutionIntentInput {
                transaction_id: transaction.clone(),
                preparation_hash: native_request.preparation_hash.clone(),
                history_intent_hash: native_request.history_intent_hash.clone(),
                native_intent_hash: ContentId::hash(&serde_json::to_vec(&native.intent)?),
                history_projection_hash: native.intent.request.history_projection_hash.clone(),
                native_identity_fingerprint: native.identity_fingerprint,
                execution_id: EntryId::random()?,
                step_execution_ids: preparation
                    .steps
                    .iter()
                    .map(|step| Ok((step.index, EntryId::random()?)))
                    .collect::<Result<_>>()?,
                created_at_ms: now_ms()?.max(native_request.captured_at_ms),
                limits: budgets.execution,
            },
        };
        let execution = self.describe_tree_restore_execution(&input)?;
        preparation = find()?;
        let pin_request = preparation
            .original_pins
            .as_ref()
            .map(|pins| pins.request.clone())
            .unwrap_or(TreeOriginalPinRequest {
                transaction_id: transaction.clone(),
                coordinator_execution_id: input.execution_id.clone(),
                execution_intent_hash: execution.intent_hash.clone(),
                reserved_at_ms: now_ms()?.max(input.created_at_ms),
                limits: budgets.originals,
            });
        let pins = self.reserve_tree_restore_original_pins(&pin_request)?;
        preparation = find()?;
        let owner_input = preparation
            .owner_description
            .as_ref()
            .map(|owner| owner.intent.input.clone())
            .unwrap_or(TreeOwnerInput {
                transaction_id: transaction.clone(),
                coordinator_execution_id: input.execution_id,
                execution_intent_hash: execution.intent_hash.clone(),
                original_request_hash: ContentId::hash(&serde_json::to_vec(&pins.request)?),
                original_closure_hash: pins.fingerprint,
                created_at_ms: now_ms()?.max(pin_request.reserved_at_ms),
            });
        let owner = self.describe_tree_restore_owner(&owner_input)?;
        if preparation.coordinator_admission.is_none() {
            self.admit_tree_restore_coordinator(&TreeCoordinatorAdmissionRequest {
                input: TreeCoordinatorAdmissionInput {
                    transaction_id: transaction.clone(),
                    coordinator_execution_id: owner_input.coordinator_execution_id,
                    admission_id: EntryId::random()?,
                    preparation_hash: native_request.preparation_hash,
                    execution_intent_hash: execution.intent_hash,
                    original_request_hash: owner_input.original_request_hash,
                    original_closure_hash: owner_input.original_closure_hash,
                    owner_intent_hash: owner.intent_hash,
                    admitted_at_ms: now_ms()?.max(owner_input.created_at_ms),
                },
                limits: budgets.coordinator,
            })?;
        }
        preparation = find()?;
        let prewrite = preparation
            .native_storage
            .as_ref()
            .map(|storage| storage.request().clone())
            .unwrap_or(TreeNativePrewriteRequest {
                transaction_id: transaction.clone(),
                created_at_ms: now_ms()?,
                layout_limits: budgets.actions,
                inventory_limits: budgets.inventory,
            });
        self.journal.prepare_tree_native_storage(
            &self.space_id,
            &prewrite,
            self.limits.max_storage_entries,
        )?;
        self.journal.admit_tree_native_future(
            &self.space_id,
            &TreeNativeFutureAdmissionRequest {
                transaction_id: transaction.clone(),
                created_at_ms: now_ms()?.max(prewrite.created_at_ms),
                layout_limits: budgets.future,
                inventory_limits: budgets.inventory,
            },
            self.limits.max_storage_entries,
        )?;
        find()
    }
}
