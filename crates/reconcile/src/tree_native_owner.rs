//! Explicit TREE owner creation under current LocalSpace policy and process locks.
use crate::{LocalSpace, ReconcileError, Result};
use std::collections::BTreeMap;
use sync_extend_core_model::EntryId;
use sync_extend_journal::{
    TreeNativeOwnerCreation, TreeNativeOwnerReadiness, TreeRestorePreparation,
};

pub struct TreeOwnerCreation<'a> {
    local: &'a LocalSpace,
    native: TreeNativeOwnerCreation,
}

pub struct TreeOwnerReadiness<'a> {
    _local: &'a LocalSpace,
    native: TreeNativeOwnerReadiness,
}

impl TreeOwnerReadiness<'_> {
    pub fn transaction_id(&self) -> &EntryId {
        self.native.transaction_id()
    }
    pub fn owner_ready(&self) -> bool {
        self.native.owner_ready()
    }
    pub fn whole_tree_completed(&self) -> bool {
        false
    }
}

impl TreeOwnerCreation<'_> {
    pub fn transaction_id(&self) -> &EntryId {
        self.native.transaction_id()
    }
}

impl LocalSpace {
    pub(super) fn verify_tree_owner_policy(
        &self,
        transaction: &EntryId,
    ) -> Result<TreeRestorePreparation> {
        self.verify_root()?;
        let preparations = self
            .journal
            .tree_restore_preparations(&self.space_id, self.limits.max_storage_entries)?;
        let preparation = preparations
            .into_iter()
            .find(|preparation| &preparation.intent.transaction_id == transaction)
            .ok_or(ReconcileError::Invariant("tree owner preparation missing"))?;
        let mut total = 0u64;
        let mut chunks = 0usize;
        for snapshot in [
            &preparation.intent.scope.baseline_snapshot,
            &preparation.intent.scope.target_snapshot,
        ] {
            let manifest = self
                .journal
                .retained_snapshot(&self.space_id, snapshot)?
                .manifest;
            if manifest.entries.len() > self.limits.max_scan_entries {
                return Err(ReconcileError::ResourceLimit("tree owner entry limit"));
            }
            for content in manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
            {
                if content.length > self.limits.max_file_bytes {
                    return Err(ReconcileError::ResourceLimit("tree owner file limit"));
                }
                total = total
                    .checked_add(content.length)
                    .filter(|total| *total <= self.limits.max_scan_bytes)
                    .ok_or(ReconcileError::ResourceLimit(
                        "tree owner aggregate byte limit",
                    ))?;
                chunks = chunks
                    .checked_add(content.chunks.len())
                    .filter(|chunks| *chunks <= self.limits.max_scan_chunks)
                    .ok_or(ReconcileError::ResourceLimit("tree owner chunk limit"))?;
                self.cas.verify(content)?;
            }
        }
        Ok(preparation)
    }

    pub(super) fn reserve_tree_owner_worktree(
        &self,
        additional: u64,
        view: Option<&dyn crate::native_file_view::NativeFileView>,
    ) -> Result<()> {
        let pass = || {
            self.verify_root()?;
            if let Some(view) = view {
                view.verify()?;
            }
            let mut inventory = BTreeMap::new();
            // Ordinary inventory intentionally skips the space marker area.
            // TREE owners live there and need this explicit bounded traversal.
            for (path, internal) in [
                (self.worktree.clone(), false),
                (self.worktree.join(".sync-extend"), true),
            ] {
                crate::storage::visit(
                    &self.worktree,
                    &path,
                    crate::storage::Region::Worktree,
                    internal,
                    (0, self.limits.max_storage_entries),
                    &mut inventory,
                    view,
                )?;
            }
            if let Some(view) = view {
                view.verify()?;
            }
            self.verify_root()?;
            Ok::<_, ReconcileError>(inventory)
        };
        let before = pass()?;
        let after = pass()?;
        if before != after {
            return Err(ReconcileError::Unstable);
        }
        if crate::storage::inventory_bytes(&after)?
            .checked_add(additional)
            .is_none_or(|bytes| bytes > self.limits.max_internal_worktree_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "TREE owner aggregate internal worktree bytes",
            ));
        }
        Ok(())
    }

    pub fn create_tree_owner(&self, transaction: &EntryId) -> Result<TreeOwnerCreation<'_>> {
        let preparation = self.verify_tree_owner_policy(transaction)?;
        let owner = preparation
            .owner_description
            .as_ref()
            .ok_or(ReconcileError::Invariant("tree owner intent absent"))?;
        let marker_bytes = serde_json::to_vec(&owner.intent.marker_payload)?.len() as u64;
        let additional = preparation
            .retained_and_staging_bytes
            .checked_add(marker_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "tree owner internal reservation",
            ))?;
        self.reserve_tree_owner_worktree(additional, None)?;
        let native = self.journal.create_tree_native_owner(
            &self.space_id,
            transaction,
            self.limits.max_storage_entries,
        )?;
        Ok(TreeOwnerCreation {
            local: self,
            native,
        })
    }

    pub fn seal_tree_owner(
        &self,
        creation: TreeOwnerCreation<'_>,
    ) -> Result<TreeOwnerReadiness<'_>> {
        if !std::ptr::eq(self, creation.local) {
            return Err(ReconcileError::Invariant("tree owner foreign LocalSpace"));
        }
        let preparation = self.verify_tree_owner_policy(creation.native.transaction_id())?;
        self.reserve_tree_owner_worktree(
            preparation.retained_and_staging_bytes,
            Some(&creation.native.file_view()),
        )?;
        let native = self
            .journal
            .seal_tree_native_owner(creation.native, self.limits.max_storage_entries)?;
        Ok(TreeOwnerReadiness {
            _local: self,
            native,
        })
    }

    pub fn reopen_tree_owner_readiness(
        &self,
        transaction: &EntryId,
    ) -> Result<TreeOwnerReadiness<'_>> {
        let preparation = self.verify_tree_owner_policy(transaction)?;
        self.reserve_tree_owner_worktree(preparation.retained_and_staging_bytes, None)?;
        let native = self.journal.reopen_tree_native_owner_readiness(
            &self.space_id,
            transaction,
            self.limits.max_storage_entries,
        )?;
        Ok(TreeOwnerReadiness {
            _local: self,
            native,
        })
    }

    /// Explicit non-atomic native TREE restore. Current policy is inspected
    /// before each action while the same LocalSpace process locks stay held.
    pub fn restore_tree_native(&self, transaction: &EntryId) -> Result<TreeNativeRestoreResult> {
        let preparation = self.verify_tree_owner_policy(transaction)?;
        if preparation.state == "native_cleaned" || preparation.state == "native_finalized" {
            self.reserve_tree_owner_worktree(0, None)?;
            let receipt = self.journal.resume_tree_native_cleanup(
                &self.space_id,
                transaction,
                self.limits.max_storage_entries,
            )?;
            return Ok(TreeNativeRestoreResult {
                transaction_id: transaction.clone(),
                snapshot_id: receipt.snapshot_id().clone(),
                owner_cleanup_complete: receipt.owner_cleanup_complete(),
                tree_atomic: false,
            });
        }
        let readiness = self.reopen_tree_owner_readiness(transaction)?;
        let execution = self.journal.begin_tree_native_execution(
            readiness.native,
            &self.space_id,
            self.limits.max_storage_entries,
        )?;
        self.finish_tree_native_execution(execution)
    }

    /// Resume exact durable native lineage; an unresolved original attempt
    /// still refuses and cannot be adopted by pathname or equal bytes.
    pub fn resume_tree_native_restore(
        &self,
        transaction: &EntryId,
    ) -> Result<TreeNativeRestoreResult> {
        let preparation = self.verify_tree_owner_policy(transaction)?;
        if ["native_finalized", "native_cleaned"].contains(&preparation.state) {
            return self.restore_tree_native(transaction);
        }
        let execution = self.journal.reopen_tree_native_execution(
            &self.space_id,
            transaction,
            self.limits.max_storage_entries,
        )?;
        self.finish_tree_native_execution(execution)
    }

    fn finish_tree_native_execution(
        &self,
        execution: sync_extend_journal::TreeNativeExecution,
    ) -> Result<TreeNativeRestoreResult> {
        let observation = self.journal.execute_tree_native_checked(
            execution,
            self.limits.max_storage_entries,
            |view| {
                self.verify_tree_owner_policy(view.transaction_id())
                    .map_err(|_| {
                        sync_extend_journal::JournalError::Invariant(
                            "tree current LocalSpace policy refused",
                        )
                    })?;
                self.reserve_tree_owner_worktree(view.remaining_internal_bytes()?, Some(view))
                    .map_err(|_| {
                        sync_extend_journal::JournalError::Invariant(
                            "tree current LocalSpace worktree capacity refused",
                        )
                    })
            },
        )?;
        self.verify_tree_owner_policy(observation.transaction_id())?;
        self.reserve_tree_owner_worktree(0, Some(&observation.file_view()))?;
        let finalized = self
            .journal
            .commit_tree_native_final(observation, self.limits.max_storage_entries)?;
        let receipt = self
            .journal
            .cleanup_tree_native_owner(finalized, self.limits.max_storage_entries)?;
        Ok(TreeNativeRestoreResult {
            transaction_id: receipt.transaction_id().clone(),
            snapshot_id: receipt.snapshot_id().clone(),
            owner_cleanup_complete: receipt.owner_cleanup_complete(),
            tree_atomic: false,
        })
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TreeNativeRestoreResult {
    pub transaction_id: EntryId,
    pub snapshot_id: sync_extend_core_model::SnapshotId,
    pub owner_cleanup_complete: bool,
    pub tree_atomic: bool,
}
