use crate::{
    fault::checkpoint,
    filesystem::{physical_identity, PathIdentity},
    now_ms,
    publish::file_matches,
    LocalSpace, ReconcileError, Result,
};
use serde::Serialize;
use std::path::Path;
use sync_extend_core_model::*;
use sync_extend_journal::{Mutation, MutationAction, MutationIntent, MutationState};

#[derive(Serialize)]
pub struct MutationCheck {
    pub transaction_id: EntryId,
    pub state: MutationState,
    pub baseline_valid: bool,
    pub executor_available: bool,
    pub worktree_modified: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub(crate) fn require_no_mutation(&self) -> Result<()> {
        if !self
            .journal
            .outstanding_mutations(&self.space_id)?
            .is_empty()
        {
            return Err(ReconcileError::Invariant(
                "prepared mutation requires explicit check/cancel; executor is unavailable",
            ));
        }
        Ok(())
    }

    pub fn prepare_replace(
        &mut self,
        expected: &SnapshotId,
        path: &PortablePath,
        source: &Path,
    ) -> Result<Mutation> {
        self.prepare_mutation(expected, path, None, Some(source))
    }

    pub fn prepare_delete(
        &mut self,
        expected: &SnapshotId,
        path: &PortablePath,
    ) -> Result<Mutation> {
        self.prepare_mutation(expected, path, None, None)
    }

    pub fn prepare_move(
        &mut self,
        expected: &SnapshotId,
        path: &PortablePath,
        destination: &PortablePath,
    ) -> Result<Mutation> {
        self.prepare_mutation(expected, path, Some(destination), None)
    }

    fn prepare_mutation(
        &mut self,
        expected: &SnapshotId,
        path: &PortablePath,
        destination: Option<&PortablePath>,
        source: Option<&Path>,
    ) -> Result<Mutation> {
        self.verify_root()?;
        self.require_no_mutation()?;
        if !self
            .journal
            .outstanding_publications(&self.space_id)?
            .is_empty()
        {
            return Err(ReconcileError::Invariant(
                "outstanding publication must be recovered first",
            ));
        }
        let baseline = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("scan a baseline first"))?;
        if baseline.root()? != *expected {
            return Err(ReconcileError::Invariant(
                "requested mutation snapshot is no longer current",
            ));
        }
        let entry = baseline
            .entries
            .values()
            .find(|entry| &entry.path == path)
            .filter(|entry| entry.kind == EntryKind::File)
            .cloned()
            .ok_or(ReconcileError::Invariant(
                "mutation requires an indexed regular file",
            ))?;
        let target = self.worktree.join(path.as_str());
        let root = PathIdentity::capture(&self.worktree)?;
        let parent = PathIdentity::capture(&self.parent_for(path)?)?;
        let file = PathIdentity::capture(&target)?;
        let content = entry
            .content
            .as_ref()
            .ok_or(ReconcileError::Invariant("missing file content"))?;
        if content.length > self.limits.max_file_bytes {
            return Err(ReconcileError::ResourceLimit("mutation baseline bytes"));
        }
        let mut destination_parent = None;
        let action = if let Some(destination) = destination {
            if destination.collision_key() == path.collision_key() || self.occupied(destination)? {
                return Err(ReconcileError::Invariant(
                    "mutation move destination occupied or unchanged",
                ));
            }
            let identity = PathIdentity::capture(&self.parent_for(destination)?)?;
            let action = MutationAction::Move {
                destination: destination.clone(),
                parent_identity: identity.physical.clone(),
            };
            destination_parent = Some(identity);
            action
        } else if let Some(source) = source {
            MutationAction::Replace {
                content: self.import_source(source)?,
            }
        } else {
            MutationAction::Delete
        };
        self.cas.verify(content)?;
        checkpoint("before_mutation_baseline_check");
        let scan = self.stable_scan()?;
        if scan.get(path).is_none_or(|scanned| {
            scanned.content.as_ref() != Some(content) || scanned.physical_identity != file.physical
        }) || baseline.entries.len() != scan.len()
            || baseline.entries.values().any(|entry| {
                scan.get(&entry.path).is_none_or(|scanned| {
                    scanned.kind != entry.kind || scanned.content != entry.content
                })
            })
            || !file_matches(&target, content)?
        {
            return Err(ReconcileError::Invariant(
                "worktree differs from requested mutation snapshot",
            ));
        }
        root.verify(&self.worktree)?;
        parent.verify(&self.parent_for(path)?)?;
        file.verify(&target)?;
        if let (Some(destination), Some(identity)) = (destination, destination_parent.as_ref()) {
            identity.verify(&self.parent_for(destination)?)?;
            if self.occupied(destination)? {
                return Err(ReconcileError::Invariant(
                    "mutation move destination became occupied",
                ));
            }
        }
        let intent = MutationIntent {
            format_version: FORMAT_VERSION,
            transaction_id: EntryId::random()?,
            space_id: self.space_id.clone(),
            baseline_root: expected.clone(),
            baseline_entry: entry,
            file_identity: file.physical,
            root_identity: root.physical,
            parent_identity: parent.physical,
            action,
            created_at_ms: now_ms()?,
        };
        checkpoint("before_mutation_intent");
        self.journal.begin_mutation(&intent)?;
        checkpoint("after_mutation_intent");
        Ok(self.journal.mutation(&intent.transaction_id)?)
    }

    pub fn mutations(&self) -> Result<Vec<Mutation>> {
        Ok(self.journal.mutations(&self.space_id)?)
    }

    pub fn check_mutation(&self, id: &EntryId) -> Result<MutationCheck> {
        self.verify_root()?;
        let mutation = self.journal.mutation(id)?;
        self.journal.verify_mutation_references(id)?;
        let intent = &mutation.intent;
        if intent.space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "mutation belongs to another space",
            ));
        }
        let active = mutation.state == MutationState::Prepared;
        let mut valid = active;
        if active {
            let baseline = self
                .journal
                .snapshot(&self.space_id, &intent.baseline_root)?;
            if baseline.entries.get(&intent.baseline_entry.entry_id) != Some(&intent.baseline_entry)
            {
                return Err(ReconcileError::Invariant(
                    "mutation retained baseline mismatch",
                ));
            }
            let content =
                intent
                    .baseline_entry
                    .content
                    .as_ref()
                    .ok_or(ReconcileError::Invariant(
                        "mutation baseline content missing",
                    ))?;
            self.cas.verify(content)?;
            if let MutationAction::Replace { content } = &intent.action {
                self.check_publication_limits(content)?;
                self.cas.verify(content)?;
            }
            valid = self
                .manifest()?
                .as_ref()
                .map(Manifest::root)
                .transpose()?
                .as_ref()
                == Some(&intent.baseline_root)
                && physical_identity(&self.worktree)? == intent.root_identity
                && physical_identity(&self.parent_for(&intent.baseline_entry.path)?)?
                    == intent.parent_identity
                && physical_identity(&self.worktree.join(intent.baseline_entry.path.as_str()))?
                    == intent.file_identity;
            let scan = self.stable_scan()?;
            valid &= baseline.entries.len() == scan.len()
                && scan
                    .get(&intent.baseline_entry.path)
                    .is_some_and(|entry| entry.physical_identity == intent.file_identity)
                && baseline.entries.values().all(|entry| {
                    scan.get(&entry.path).is_some_and(|scanned| {
                        scanned.kind == entry.kind && scanned.content == entry.content
                    })
                });
            if let MutationAction::Move {
                destination,
                parent_identity,
            } = &intent.action
            {
                valid &= physical_identity(&self.parent_for(destination)?)? == *parent_identity
                    && !self.occupied(destination)?;
            }
            valid &= physical_identity(&self.worktree)? == intent.root_identity
                && physical_identity(&self.parent_for(&intent.baseline_entry.path)?)?
                    == intent.parent_identity
                && physical_identity(&self.worktree.join(intent.baseline_entry.path.as_str()))?
                    == intent.file_identity;
        }
        Ok(MutationCheck {
            transaction_id: id.clone(),
            state: mutation.state,
            baseline_valid: valid,
            executor_available: false,
            worktree_modified: false,
            remote_backup_complete: false,
        })
    }

    pub fn cancel_mutation(&mut self, id: &EntryId) -> Result<()> {
        // Preparation has no worktree writes; cancellation releases only journal pins.
        checkpoint("before_mutation_cancel");
        self.journal.cancel_mutation(&self.space_id, id)?;
        checkpoint("after_mutation_cancel");
        Ok(())
    }
}
