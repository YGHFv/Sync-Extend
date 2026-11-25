//! Every derived directory slot is backed by actual original CREATE and ledger intent.
use super::{
    CreatedNodeRestoreRoots, CreatedNodeWorktreeMarker, NodeRestoreDirectory, NodeRestoreLayout,
    NodeRestoreLedger, NodeRestoreMappedLayout, NodeTargetRoot, VerifiedNodeStateArchive,
};
use crate::{ReconcileError, Result};
use std::{collections::BTreeMap, path::PathBuf};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{FileKey, LockedDirectoryMutation};

pub struct CreatedNodeDirectorySet<'a> {
    pub(super) roots: &'a CreatedNodeRestoreRoots,
    pub(super) marker: &'a CreatedNodeWorktreeMarker<'a>,
    pub(super) mapped: &'a NodeRestoreMappedLayout,
    pub(super) original: &'a NodeRestoreLayout,
    directories: BTreeMap<(NodeTargetRoot, Vec<String>), CreatedDirectory>,
    archive_digest: ContentId,
}

struct CreatedDirectory {
    creator: LockedDirectoryMutation,
    path: PathBuf,
    key: FileKey,
    parent: FileKey,
}

impl CreatedNodeDirectorySet<'_> {
    pub fn close_into_attempt<'scope>(
        self,
        attempt: &mut super::OriginalNodeResourceCloseAttempt<'scope>,
    ) where
        Self: 'scope,
    {
        let Self { roots, marker, mapped, original, directories, archive_digest } = self;
        attempt.keep_context((roots, marker, mapped, original, archive_digest));
        for (slot, original) in directories.into_iter().rev() {
            let CreatedDirectory { creator, path, key, parent } = original;
            attempt.keep_context((slot, path, key, parent));
            creator.close_into_attempt(&mut attempt.native);
        }
    }

    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn verify(&self) -> Result<()> {
        self.roots.verify()?;
        self.marker.verify()?;
        if self.roots.archive_digest() != &self.archive_digest
            || self.marker.archive_digest() != &self.archive_digest
            || self.mapped.archive_digest() != &self.archive_digest
            || self.original.archive_digest() != &self.archive_digest
        {
            return Err(ReconcileError::Invariant(
                "original directory set archive scope",
            ));
        }
        for directory in self.directories.values() {
            let original = directory.creator.original_creation()?;
            if original.key()? != directory.key
                || original.parent_key()? != directory.parent
                || !directory.creator.matches_path(&directory.path)?
            {
                return Err(ReconcileError::Invariant(
                    "original derived directory slot changed",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn parent(
        &self,
        root: NodeTargetRoot,
        parts: &[String],
    ) -> Result<&LockedDirectoryMutation> {
        if parts.is_empty() {
            return Ok(match root {
                NodeTargetRoot::Worktree => &self.roots.worktree,
                NodeTargetRoot::Data => &self.roots.data,
            });
        }
        if root == NodeTargetRoot::Worktree && parts == [".sync-extend"] {
            return Ok(&self.marker.directory);
        }
        self.directories
            .get(&(root, parts.to_vec()))
            .map(|directory| &directory.creator)
            .ok_or(ReconcileError::Invariant(
                "original derived parent directory not created",
            ))
    }
    pub(super) fn path(&self, root: NodeTargetRoot, parts: &[String]) -> PathBuf {
        let mut path = match root {
            NodeTargetRoot::Worktree => self.roots.worktree_path.clone(),
            NodeTargetRoot::Data => self.roots.data_path.clone(),
        };
        for part in parts {
            path.push(part);
        }
        path
    }
}

impl VerifiedNodeStateArchive {
    /// No caller can nominate an arbitrary directory path or construct a source
    /// directory token. Entire derived map is checked before native child CREATE.
    /// Errors leave possibly created original directories and ledger evidence.
    pub fn create_original_layout_directories<'a>(
        &self,
        roots: &'a CreatedNodeRestoreRoots,
        marker: &'a CreatedNodeWorktreeMarker<'a>,
        ledger: &mut NodeRestoreLedger,
        original: &'a NodeRestoreLayout,
        mapped: &'a NodeRestoreMappedLayout,
    ) -> Result<CreatedNodeDirectorySet<'a>> {
        roots.verify()?;
        marker.verify()?;
        ledger.verify_external()?;
        if self.digest() != roots.archive_digest()
            || self.digest() != marker.archive_digest()
            || self.digest() != ledger.archive_digest()
            || self.digest() != mapped.archive_digest()
            || self.digest() != original.archive_digest()
        {
            return Err(ReconcileError::Invariant(
                "original archive derived directory scope",
            ));
        }
        let mut result = CreatedNodeDirectorySet {
            roots,
            marker,
            mapped,
            original,
            directories: BTreeMap::new(),
            archive_digest: self.digest().clone(),
        };
        for slot in mapped.directories() {
            let source = mapped.directory(slot, original)?;
            if matches!(source, NodeRestoreDirectory::WorktreeMarker) {
                if slot.root() != NodeTargetRoot::Worktree || slot.components() != [".sync-extend"]
                {
                    return Err(ReconcileError::Invariant(
                        "original fixed marker derived slot",
                    ));
                }
                continue;
            }
            let parts = slot.components();
            let name = parts.last().ok_or(ReconcileError::Invariant(
                "derived directory component absent",
            ))?;
            let parent_parts = &parts[..parts.len() - 1];
            result.verify()?;
            let parent = result.parent(slot.root(), parent_parts)?;
            let proof = parent.original_creation()?;
            let parent_key = proof.key()?;
            let mut intended = ledger.intend_directory(&proof, name)?;
            crate::fault::checkpoint("node_layout_directory_intended");
            let creator = parent.create_new_child(name)?;
            ledger.created_directory(&mut intended, &creator.original_creation()?)?;
            crate::fault::checkpoint("node_layout_directory_created");
            let key = creator.key()?;
            let path = result.path(slot.root(), parts);
            if result
                .directories
                .insert(
                    (slot.root(), parts.to_vec()),
                    CreatedDirectory {
                        creator,
                        path,
                        key,
                        parent: parent_key,
                    },
                )
                .is_some()
            {
                return Err(ReconcileError::Invariant(
                    "duplicate original created directory slot",
                ));
            }
        }
        result.verify()?;
        Ok(result)
    }
}
