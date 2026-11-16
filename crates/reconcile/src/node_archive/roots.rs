//! Target root CREATE follows external durable intent and retains all ancestors.
use super::{NodeRestoreLedger, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::path::{Path, PathBuf};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{FileKey, LockedDirectory, LockedDirectoryMutation};

/// Actual original target roots, never reconstructed from restart evidence.
/// No borrowed mutating handles escape the complete restore coordinator.
pub struct CreatedNodeRestoreRoots {
    archive_digest: ContentId,
    pub(super) worktree: LockedDirectoryMutation,
    pub(super) data: LockedDirectoryMutation,
    pub(super) worktree_path: PathBuf,
    pub(super) data_path: PathBuf,
    worktree_ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
    data_ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
}

impl CreatedNodeRestoreRoots {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn verify(&self) -> Result<()> {
        for (path, held, key) in self.worktree_ancestors.iter().chain(&self.data_ancestors) {
            if held.key()? != *key || !held.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "restore target retained ancestor differs",
                ));
            }
        }
        self.worktree.original_creation()?.verify()?;
        self.data.original_creation()?.verify()?;
        if !self.worktree.matches_path(&self.worktree_path)?
            || !self.data.matches_path(&self.data_path)?
        {
            return Err(ReconcileError::Invariant(
                "restore original target root slot differs",
            ));
        }
        Ok(())
    }
}

pub(super) fn split_target(path: &Path) -> Result<(&Path, &str)> {
    if !path.is_absolute() {
        return Err(ReconcileError::Invariant(
            "restore target root absolute path required",
        ));
    }
    let parent = path.parent().ok_or(ReconcileError::Invariant(
        "restore target root parent absent",
    ))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ReconcileError::Invariant(
            "restore target root component encoding",
        ))?;
    let ordinary = sync_extend_core_model::PortablePath::new(name)?;
    if ordinary.as_str() != name || ordinary.parent().is_some() {
        return Err(ReconcileError::Invariant(
            "restore target root exact ordinary component",
        ));
    }
    Ok((parent, name))
}

impl VerifiedNodeStateArchive {
    /// Requires a previously constructed live external owner ledger with this
    /// exact archive scope. Preflights both absent slots before the first intent.
    /// Error preserves all possible original partial roots, never removes them.
    pub fn create_restore_roots(
        &self,
        ledger: &mut NodeRestoreLedger,
        worktree_path: &Path,
        data_path: &Path,
    ) -> Result<CreatedNodeRestoreRoots> {
        ledger.verify_external()?;
        if ledger.archive_digest() != self.digest() {
            return Err(ReconcileError::Invariant(
                "restore root external archive scope differs",
            ));
        }
        let (worktree_parent, worktree_name) = split_target(worktree_path)?;
        let (data_parent, data_name) = split_target(data_path)?;
        let worktree_ancestors = super::external::hold_ancestors(worktree_parent)?;
        let data_ancestors = super::external::hold_ancestors(data_parent)?;
        let work_parent = &worktree_ancestors
            .last()
            .ok_or(ReconcileError::Invariant(
                "restore worktree original parent absent",
            ))?
            .1;
        let data_parent = &data_ancestors
            .last()
            .ok_or(ReconcileError::Invariant(
                "restore data original parent absent",
            ))?
            .1;
        if work_parent.key()? == data_parent.key()?
            && sync_extend_core_model::PortablePath::new(worktree_name)?.collision_key()
                == sync_extend_core_model::PortablePath::new(data_name)?.collision_key()
        {
            return Err(ReconcileError::Invariant("restore target root aliases"));
        }
        for target in [worktree_path, data_path] {
            match std::fs::symlink_metadata(target) {
                Ok(_) => {
                    return Err(ReconcileError::Invariant(
                        "restore target root slot occupied",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        let mut work_intent = ledger.intend_root(work_parent, worktree_name)?;
        crate::fault::checkpoint("node_root_worktree_intended");
        let worktree = work_parent.create_new_child(worktree_name)?;
        ledger.created_directory(&mut work_intent, &worktree.original_creation()?)?;
        crate::fault::checkpoint("node_root_worktree_created");
        let mut data_intent = ledger.intend_root(data_parent, data_name)?;
        crate::fault::checkpoint("node_root_data_intended");
        let data = data_parent.create_new_child(data_name)?;
        ledger.created_directory(&mut data_intent, &data.original_creation()?)?;
        crate::fault::checkpoint("node_root_data_created");
        let roots = CreatedNodeRestoreRoots {
            archive_digest: self.digest().clone(),
            worktree,
            data,
            worktree_path: worktree_path.to_owned(),
            data_path: data_path.to_owned(),
            worktree_ancestors,
            data_ancestors,
        };
        roots.verify()?;
        Ok(roots)
    }
}

impl CreatedNodeRestoreRoots {
    /// Observers come from the original retained ancestors and real root CREATE.
    /// No recovered manifest or metadata slot lookup grants directory rights.
    pub(super) fn original_writer_chain(
        &self,
        worktree: bool,
    ) -> Result<Vec<sync_extend_platform_fs::RetainedWriterDirectory>> {
        self.verify()?;
        let (ancestors, root, path) = if worktree {
            (
                &self.worktree_ancestors,
                &self.worktree,
                &self.worktree_path,
            )
        } else {
            (&self.data_ancestors, &self.data, &self.data_path)
        };
        let mut retained = Vec::with_capacity(ancestors.len() + 1);
        for (path, held, key) in ancestors {
            if held.key()? != *key || !held.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "original writer ancestor differs",
                ));
            }
            retained.push(held.retain_writer_directory(path)?);
        }
        retained.push(root.original_creation()?.retain_writer_directory(path)?);
        self.verify()?;
        Ok(retained)
    }
}
