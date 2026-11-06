use crate::{check_ancestors, read_marker, LocalSpace, ReconcileError, Result};
use std::{fs, fs::OpenOptions, io::Write, path::Path};
use sync_extend_core_model::{limits::LocalLimits, SpaceId};

impl LocalSpace {
    /// Explicitly join an approved space without copying another device's secret.
    /// Existing worktree metadata is never replaced or silently reassigned.
    pub fn join_space(
        data_dir: &Path,
        worktree: &Path,
        space_id: &SpaceId,
        limits: LocalLimits,
    ) -> Result<Self> {
        limits.validate()?;
        check_ancestors(worktree)?;
        check_ancestors(data_dir)?;
        let worktree = fs::canonicalize(worktree)?;
        crate::validate_roots(&crate::canonical_destination(data_dir)?, &worktree)?;
        let marker_directory = worktree.join(".sync-extend");
        let marker = marker_directory.join("space-id");
        if marker_directory.try_exists()? {
            if read_marker(&marker)? != *space_id {
                return Err(ReconcileError::Invariant(
                    "worktree belongs to another space",
                ));
            }
        } else {
            fs::create_dir(&marker_directory)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)?;
            file.write_all(space_id.as_str().as_bytes())?;
            file.sync_all()?;
            sync_extend_cas::sync_directory(&marker_directory)?;
            sync_extend_cas::sync_directory(&worktree)?;
        }
        Self::initialize_with_limits(data_dir, &worktree, limits)
    }
}
