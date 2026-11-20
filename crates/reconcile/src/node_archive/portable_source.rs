//! Original owner history preflight before any target or ledger effects.
use crate::{ReconcileError, Result};
use std::path::{Component, Path, PathBuf};
use sync_extend_core_model::{ContentId, DeviceId, SpaceId};
use sync_extend_journal::{
    ArchivedReadLeaseHold, JournalBackupImage, NodeInspectionBounds,
    OriginalNodeHistoryMappingEvidence,
};

#[derive(serde::Serialize)]
pub struct ReadLeaseMigrationPreview {
    pub archive_digest: ContentId,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub desired_worktree: PathBuf,
    pub desired_data: PathBuf,
    pub original_read_lease_hold: ArchivedReadLeaseHold,
    pub separate_config_mapping_required: bool,
    pub journal_mapping: Option<OriginalNodeHistoryMappingEvidence>,
}

impl super::VerifiedNodeStateArchive {
    pub fn require_portable_restore_source(
        &self,
        bounds: sync_extend_journal::NodeInspectionBounds,
    ) -> crate::Result<()> {
        let bytes = self.archive.section(&super::ArchiveRole::Journal).ok_or(
            crate::ReconcileError::Invariant("original source Journal absent"),
        )?;
        let digest = sync_extend_core_model::ContentId::hash(bytes);
        let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
            bytes.to_vec(),
            digest.as_str(),
            bytes.len(),
            self.space(),
            bounds,
        )?;
        let scope = image.portable_node_scope(self.space(), bounds)?;
        if scope.device() != self.device() || scope.original_worktree() != self.original_worktree()
        {
            return Err(crate::ReconcileError::Invariant(
                "original portable source scope differs",
            ));
        }
        Ok(())
    }

    /// Prove that the archived lease clock, state and individual CAS pins
    /// survive a detached worktree mapping. Only the ordinary portable image
    /// families and the two read lease tables participate in this preview.
    pub fn preview_read_lease_migration(
        &self,
        worktree: &Path,
        data: &Path,
        inspection: NodeInspectionBounds,
        max_image_bytes: usize,
    ) -> Result<ReadLeaseMigrationPreview> {
        for path in [worktree, data] {
            super::roots::split_target(path)?;
            if path
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            {
                return Err(ReconcileError::Invariant(
                    "read lease migration preview requires normalized roots",
                ));
            }
        }
        if worktree.starts_with(data)
            || data.starts_with(worktree)
            || worktree.starts_with(self.original_worktree())
            || self.original_worktree().starts_with(worktree)
            || data.starts_with(self.original_worktree())
            || self.original_worktree().starts_with(data)
        {
            return Err(ReconcileError::Invariant(
                "read lease migration preview roots overlap",
            ));
        }
        let separate_config_mapping_required = self
            .archive
            .roles()
            .any(|role| matches!(role, super::ArchiveRole::ExplicitConfig { .. }));
        let raw = self.journal_bytes()?;
        if max_image_bytes > 256 * 1024 * 1024 || raw.len() > max_image_bytes {
            return Err(ReconcileError::ResourceLimit(
                "read lease migration preview Journal bytes",
            ));
        }
        let image = JournalBackupImage::from_current_node_image(
            raw.to_vec(),
            self.journal_digest.as_str(),
            max_image_bytes,
            self.space(),
            inspection,
        )?;
        let hold = image.inspect_archived_read_lease_hold(self.space(), inspection)?;
        // The Verified archive has the full archived CAS closure. This
        // detached image verifies that exactly the worktree row changes.
        let journal_mapping = if hold.other_owner_tables.is_empty()
            && !hold.root_bound_local_state
            && !separate_config_mapping_required
        {
            let detached = image.map_detached_original_history(
                self.space(),
                self.original_worktree(),
                worktree,
                inspection,
                max_image_bytes,
                max_image_bytes * 2,
            )?;
            Some(detached.evidence().clone())
        } else {
            None
        };
        Ok(ReadLeaseMigrationPreview {
            archive_digest: self.digest().clone(),
            space_id: self.space().clone(),
            device_id: self.device().clone(),
            desired_worktree: worktree.into(),
            desired_data: data.into(),
            original_read_lease_hold: hold,
            separate_config_mapping_required,
            journal_mapping,
        })
    }
}
