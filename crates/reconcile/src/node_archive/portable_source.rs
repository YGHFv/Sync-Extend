//! Refuse unsupported native history before any target/root/ledger effects.
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
}
