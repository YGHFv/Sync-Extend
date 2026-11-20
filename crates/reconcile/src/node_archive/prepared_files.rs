// Same original precomputed plan/image, no remapping after target effects.
impl super::PreparedOriginalNodeRestore {
    pub fn create_original_files<'a>(
        &self,
        archive: &super::VerifiedNodeStateArchive,
        directories: &'a super::CreatedNodeDirectorySet<'a>,
        ledger: &mut super::NodeRestoreLedger,
        inspection: sync_extend_journal::NodeInspectionBounds,
    ) -> crate::Result<super::CreatedNodeFileSet<'a>> {
        if archive.digest() != &self.archive_digest
            || !std::ptr::eq(directories.mapped, &self.mapped)
            || !std::ptr::eq(directories.original, &self.original)
            || directories.roots.worktree_path != self.worktree
            || directories.roots.data_path != self.data
        {
            return Err(crate::ReconcileError::Invariant(
                "preflight files require exact original plan and target root scope",
            ));
        }
        let result = archive.create_original_layout_files_with_image(
            directories,
            ledger,
            inspection,
            self.required_file_bytes,
            Some(self),
        )?;
        if result.mapped_journal_digest().as_str() != self.journal.digest() {
            return Err(crate::ReconcileError::Invariant(
                "original created Journal differs from preflight image",
            ));
        }
        result.verify_inventory()?;
        Ok(result)
    }
}
