//! Consume actual original file creators into Journal and protected content readers.
use super::original_content::OriginalContent;
use super::{CreatedNodeDataLocks, CreatedNodeDirectorySet, CreatedNodeFileSet, NodeTargetRoot};
use crate::{ReconcileError, Result};
use std::collections::BTreeMap;
use sync_extend_cas::Cas;
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_journal::Journal;

/// Real Journal/CAS assembly while the complete original directory/root/marker
/// scope remains held. This type is not yet a fully opened LocalSpace.
pub struct OriginalNodeReadAssembly<'a> {
    pub(super) directories: &'a CreatedNodeDirectorySet<'a>,
    pub(super) data_locks: CreatedNodeDataLocks<'a>,
    pub(super) readers: ReadContents,
    pub(super) journal: Journal,
    pub(super) cas: Cas,
    pub(super) original_cas_readers: crate::original_managed_cas::OriginalManagedCasReadResources,
    pub(super) archive_digest: ContentId,
    pub(super) read_lease_hold: Option<ContentId>,
    pub(super) space: SpaceId,
}
pub(super) type ReadContents = BTreeMap<(NodeTargetRoot, Vec<String>), ReadContent>;
pub(super) struct ReadContent {
    pub(super) original: OriginalContent,
    pub(super) bytes: u64,
    pub(super) digest: ContentId,
}

impl OriginalNodeReadAssembly<'_> {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn verify(&self) -> Result<()> {
        self.directories.verify()?;
        self.data_locks.verify()?;
        self.journal.verify_original_created_image()?;
        if self.directories.archive_digest() != &self.archive_digest {
            return Err(ReconcileError::Invariant(
                "original read assembly archive scope",
            ));
        }
        for ((root, parts), file) in &self.readers {
            super::read_content::verify(&file.original, file.bytes, &file.digest)?;
            if !file
                .original
                .matches_path(&self.directories.path(*root, parts))?
            {
                return Err(ReconcileError::Invariant(
                    "original read assembly content slot changed",
                ));
            }
        }
        let manifest = self
            .journal
            .current(&self.space)?
            .ok_or(ReconcileError::Invariant(
                "original read assembly current manifest absent",
            ))?;
        for file in manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            self.cas.verify(file)?;
        }
        self.journal.integrity_check()?;
        super::inventory::verify_after_journal(self.directories)?;
        Ok(())
    }
}

impl<'a> CreatedNodeFileSet<'a> {
    /// Journal consumes original metadata identity; every other exact CREATE
    /// becomes a sameobject protected reader and is fully verified after handoff.
    /// Directory/root/marker proofs remain borrowed for the entire assembly.
    /// Errors retain on-disk original partials, no reconstructed native ownership.
    pub fn into_original_read_assembly(
        self,
        max_storage_entries: usize,
        data_locks: CreatedNodeDataLocks<'a>,
    ) -> Result<OriginalNodeReadAssembly<'a>> {
        self.into_original_read_assembly_retaining(max_storage_entries, data_locks)
            .map_err(|original| original.retain_and_report())
    }

    pub fn into_original_read_assembly_retaining(
        self,
        max_storage_entries: usize,
        data_locks: CreatedNodeDataLocks<'a>,
    ) -> std::result::Result<
        OriginalNodeReadAssembly<'a>,
        super::OriginalNodeScopedResourceCloseFailure<'a>,
    > {
        super::assembly_prepare::assemble_original_files(self, max_storage_entries, data_locks)
    }
}
