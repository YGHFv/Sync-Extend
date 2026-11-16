//! Consume actual original file creators into Journal and protected content readers.
use super::original_content::OriginalContent;
use super::{CreatedNodeDataLocks, CreatedNodeDirectorySet, CreatedNodeFileSet, NodeTargetRoot};
use crate::{LocalSpace, ReconcileError, Result};
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
    pub(super) archive_digest: ContentId,
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
        mut self,
        max_storage_entries: usize,
        mut data_locks: CreatedNodeDataLocks<'a>,
    ) -> Result<OriginalNodeReadAssembly<'a>> {
        self.verify_inventory_with_data_locks(&data_locks)?;
        let journal_slot = (NodeTargetRoot::Data, vec!["journal.sqlite".to_owned()]);
        let journal_file = self
            .files
            .remove(&journal_slot)
            .ok_or(ReconcileError::Invariant(
                "original created Journal slot absent",
            ))?;
        let path = journal_file.path.clone();
        let main = match journal_file.creator.handoff_original_sqlite_main(&path) {
            Ok(value) => value,
            Err(sync_extend_platform_fs::OriginalSqliteMainHandoffFailure::Creator {
                error,
                ..
            })
            | Err(sync_extend_platform_fs::OriginalSqliteMainHandoffFailure::Released {
                error,
                ..
            }) => return Err(error.into()),
        };
        crate::fault::checkpoint("node_assembly_journal_released");
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            match std::fs::symlink_metadata(std::path::Path::new(&sidecar)) {
                Ok(_) => {
                    return Err(ReconcileError::Invariant(
                        "original Journal sidecar occupied beforeSQLiteopen",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        let inspection = sync_extend_journal::NodeInspectionBounds {
            max_entries: max_storage_entries,
            capacity: sync_extend_journal::JournalCapacityLimits {
                inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                    max_rows: max_storage_entries,
                    max_logical_bytes: max_storage_entries as u64 * 1024,
                },
                max_rows: max_storage_entries as u64,
                max_logical_bytes: max_storage_entries as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        let mut journal = match Journal::reopen_original_handoff_readonly(main, inspection) {
            Ok(journal) => journal,
            Err((_original, error)) => return Err(error.into()),
        };
        journal.verify_original_created_image()?;
        crate::fault::checkpoint("node_assembly_journal_opened");
        let sentinel = data_locks.release_cas()?;
        journal
            .bind_original_cas_coordination(sentinel)
            .map_err(|(_original, error)| error)?;
        crate::fault::checkpoint("node_assembly_original_cas_bound");
        let mut readers = BTreeMap::new();
        for (slot, file) in self.files {
            let original = if slot.0 == NodeTargetRoot::Worktree {
                OriginalContent::Sealed(file.creator.seal_original()?)
            } else {
                let identity = file
                    .creator
                    .release_for_identity_checked_reopen()
                    .map_err(|(_creator, error)| error)?;
                let read = identity
                    .retain_read_after_creation()
                    .map_err(|(_identity, error)| error)?;
                OriginalContent::Read(read)
            };
            super::read_content::verify(&original, file.bytes, &file.digest)?;
            if !original.matches_path(&file.path)? {
                return Err(ReconcileError::Invariant(
                    "original content read handoff slot differs",
                ));
            }
            readers.insert(
                slot,
                ReadContent {
                    original,
                    bytes: file.bytes,
                    digest: file.digest,
                },
            );
            crate::fault::checkpoint("node_assembly_file_read_verified");
        }
        let data = &self.directories.roots.data_path;
        // Existing original callbacks must find a separately created/owned
        // coordination sentinel. See pending data-lock handoff contract.
        let cas = LocalSpace::existing_original_managed_cas(data, &journal)?;
        let state = journal
            .state("space_id")?
            .ok_or(ReconcileError::Invariant("original space absent"))?;
        let result = OriginalNodeReadAssembly {
            directories: self.directories,
            data_locks,
            readers,
            journal,
            cas,
            archive_digest: self.archive_digest,
            space: state.parse()?,
        };
        result.verify()?;
        crate::fault::checkpoint("node_assembly_full_read_verified");
        Ok(result)
    }
}
