//! Exact original mapped content -> durable intent -> actual file CREATE receipts.
use super::{
    ArchiveRole, CreatedNodeDirectorySet, NodeRestoreFile, NodeRestoreLedger, NodeTargetRoot,
    VerifiedNodeStateArchive,
};
use crate::{ReconcileError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use sync_extend_core_model::ContentId;
use sync_extend_journal::{JournalBackupImage, NodeInspectionBounds};
use sync_extend_platform_fs::{FileKey, OwnedFileCreation};

pub struct CreatedNodeFileSet<'a> {
    pub(super) directories: &'a CreatedNodeDirectorySet<'a>,
    pub(super) files: BTreeMap<(NodeTargetRoot, Vec<String>), CreatedFile>,
    pub(super) archive_digest: ContentId,
    source_journal_digest: ContentId,
    mapped_journal_digest: ContentId,
}
pub(super) struct CreatedFile {
    pub(super) creator: OwnedFileCreation,
    pub(super) path: PathBuf,
    pub(super) key: FileKey,
    pub(super) parent: FileKey,
    pub(super) bytes: u64,
    pub(super) digest: ContentId,
}
impl CreatedNodeFileSet<'_> {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn source_journal_digest(&self) -> &ContentId {
        &self.source_journal_digest
    }
    pub fn mapped_journal_digest(&self) -> &ContentId {
        &self.mapped_journal_digest
    }
    pub fn verify(&self) -> Result<()> {
        self.directories.verify()?;
        if self.directories.archive_digest() != &self.archive_digest {
            return Err(ReconcileError::Invariant(
                "original file set directory/archive scope",
            ));
        }
        for original in self.files.values() {
            super::created_bytes::verify(
                &original.creator,
                original.key,
                original.parent,
                original.bytes,
                &original.digest,
            )?;
            if !sync_extend_platform_fs::regular_file_matches_path(
                original.creator.reader(),
                &original.path,
            )? {
                return Err(ReconcileError::Invariant(
                    "original created content slot changed",
                ));
            }
        }
        Ok(())
    }
}

impl VerifiedNodeStateArchive {
    /// Portable Journal mapping and all source-derived slots precede first file
    /// intent/CREATE. Unmapped native history refuses before file effects.
    /// Current files use original ordered CAS chunks, never caller manifests.
    pub fn create_original_layout_files<'a>(
        &self,
        directories: &'a CreatedNodeDirectorySet<'a>,
        ledger: &mut NodeRestoreLedger,
        inspection: NodeInspectionBounds,
        max_file_bytes: u64,
    ) -> Result<CreatedNodeFileSet<'a>> {
        self.create_original_layout_files_with_image(
            directories,
            ledger,
            inspection,
            max_file_bytes,
            None,
        )
    }
    pub(super) fn create_original_layout_files_with_image<'a>(
        &self,
        directories: &'a CreatedNodeDirectorySet<'a>,
        ledger: &mut NodeRestoreLedger,
        inspection: NodeInspectionBounds,
        max_file_bytes: u64,
        prepared: Option<&JournalBackupImage>,
    ) -> Result<CreatedNodeFileSet<'a>> {
        directories.verify()?;
        ledger.verify_external()?;
        if directories.archive_digest() != self.digest()
            || ledger.archive_digest() != self.digest()
            || max_file_bytes == 0
            || max_file_bytes > 1024 * 1024 * 1024
        {
            return Err(ReconcileError::Invariant(
                "original file scope and explicit bound",
            ));
        }
        let journal_bytes =
            self.archive
                .section(&ArchiveRole::Journal)
                .ok_or(ReconcileError::Invariant(
                    "original source Journal section absent",
                ))?;
        let source_digest = ContentId::hash(journal_bytes);
        let computed;
        let mapped = if let Some(mapped) = prepared {
            mapped
        } else {
            computed = {
                let image = JournalBackupImage::from_current_node_image(
                    journal_bytes.to_vec(),
                    source_digest.as_str(),
                    journal_bytes.len(),
                    self.space(),
                    inspection,
                )?;
                image.mapped_portable_worktree_image(
                    self.space(),
                    self.original_worktree(),
                    &directories.roots.worktree_path,
                    inspection,
                    256 * 1024 * 1024,
                )?
            };
            &computed
        };
        let mapped_digest: ContentId = mapped.digest().parse()?;
        let mut expected_total = self.space().as_str().len() as u64;
        for slot in directories.mapped.files() {
            let source = directories.mapped.file(slot, directories.original)?;
            let length = match source {
                NodeRestoreFile::Journal => mapped.bytes().len() as u64,
                NodeRestoreFile::WorktreeCurrent { bytes, .. } => *bytes,
                NodeRestoreFile::WorktreeSpaceMarker => continue,
                other => {
                    let role = match other {
                        NodeRestoreFile::ProtectedDeviceIdentity => ArchiveRole::DeviceSecret,
                        NodeRestoreFile::CasObject { content_id } => ArchiveRole::CasObject {
                            content_id: content_id.clone(),
                        },
                        NodeRestoreFile::PeerApproval { device_id } => ArchiveRole::PeerApproval {
                            device_id: device_id.clone(),
                        },
                        _ => {
                            return Err(ReconcileError::Invariant(
                                "original file budget role unsupported",
                            ))
                        }
                    };
                    self.archive
                        .section(&role)
                        .ok_or(ReconcileError::Invariant(
                            "original mapped section absent beforeCREATE",
                        ))?
                        .len() as u64
                }
            };
            expected_total = expected_total
                .checked_add(length)
                .filter(|count| *count <= max_file_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "whole original mapped file bytes beforeCREATE",
                ))?;
        }
        let mut result = CreatedNodeFileSet {
            directories,
            files: BTreeMap::new(),
            archive_digest: self.digest().clone(),
            source_journal_digest: source_digest,
            mapped_journal_digest: mapped_digest,
        };
        let mut total = self.space().as_str().len() as u64;
        for slot in directories.mapped.files() {
            let source = directories.mapped.file(slot, directories.original)?;
            if matches!(source, NodeRestoreFile::WorktreeSpaceMarker) {
                directories.marker.verify()?;
                continue;
            }
            let parts = slot.components();
            let name = parts
                .last()
                .ok_or(ReconcileError::Invariant("original file component absent"))?;
            let parent = directories.parent(slot.root(), &parts[..parts.len() - 1])?;
            directories.verify()?;
            let mut intended = ledger.intend_file(&parent.original_creation()?, name)?;
            crate::fault::checkpoint("node_layout_file_intended");
            let mut creator = parent.create_new_file(name)?;
            ledger.created_file(&mut intended, &creator.original_creation()?)?;
            crate::fault::checkpoint("node_layout_file_created");
            let (digest, bytes) = match source {
                NodeRestoreFile::Journal => {
                    let receipt = mapped.restore_created(&mut creator)?;
                    receipt.verify()?;
                    ledger.close_created_journal(&mut intended, &receipt)?;
                    (receipt.digest().parse()?, receipt.bytes())
                }
                NodeRestoreFile::WorktreeCurrent { entry_id, .. } => {
                    let receipt = self.materialize_created_current_file(
                        entry_id,
                        &mut creator,
                        inspection,
                        max_file_bytes,
                    )?;
                    receipt.verify()?;
                    ledger.close_current_file(&mut intended, &receipt)?;
                    (receipt.digest().clone(), receipt.bytes())
                }
                other => {
                    let role = match other {
                        NodeRestoreFile::ProtectedDeviceIdentity => ArchiveRole::DeviceSecret,
                        NodeRestoreFile::CasObject { content_id } => ArchiveRole::CasObject {
                            content_id: content_id.clone(),
                        },
                        NodeRestoreFile::PeerApproval { device_id } => ArchiveRole::PeerApproval {
                            device_id: device_id.clone(),
                        },
                        _ => {
                            return Err(ReconcileError::Invariant(
                                "original mapped file role unsupported",
                            ))
                        }
                    };
                    let receipt = self.materialize_created_section(&role, &mut creator)?;
                    receipt.verify()?;
                    ledger.close_section(&mut intended, &receipt)?;
                    (receipt.digest().clone(), receipt.bytes())
                }
            };
            total = total
                .checked_add(bytes)
                .filter(|bytes| *bytes <= max_file_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "original materialized aggregate file bytes",
                ))?;
            let original = creator.original_creation()?;
            let key = original.key()?;
            let parent = original.parent_key()?;
            let path = directories.path(slot.root(), parts);
            if result
                .files
                .insert(
                    (slot.root(), parts.to_vec()),
                    CreatedFile {
                        creator,
                        path,
                        key,
                        parent,
                        bytes,
                        digest,
                    },
                )
                .is_some()
            {
                return Err(ReconcileError::Invariant(
                    "original file slot created twice",
                ));
            }
            crate::fault::checkpoint("node_layout_file_content_closed");
        }
        if total != expected_total {
            return Err(ReconcileError::Invariant(
                "complete original mapped byte total differs",
            ));
        }
        result.verify()?;
        result.verify_inventory()?;
        Ok(result)
    }
}

impl CreatedNodeFileSet<'_> {
    /// Bound actual direct memberships to original derived map plus held marker
    /// and writerlock. Unknown/missing/reparse children refuse; no cleanup.
    pub fn verify_inventory(&self) -> Result<()> {
        self.verify_inventory_phase(false)
    }
    pub(super) fn verify_inventory_with_data_locks(
        &self,
        locks: &super::CreatedNodeDataLocks<'_>,
    ) -> Result<()> {
        if !locks.matches_roots(self.directories.roots) {
            return Err(ReconcileError::Invariant(
                "data lock belongs to another original root set",
            ));
        }
        locks.verify_inventory()?;
        self.verify_inventory_phase(true)
    }
    fn verify_inventory_phase(&self, include_data_locks: bool) -> Result<()> {
        self.verify()?;
        let mut expected: BTreeMap<(NodeTargetRoot, Vec<String>), BTreeSet<String>> =
            BTreeMap::new();
        expected.insert((NodeTargetRoot::Worktree, Vec::new()), BTreeSet::new());
        expected.insert((NodeTargetRoot::Data, Vec::new()), BTreeSet::new());
        for slot in self
            .directories
            .mapped
            .directories()
            .iter()
            .chain(self.directories.mapped.files())
        {
            let parts = slot.components();
            let name = parts.last().ok_or(ReconcileError::Invariant(
                "inventory original component absent",
            ))?;
            expected
                .entry((slot.root(), parts[..parts.len() - 1].to_vec()))
                .or_default()
                .insert(name.clone());
        }
        for slot in self.directories.mapped.directories() {
            expected
                .entry((slot.root(), slot.components().to_vec()))
                .or_default();
        }
        expected
            .entry((NodeTargetRoot::Worktree, vec![".sync-extend".into()]))
            .or_default()
            .insert("writer.lock".into());
        if include_data_locks {
            let names = expected
                .entry((NodeTargetRoot::Data, Vec::new()))
                .or_default();
            names.insert("writer.lock".to_owned());
            names.insert("cas-access.lock".to_owned());
        }
        for ((root, parts), names) in expected {
            let path = self.directories.path(root, &parts);
            let mut actual = BTreeSet::new();
            for item in std::fs::read_dir(&path)? {
                let item = item?;
                let kind = item.file_type()?;
                if kind.is_symlink() || sync_extend_cas::is_reparse(&item.metadata()?) {
                    return Err(ReconcileError::Invariant("original inventory link/reparse"));
                }
                let name = item
                    .file_name()
                    .into_string()
                    .map_err(|_| ReconcileError::Invariant("inventory filename encoding"))?;
                if actual.len() >= names.len() || !actual.insert(name) {
                    return Err(ReconcileError::Invariant(
                        "original inventory unexpected entry",
                    ));
                }
            }
            if actual != names {
                return Err(ReconcileError::Invariant(
                    "original full inventory names differ",
                ));
            }
        }
        self.verify()
    }
}
