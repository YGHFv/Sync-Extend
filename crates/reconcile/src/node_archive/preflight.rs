//! Whole source and ledger capacity checks before the first target root effect.
use super::{
    CreatedNodeRestoreRoots, LedgerBounds, NodeRestoreFile, NodeRestoreLayout, NodeRestoreLedger,
    NodeRestoreMappedLayout, NodeTargetRoot, VerifiedNodeStateArchive,
};
use crate::{ReconcileError, Result};
use std::path::{Path, PathBuf};
use sync_extend_core_model::ContentId;
use sync_extend_journal::{JournalBackupImage, NodeInspectionBounds};

/// Owns the exact precomputed Journal mapping and source-derived layout.
/// It carries no native CREATE or restart/adoption authority. Every actual
/// CREATE still requires the independently live original external ledger.
pub struct PreparedOriginalNodeRestore {
    pub(super) archive_digest: ContentId,
    pub(super) original: NodeRestoreLayout,
    pub(super) mapped: NodeRestoreMappedLayout,
    pub(super) journal: JournalBackupImage,
    pub(super) read_lease_hold: Option<ContentId>,
    pub(super) worktree: PathBuf,
    pub(super) data: PathBuf,
    pub(super) required_file_bytes: u64,
    pub(super) required_records: u64,
    pub(super) required_intents: usize,
    pub(super) reserved_record_bytes: u64,
    pub(super) completion_manifest_reserve: u64,
    pub(super) reserved_database_bytes: u64,
    pub(super) ledger_bounds: LedgerBounds,
    future_file_bytes: Vec<(NodeTargetRoot, u64)>,
}

impl PreparedOriginalNodeRestore {
    pub fn required_file_bytes(&self) -> u64 {
        self.required_file_bytes
    }
    pub fn required_records(&self) -> u64 {
        self.required_records
    }
    pub fn required_intents(&self) -> usize {
        self.required_intents
    }
    pub fn reserved_record_bytes(&self) -> u64 {
        self.reserved_record_bytes
    }
    pub fn completion_manifest_reserve(&self) -> u64 {
        self.completion_manifest_reserve
    }
    pub fn reserved_database_bytes(&self) -> u64 {
        self.reserved_database_bytes
    }
    pub fn original_journal_bytes(&self) -> u64 {
        self.journal.bytes().len() as u64
    }
    /// Exact planned native file lengths, in mapped file order. Separately
    /// owned deployment configs and the three empty coordination sentinels
    /// have their own slots and are budgeted by their actual owners.
    /// These values grant no filesystem or creation authority.
    pub fn future_file_bytes_by_root(&self) -> Result<Vec<(NodeTargetRoot, u64)>> {
        if self.future_file_bytes.len() != self.mapped.files().len()
            || self
                .future_file_bytes
                .iter()
                .zip(self.mapped.files())
                .any(|((root, _), slot)| *root != slot.root())
        {
            return Err(ReconcileError::Invariant(
                "prepared original per-file liability scope differs",
            ));
        }
        let total = self.future_file_bytes.iter().try_fold(0u64, |total, (_, bytes)| {
            total.checked_add(*bytes).ok_or(ReconcileError::ResourceLimit(
                "prepared original per-file liability overflow",
            ))
        })?;
        if total > self.required_file_bytes {
            return Err(ReconcileError::Invariant(
                "prepared original native files exceed full source budget",
            ));
        }
        Ok(self.future_file_bytes.clone())
    }
    /// Read-only original first-write budget. It supplies no native creator,
    /// registered VFS, descriptor, ledger, or reactivation authority.
    pub fn original_first_write_main_limit(&self) -> Result<u64> {
        super::node_write_transition::original_write_main_limit(self.original_journal_bytes())
    }
    pub fn original_first_write_sidecar_limit(&self) -> u64 {
        super::node_write_transition::ORIGINAL_WRITE_SIDECAR_LIMIT
    }
    pub fn original_layout(&self) -> &NodeRestoreLayout {
        &self.original
    }
    pub fn mapped_layout(&self) -> &NodeRestoreMappedLayout {
        &self.mapped
    }
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }

    /// No target filesystem effect occurs before the complete source mapping,
    /// aggregate bytes and the exact live ledger's reserved capacity are checked.
    /// Original partial roots remain intact if later native effects fail.
    pub fn create_original_roots(
        &self,
        archive: &VerifiedNodeStateArchive,
        ledger: &mut NodeRestoreLedger,
    ) -> Result<CreatedNodeRestoreRoots> {
        if archive.digest() != &self.archive_digest {
            return Err(ReconcileError::Invariant(
                "preflight root original archive differs",
            ));
        }
        self.original
            .verify_original_source_scope(archive, &self.worktree, &self.data)?;
        ledger.require_original_preflight_capacity(self)?;
        ledger.prepare_durable_original_completion(self.completion_manifest_reserve)?;
        archive.create_restore_roots(ledger, &self.worktree, &self.data)
    }
}

impl VerifiedNodeStateArchive {
    /// Performs only bounded source/memory work. Neither target path is opened,
    /// created or modified. Unsupported native history and explicit configuration
    /// roles refuse before external ledger or target CREATE.
    pub fn prepare_original_node_restore(
        &self,
        worktree: &Path,
        data: &Path,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        ledger_bounds: LedgerBounds,
    ) -> Result<PreparedOriginalNodeRestore> {
        self.prepare_original_node_restore_inner(
            worktree,
            data,
            inspection,
            max_creations,
            max_file_bytes,
            ledger_bounds,
            None,
            super::restore_layout::NodeConfigRestoreScope::Ordinary,
        )
    }

    /// The exact preview inventory must be supplied for active lease owners.
    /// Their source rows survive with a durable target hold and no new issuer.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_original_node_restore_with_read_lease_hold(
        &self,
        worktree: &Path,
        data: &Path,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        ledger_bounds: LedgerBounds,
        expected_hold: &ContentId,
    ) -> Result<PreparedOriginalNodeRestore> {
        self.prepare_original_node_restore_inner(
            worktree,
            data,
            inspection,
            max_creations,
            max_file_bytes,
            ledger_bounds,
            Some(expected_hold),
            super::restore_layout::NodeConfigRestoreScope::Ordinary,
        )
    }

    /// The verified deployment protocol owns the separately mapped config
    /// CREATEs. Its non-cloneable proof remains in the owned original layout.
    #[cfg(windows)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_original_node_restore_for_deployment(
        &self,
        worktree: &Path,
        data: &Path,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        ledger_bounds: LedgerBounds,
        separated_configs: crate::SeparatedDeploymentNodeConfigs,
        expected_hold: Option<&ContentId>,
    ) -> Result<PreparedOriginalNodeRestore> {
        self.prepare_original_node_restore_inner(
            worktree,
            data,
            inspection,
            max_creations,
            max_file_bytes,
            ledger_bounds,
            expected_hold,
            super::restore_layout::NodeConfigRestoreScope::SeparatedDeployment {
                configs: separated_configs,
                worktree: worktree.to_owned(),
                data: data.to_owned(),
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_original_node_restore_inner(
        &self,
        worktree: &Path,
        data: &Path,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        ledger_bounds: LedgerBounds,
        expected_hold: Option<&ContentId>,
        config_scope: super::restore_layout::NodeConfigRestoreScope,
    ) -> Result<PreparedOriginalNodeRestore> {
        ledger_bounds.validate().map_err(ReconcileError::from)?;
        super::roots::split_target(worktree)?;
        super::roots::split_target(data)?;
        if worktree == data || worktree.starts_with(data) || data.starts_with(worktree) {
            return Err(ReconcileError::Invariant(
                "original restore target roots overlap",
            ));
        }
        if expected_hold.is_some() {
            self.validate_read_lease_migration_roots(worktree, data)?;
        }
        let original = self.current_node_restore_layout_inner(
            inspection,
            max_creations,
            max_file_bytes,
            config_scope,
        )?;
        let mapped = original.map_original_slots(max_creations)?;
        let bytes = self.journal_bytes()?;
        let journal = self.map_original_restore_journal(
            worktree,
            inspection,
            usize::try_from(max_file_bytes.min(256 * 1024 * 1024))
                .map_err(|_| ReconcileError::ResourceLimit("preflight Journal byte bound"))?,
            expected_hold,
        )?;
        // Layout already includes source Journal, marker, sections and all
        // current files. Substitute the exact precomputed mapped Journal length.
        let required_file_bytes = original
            .required_file_bytes()
            .checked_sub(bytes.len() as u64)
            .and_then(|count| count.checked_add(journal.bytes().len() as u64))
            .filter(|count| *count <= max_file_bytes && *count <= ledger_bounds.max_content_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "whole original mapped content before root CREATE",
            ))?;
        if !original
            .files()
            .iter()
            .any(|file| matches!(file, NodeRestoreFile::Journal))
        {
            return Err(ReconcileError::Invariant("preflight Journal slot absent"));
        }
        let mut future_file_bytes = Vec::with_capacity(mapped.files().len());
        let mut native_file_total = 0u64;
        for slot in mapped.files() {
            let length = match mapped.file(slot, &original)? {
                NodeRestoreFile::Journal => journal.bytes().len() as u64,
                NodeRestoreFile::WorktreeCurrent { bytes, .. } => *bytes,
                NodeRestoreFile::WorktreeSpaceMarker => self.space().as_str().len() as u64,
                source => {
                    let role = match source {
                        NodeRestoreFile::ProtectedDeviceIdentity => super::ArchiveRole::DeviceSecret,
                        NodeRestoreFile::CasObject { content_id } => super::ArchiveRole::CasObject {
                            content_id: content_id.clone(),
                        },
                        NodeRestoreFile::PeerApproval { device_id } => super::ArchiveRole::PeerApproval {
                            device_id: device_id.clone(),
                        },
                        _ => return Err(ReconcileError::Invariant(
                            "prepared original native file liability role unsupported",
                        )),
                    };
                    self.archive.section(&role).ok_or(ReconcileError::Invariant(
                        "prepared original file liability section absent",
                    ))?.len() as u64
                }
            };
            native_file_total = native_file_total.checked_add(length).ok_or(
                ReconcileError::ResourceLimit("prepared original native file liability overflow"),
            )?;
            future_file_bytes.push((slot.root(), length));
        }
        if native_file_total > required_file_bytes {
            return Err(ReconcileError::Invariant(
                "prepared original native file liability exceeds full source",
            ));
        }
        // Two roots plus all derived directories/files; three additional empty
        // writer/CAS sentinels are not represented by the original archive.
        let required_intents = mapped
            .directories()
            .len()
            .checked_add(mapped.files().len())
            .and_then(|count| count.checked_add(5))
            .filter(|count| *count <= max_creations && *count <= ledger_bounds.max_intents)
            .ok_or(ReconcileError::ResourceLimit(
                "whole original CREATE count before root CREATE",
            ))?;
        let required_records = (required_intents as u64)
            .checked_mul(2)
            .and_then(|count| count.checked_add(mapped.files().len() as u64))
            .filter(|count| *count <= ledger_bounds.max_records)
            .ok_or(ReconcileError::ResourceLimit(
                "whole original ledger transitions before root CREATE",
            ))?;
        // Each exact canonical row contains at most one 255-byte component,
        // fixed hashes/keys, bounded counters and escaped JSON. 4096 bytes per
        // record bounds even six-byte JSON escaping for every component byte.
        // The completion repeats every relative component, including deep paths.
        // Bound worst-case JSON escaping before schema or target effects.
        let mut completion_manifest_reserve = 4096u64;
        for target in [worktree, data] {
            let path = target.to_str().filter(|value| value.len() <= 4096).ok_or(
                ReconcileError::Invariant("completion beforeeffects exact UTF8 target path"),
            )?;
            completion_manifest_reserve = completion_manifest_reserve
                .checked_add(path.len() as u64 * 6 + 32)
                .ok_or(ReconcileError::ResourceLimit(
                    "completion target path reservation overflow",
                ))?;
        }
        // Fixed roots and three sentinels have fewer than two path components.
        completion_manifest_reserve = completion_manifest_reserve.checked_add(5 * 4096).ok_or(
            ReconcileError::ResourceLimit("completion fixedslot reservation overflow"),
        )?;
        for slot in mapped.directories().iter().chain(mapped.files()) {
            let component_bytes = slot.components().iter().try_fold(0u64, |count, part| {
                count
                    .checked_add(part.len() as u64 * 6 + 4)
                    .ok_or(ReconcileError::ResourceLimit(
                        "completion escaped component reservation overflow",
                    ))
            })?;
            completion_manifest_reserve = completion_manifest_reserve
                .checked_add(component_bytes)
                .and_then(|count| count.checked_add(4096))
                .ok_or(ReconcileError::ResourceLimit(
                    "completion fullobject reservation overflow",
                ))?;
        }
        if completion_manifest_reserve > super::completion_codec::MAX_BYTES as u64 {
            return Err(ReconcileError::ResourceLimit(
                "completion whole canonical manifest budget before roots",
            ));
        }
        let reserved_record_bytes = required_records
            .checked_mul(4096)
            .and_then(|count| count.checked_add(completion_manifest_reserve))
            .filter(|count| *count <= ledger_bounds.max_record_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "whole original ledger JSON bytes before root CREATE",
            ))?;
        // Conservative room for payload pages, row headers and the fixed schema.
        // Exact SQLite max_page_count is installed on the living ledger as well.
        let reserved_database_bytes = reserved_record_bytes
            .checked_mul(2)
            .and_then(|count| count.checked_add(64 * 1024))
            .filter(|count| *count <= ledger_bounds.max_database_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "whole original ledger physical budget before root CREATE",
            ))?;
        Ok(PreparedOriginalNodeRestore {
            archive_digest: self.digest().clone(),
            original,
            mapped,
            journal,
            read_lease_hold: expected_hold.cloned(),
            worktree: worktree.to_owned(),
            data: data.to_owned(),
            required_file_bytes,
            required_records,
            required_intents,
            reserved_record_bytes,
            completion_manifest_reserve,
            reserved_database_bytes,
            ledger_bounds,
            future_file_bytes,
        })
    }
}
