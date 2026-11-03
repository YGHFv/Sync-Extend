use crate::{
    check_ancestors, fault::checkpoint, filesystem::ObservedFile, LocalSpace, ReconcileError,
    Result,
};
use serde::Serialize;
use std::{fs, io::Read, path::Path};
use sync_extend_cas::is_reparse;
use sync_extend_core_model::limits::LocalLimits;
use sync_extend_core_model::{ContentId, EntryId, SnapshotId};
use sync_extend_journal::{ReferenceReservation, ReferenceReservationIntent};

#[derive(Serialize)]
pub struct ReservedChunkImport {
    pub owner_id: EntryId,
    pub content_id: ContentId,
    pub bytes: u32,
    pub imported_chunk_verified: bool,
    pub whole_file_verified: bool,
    pub worktree_materialized: bool,
    pub owner_released: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub fn ingest_reserved_chunk(
        &mut self,
        owner_id: &EntryId,
        content_id: &ContentId,
        source: &Path,
    ) -> Result<ReservedChunkImport> {
        self.verify_root()?;
        checkpoint("before_reserved_chunk_ingest");
        let (guard, result) = self.journal.with_reserved_chunk(
            &self.space_id,
            owner_id,
            content_id,
            self.limits.max_storage_entries,
            |chunk| -> Result<ReservedChunkImport> {
                checkpoint("after_reserved_chunk_lock");
                if u64::from(chunk.length) > self.limits.max_file_bytes
                    || u64::from(chunk.length) > self.limits.max_staging_bytes
                {
                    return Err(ReconcileError::ResourceLimit("reserved chunk bytes"));
                }
                check_ancestors(source)?;
                let metadata = fs::symlink_metadata(source)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata)
                {
                    return Err(ReconcileError::Invariant("chunk source must be regular"));
                }
                let source = fs::canonicalize(source)?;
                if source.starts_with(&self.data_dir)
                    || source.components().any(|component| {
                        component.as_os_str().to_str().is_some_and(|part| {
                            [".sync-extend", ".sync-tmp", ".git"]
                                .iter()
                                .any(|reserved| part.eq_ignore_ascii_case(reserved))
                        })
                    })
                {
                    return Err(ReconcileError::Invariant("chunk source is internal data"));
                }
                let observed = ObservedFile::open(&source)?;
                if observed.metadata.len() != u64::from(chunk.length) {
                    return Err(ReconcileError::Invariant("reserved chunk source length"));
                }
                require_single_link(&observed)?;
                checkpoint("after_reserved_chunk_source_open");
                let mut bytes = Vec::with_capacity(chunk.length as usize);
                (&observed.file)
                    .take(u64::from(chunk.length) + 1)
                    .read_to_end(&mut bytes)?;
                observed.verify(&source)?;
                if bytes.len() != chunk.length as usize || ContentId::hash(&bytes) != *content_id {
                    return Err(ReconcileError::Invariant("reserved chunk hash mismatch"));
                }
                checkpoint("before_reserved_chunk_put");
                observed.verify(&source)?;
                require_single_link(&observed)?;
                let actual = self.cas.put(&bytes)?;
                if actual != *chunk {
                    return Err(ReconcileError::Invariant(
                        "reserved chunk publication mismatch",
                    ));
                }
                checkpoint("after_reserved_chunk_put");
                observed.verify(&source)?;
                require_single_link(&observed)?;
                self.cas.read(chunk)?;
                self.verify_root()?;
                Ok(ReservedChunkImport {
                    owner_id: owner_id.clone(),
                    content_id: content_id.clone(),
                    bytes: chunk.length,
                    imported_chunk_verified: true,
                    whole_file_verified: false,
                    worktree_materialized: false,
                    owner_released: false,
                    remote_backup_complete: false,
                })
            },
        )?;
        checkpoint("after_reserved_chunk_commit");
        drop(guard);
        self.verify_root()?;
        Ok(result)
    }

    pub fn reference_reservations(&self) -> Result<Vec<ReferenceReservation>> {
        self.verify_root()?;
        let owners = self
            .journal
            .reference_reservations(&self.space_id, self.limits.max_storage_entries)?;
        self.verify_root()?;
        Ok(owners)
    }

    /// Reserve exact expected chunks locally; does not import or start a worker.
    pub fn reserve_content(
        &mut self,
        intent: &ReferenceReservationIntent,
    ) -> Result<ReferenceReservation> {
        self.verify_root()?;
        if intent.scope.space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "reservation local space mismatch",
            ));
        }
        check_limits(intent, &self.limits)?;
        checkpoint("before_reference_reservation");
        let (guards, owner) = self.journal.with_reference_reservation(
            intent,
            self.limits.max_storage_entries,
            |_| -> Result<_> {
                checkpoint("after_reference_reservation_pins");
                self.verify_root()?;
                Ok(())
            },
        )?;
        checkpoint("after_reference_reservation_commit");
        drop(guards);
        self.verify_root()?;
        Ok(owner)
    }

    pub fn handoff_content(
        &mut self,
        owner_id: &EntryId,
        snapshot_id: &SnapshotId,
    ) -> Result<ReferenceReservation> {
        self.verify_root()?;
        checkpoint("before_reference_snapshot_handoff");
        let (guards, owner) = self.journal.with_reference_snapshot_handoff(
            &self.space_id,
            owner_id,
            snapshot_id,
            self.limits.max_storage_entries,
            |intent| -> Result<()> {
                checkpoint("after_reference_snapshot_handoff_lock");
                check_limits(intent, &self.limits)?;
                for file in &intent.scope.files {
                    self.cas.verify(file)?;
                }
                checkpoint("after_reference_snapshot_handoff_verify");
                self.verify_root()?;
                Ok(())
            },
        )?;
        checkpoint("after_reference_snapshot_handoff_commit");
        drop(guards);
        self.verify_root()?;
        Ok(owner)
    }
}

fn require_single_link(source: &ObservedFile) -> Result<()> {
    #[cfg(windows)]
    {
        sync_extend_platform_fs::verify_regular_file(&source.file)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if source.file.metadata()?.nlink() != 1 {
            return Err(ReconcileError::Invariant(
                "chunk source is a hardlink alias",
            ));
        }
    }
    Ok(())
}

fn check_limits(intent: &ReferenceReservationIntent, limits: &LocalLimits) -> Result<()> {
    intent.scope.validate()?;
    if intent.scope.files.len() > limits.max_scan_entries {
        return Err(ReconcileError::ResourceLimit("reservation files"));
    }
    let mut bytes = 0u64;
    let mut chunks = 0usize;
    for file in &intent.scope.files {
        if file.length > limits.max_file_bytes {
            return Err(ReconcileError::ResourceLimit("reservation file bytes"));
        }
        bytes = bytes
            .checked_add(file.length)
            .filter(|n| *n <= limits.max_scan_bytes)
            .ok_or(ReconcileError::ResourceLimit("reservation logical bytes"))?;
        chunks = chunks
            .checked_add(file.chunks.len())
            .filter(|n| *n <= limits.max_scan_chunks)
            .ok_or(ReconcileError::ResourceLimit("reservation chunks"))?;
    }
    Ok(())
}
