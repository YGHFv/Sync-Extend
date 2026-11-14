//! Explicit metadata-only retirement assessment; no path deletion or GC execution grant.
use crate::{ReconcileError, Result, StorageNode};
use std::collections::BTreeSet;
use sync_extend_core_model::{ContentId, EntryId};

#[derive(Debug, serde::Serialize)]
pub struct StorageRetirementAssessment {
    pub storage_id: ContentId,
    pub owner_id: EntryId,
    pub exact_owner_handoff_complete: bool,
    pub distinct_retained_chunks: usize,
    pub chunks_still_protected: usize,
    pub chunks_no_longer_protected: usize,
    pub physically_present_chunks: usize,
    pub missing_chunks: usize,
    pub present_verified_bytes: u64,
    pub metadata_retained: bool,
    pub physical_disposal_enabled: bool,
    pub deletion_authorized: bool,
    pub remote_backup_complete: bool,
}

impl StorageNode {
    #[cfg(windows)]
    pub(super) fn retained_retirement_metadata_hash(
        &self,
        storage_id: &ContentId,
    ) -> Result<ContentId> {
        let pages = self.traffic.pages(&self.config, &self.device)?;
        let snapshots = self.traffic.snapshots(&self.config, &self.device)?;
        let page = pages
            .iter()
            .find(|page| page.signed_page.page.storage_id().ok().as_ref() == Some(storage_id));
        let snapshot = snapshots
            .iter()
            .find(|snapshot| snapshot.storage_id().ok().as_ref() == Some(storage_id));
        if page.is_some() == snapshot.is_some() {
            return Err(ReconcileError::Invariant(
                "retirement exact original metadata scope",
            ));
        }
        let bytes = if let Some(page) = page {
            serde_json::to_vec(&page.signed_page)?
        } else {
            serde_json::to_vec(
                &snapshot
                    .ok_or(ReconcileError::Invariant(
                        "retirement exact original snapshot missing",
                    ))?
                    .signed_report,
            )?
        };
        Ok(ContentId::hash(&bytes))
    }
    pub(super) fn retired_storage_chunks(
        &self,
        storage_id: &ContentId,
    ) -> Result<(
        EntryId,
        std::collections::BTreeMap<ContentId, sync_extend_core_model::ChunkRef>,
    )> {
        let owner_id: EntryId = storage_id.as_str()[..32].parse()?;
        let owners = self
            .journal
            .reference_reservations(&self.config.space_id, self.config.max_metadata_entries)?;
        let owner = owners
            .iter()
            .find(|owner| owner.intent.owner_id == owner_id)
            .ok_or(ReconcileError::Invariant(
                "storage retirement exact owner absent",
            ))?;
        let exact_metadata = match owner.state {
            "transferred_to_storage_target" => self
                .traffic
                .pages(&self.config, &self.device)?
                .into_iter()
                .any(|retained| {
                    retained.signed_page.page.storage_id().ok().as_ref() == Some(storage_id)
                }),
            "transferred_to_snapshot_storage" => self
                .traffic
                .snapshots(&self.config, &self.device)?
                .into_iter()
                .any(|retained| retained.storage_id().ok().as_ref() == Some(storage_id)),
            _ => {
                return Err(ReconcileError::Invariant(
                    "storage retirement requires durable exact handoff",
                ))
            }
        };
        if !exact_metadata {
            return Err(ReconcileError::Invariant(
                "storage retirement exact retained metadata absent",
            ));
        }
        let mut chunks = std::collections::BTreeMap::new();
        for file in &owner.intent.scope.files {
            for chunk in &file.chunks {
                if chunks
                    .insert(chunk.content_id.clone(), chunk.clone())
                    .is_some_and(|prior| prior != *chunk)
                {
                    return Err(ReconcileError::Invariant(
                        "storage retirement conflicting chunk",
                    ));
                }
            }
        }
        Ok((owner_id, chunks))
    }
    /// An exact durable delivery/snapshot handoff ends only its own pin lifetime.
    /// Other owners and immutable original metadata remain independently audited.
    pub fn assess_retired_storage_content(
        &self,
        storage_id: &ContentId,
    ) -> Result<StorageRetirementAssessment> {
        self.verify_storage()?;
        let _session = self.cas.acquire_session()?;
        self.journal.with_gc_diagnostics(
            &self.config.space_id,
            self.config.max_metadata_entries,
            |_| {
                self.verify_storage()?;
                let (owner_id, chunks) = self.retired_storage_chunks(storage_id)?;
                let protected = self
                    .journal
                    .protected_objects()?
                    .into_iter()
                    .collect::<BTreeSet<_>>();
                let mut remaining = 0usize;
                let mut present = 0usize;
                let mut missing = 0usize;
                let mut bytes = 0u64;
                for chunk in chunks.values() {
                    remaining += usize::from(protected.contains(&chunk.content_id));
                    match self.cas.read(chunk) {
                        Ok(value) => {
                            present += 1;
                            bytes = bytes
                                .checked_add(value.len() as u64)
                                .ok_or(ReconcileError::ResourceLimit("storage retirement bytes"))?;
                        }
                        Err(sync_extend_cas::CasError::Io(error))
                            if error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            missing += 1
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                self.verify_storage()?;
                Ok(StorageRetirementAssessment {
                    storage_id: storage_id.clone(),
                    owner_id,
                    exact_owner_handoff_complete: true,
                    distinct_retained_chunks: chunks.len(),
                    chunks_still_protected: remaining,
                    chunks_no_longer_protected: chunks.len() - remaining,
                    physically_present_chunks: present,
                    missing_chunks: missing,
                    present_verified_bytes: bytes,
                    metadata_retained: true,
                    physical_disposal_enabled: false,
                    deletion_authorized: false,
                    remote_backup_complete: false,
                })
            },
        )
    }
}
