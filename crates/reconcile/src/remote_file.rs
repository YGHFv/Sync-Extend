//! Explicit authenticated file-copy boundary. Remote causal operations are not applied.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use sync_extend_core_model::{
    reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope},
    remote_file::{RemoteFileOffer, MAX_REMOTE_FILE_OFFER_BYTES},
    ChunkRef, ContentId, DeviceId, EntryId, FileManifest, SnapshotId, FORMAT_VERSION,
};
use sync_extend_journal::{PublicationState, ReferenceReservation, ReferenceReservationIntent};

#[derive(Serialize)]
pub struct RemoteFilePreparation {
    pub transfer_id: EntryId,
    pub source_snapshot: SnapshotId,
    pub entry_id: EntryId,
    pub reservation: ReferenceReservation,
    pub missing_chunks: Vec<ChunkRef>,
    pub metadata_received: bool,
    pub content_closed: bool,
    pub worktree_materialized: bool,
    pub causal_operation_materialized: bool,
}

#[derive(Serialize)]
pub struct RemoteFileChunkImport {
    pub transfer_id: EntryId,
    pub chunk: ChunkRef,
    pub chunk_verified: bool,
    pub content_closed: bool,
    pub worktree_materialized: bool,
}

#[derive(Serialize)]
pub struct RemoteFileMaterialization {
    pub transfer_id: EntryId,
    pub source_snapshot: SnapshotId,
    pub source_entry_id: EntryId,
    pub publication: crate::PublishResult,
    pub owner_transferred_to_snapshot: bool,
    pub content_closed: bool,
    pub worktree_materialized: bool,
    pub causal_operation_materialized: bool,
    pub whole_snapshot_materialized: bool,
}

impl LocalSpace {
    /// The caller must authenticate the signed canonical offer and authorize
    /// its exact sender/space before entering any remote receive method.
    pub fn prepare_remote_file(
        &mut self,
        authenticated_device: &DeviceId,
        offer: &RemoteFileOffer,
    ) -> Result<RemoteFilePreparation> {
        self.check_remote_file(authenticated_device, offer)?;
        let intent = self.remote_file_reservation(offer)?;
        checkpoint("before_remote_file_reservation");
        let owner = self.reserve_content(&intent)?;
        checkpoint("after_remote_file_reservation");
        let content = offer.content()?;
        let missing_chunks = self.missing_remote_chunks(content)?;
        let content_closed = missing_chunks.is_empty() && self.cas.verify(content).is_ok();
        if missing_chunks.is_empty() {
            self.cas.verify(content)?;
        }
        self.verify_root()?;
        Ok(RemoteFilePreparation {
            transfer_id: intent.owner_id,
            source_snapshot: offer.source_snapshot.clone(),
            entry_id: offer.entry_id.clone(),
            worktree_materialized: owner.snapshot_handoff.is_some(),
            reservation: owner,
            missing_chunks,
            metadata_received: true,
            content_closed,
            causal_operation_materialized: false,
        })
    }

    pub fn ingest_remote_file_chunk(
        &mut self,
        authenticated_device: &DeviceId,
        offer: &RemoteFileOffer,
        content_id: &ContentId,
        bytes: &[u8],
    ) -> Result<RemoteFileChunkImport> {
        self.check_remote_file(authenticated_device, offer)?;
        let expected = self
            .remote_file_chunks(offer.content()?)?
            .remove(content_id)
            .ok_or(ReconcileError::Invariant(
                "chunk is outside remote file offer",
            ))?;
        if bytes.len() != expected.length as usize || ContentId::hash(bytes) != *content_id {
            return Err(ReconcileError::Invariant(
                "remote chunk length or hash mismatch",
            ));
        }
        let owner_id = offer.transfer_id()?;
        checkpoint("before_remote_chunk_ingest");
        let (guard, chunk) = self.journal.with_reserved_chunk(
            &self.space_id,
            &owner_id,
            content_id,
            self.limits.max_storage_entries,
            |reserved| -> Result<ChunkRef> {
                if *reserved != expected {
                    return Err(ReconcileError::Invariant(
                        "remote reservation chunk mismatch",
                    ));
                }
                checkpoint("after_remote_chunk_owner_lock");
                let actual = self.cas.put(bytes)?;
                if actual != expected || self.cas.read(&expected)?.as_slice() != bytes {
                    return Err(ReconcileError::Invariant(
                        "remote chunk publication mismatch",
                    ));
                }
                checkpoint("after_remote_chunk_put");
                self.verify_root()?;
                Ok(actual)
            },
        )?;
        checkpoint("after_remote_chunk_commit");
        drop(guard);
        self.verify_root()?;
        Ok(RemoteFileChunkImport {
            transfer_id: owner_id,
            chunk,
            chunk_verified: true,
            content_closed: false,
            worktree_materialized: false,
        })
    }

    /// Publish a real guarded local copy, never a claim that the remote causal
    /// operation or the entire remote snapshot has converged/materialized.
    pub fn materialize_remote_file(
        &mut self,
        authenticated_device: &DeviceId,
        offer: &RemoteFileOffer,
    ) -> Result<RemoteFileMaterialization> {
        self.check_remote_file(authenticated_device, offer)?;
        let preparation = self.prepare_remote_file(authenticated_device, offer)?;
        if !preparation.content_closed {
            return Err(ReconcileError::Invariant(
                "remote file content is incomplete",
            ));
        }
        let content = offer.content()?;
        let transaction = offer.publication_id()?;
        let existing = self.journal.find_publication(&transaction)?;
        if let Some(publication) = &existing {
            if publication.intent.space_id != self.space_id
                || publication.intent.entry_id != offer.local_entry_id()?
                || publication.intent.requested_path != offer.entry()?.path
                || publication.intent.content != *content
                || publication.intent.source_snapshot.is_some()
            {
                return Err(ReconcileError::Invariant(
                    "remote publication identity collision",
                ));
            }
        }
        let _session = self.cas.acquire_session()?;
        self.cas.verify(content)?;
        if existing.is_none() {
            self.recover()?;
            self.scan_without_recovery()?;
            self.begin_content_with_ids(
                offer.entry()?.path.clone(),
                content.clone(),
                None,
                transaction.clone(),
                offer.local_entry_id()?,
            )?;
            checkpoint("after_remote_file_publication_intent");
        } else if existing
            .as_ref()
            .is_some_and(|publication| publication.state != PublicationState::Committed)
        {
            self.require_remote_publication_exclusive(&transaction)?;
        }
        self.recover_transaction(&transaction)?;
        checkpoint("after_remote_file_materialization");
        let publication = self.publication_result(&transaction)?;
        // Inspect the publication's immutable committed snapshot even when a
        // later native user edit changes the current worktree. The receipt
        // proves this publication's commit, not perpetual live path equality.
        let owner = self.handoff_content(&offer.transfer_id()?, &publication.snapshot_id)?;
        checkpoint("after_remote_file_owner_handoff");
        self.verify_root()?;
        Ok(RemoteFileMaterialization {
            transfer_id: offer.transfer_id()?,
            source_snapshot: offer.source_snapshot.clone(),
            source_entry_id: offer.entry_id.clone(),
            owner_transferred_to_snapshot: owner.snapshot_handoff.is_some(),
            publication,
            content_closed: true,
            worktree_materialized: true,
            causal_operation_materialized: false,
            whole_snapshot_materialized: false,
        })
    }

    pub fn offer_remote_file(
        &self,
        snapshot: &SnapshotId,
        entry: &EntryId,
    ) -> Result<RemoteFileOffer> {
        self.verify_root()?;
        let retained = self.journal.retained_snapshot(&self.space_id, snapshot)?;
        if retained.state != "materialized" {
            return Err(ReconcileError::Invariant(
                "offer requires a materialized local snapshot",
            ));
        }
        let offer = RemoteFileOffer {
            format_version: FORMAT_VERSION,
            source_device: self.device_id.clone(),
            source_snapshot: snapshot.clone(),
            manifest: retained.manifest,
            entry_id: entry.clone(),
            created_at_ms: retained.created_at_ms,
        };
        self.check_remote_offer_limits(&offer)?;
        let _session = self.cas.acquire_session()?;
        self.cas.verify(offer.content()?)?;
        self.verify_root()?;
        Ok(offer)
    }

    pub fn read_remote_file_chunk(
        &self,
        offer: &RemoteFileOffer,
        content_id: &ContentId,
    ) -> Result<Vec<u8>> {
        self.verify_root()?;
        self.check_remote_offer_limits(offer)?;
        if offer.source_device != self.device_id || offer.manifest.space_id != self.space_id {
            return Err(ReconcileError::Invariant("remote chunk offer is not local"));
        }
        let retained = self
            .journal
            .retained_snapshot(&self.space_id, &offer.source_snapshot)?;
        if retained.state != "materialized"
            || retained.manifest != offer.manifest
            || retained.created_at_ms != offer.created_at_ms
        {
            return Err(ReconcileError::Invariant(
                "remote chunk source snapshot changed",
            ));
        }
        let chunk = self
            .remote_file_chunks(offer.content()?)?
            .remove(content_id)
            .ok_or(ReconcileError::Invariant("chunk is outside source file"))?;
        let _session = self.cas.acquire_session()?;
        let bytes = self.cas.read(&chunk)?;
        self.verify_root()?;
        Ok(bytes)
    }

    fn check_remote_file(&self, authenticated: &DeviceId, offer: &RemoteFileOffer) -> Result<()> {
        self.verify_root()?;
        self.check_remote_offer_limits(offer)?;
        if offer.source_device != *authenticated
            || offer.source_device == self.device_id
            || offer.manifest.space_id != self.space_id
        {
            return Err(ReconcileError::Invariant(
                "remote offer authenticated scope mismatch",
            ));
        }
        self.journal
            .require_no_tree_restore(&self.space_id, self.limits.max_storage_entries)?;
        Ok(())
    }

    fn check_remote_offer_limits(&self, offer: &RemoteFileOffer) -> Result<()> {
        offer.validate()?;
        if serde_json::to_vec(offer)?.len() > MAX_REMOTE_FILE_OFFER_BYTES
            || offer.manifest.entries.len() > self.limits.max_scan_entries
            || offer.manifest.tombstones.len() > self.limits.max_scan_entries
        {
            return Err(ReconcileError::ResourceLimit("remote offer metadata"));
        }
        self.check_publication_limits(offer.content()?)?;
        self.remote_file_chunks(offer.content()?)?;
        Ok(())
    }

    fn remote_file_chunks(&self, content: &FileManifest) -> Result<BTreeMap<ContentId, ChunkRef>> {
        content.validate()?;
        if content.chunks.len() > self.limits.max_scan_chunks {
            return Err(ReconcileError::ResourceLimit("remote file chunks"));
        }
        let mut unique = BTreeMap::new();
        for chunk in &content.chunks {
            if unique
                .insert(chunk.content_id.clone(), chunk.clone())
                .is_some_and(|old| old != *chunk)
            {
                return Err(ReconcileError::Invariant(
                    "remote chunk description mismatch",
                ));
            }
        }
        Ok(unique)
    }

    fn missing_remote_chunks(&self, content: &FileManifest) -> Result<Vec<ChunkRef>> {
        let _session = self.cas.acquire_session()?;
        let mut missing = Vec::new();
        for chunk in self.remote_file_chunks(content)?.into_values() {
            match self.cas.read(&chunk) {
                Ok(_) => {}
                Err(sync_extend_cas::CasError::Io(error))
                    if error.kind() == std::io::ErrorKind::NotFound =>
                {
                    missing.push(chunk);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(missing)
    }

    fn remote_file_reservation(
        &self,
        offer: &RemoteFileOffer,
    ) -> Result<ReferenceReservationIntent> {
        Ok(ReferenceReservationIntent {
            owner_id: offer.transfer_id()?,
            scope: ReferenceOwnerScope {
                format_version: FORMAT_VERSION,
                space_id: self.space_id.clone(),
                kind: ReferenceOwnerKind::Download,
                target_device: None,
                files: vec![offer.content()?.clone()],
            },
            created_at_ms: offer.created_at_ms,
        })
    }

    fn require_remote_publication_exclusive(&self, transaction: &EntryId) -> Result<()> {
        self.require_no_mutation()?;
        if self
            .journal
            .outstanding_publications(&self.space_id)?
            .iter()
            .any(|publication| publication.intent.transaction_id != *transaction)
        {
            return Err(ReconcileError::Invariant(
                "another publication must be recovered first",
            ));
        }
        Ok(())
    }
}
