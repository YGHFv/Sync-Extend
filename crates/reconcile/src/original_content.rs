//! Signed page restart and original content owners; no metadata or native worker.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{
    reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope},
    Change, ChunkRef, ContentId, DeviceId, EntryId, OperationId, SpaceId, FORMAT_VERSION,
};
use sync_extend_transport::{
    PeerIdentity, SignedOriginalContentRequest, SignedOriginalOperationPage,
    VerifiedOriginalContentOffer,
};

#[derive(Serialize)]
pub struct OriginalContentPreparation {
    pub page_request_id: ContentId,
    pub reservation: Option<crate::ReferenceReservation>,
    pub reservations: Vec<crate::ReferenceReservation>,
    pub missing_chunks: Vec<ChunkRef>,
    pub content_closed: bool,
    pub signed_provenance_persisted: bool,
    pub signed_page_inbox_persisted: bool,
    pub operations_received: bool,
    pub worktree_materialized: bool,
    pub remote_backup_complete: bool,
}

#[derive(Serialize)]
pub struct OriginalContentImport {
    pub page_request_id: ContentId,
    pub chunk: ChunkRef,
    pub chunk_verified: bool,
    pub whole_file_verified: bool,
    pub worktree_materialized: bool,
}

impl LocalSpace {
    fn original_content_offer(
        &self,
        source: &PeerIdentity,
        page: &SignedOriginalOperationPage,
    ) -> Result<VerifiedOriginalContentOffer> {
        self.verify_root()?;
        if source.space_id != self.space_id
            || source.device_id == self.device_id
            || self.read_transport_peer(&source.device_id)? != *source
        {
            return Err(ReconcileError::Invariant(
                "original page current source approval",
            ));
        }
        let receiver = self.transport_identity()?;
        page.verify_content_offer(
            source,
            receiver.peer_identity(),
            &page.page.channel_binding,
            page.page.after_sequence,
            &self.limits,
        )
        .map_err(|_| ReconcileError::Invariant("original content authenticated page/limits"))
    }

    /// Persist originals and reserve each Put before block import. Owners exclude
    /// page/session boundaries, while every network request still binds its page.
    pub fn prepare_original_content(
        &mut self,
        source: &PeerIdentity,
        page: &SignedOriginalOperationPage,
    ) -> Result<OriginalContentPreparation> {
        let offer = self.original_content_offer(source, page)?;
        let request = page
            .page
            .request_id()
            .map_err(|_| ReconcileError::Invariant("original page request invalid"))?;
        // Reject original equivocation before allocating a different content owner.
        for signed in &page.page.operations {
            self.journal.retain_original_provenance(
                &sync_extend_journal::RemotePublicationProof {
                    public_key: source.public_key,
                    operation: signed.operation.clone(),
                    signature: signed.signature.clone(),
                },
                &source.public_key,
            )?;
        }
        let persisted = !page.page.operations.is_empty();
        if persisted {
            checkpoint("before_original_page_inbox");
            self.journal.retain_original_page(
                &sync_extend_journal::OriginalPageEnvelope {
                    source: source.clone(),
                    receiver: self.transport_identity()?.peer_identity().clone(),
                    signed_page: page.clone(),
                },
                &source.public_key,
            )?;
            checkpoint("after_original_page_inbox");
        }
        let (reservations, missing, closed) =
            self.reserve_original_offer_content(&page.page.operations, &offer)?;
        self.verify_root()?;
        Ok(OriginalContentPreparation {
            page_request_id: request,
            reservation: reservations.first().cloned(),
            reservations,
            missing_chunks: missing,
            content_closed: closed,
            signed_provenance_persisted: true,
            signed_page_inbox_persisted: persisted,
            operations_received: false,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }

    pub(crate) fn reserve_original_offer_content(
        &mut self,
        operations: &[sync_extend_transport::SignedOperation],
        offer: &VerifiedOriginalContentOffer,
    ) -> Result<(Vec<crate::ReferenceReservation>, Vec<ChunkRef>, bool)> {
        let mut reservations = Vec::new();
        for signed in operations {
            let Change::Put { entry } = &signed.operation.payload.change else {
                continue;
            };
            let Some(file) = &entry.content else {
                continue;
            };
            let intent = crate::ReferenceReservationIntent {
                owner_id: original_owner_id(
                    &self.space_id,
                    &self.device_id,
                    &signed.operation.op_id,
                )?,
                scope: ReferenceOwnerScope {
                    format_version: FORMAT_VERSION,
                    space_id: self.space_id.clone(),
                    kind: ReferenceOwnerKind::Download,
                    target_device: None,
                    files: vec![file.clone()],
                },
                created_at_ms: signed.operation.payload.created_at_ms,
            };
            checkpoint("before_original_content_reservation");
            reservations.push(self.reserve_content(&intent)?);
            checkpoint("after_original_content_reservation");
        }
        let mut all = std::collections::BTreeMap::new();
        for file in offer.files() {
            for chunk in &file.chunks {
                all.insert(chunk.content_id.clone(), chunk.clone());
            }
        }
        let mut missing = Vec::new();
        for chunk in all.into_values() {
            if self.cas.object_path(&chunk.content_id).try_exists()? {
                self.cas.read(&chunk)?;
            } else {
                missing.push(chunk);
            }
        }
        let closed = missing.is_empty();
        if closed {
            for file in offer.files() {
                self.cas.verify(file)?;
            }
        }
        self.verify_root()?;
        Ok((reservations, missing, closed))
    }

    /// Recover exact signed pages without peer-supplied reconstruction. Current
    /// stored approval, root identity and configured limits are rechecked.
    pub fn original_content_inbox(
        &self,
        max: usize,
    ) -> Result<Vec<sync_extend_journal::OriginalPageEnvelope>> {
        self.verify_root()?;
        let receiver = self.transport_identity()?;
        let pages = self.journal.original_pages(&self.space_id, max)?;
        for envelope in &pages {
            if envelope.receiver != *receiver.peer_identity() {
                return Err(ReconcileError::Invariant(
                    "original inbox receiver identity drift",
                ));
            }
            self.original_content_offer(&envelope.source, &envelope.signed_page)?;
        }
        self.verify_root()?;
        Ok(pages)
    }

    /// Old page provenance restores owners/content state, never authorizes a new
    /// network channel. A reconnect still requires its freshly signed wire page.
    pub fn resume_original_content(
        &mut self,
        request: &ContentId,
    ) -> Result<OriginalContentPreparation> {
        let envelope = self
            .original_content_inbox(self.limits.max_storage_entries)?
            .into_iter()
            .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(request))
            .ok_or(ReconcileError::Invariant("original inbox request absent"))?;
        self.prepare_original_content(&envelope.source, &envelope.signed_page)
    }

    /// Original request and current approval are reverified on every call. The
    /// pre-existing durable reservation must match before the managed CAS put.
    pub fn ingest_original_content_block(
        &mut self,
        source: &PeerIdentity,
        page: &SignedOriginalOperationPage,
        request: &SignedOriginalContentRequest,
        id: &ContentId,
        bytes: &[u8],
    ) -> Result<OriginalContentImport> {
        let offer = self.original_content_offer(source, page)?;
        let identity = self.transport_identity()?;
        request
            .verify_block(identity.peer_identity(), &offer, id, bytes)
            .map_err(|_| ReconcileError::Invariant("original exact requested block invalid"))?;
        self.ingest_verified_original_content(source, &page.page.operations, request, id, bytes)
    }

    pub(crate) fn ingest_verified_original_content(
        &mut self,
        source: &PeerIdentity,
        operations: &[sync_extend_transport::SignedOperation],
        request: &SignedOriginalContentRequest,
        id: &ContentId,
        bytes: &[u8],
    ) -> Result<OriginalContentImport> {
        self.verify_root()?;
        if self.read_transport_peer(&source.device_id)? != *source {
            return Err(ReconcileError::Invariant(
                "original block current source approval changed",
            ));
        }
        for signed in operations {
            let expected = sync_extend_journal::RemotePublicationProof {
                public_key: source.public_key,
                operation: signed.operation.clone(),
                signature: signed.signature.clone(),
            };
            if self.journal.original_provenance(
                &self.space_id,
                &source.device_id,
                signed.operation.payload.origin_seq,
            )? != Some(expected)
            {
                return Err(ReconcileError::Invariant(
                    "original block requires exact retained signing provenance",
                ));
            }
        }
        let original = operations
            .iter()
            .find(|signed| {
                matches!(&signed.operation.payload.change, Change::Put { entry }
                if entry.content.as_ref().is_some_and(|file|
                    file.chunks.iter().any(|chunk| &chunk.content_id == id)))
            })
            .ok_or(ReconcileError::Invariant(
                "original chunk has no owning Put",
            ))?;
        let owner_id =
            original_owner_id(&self.space_id, &self.device_id, &original.operation.op_id)?;
        let Change::Put { entry } = &original.operation.payload.change else {
            unreachable!()
        };
        let owner = self
            .reference_reservations()?
            .into_iter()
            .find(|owner| owner.intent.owner_id == owner_id)
            .ok_or(ReconcileError::Invariant(
                "original operation content owner absent",
            ))?;
        if owner.intent.scope.kind != ReferenceOwnerKind::Download
            || owner.intent.scope.space_id != self.space_id
            || owner.intent.scope.target_device.is_some()
            || owner.intent.scope.files.as_slice() != entry.content.as_slice()
            || owner.intent.created_at_ms != original.operation.payload.created_at_ms
        {
            return Err(ReconcileError::Invariant(
                "original content owner scope differs",
            ));
        }
        let expected = request
            .request
            .chunks
            .iter()
            .find(|chunk| &chunk.content_id == id)
            .ok_or(ReconcileError::Invariant("original requested chunk absent"))?;
        checkpoint("before_original_content_block");
        let (guard, actual) = self.journal.with_reserved_chunk(
            &self.space_id,
            &owner_id,
            id,
            self.limits.max_storage_entries,
            |reserved| -> Result<ChunkRef> {
                if reserved != expected {
                    return Err(ReconcileError::Invariant("original reserved chunk differs"));
                }
                checkpoint("after_original_content_owner_lock");
                let actual = self.cas.put(bytes)?;
                if &actual != expected || self.cas.read(&actual)?.as_slice() != bytes {
                    return Err(ReconcileError::Invariant("original imported chunk differs"));
                }
                checkpoint("after_original_content_put");
                self.verify_root()?;
                Ok(actual)
            },
        )?;
        drop(guard);
        self.verify_root()?;
        Ok(OriginalContentImport {
            page_request_id: request.request.page_request_id.clone(),
            chunk: actual,
            chunk_verified: true,
            whole_file_verified: false,
            worktree_materialized: false,
        })
    }
}

pub(crate) fn original_owner_id(
    space: &SpaceId,
    receiver: &DeviceId,
    operation: &OperationId,
) -> Result<EntryId> {
    let bound = ContentId::hash(&serde_json::to_vec(&(
        "original-operation-content-owner-v1",
        space,
        receiver,
        operation,
    ))?);
    Ok(bound.as_str()[..32].parse()?)
}
