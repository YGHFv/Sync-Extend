//! Client forwarding keeps independent provenance and uses the original native drivers.
use crate::{
    fault::checkpoint, LocalSpace, OriginalContentImport, OriginalContentPreparation,
    ReconcileError, Result,
};
use serde::Serialize;
use sync_extend_core_model::ContentId;
#[cfg(windows)]
use sync_extend_core_model::OperationId;
use sync_extend_transport::{
    ForwardedPageEnvelope, PeerIdentity, SignedForwardedOperationPage,
    SignedOriginalContentRequest, VerifiedForwardedPage, VerifiedOriginalContentOffer,
};

#[derive(Serialize)]
pub struct ForwardedMetadataReceive {
    pub request_id: ContentId,
    pub accepted_operations: usize,
    pub duplicate_operations: usize,
    pub pending_on_admission: usize,
    pub contiguous_received_sequence: u64,
    pub worktree_materialized: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    fn verify_client_forwarded_page(
        &self,
        origin: &PeerIdentity,
        forwarder: &PeerIdentity,
        signed: &SignedForwardedOperationPage,
        binding: &ContentId,
    ) -> Result<VerifiedForwardedPage> {
        self.verify_root()?;
        if self.read_transport_peer(&origin.device_id)? != *origin
            || self.read_transport_peer(&forwarder.device_id)? != *forwarder
        {
            return Err(ReconcileError::Invariant(
                "client forwarding requires two current independent approvals",
            ));
        }
        let cursor = self.journal.cursor(&self.space_id, &origin.device_id)?;
        if signed.page.after_sequence > cursor {
            return Err(ReconcileError::Invariant(
                "client forwarded page skips durable original prefix",
            ));
        }
        let receiver = self.transport_identity()?;
        let verified = signed
            .verify(
                origin,
                forwarder,
                receiver.peer_identity(),
                binding,
                signed.page.after_sequence,
            )
            .map_err(|_| {
                ReconcileError::Invariant("client original/forwarder signature channel scope")
            })?;
        VerifiedOriginalContentOffer::from_verified_forward(&verified, &self.limits)
            .map_err(|_| ReconcileError::ResourceLimit("client forwarded page content bounds"))?;
        Ok(verified)
    }

    /// The binding is supplied by the authenticated connection. The immutable
    /// inbox is written before owners, content reception or any native effect.
    pub fn prepare_forwarded_content(
        &mut self,
        origin: &PeerIdentity,
        forwarder: &PeerIdentity,
        signed: &SignedForwardedOperationPage,
        binding: &ContentId,
    ) -> Result<OriginalContentPreparation> {
        let verified = self.verify_client_forwarded_page(origin, forwarder, signed, binding)?;
        let offer = VerifiedOriginalContentOffer::from_verified_forward(&verified, &self.limits)
            .map_err(|_| ReconcileError::ResourceLimit("client forwarded content bounds"))?;
        for original in &verified.page().operations {
            self.journal.retain_original_provenance(
                &sync_extend_journal::RemotePublicationProof {
                    public_key: origin.public_key,
                    operation: original.operation.clone(),
                    signature: original.signature.clone(),
                },
                &origin.public_key,
            )?;
        }
        let persisted = !verified.page().operations.is_empty();
        if persisted {
            checkpoint("before_forwarded_page_inbox");
            self.journal.retain_forwarded_page(
                &verified.envelope(),
                &origin.public_key,
                &forwarder.public_key,
            )?;
            checkpoint("after_forwarded_page_inbox");
        }
        let (reservations, missing_chunks, content_closed) =
            self.reserve_original_offer_content(&verified.page().operations, &offer)?;
        Ok(OriginalContentPreparation {
            page_request_id: verified
                .request_id()
                .map_err(|_| ReconcileError::Invariant("client forwarded request identity"))?,
            reservation: reservations.first().cloned(),
            reservations,
            missing_chunks,
            content_closed,
            signed_provenance_persisted: true,
            signed_page_inbox_persisted: persisted,
            operations_received: false,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }

    /// Historical bindings restore only durable provenance and owner state.
    /// New network transfers must supply their current connection binding.
    pub fn forwarded_content_inbox(&self, max: usize) -> Result<Vec<ForwardedPageEnvelope>> {
        self.verify_root()?;
        let receiver = self.transport_identity()?;
        let envelopes = self.journal.forwarded_pages(&self.space_id, max)?;
        for envelope in &envelopes {
            if envelope.receiver != *receiver.peer_identity() {
                return Err(ReconcileError::Invariant(
                    "client forwarded receiver identity changed",
                ));
            }
            self.verify_client_forwarded_page(
                &envelope.origin,
                &envelope.forwarder,
                &envelope.signed_page,
                &envelope.signed_page.page.channel_binding,
            )?;
        }
        self.verify_root()?;
        Ok(envelopes)
    }

    pub fn resume_forwarded_content(
        &mut self,
        request: &ContentId,
    ) -> Result<OriginalContentPreparation> {
        let envelope = self.forwarded_inbox_request(request)?;
        self.prepare_forwarded_content(
            &envelope.origin,
            &envelope.forwarder,
            &envelope.signed_page,
            &envelope.signed_page.page.channel_binding,
        )
    }

    fn forwarded_inbox_request(&self, request: &ContentId) -> Result<ForwardedPageEnvelope> {
        self.forwarded_content_inbox(self.limits.max_storage_entries)?
            .into_iter()
            .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(request))
            .ok_or(ReconcileError::Invariant(
                "client forwarded inbox request absent",
            ))
    }

    pub fn ingest_forwarded_content_block(
        &mut self,
        envelope: &ForwardedPageEnvelope,
        binding: &ContentId,
        request: &SignedOriginalContentRequest,
        id: &ContentId,
        bytes: &[u8],
    ) -> Result<OriginalContentImport> {
        let verified = self.verify_client_forwarded_page(
            &envelope.origin,
            &envelope.forwarder,
            &envelope.signed_page,
            binding,
        )?;
        let offer = VerifiedOriginalContentOffer::from_verified_forward(&verified, &self.limits)
            .map_err(|_| ReconcileError::ResourceLimit("client forwarded content bounds"))?;
        request
            .verify_block(
                self.transport_identity()?.peer_identity(),
                &offer,
                id,
                bytes,
            )
            .map_err(|_| ReconcileError::Invariant("client forwarded exact requested bytes"))?;
        if self.forwarded_inbox_request(&request.request.page_request_id)? != *envelope {
            return Err(ReconcileError::Invariant(
                "client forwarded exact retained inbox required",
            ));
        }
        self.ingest_verified_original_content(
            &envelope.origin,
            &verified.page().operations,
            request,
            id,
            bytes,
        )
    }

    /// A durable received prefix is metadata only. This never signs a stored or
    /// applied receipt and never changes the applied worktree frontier.
    pub fn receive_forwarded_page(
        &mut self,
        request: &ContentId,
    ) -> Result<ForwardedMetadataReceive> {
        let envelope = self.forwarded_inbox_request(request)?;
        let mut accepted = 0;
        let mut duplicates = 0;
        let mut pending = 0;
        for signed in &envelope.signed_page.page.operations {
            self.verify_client_forwarded_page(
                &envelope.origin,
                &envelope.forwarder,
                &envelope.signed_page,
                &envelope.signed_page.page.channel_binding,
            )?;
            checkpoint("before_forwarded_metadata_receive");
            match self.journal.receive(&signed.operation)? {
                sync_extend_journal::ReceiveOutcome::Duplicate => duplicates += 1,
                sync_extend_journal::ReceiveOutcome::Pending => {
                    accepted += 1;
                    pending += 1;
                }
                sync_extend_journal::ReceiveOutcome::Received => accepted += 1,
            }
            checkpoint("after_forwarded_metadata_receive");
        }
        let cursor = self
            .journal
            .cursor(&self.space_id, &envelope.origin.device_id)?;
        self.verify_root()?;
        Ok(ForwardedMetadataReceive {
            request_id: request.clone(),
            accepted_operations: accepted,
            duplicate_operations: duplicates,
            pending_on_admission: pending,
            contiguous_received_sequence: cursor,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }

    #[cfg(windows)]
    pub fn apply_forwarded_operation(
        &mut self,
        request: &ContentId,
        operation: &OperationId,
    ) -> Result<crate::OriginalApplyResult> {
        let envelope = self.forwarded_inbox_request(request)?;
        let signed = envelope
            .signed_page
            .page
            .operations
            .iter()
            .find(|s| &s.operation.op_id == operation)
            .ok_or(ReconcileError::Invariant(
                "client forwarded operation outside exact inbox",
            ))?;
        self.apply_verified_original_operation(request, operation, &envelope.origin, signed)
    }
}
