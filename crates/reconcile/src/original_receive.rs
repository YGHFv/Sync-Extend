//! Explicit individually signed page reception; never materialization or completion.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{ContentId, VersionVector, PROTOCOL_VERSION};
use sync_extend_transport::{
    OriginalPageReceiveReceipt, SignedOriginalOperationPage, SignedOriginalPageReceiveReceipt,
};

#[derive(Serialize)]
pub struct OriginalMetadataReceive {
    pub request_id: ContentId,
    pub accepted_operations: usize,
    pub duplicate_operations: usize,
    pub pending_on_admission: usize,
    pub contiguous_received_sequence: u64,
    pub signed_receipt: Option<SignedOriginalPageReceiveReceipt>,
    pub worktree_materialized: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    /// Only existing authenticated durable inbox entries can become received.
    /// Each original Journal receive commits independently; an error can leave a
    /// durable prefix, but cannot issue a falsely complete page receipt.
    pub fn receive_original_page(
        &mut self,
        request: &ContentId,
    ) -> Result<OriginalMetadataReceive> {
        let envelope = self
            .original_content_inbox(self.limits.max_storage_entries)?
            .into_iter()
            .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(request))
            .ok_or(ReconcileError::Invariant(
                "original metadata inbox request absent",
            ))?;
        let mut accepted = 0;
        let mut duplicates = 0;
        let mut pending = 0;
        for signed in &envelope.signed_page.page.operations {
            if self.read_transport_peer(&envelope.source.device_id)? != envelope.source {
                return Err(ReconcileError::Invariant(
                    "original metadata current approval changed",
                ));
            }
            signed
                .verify(&envelope.source)
                .map_err(|_| ReconcileError::Invariant("original metadata individual signature"))?;
            checkpoint("before_original_metadata_receive");
            match self.journal.receive(&signed.operation)? {
                sync_extend_journal::ReceiveOutcome::Duplicate => duplicates += 1,
                sync_extend_journal::ReceiveOutcome::Pending => {
                    accepted += 1;
                    pending += 1;
                }
                sync_extend_journal::ReceiveOutcome::Received => accepted += 1,
            }
            checkpoint("after_original_metadata_receive");
        }
        let page = &envelope.signed_page.page;
        let cursor = self
            .journal
            .cursor(&self.space_id, &envelope.source.device_id)?;
        let last = page
            .operations
            .last()
            .map_or(page.after_sequence, |op| op.operation.payload.origin_seq);
        let signed_receipt = if cursor >= last {
            Some(self.original_received_receipt(&envelope.signed_page)?)
        } else {
            None
        };
        self.verify_root()?;
        Ok(OriginalMetadataReceive {
            request_id: request.clone(),
            accepted_operations: accepted,
            duplicate_operations: duplicates,
            pending_on_admission: pending,
            contiguous_received_sequence: cursor,
            signed_receipt,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }

    fn original_received_receipt(
        &self,
        signed: &SignedOriginalOperationPage,
    ) -> Result<SignedOriginalPageReceiveReceipt> {
        let page = &signed.page;
        let mut vector = VersionVector::default();
        for operation in self.journal.operations(&self.space_id)? {
            let origin = &operation.payload.origin_device_id;
            if vector.get(origin) == 0 {
                vector.observe(origin.clone(), self.journal.cursor(&self.space_id, origin)?);
            }
        }
        let identity = self.transport_identity()?;
        let receipt = SignedOriginalPageReceiveReceipt::sign(
            &identity,
            OriginalPageReceiveReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                device_id: self.device_id.clone(),
                origin_device: page.origin_device.clone(),
                channel_binding: page.channel_binding.clone(),
                request_id: page
                    .request_id()
                    .map_err(|_| ReconcileError::Invariant("original metadata request identity"))?,
                after_sequence: page.after_sequence,
                last_offered_sequence: page
                    .operations
                    .last()
                    .map_or(page.after_sequence, |op| op.operation.payload.origin_seq),
                contiguous_received_sequence: self
                    .journal
                    .cursor(&self.space_id, &page.origin_device)?,
                received_vector: vector,
            },
        )
        .map_err(|_| ReconcileError::Invariant("original target received-only receipt signing"))?;
        receipt
            .verify(identity.peer_identity(), page)
            .map_err(|_| {
                ReconcileError::Invariant("original target receipt post-sign verification")
            })?;
        Ok(receipt)
    }
}
