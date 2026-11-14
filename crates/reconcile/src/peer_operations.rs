//! Direct own-origin metadata reception only. No causal/native apply authority.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{
    causal::CausalReduction, operation_batch::OperationBatch, ContentId, DeviceId, PROTOCOL_VERSION,
};
use sync_extend_transport::{
    Connection, OperationBatchRequest, OperationReceiveReceipt, SignedOperationBatch,
    SignedOperationReceiveReceipt,
};

#[derive(Serialize)]
pub struct PeerOperationPull {
    pub request_id: ContentId,
    pub source_device: DeviceId,
    pub after_sequence: u64,
    pub last_offered_sequence: u64,
    pub source_tip_sequence: u64,
    pub contiguous_received_sequence: u64,
    pub accepted_operations: usize,
    pub duplicate_operations: usize,
    pub pending_on_admission: usize,
    pub worktree_materialized: bool,
    pub whole_space_converged: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub fn causal_frontiers(&self) -> Result<CausalReduction> {
        self.verify_root()?;
        let result = self.journal.causal_frontiers(&self.space_id)?;
        self.verify_root()?;
        Ok(result)
    }

    pub async fn serve_peer_operations(&self, connection: &mut Connection) -> Result<()> {
        self.verify_root()?;
        let identity = self.transport_identity()?;
        let request = connection
            .receive_json::<OperationBatchRequest>()
            .await
            .map_err(|_| ReconcileError::Invariant("operation batch request failed"))?;
        request
            .validate(identity.peer_identity())
            .map_err(|_| ReconcileError::Invariant("operation batch request scope"))?;
        if connection.peer_identity().space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "operation connection space mismatch",
            ));
        }
        let batch = self.journal.own_operation_batch(
            &self.space_id,
            &self.device_id,
            request.after_sequence,
        )?;
        let request_id = batch.request_id()?;
        let last_sequence = batch.last_sequence()?;
        let signed = SignedOperationBatch::sign(&identity, batch)
            .map_err(|_| ReconcileError::Invariant("operation batch signing failed"))?;
        connection
            .send_json(&signed)
            .await
            .map_err(|_| ReconcileError::Invariant("operation batch response failed"))?;
        connection
            // The receiver durably admits the bounded page before acknowledging it.
            .receive_json_after_application::<SignedOperationReceiveReceipt>()
            .await
            .map_err(|_| ReconcileError::Invariant("operation receipt missing"))?
            .verify(
                connection.peer_identity(),
                connection.channel_binding(),
                &request_id,
                &self.device_id,
                last_sequence,
            )
            .map_err(|_| ReconcileError::Invariant("operation receive receipt invalid"))?;
        self.verify_root()?;
        Ok(())
    }

    /// Page from an explicit cursor, not from a false materialized vector.
    /// A dropped session can commit a durable prefix; exact retry is idempotent.
    pub async fn pull_peer_operations(
        &mut self,
        connection: &mut Connection,
        after_sequence: u64,
    ) -> Result<PeerOperationPull> {
        self.verify_root()?;
        if after_sequence > i64::MAX as u64 || connection.peer_identity().space_id != self.space_id
        {
            return Err(ReconcileError::Invariant(
                "operation pull scope or sequence",
            ));
        }
        let peer = connection.peer_identity().clone();
        let request = OperationBatchRequest {
            protocol_version: PROTOCOL_VERSION,
            space_id: self.space_id.clone(),
            origin_device: peer.device_id.clone(),
            after_sequence,
        };
        connection
            .send_json(&request)
            .await
            .map_err(|_| ReconcileError::Invariant("operation batch pull request failed"))?;
        let signed = connection
            .receive_json::<SignedOperationBatch>()
            .await
            .map_err(|_| ReconcileError::Invariant("operation batch pull response failed"))?;
        signed
            .verify(&peer)
            .map_err(|_| ReconcileError::Invariant("operation batch authentication failed"))?;
        if signed.batch.after_sequence != after_sequence {
            return Err(ReconcileError::Invariant(
                "operation batch pull cursor mismatch",
            ));
        }
        let result = self.receive_operation_batch(&peer.device_id, &signed.batch)?;
        let identity = self.transport_identity()?;
        let receipt = SignedOperationReceiveReceipt::sign(
            &identity,
            OperationReceiveReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                device_id: self.device_id.clone(),
                origin_device: peer.device_id,
                channel_binding: connection.channel_binding().clone(),
                request_id: result.request_id.clone(),
                last_offered_sequence: result.last_offered_sequence,
                contiguous_received_sequence: result.contiguous_received_sequence,
                materialized: false,
                backup_complete: false,
            },
        )
        .map_err(|_| ReconcileError::Invariant("operation receive receipt signing failed"))?;
        connection
            .send_json(&receipt)
            .await
            .map_err(|_| ReconcileError::Invariant("operation receive receipt sending failed"))?;
        Ok(result)
    }

    fn receive_operation_batch(
        &mut self,
        authenticated_device: &DeviceId,
        batch: &OperationBatch,
    ) -> Result<PeerOperationPull> {
        batch.validate()?;
        self.verify_root()?;
        if batch.space_id != self.space_id
            || batch.origin_device != *authenticated_device
            || batch.origin_device == self.device_id
        {
            return Err(ReconcileError::Invariant(
                "operation receive authenticated scope",
            ));
        }
        let mut accepted_operations = 0;
        let mut duplicate_operations = 0;
        let mut pending_on_admission = 0;
        for operation in &batch.operations {
            checkpoint("before_peer_operation_receive");
            match self.journal.receive(operation)? {
                sync_extend_journal::ReceiveOutcome::Duplicate => duplicate_operations += 1,
                sync_extend_journal::ReceiveOutcome::Pending => {
                    accepted_operations += 1;
                    pending_on_admission += 1;
                }
                sync_extend_journal::ReceiveOutcome::Received => accepted_operations += 1,
            }
            checkpoint("after_peer_operation_receive");
        }
        let contiguous_received_sequence =
            self.journal.cursor(&self.space_id, &batch.origin_device)?;
        self.verify_root()?;
        Ok(PeerOperationPull {
            request_id: batch.request_id()?,
            source_device: batch.origin_device.clone(),
            after_sequence: batch.after_sequence,
            last_offered_sequence: batch.last_sequence()?,
            source_tip_sequence: batch.tip_sequence,
            contiguous_received_sequence,
            accepted_operations,
            duplicate_operations,
            pending_on_admission,
            worktree_materialized: false,
            whole_space_converged: false,
            remote_backup_complete: false,
        })
    }
}
