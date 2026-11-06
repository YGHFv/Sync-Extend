//! Bounded two-way own-origin reception, not native synchronization.
use crate::{LocalSpace, PeerOperationPull, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::DeviceId;
use sync_extend_transport::{Connection, MetadataCycleHello, MAX_METADATA_CYCLE_ROUNDS};

#[derive(Debug, Serialize)]
pub struct PeerMetadataCycle {
    pub local_device: DeviceId,
    pub peer_device: DeviceId,
    pub completed_rounds: u32,
    pub received_operations: usize,
    pub duplicate_operations: usize,
    pub pending_on_admission: usize,
    pub last_advertised_peer_tip: u64,
    pub contiguous_received_sequence: u64,
    pub worktree_materialized: bool,
    pub whole_space_converged: bool,
    pub remote_backup_complete: bool,
}

impl PeerMetadataCycle {
    fn observe(&mut self, page: PeerOperationPull) -> Result<()> {
        if page.source_device != self.peer_device
            || page.worktree_materialized
            || page.whole_space_converged
            || page.remote_backup_complete
        {
            return Err(ReconcileError::Invariant("metadata cycle page scope"));
        }
        self.received_operations = self
            .received_operations
            .checked_add(page.accepted_operations)
            .ok_or(ReconcileError::ResourceLimit(
                "metadata cycle accepted count",
            ))?;
        self.duplicate_operations = self
            .duplicate_operations
            .checked_add(page.duplicate_operations)
            .ok_or(ReconcileError::ResourceLimit(
                "metadata cycle duplicate count",
            ))?;
        self.pending_on_admission = self
            .pending_on_admission
            .checked_add(page.pending_on_admission)
            .ok_or(ReconcileError::ResourceLimit(
                "metadata cycle pending count",
            ))?;
        self.last_advertised_peer_tip = page.source_tip_sequence;
        self.contiguous_received_sequence = page.contiguous_received_sequence;
        Ok(())
    }
}

impl LocalSpace {
    /// The initiator pulls then serves; the responder serves then pulls on the
    /// SAME stream. No second dial while holding the local writer lock is needed.
    pub async fn exchange_peer_metadata(
        &mut self,
        connection: &mut Connection,
        rounds: u32,
    ) -> Result<PeerMetadataCycle> {
        self.verify_root()?;
        let identity = self.transport_identity()?;
        let hello =
            MetadataCycleHello::new(identity.peer_identity(), connection.peer_identity(), rounds)
                .map_err(|_| ReconcileError::Invariant("metadata cycle configuration"))?;
        connection
            .send_json(&hello)
            .await
            .map_err(|_| ReconcileError::Invariant("metadata cycle hello send"))?;
        let accepted = connection
            .receive_json::<MetadataCycleHello>()
            .await
            .map_err(|_| ReconcileError::Invariant("metadata cycle hello receive"))?;
        if accepted != hello {
            return Err(ReconcileError::Invariant("metadata cycle hello mismatch"));
        }
        self.metadata_cycle_inner(connection, rounds, true).await
    }

    /// Accept only an explicitly bounded metadata-only cycle. Per-page receipt
    /// durability is independent; a failure preserves the committed prefix.
    pub async fn serve_peer_metadata_cycle(
        &mut self,
        connection: &mut Connection,
        max_rounds: u32,
    ) -> Result<PeerMetadataCycle> {
        self.verify_root()?;
        if max_rounds == 0 || max_rounds > MAX_METADATA_CYCLE_ROUNDS {
            return Err(ReconcileError::Invariant("metadata cycle server bound"));
        }
        let identity = self.transport_identity()?;
        let hello = connection
            .receive_json::<MetadataCycleHello>()
            .await
            .map_err(|_| ReconcileError::Invariant("metadata cycle hello receive"))?;
        hello
            .validate(
                connection.peer_identity(),
                identity.peer_identity(),
                max_rounds,
            )
            .map_err(|_| ReconcileError::Invariant("metadata cycle hello scope"))?;
        connection
            .send_json(&hello)
            .await
            .map_err(|_| ReconcileError::Invariant("metadata cycle hello send"))?;
        self.metadata_cycle_inner(connection, hello.rounds, false)
            .await
    }

    async fn metadata_cycle_inner(
        &mut self,
        connection: &mut Connection,
        rounds: u32,
        initiator: bool,
    ) -> Result<PeerMetadataCycle> {
        let peer_device = connection.peer_identity().device_id.clone();
        if connection.peer_identity().space_id != self.space_id || peer_device == self.device_id {
            return Err(ReconcileError::Invariant("metadata cycle peer scope"));
        }
        let mut result = PeerMetadataCycle {
            local_device: self.device_id.clone(),
            peer_device: peer_device.clone(),
            completed_rounds: 0,
            received_operations: 0,
            duplicate_operations: 0,
            pending_on_admission: 0,
            last_advertised_peer_tip: 0,
            contiguous_received_sequence: self.journal.cursor(&self.space_id, &peer_device)?,
            worktree_materialized: false,
            whole_space_converged: false,
            remote_backup_complete: false,
        };
        for _ in 0..rounds {
            if !initiator {
                self.serve_peer_operations(connection).await?;
            }
            // Always derive retry position from durable received metadata, not
            // caller memory or the native/materialized manifest version vector.
            let cursor = self.journal.cursor(&self.space_id, &peer_device)?;
            let page = self.pull_peer_operations(connection, cursor).await?;
            result.observe(page)?;
            if initiator {
                self.serve_peer_operations(connection).await?;
            }
            result.completed_rounds += 1;
        }
        self.verify_root()?;
        Ok(result)
    }
}
