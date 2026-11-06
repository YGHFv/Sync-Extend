use crate::{LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{remote_file::RemoteFileOffer, PortablePath, FORMAT_VERSION};
use sync_extend_transport::{Connection, FileRequest, FileResponse};

#[derive(Serialize)]
pub struct PeerFilePull {
    pub request_id: sync_extend_core_model::ContentId,
    pub source_device: sync_extend_core_model::DeviceId,
    pub received_metadata: bool,
    pub content_closed: bool,
    pub local_copy: crate::remote_file::RemoteFileMaterialization,
    pub transferred_chunks: usize,
    pub transferred_bytes: u64,
    pub remote_causal_materialized: bool,
    pub whole_space_converged: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    /// Explicit single-file pull with verified content and conflict-preserving
    /// local publication. It does NOT claim remote causal/whole-space convergence.
    pub async fn pull_peer_file(
        &mut self,
        connection: &mut Connection,
        path: PortablePath,
    ) -> Result<PeerFilePull> {
        let wire = self.request_peer_offer(connection, path).await?;
        let request_id = wire
            .request_id()
            .map_err(|_| ReconcileError::Invariant("invalid peer offer request id"))?;
        let source_device = wire.source_device.clone();
        let offer = RemoteFileOffer {
            format_version: FORMAT_VERSION,
            source_device: source_device.clone(),
            source_snapshot: wire.snapshot_id,
            manifest: wire.manifest,
            entry_id: wire.entry_id,
            created_at_ms: wire.snapshot_created_at_ms,
        };
        let preparation = self.prepare_remote_file(&source_device, &offer)?;
        let mut transferred_bytes = 0u64;
        let transferred_chunks = preparation.missing_chunks.len();
        for chunk in preparation.missing_chunks {
            let bytes = self
                .request_peer_chunk(connection, &request_id, &chunk)
                .await?;
            transferred_bytes = transferred_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(ReconcileError::ResourceLimit("peer transferred bytes"))?;
            self.ingest_remote_file_chunk(&source_device, &offer, &chunk.content_id, &bytes)?;
        }
        let completed = self.prepare_remote_file(&source_device, &offer)?;
        if !completed.content_closed {
            return Err(ReconcileError::Invariant("peer file content is not closed"));
        }
        connection
            .send_json(&FileRequest::Finish {
                request_id: request_id.clone(),
            })
            .await
            .map_err(|_| ReconcileError::Invariant("peer finish request failed"))?;
        match connection
            .receive_json::<FileResponse>()
            .await
            .map_err(|_| ReconcileError::Invariant("peer finish response failed"))?
        {
            FileResponse::Finished {
                request_id: received,
            } if received == request_id => {}
            _ => return Err(ReconcileError::Invariant("peer finish binding mismatch")),
        }
        let local_copy = self.materialize_remote_file(&source_device, &offer)?;
        Ok(PeerFilePull {
            request_id,
            source_device,
            received_metadata: true,
            content_closed: true,
            local_copy,
            transferred_chunks,
            transferred_bytes,
            remote_causal_materialized: false,
            whole_space_converged: false,
            remote_backup_complete: false,
        })
    }
}
