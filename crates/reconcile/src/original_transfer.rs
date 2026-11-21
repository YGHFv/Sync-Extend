//! One bounded own-origin signed content page; no durable signed inbox or apply.
use crate::{LocalSpace, OriginalContentPreparation, ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{ContentId, DeviceId, SpaceId, PROTOCOL_VERSION};
use sync_extend_transport::ProducerKind;
use sync_extend_transport::{
    Connection, OriginalOperationPage, SignedOperation, SignedOriginalContentRequest,
    SignedOriginalOperationPage, MAX_ORIGINAL_CONTENT_CHUNKS,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol_version: u32,
    space_id: SpaceId,
    source: DeviceId,
    receiver: DeviceId,
    channel_binding: ContentId,
    after_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ContentControl {
    Chunks {
        request: SignedOriginalContentRequest,
    },
    Finish {
        page_request_id: ContentId,
    },
}

#[derive(Serialize)]
pub struct OriginalContentPull {
    pub preparation: OriginalContentPreparation,
    pub signed_page: SignedOriginalOperationPage,
    pub transferred_chunks: usize,
    pub transferred_bytes: u64,
    pub signed_provenance_persisted: bool,
    pub operations_received: bool,
    pub worktree_materialized: bool,
}

impl LocalSpace {
    fn original_transfer_approval(&self, connection: &Connection) -> Result<()> {
        self.verify_root()?;
        if self.read_transport_peer(&connection.peer_identity().device_id)?
            != *connection.peer_identity()
        {
            return Err(ReconcileError::Invariant(
                "original transfer current pairing differs",
            ));
        }
        Ok(())
    }

    pub async fn serve_original_content_page(&self, connection: &mut Connection) -> Result<()> {
        self.serve_original_content_page_inner(connection)
            .await
            .map(|_| ())
    }

    pub(crate) async fn serve_original_content_page_inner(
        &self,
        connection: &mut Connection,
    ) -> Result<SignedOriginalOperationPage> {
        self.original_transfer_approval(connection)?;
        let request = connection
            .receive_json_with_permit::<Request>(
                connection.reserve_incoming_json(ProducerKind::OriginalPageControl)?,
            )
            .await?;
        if request.protocol_version != PROTOCOL_VERSION
            || request.space_id != self.space_id
            || request.source != self.device_id
            || request.receiver != connection.peer_identity().device_id
            || request.channel_binding != *connection.channel_binding()
        {
            return Err(ReconcileError::Invariant(
                "original page connection/request differs",
            ));
        }
        let identity = self.transport_identity()?;
        let page_permit = connection.reserve_outgoing_json(ProducerKind::OriginalPageControl)?;
        let batch = self.journal.own_operation_batch(
            &self.space_id,
            &self.device_id,
            request.after_sequence,
        )?;
        let operations = batch
            .operations
            .into_iter()
            .map(|operation| {
                SignedOperation::sign(&identity, operation)
                    .map_err(|_| ReconcileError::Invariant("original own-origin signing failed"))
            })
            .collect::<Result<Vec<_>>>()?;
        let signed = SignedOriginalOperationPage::sign(
            &identity,
            OriginalOperationPage {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                origin_device: self.device_id.clone(),
                receiver_device: request.receiver,
                channel_binding: connection.channel_binding().clone(),
                after_sequence: request.after_sequence,
                tip_sequence: batch.tip_sequence,
                operations,
            },
        )
        .map_err(|_| ReconcileError::Invariant("original page signature/encoded bounds"))?;
        let offer = signed
            .verify_content_offer(
                identity.peer_identity(),
                connection.peer_identity(),
                connection.channel_binding(),
                request.after_sequence,
                &self.limits,
            )
            .map_err(|_| ReconcileError::Invariant("original source content limits"))?;
        let page_id = signed
            .page
            .request_id()
            .map_err(|_| ReconcileError::Invariant("original source page id"))?;
        let _session = self.cas.acquire_session()?;
        // The page is authenticated metadata. Keep the CAS session/reference
        // fence, but do not read payload that the peer has not requested.
        connection
            .send_json_with_permit(page_permit, &signed)
            .await?;
        let mut seen = BTreeSet::new();
        let mut bytes = 0u64;
        let mut frame_bytes = 0u64;
        for _ in 0..2 {
            match connection
                .receive_json_with_permit::<ContentControl>(
                    connection.reserve_incoming_json(ProducerKind::OriginalContentControl)?,
                )
                .await?
            {
                ContentControl::Chunks { request } => {
                    self.original_transfer_approval(connection)?;
                    request
                        .verify(connection.peer_identity(), &offer)
                        .map_err(|_| {
                            ReconcileError::Invariant("original signed content request invalid")
                        })?;
                    let (requested_bytes, requested_frame_bytes) =
                        self.original_content_frame_liability(&request.request.chunks)?;
                    for chunk in &request.request.chunks {
                        if !seen.insert(chunk.content_id.clone())
                            || seen.len() > MAX_ORIGINAL_CONTENT_CHUNKS
                        {
                            return Err(ReconcileError::ResourceLimit(
                                "original one-page chunk requests",
                            ));
                        }
                    }
                    bytes = bytes
                        .checked_add(requested_bytes)
                        .filter(|n| {
                            *n <= self
                                .limits
                                .max_staging_bytes
                                .min(sync_extend_transport::MAX_ORIGINAL_CONTENT_BYTES)
                        })
                        .ok_or(ReconcileError::ResourceLimit(
                            "original one-page transfer bytes",
                        ))?;
                    frame_bytes = frame_bytes
                        .checked_add(requested_frame_bytes)
                        .filter(|n| {
                            *n <= self
                                .limits
                                .max_staging_bytes
                                .min(sync_extend_transport::MAX_ORIGINAL_CONTENT_BYTES)
                                + 5 * MAX_ORIGINAL_CONTENT_CHUNKS as u64
                        })
                        .ok_or(ReconcileError::ResourceLimit(
                            "original one-page transfer frame bytes",
                        ))?;
                    let mut block_permits = Vec::new();
                    block_permits
                        .try_reserve_exact(request.request.chunks.len())
                        .map_err(|_| {
                            ReconcileError::ResourceLimit("original outgoing block permit list")
                        })?;
                    // A later budget refusal keeps earlier unused liabilities
                    // charged, and precedes every corresponding payload read.
                    for chunk in &request.request.chunks {
                        self.original_transfer_approval(connection)?;
                        block_permits.push(connection.reserve_outgoing_block(
                            ProducerKind::OriginalContentBlock,
                            &chunk.content_id,
                            chunk.length,
                        )?);
                    }
                    for (chunk, block_permit) in request.request.chunks.iter().zip(block_permits) {
                        self.original_transfer_approval(connection)?;
                        let block = self.cas.read(chunk)?;
                        connection
                            .send_block_with_permit(block_permit, &chunk.content_id, &block)
                            .await?;
                    }
                }
                ContentControl::Finish { page_request_id } if page_request_id == page_id => {
                    connection
                        .send_json_with_permit(
                            connection
                                .reserve_outgoing_json(ProducerKind::OriginalContentControl)?,
                            &ContentControl::Finish { page_request_id },
                        )
                        .await?;
                    return Ok(signed);
                }
                _ => return Err(ReconcileError::Invariant("original finish request differs")),
            }
        }
        Err(ReconcileError::ResourceLimit(
            "original page control attempts",
        ))
    }

    /// Returns the authenticated page to the explicit caller for a retry. It
    /// deliberately does not receive metadata or imply unattended restart.
    pub async fn pull_original_content_page(
        &mut self,
        connection: &mut Connection,
        after: u64,
    ) -> Result<OriginalContentPull> {
        self.original_transfer_approval(connection)?;
        let identity = self.transport_identity()?;
        let peer = connection.peer_identity().clone();
        let request_permit = connection.reserve_outgoing_json(ProducerKind::OriginalPageControl)?;
        let request = Request {
            protocol_version: PROTOCOL_VERSION,
            space_id: self.space_id.clone(),
            source: peer.device_id.clone(),
            receiver: self.device_id.clone(),
            channel_binding: connection.channel_binding().clone(),
            after_sequence: after,
        };
        connection
            .send_json_with_permit(request_permit, &request)
            .await?;
        let signed = connection
            .receive_json_with_permit::<SignedOriginalOperationPage>(
                connection.reserve_incoming_json(ProducerKind::OriginalPageControl)?,
            )
            .await?;
        let offer = signed
            .verify_content_offer(
                &peer,
                identity.peer_identity(),
                connection.channel_binding(),
                after,
                &self.limits,
            )
            .map_err(|_| ReconcileError::Invariant("original connection page invalid"))?;
        let planned_chunks = self.original_content_chunk_plan(&offer)?;
        let mut request_permit = if planned_chunks.is_empty() {
            None
        } else {
            Some(connection.reserve_outgoing_json(ProducerKind::OriginalContentControl)?)
        };
        let admitted = connection.reserve_incoming_blocks(
            ProducerKind::OriginalContentBlock,
            planned_chunks
                .iter()
                .map(|chunk| (&chunk.content_id, chunk.length)),
        )?;
        let mut block_permits = planned_chunks
            .into_iter()
            .zip(admitted)
            .map(|(chunk, permit)| (chunk.content_id, permit))
            .collect::<BTreeMap<_, _>>();
        // Complete incoming admission precedes provenance/reference preparation
        // and cached payload verification. Unused cached permits are not refunded.
        let mut preparation = self.prepare_original_content(&peer, &signed)?;
        let mut transferred_bytes = 0u64;
        let transferred_chunks = preparation.missing_chunks.len();
        if !preparation.missing_chunks.is_empty() {
            let request_permit = request_permit.take().ok_or(ReconcileError::Invariant(
                "original missing content control permit",
            ))?;
            let request = offer
                .request(preparation.missing_chunks.clone())
                .map_err(|_| {
                    ReconcileError::ResourceLimit("original page requires bounded partial followup")
                })?;
            let request = SignedOriginalContentRequest::sign(&identity, &offer, request)
                .map_err(|_| ReconcileError::Invariant("original target request signing"))?;
            let mut missing_permits = Vec::new();
            for chunk in &request.request.chunks {
                missing_permits.push(block_permits.remove(&chunk.content_id).ok_or(
                    ReconcileError::Invariant("original missing content exact admitted permit"),
                )?);
            }
            connection
                .send_json_with_permit(
                    request_permit,
                    &ContentControl::Chunks {
                        request: request.clone(),
                    },
                )
                .await?;
            for (chunk, block_permit) in request.request.chunks.iter().zip(missing_permits) {
                let block = connection
                    .receive_block_with_permit(block_permit, &chunk.content_id, chunk.length)
                    .await?;
                self.ingest_original_content_block(
                    &peer,
                    &signed,
                    &request,
                    &chunk.content_id,
                    &block,
                )?;
                transferred_bytes = transferred_bytes
                    .checked_add(block.len() as u64)
                    .ok_or(ReconcileError::ResourceLimit("original received byte sum"))?;
            }
            preparation = self.prepare_original_content(&peer, &signed)?;
        }
        let finish_permit =
            connection.reserve_outgoing_json(ProducerKind::OriginalContentControl)?;
        let finish = ContentControl::Finish {
            page_request_id: preparation.page_request_id.clone(),
        };
        connection
            .send_json_with_permit(finish_permit, &finish)
            .await?;
        if connection
            .receive_json_with_permit::<ContentControl>(
                connection.reserve_incoming_json(ProducerKind::OriginalContentControl)?,
            )
            .await?
            != finish
        {
            return Err(ReconcileError::Invariant(
                "original page finish response differs",
            ));
        }
        Ok(OriginalContentPull {
            preparation,
            signed_page: signed,
            transferred_chunks,
            transferred_bytes,
            signed_provenance_persisted: true,
            operations_received: false,
            worktree_materialized: false,
        })
    }
}
