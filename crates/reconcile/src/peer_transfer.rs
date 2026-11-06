use crate::{LocalSpace, ReconcileError, Result};
use sync_extend_core_model::{ContentId, PortablePath, PROTOCOL_VERSION};
use sync_extend_transport::{Connection, FileOffer, FileRequest, FileResponse, SignedFileOffer};

impl LocalSpace {
    /// Serve only retained local bytes under the connection's explicitly paired
    /// space/device. This does not apply remote operations or certify backups.
    pub async fn serve_peer_file(&mut self, connection: &mut Connection) -> Result<()> {
        self.verify_root()?;
        let identity = self.transport_identity()?;
        if connection.peer_identity().space_id != self.space_id {
            return Err(ReconcileError::Invariant("connection space mismatch"));
        }
        let request: FileRequest = connection
            .receive_json()
            .await
            .map_err(|_| ReconcileError::Invariant("peer offer request failed"))?;
        let FileRequest::Offer {
            protocol_version,
            space_id,
            path,
        } = request
        else {
            return Err(ReconcileError::Invariant(
                "expected peer file offer request",
            ));
        };
        if protocol_version != PROTOCOL_VERSION || space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "peer request protocol or space mismatch",
            ));
        }
        self.scan()?;
        let manifest = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("missing file offer baseline"))?;
        let entry_id = manifest
            .entries
            .values()
            .find(|entry| entry.path == path)
            .ok_or(ReconcileError::Invariant("requested peer file is absent"))?
            .entry_id
            .clone();
        let retained = self
            .journal
            .retained_snapshot(&self.space_id, &manifest.root()?)?;
        let offer = FileOffer {
            protocol_version: PROTOCOL_VERSION,
            source_device: self.device_id.clone(),
            snapshot_id: manifest.root()?,
            manifest,
            entry_id,
            snapshot_created_at_ms: retained.created_at_ms,
        };
        let request_id = offer
            .request_id()
            .map_err(|_| ReconcileError::Invariant("invalid peer file offer"))?;
        let content = offer
            .manifest
            .entries
            .get(&offer.entry_id)
            .and_then(|entry| entry.content.clone())
            .ok_or(ReconcileError::Invariant(
                "peer offer requires a regular file",
            ))?;
        self.check_publication_limits(&content)?;
        self.cas.verify(&content)?;
        let signed = SignedFileOffer::sign(&identity, offer)
            .map_err(|_| ReconcileError::Invariant("file offer signing failed"))?;
        // A session fence prevents object disposition for the entire transfer.
        // This prototype does not promise an expiring detached read lease.
        let session = self.cas.acquire_session()?;
        connection
            .send_json(&FileResponse::Offer {
                offer: Box::new(signed),
            })
            .await
            .map_err(|_| ReconcileError::Invariant("sending file offer failed"))?;
        let unique: std::collections::BTreeMap<_, _> = content
            .chunks
            .iter()
            .map(|chunk| (chunk.content_id.clone(), chunk.clone()))
            .collect();
        let max_requests = unique
            .len()
            .checked_add(1)
            .ok_or(ReconcileError::ResourceLimit("peer request count"))?;
        let mut requested = std::collections::BTreeSet::new();
        for _ in 0..max_requests {
            match connection
                .receive_json::<FileRequest>()
                .await
                .map_err(|_| ReconcileError::Invariant("peer content request failed"))?
            {
                FileRequest::Chunk {
                    request_id: received,
                    chunk,
                } => {
                    if received != request_id
                        || unique.get(&chunk.content_id) != Some(&chunk)
                        || !requested.insert(chunk.content_id.clone())
                    {
                        return Err(ReconcileError::Invariant(
                            "peer chunk is outside the retained offer",
                        ));
                    }
                    self.verify_root()?;
                    let bytes = self.cas.read(&chunk)?;
                    connection
                        .send_json(&FileResponse::Chunk {
                            request_id: request_id.clone(),
                            chunk: chunk.clone(),
                        })
                        .await
                        .map_err(|_| ReconcileError::Invariant("peer chunk response failed"))?;
                    connection
                        .send_block(&chunk.content_id, &bytes)
                        .await
                        .map_err(|_| ReconcileError::Invariant("peer block transfer failed"))?;
                }
                FileRequest::Finish {
                    request_id: received,
                } if received == request_id => {
                    connection
                        .send_json(&FileResponse::Finished { request_id })
                        .await
                        .map_err(|_| ReconcileError::Invariant("peer finish response failed"))?;
                    drop(session);
                    return Ok(());
                }
                _ => {
                    return Err(ReconcileError::Invariant(
                        "unexpected or wrong-bound peer request",
                    ))
                }
            }
        }
        Err(ReconcileError::ResourceLimit("peer request count"))
    }

    pub async fn request_peer_offer(
        &self,
        connection: &mut Connection,
        path: PortablePath,
    ) -> Result<FileOffer> {
        self.verify_root()?;
        connection
            .send_json(&FileRequest::Offer {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                path,
            })
            .await
            .map_err(|_| ReconcileError::Invariant("peer offer request failed"))?;
        let FileResponse::Offer { offer } = connection
            .receive_json()
            .await
            .map_err(|_| ReconcileError::Invariant("peer offer response failed"))?
        else {
            return Err(ReconcileError::Invariant("peer did not return an offer"));
        };
        offer
            .verify(connection.peer_identity())
            .map_err(|_| ReconcileError::Invariant("unverified peer file offer"))?;
        Ok(offer.offer)
    }

    pub async fn request_peer_chunk(
        &self,
        connection: &mut Connection,
        request_id: &ContentId,
        chunk: &sync_extend_core_model::ChunkRef,
    ) -> Result<Vec<u8>> {
        connection
            .send_json(&FileRequest::Chunk {
                request_id: request_id.clone(),
                chunk: chunk.clone(),
            })
            .await
            .map_err(|_| ReconcileError::Invariant("peer chunk request failed"))?;
        match connection
            .receive_json::<FileResponse>()
            .await
            .map_err(|_| ReconcileError::Invariant("peer chunk header failed"))?
        {
            FileResponse::Chunk {
                request_id: received,
                chunk: expected,
            } if received == *request_id && expected == *chunk => {}
            _ => {
                return Err(ReconcileError::Invariant(
                    "peer chunk response binding mismatch",
                ))
            }
        }
        connection
            .receive_block(&chunk.content_id, chunk.length)
            .await
            .map_err(|_| ReconcileError::Invariant("peer chunk integrity failed"))
    }
}
