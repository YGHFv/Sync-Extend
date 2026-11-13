//! Explicit bounded storage invocations; origin signatures stay independent of channel peer.
use serde::{Deserialize, Serialize};
use std::path::Path;
use sync_extend_core_model::{storage_node::StorageNodeConfig, ChunkRef, ContentId};
use sync_extend_reconcile::StorageNode;
use sync_extend_transport::{
    Connection, ForwardedSnapshotEnvelope, Listener, PeerIdentity, SignedForwardStoreReceipt,
    SignedForwardedOperationPage,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn load<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = super::config_file::read(path, 65_536)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_snapshot_report(
    path: &Path,
) -> Result<sync_extend_transport::SignedStorageSnapshotReport> {
    let bytes = super::config_file::read(path, sync_extend_transport::MAX_CONTROL_BYTES)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_retention_evidence(
    path: &Path,
) -> Result<Vec<sync_extend_transport::ForwardedAppliedEvidence>> {
    let bytes = super::config_file::read(path, sync_extend_transport::MAX_CONTROL_BYTES)?;
    let evidence: Vec<sync_extend_transport::ForwardedAppliedEvidence> =
        serde_json::from_slice(&bytes)?;
    if evidence.len() > 1024 {
        return Err("retention evidence target bound".into());
    }
    Ok(evidence)
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    StorePage {
        origin: PeerIdentity,
        signed_page: SignedForwardedOperationPage,
    },
    PullPage {
        origin: PeerIdentity,
        after_sequence: u64,
    },
    Snapshot {
        envelope: Box<ForwardedSnapshotEnvelope>,
    },
    Chunk {
        storage_id: ContentId,
        chunk: ChunkRef,
    },
    SnapshotChunk {
        storage_id: ContentId,
        chunk: ChunkRef,
    },
    Finish {
        storage_id: ContentId,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Page {
        signed_page: SignedForwardedOperationPage,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot: Option<Box<ForwardedSnapshotEnvelope>>,
    },
    Stored {
        receipt: SignedForwardStoreReceipt,
    },
    SnapshotStored {
        storage_id: ContentId,
    },
    Chunk {
        storage_id: ContentId,
        chunk: ChunkRef,
    },
    Finished {
        storage_id: ContentId,
    },
}

/// One paired QUIC connection and one bounded page, then the process closes.
pub async fn serve(config: StorageNodeConfig, forwarder: PeerIdentity) -> Result<()> {
    config.validate()?;
    forwarder.validate()?;
    let mut node = StorageNode::open(config.clone())?;
    node.verify_forwarding_peer(&forwarder)?;
    node.recover_forwarded_pages()?;
    node.recover_forwarded_snapshots()?;
    let identity = node.transport_identity()?;
    let listener = Listener::bind(config.bind, &identity, &forwarder)?;
    super::shutdown::ready()?;
    println!(
        "{}",
        serde_json::json!({"listening":listener.local_address()?,
        "storage_device":identity.peer_identity().device_id,"worktree":null})
    );
    tokio::select! {
        result = super::shutdown::requested() => { result?; }
        result = async {
            let mut connection = listener.accept(&identity, &forwarder).await?;
            node.verify_forwarding_peer(connection.peer_identity())?;
            serve_session(&config, &mut node, &mut connection).await
        } => { result?; }
    }
    Ok(())
}

async fn serve_session(
    config: &StorageNodeConfig,
    node: &mut StorageNode,
    connection: &mut Connection,
) -> Result<()> {
    let request: Request = connection.receive_json().await?;
    match request {
        Request::StorePage {
            origin,
            signed_page,
        } => {
            let received = node.receive_forwarded_page(
                &signed_page,
                &origin,
                connection.peer_identity(),
                connection.channel_binding(),
            )?;
            let id = signed_page.page.storage_id()?;
            connection
                .send_json(&Response::Stored {
                    receipt: node.stored_receipt(&received)?,
                })
                .await?;
            let mut count = 0usize;
            let mut bytes = 0u64;
            let mut snapshot_received = None;
            loop {
                node.verify_forwarding_peer(connection.peer_identity())?;
                match connection.receive_json::<Request>().await? {
                    Request::Chunk { storage_id, chunk } if storage_id == id => {
                        count += 1;
                        bytes = bytes
                            .checked_add(u64::from(chunk.length))
                            .ok_or("storage transfer sum")?;
                        if count > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
                            || bytes > config.max_request_bytes
                        {
                            return Err("one storage transfer request quota".into());
                        }
                        node.admit_forwarded_chunk(&received, &chunk)?;
                        let content = connection
                            .receive_block(&chunk.content_id, chunk.length)
                            .await?;
                        node.ingest_forwarded_chunk(&received, &chunk, &content)?;
                        connection
                            .send_json(&Response::Stored {
                                receipt: node.stored_receipt(&received)?,
                            })
                            .await?;
                    }
                    Request::Snapshot { envelope } => {
                        if snapshot_received.is_some() {
                            return Err("one snapshot report per storage page".into());
                        }
                        let snapshot = node.receive_forwarded_snapshot(
                            &envelope,
                            &origin,
                            connection.peer_identity(),
                            connection.channel_binding(),
                        )?;
                        let snapshot_id = envelope.storage_id()?;
                        snapshot_received = Some((snapshot_id.clone(), snapshot));
                        connection
                            .send_json(&Response::SnapshotStored {
                                storage_id: snapshot_id,
                            })
                            .await?;
                    }
                    Request::SnapshotChunk { storage_id, chunk } => {
                        let (expected, snapshot) = snapshot_received
                            .as_ref()
                            .ok_or("snapshot report required before snapshot chunk")?;
                        if storage_id != *expected {
                            return Err("snapshot chunk request scope differs".into());
                        }
                        count += 1;
                        bytes = bytes
                            .checked_add(u64::from(chunk.length))
                            .ok_or("storage snapshot transfer sum")?;
                        if count > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
                            || bytes > config.max_request_bytes
                        {
                            return Err("one storage transfer request quota".into());
                        }
                        node.admit_snapshot_chunk(snapshot, &chunk)?;
                        let content = connection
                            .receive_block(&chunk.content_id, chunk.length)
                            .await?;
                        node.ingest_snapshot_chunk(snapshot, &chunk, &content)?;
                        connection
                            .send_json(&Response::SnapshotStored {
                                storage_id: expected.clone(),
                            })
                            .await?;
                    }
                    Request::Finish { storage_id } if storage_id == id => {
                        connection
                            .send_json(&Response::Stored {
                                receipt: node.stored_receipt(&received)?,
                            })
                            .await?;
                        break;
                    }
                    _ => return Err("storage request phase/scope differs".into()),
                }
            }
        }
        Request::PullPage {
            origin,
            after_sequence,
        } => {
            let offer = node.forwarded_offer(
                &origin,
                connection.peer_identity(),
                connection.channel_binding().clone(),
                after_sequence,
            )?;
            let id = offer.page.storage_id()?;
            let snapshot = node.forwarded_snapshot_offer(
                &origin,
                connection.peer_identity(),
                connection.channel_binding().clone(),
            )?;
            connection
                .send_json(&Response::Page {
                    signed_page: offer.clone(),
                    snapshot: snapshot.clone().map(Box::new),
                })
                .await?;
            let mut count = 0usize;
            let mut bytes = 0u64;
            loop {
                match connection.receive_json::<Request>().await? {
                    Request::Chunk { storage_id, chunk } if storage_id == id => {
                        count += 1;
                        bytes = bytes
                            .checked_add(u64::from(chunk.length))
                            .ok_or("storage egress sum")?;
                        if count > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
                            || bytes > config.max_request_bytes
                        {
                            return Err("storage egress request quota".into());
                        }
                        let content = node.read_forwarded_chunk(
                            &origin,
                            connection.peer_identity(),
                            &offer,
                            connection.channel_binding(),
                            &chunk,
                        )?;
                        connection
                            .send_json(&Response::Chunk {
                                storage_id: id.clone(),
                                chunk: chunk.clone(),
                            })
                            .await?;
                        connection.send_block(&chunk.content_id, &content).await?;
                    }
                    Request::SnapshotChunk { storage_id, chunk } => {
                        let snapshot = snapshot.as_ref().ok_or("storage snapshot offer absent")?;
                        if storage_id != snapshot.storage_id()? {
                            return Err("snapshot egress request identity".into());
                        }
                        count += 1;
                        bytes = bytes
                            .checked_add(u64::from(chunk.length))
                            .ok_or("storage snapshot egress sum")?;
                        if count > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
                            || bytes > config.max_request_bytes
                        {
                            return Err("storage egress request quota".into());
                        }
                        let content = node.read_snapshot_chunk(
                            &origin,
                            connection.peer_identity(),
                            snapshot,
                            connection.channel_binding(),
                            &chunk,
                        )?;
                        connection
                            .send_json(&Response::Chunk {
                                storage_id,
                                chunk: chunk.clone(),
                            })
                            .await?;
                        connection.send_block(&chunk.content_id, &content).await?;
                    }
                    Request::Finish { storage_id } if storage_id == id => {
                        connection
                            .send_json(&Response::Finished { storage_id: id })
                            .await?;
                        break;
                    }
                    _ => return Err("storage egress phase/scope differs".into()),
                }
            }
        }
        _ => return Err("storage initial page required".into()),
    }
    connection.finish().await?;
    Ok(())
}

/// Keep the exact same storage lock and identity for consecutive bounded sessions.
/// A safety/protocol failure stops the service; no process restart loop hides it.
pub async fn run(
    config: StorageNodeConfig,
    forwarder: PeerIdentity,
    max_sessions: u32,
    session_timeout_secs: u64,
    between_sessions_secs: u64,
) -> Result<()> {
    if !(1..=1_000_000).contains(&max_sessions)
        || !(1..=86_400).contains(&session_timeout_secs)
        || !(1..=3_600).contains(&between_sessions_secs)
    {
        return Err("storage explicit bounded lifecycle policy".into());
    }
    config.validate()?;
    forwarder.validate()?;
    let mut node = StorageNode::open(config.clone())?;
    node.verify_forwarding_peer(&forwarder)?;
    node.recover_forwarded_pages()?;
    node.recover_forwarded_snapshots()?;
    let identity = node.transport_identity()?;
    let listener = Listener::bind(config.bind, &identity, &forwarder)?;
    super::shutdown::ready()?;
    println!(
        "{}",
        serde_json::json!({
            "listening": listener.local_address()?,
            "storage_device": identity.peer_identity().device_id,
            "max_sessions": max_sessions, "session_timeout_secs": session_timeout_secs,
            "worktree": null
        })
    );
    let shutdown = super::shutdown::requested();
    tokio::pin!(shutdown);
    for session in 0..max_sessions {
        node.verify_forwarding_peer(&forwarder)?;
        let connection = tokio::select! {
            result = &mut shutdown => { result?; return Ok(()); }
            result = listener.accept(&identity, &forwarder) => result?,
        };
        let mut connection = connection;
        node.verify_forwarding_peer(connection.peer_identity())?;
        tokio::select! {
            result = &mut shutdown => { result?; return Ok(()); }
            result = tokio::time::timeout(
                std::time::Duration::from_secs(session_timeout_secs),
                serve_session(&config, &mut node, &mut connection),
            ) => { result.map_err(|_| "storage bounded session deadline")??; }
        }
        drop(connection);
        println!(
            "{}",
            serde_json::json!({
                "completed_storage_session": session + 1,
                "backup_complete": false, "worktree": null
            })
        );
        if session + 1 < max_sessions {
            tokio::select! {
                result = &mut shutdown => { result?; return Ok(()); }
                _ = tokio::time::sleep(std::time::Duration::from_secs(between_sessions_secs)) => {}
            }
        }
    }
    Ok(())
}

pub async fn pull(
    config: StorageNodeConfig,
    source: PeerIdentity,
    origin: PeerIdentity,
    address: std::net::SocketAddr,
    after: u64,
) -> Result<()> {
    let mut node = StorageNode::open(config.clone())?;
    node.verify_forwarding_peer(&source)?;
    let identity = node.transport_identity()?;
    let mut connection = Connection::connect(address, &identity, &source).await?;
    connection
        .send_json(&Request::PullPage {
            origin: origin.clone(),
            after_sequence: after,
        })
        .await?;
    let Response::Page {
        signed_page,
        snapshot,
    } = connection.receive_json::<Response>().await?
    else {
        return Err("storage peer page response required".into());
    };
    let received =
        node.receive_forwarded_page(&signed_page, &origin, &source, connection.channel_binding())?;
    let id = signed_page.page.storage_id()?;
    let mut chunks = std::collections::BTreeMap::new();
    for signed in &signed_page.page.operations {
        if let sync_extend_core_model::Change::Put { entry } = &signed.operation.payload.change {
            if let Some(file) = &entry.content {
                for chunk in &file.chunks {
                    chunks.insert(chunk.content_id.clone(), chunk.clone());
                }
            }
        }
    }
    let mut transferred = 0u64;
    for chunk in chunks.values() {
        transferred = transferred
            .checked_add(u64::from(chunk.length))
            .ok_or("storage pull sum")?;
        if transferred > config.max_request_bytes {
            return Err("storage pull request quota".into());
        }
        connection
            .send_json(&Request::Chunk {
                storage_id: id.clone(),
                chunk: chunk.clone(),
            })
            .await?;
        let Response::Chunk {
            storage_id,
            chunk: actual,
        } = connection.receive_json::<Response>().await?
        else {
            return Err("storage expected chunk response".into());
        };
        if storage_id != id || actual != *chunk {
            return Err("storage response chunk identity".into());
        }
        node.admit_forwarded_chunk(&received, chunk)?;
        let bytes = connection
            .receive_block(&chunk.content_id, chunk.length)
            .await?;
        node.ingest_forwarded_chunk(&received, chunk, &bytes)?;
    }
    if let Some(envelope) = snapshot {
        let snapshot = node.receive_forwarded_snapshot(
            &envelope,
            &origin,
            &source,
            connection.channel_binding(),
        )?;
        let snapshot_id = envelope.storage_id()?;
        let mut snapshot_chunks = std::collections::BTreeMap::new();
        for file in envelope
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &file.chunks {
                if snapshot_chunks
                    .insert(chunk.content_id.clone(), chunk.clone())
                    .is_some_and(|prior| prior != *chunk)
                {
                    return Err("storage pull snapshot chunk lengths".into());
                }
                if snapshot_chunks.len() + chunks.len()
                    > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
                {
                    return Err("storage pull snapshot chunk count".into());
                }
            }
        }
        for chunk in snapshot_chunks.values() {
            if chunks.get(&chunk.content_id) == Some(chunk) {
                continue;
            }
            transferred = transferred
                .checked_add(u64::from(chunk.length))
                .ok_or("storage pull snapshot sum")?;
            if transferred > config.max_request_bytes {
                return Err("storage pull request quota".into());
            }
            node.admit_snapshot_chunk(&snapshot, chunk)?;
            connection
                .send_json(&Request::SnapshotChunk {
                    storage_id: snapshot_id.clone(),
                    chunk: chunk.clone(),
                })
                .await?;
            let Response::Chunk {
                storage_id,
                chunk: actual,
            } = connection.receive_json::<Response>().await?
            else {
                return Err("storage expected snapshot chunk response".into());
            };
            if storage_id != snapshot_id || actual != *chunk {
                return Err("storage snapshot response chunk identity".into());
            }
            let bytes = connection
                .receive_block(&chunk.content_id, chunk.length)
                .await?;
            node.ingest_snapshot_chunk(&snapshot, chunk, &bytes)?;
        }
    }
    connection
        .send_json(&Request::Finish {
            storage_id: id.clone(),
        })
        .await?;
    let Response::Finished { storage_id } = connection.receive_json::<Response>().await? else {
        return Err("storage final response required".into());
    };
    if storage_id != id {
        return Err("storage final identity differs".into());
    }
    connection.finish().await?;
    println!(
        "{}",
        serde_json::to_string(&node.stored_receipt(&received)?)?
    );
    Ok(())
}

pub async fn push(
    data: std::path::PathBuf,
    origin: PeerIdentity,
    storage: PeerIdentity,
    address: std::net::SocketAddr,
    after: u64,
) -> Result<()> {
    push_with_snapshot(data, origin, storage, address, after, None).await
}

/// Preserve exact independently signed originals while the original device is offline.
/// Metadata reception and verified CAS storage do not assert native apply or backup.
pub async fn client_pull(
    data: std::path::PathBuf,
    source: PeerIdentity,
    origin: PeerIdentity,
    address: std::net::SocketAddr,
    after: u64,
    limits: &sync_extend_core_model::limits::LocalLimits,
) -> Result<()> {
    let mut local = sync_extend_reconcile::LocalSpace::open_with_limits(&data, limits.clone())?;
    if local.read_transport_peer(&source.device_id)? != source
        || local.read_transport_peer(&origin.device_id)? != origin
    {
        return Err(
            "client storage requires independently approved original and transport peers".into(),
        );
    }
    let identity = local.transport_identity()?;
    let mut connection = Connection::connect(address, &identity, &source).await?;
    connection
        .send_json(&Request::PullPage {
            origin: origin.clone(),
            after_sequence: after,
        })
        .await?;
    let Response::Page {
        signed_page,
        snapshot: _,
    } = connection.receive_json::<Response>().await?
    else {
        return Err("client storage expected forwarded page".into());
    };
    let prepared = local.prepare_forwarded_content(
        &origin,
        &source,
        &signed_page,
        connection.channel_binding(),
    )?;
    let verified = signed_page.verify(
        &origin,
        &source,
        identity.peer_identity(),
        connection.channel_binding(),
        after,
    )?;
    let offer = sync_extend_transport::VerifiedOriginalContentOffer::from_verified_forward(
        &verified, limits,
    )?;
    let envelope = verified.envelope();
    let storage_id = signed_page.page.storage_id()?;
    if prepared.missing_chunks.len() > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS {
        return Err("client forwarded page exceeds bounded chunk request count".into());
    }
    if !prepared.missing_chunks.is_empty() {
        let request = sync_extend_transport::SignedOriginalContentRequest::sign(
            &identity,
            &offer,
            offer.request(prepared.missing_chunks.clone())?,
        )?;
        for chunk in &prepared.missing_chunks {
            connection
                .send_json(&Request::Chunk {
                    storage_id: storage_id.clone(),
                    chunk: chunk.clone(),
                })
                .await?;
            let Response::Chunk {
                storage_id: actual_id,
                chunk: actual,
            } = connection.receive_json::<Response>().await?
            else {
                return Err("client storage expected exact chunk response".into());
            };
            if actual_id != storage_id || actual != *chunk {
                return Err("client storage response request/chunk differs".into());
            }
            let bytes = connection
                .receive_block(&chunk.content_id, chunk.length)
                .await?;
            local.ingest_forwarded_content_block(
                &envelope,
                connection.channel_binding(),
                &request,
                &chunk.content_id,
                &bytes,
            )?;
        }
    }
    let closed = local.resume_forwarded_content(&prepared.page_request_id)?;
    if !closed.content_closed {
        return Err("client forwarded whole content verification remains incomplete".into());
    }
    let received = local.receive_forwarded_page(&prepared.page_request_id)?;
    connection
        .send_json(&Request::Finish {
            storage_id: storage_id.clone(),
        })
        .await?;
    let Response::Finished {
        storage_id: actual_id,
    } = connection.receive_json::<Response>().await?
    else {
        return Err("client storage final response required".into());
    };
    if actual_id != storage_id {
        return Err("client storage final page identity differs".into());
    }
    connection.finish().await?;
    println!("{}", serde_json::to_string(&received)?);
    Ok(())
}

pub async fn push_with_snapshot(
    data: std::path::PathBuf,
    origin: PeerIdentity,
    storage: PeerIdentity,
    address: std::net::SocketAddr,
    after: u64,
    report: Option<sync_extend_transport::SignedStorageSnapshotReport>,
) -> Result<()> {
    let local = sync_extend_reconcile::LocalSpace::open(&data)?;
    let identity = local.transport_identity()?;
    let mut connection = Connection::connect(address, &identity, &storage).await?;
    let signed = StorageNode::local_forwarding_page(
        &local,
        &origin,
        &storage,
        connection.channel_binding().clone(),
        after,
    )?;
    connection
        .send_json(&Request::StorePage {
            origin: origin.clone(),
            signed_page: signed.clone(),
        })
        .await?;
    let Response::Stored { receipt } = connection.receive_json::<Response>().await? else {
        return Err("storage initial signed receipt required".into());
    };
    receipt.verify(&storage, &signed.page)?;
    let id = signed.page.storage_id()?;
    let mut chunks = std::collections::BTreeMap::new();
    for original in &signed.page.operations {
        if let sync_extend_core_model::Change::Put { entry } = &original.operation.payload.change {
            if let Some(file) = &entry.content {
                for chunk in &file.chunks {
                    chunks.insert(chunk.content_id.clone(), chunk.clone());
                }
            }
        }
    }
    let mut transferred = 0u64;
    for chunk in chunks.values() {
        transferred = transferred
            .checked_add(u64::from(chunk.length))
            .ok_or("client forward byte sum")?;
        if transferred > sync_extend_transport::MAX_ORIGINAL_CONTENT_BYTES
            || chunks.len() > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
        {
            return Err("client forward bounded request".into());
        }
        let bytes = StorageNode::local_forwarded_chunk(&local, &origin, &storage, &signed, chunk)?;
        connection
            .send_json(&Request::Chunk {
                storage_id: id.clone(),
                chunk: chunk.clone(),
            })
            .await?;
        connection.send_block(&chunk.content_id, &bytes).await?;
        let Response::Stored { receipt } = connection.receive_json::<Response>().await? else {
            return Err("storage signed chunk receipt required".into());
        };
        receipt.verify(&storage, &signed.page)?;
    }
    if let Some(report) = report {
        let envelope = StorageNode::local_forwarding_snapshot(
            &local,
            &origin,
            &storage,
            connection.channel_binding().clone(),
            report,
        )?;
        let snapshot_id = envelope.storage_id()?;
        connection
            .send_json(&Request::Snapshot {
                envelope: Box::new(envelope.clone()),
            })
            .await?;
        let Response::SnapshotStored { storage_id } = connection.receive_json::<Response>().await?
        else {
            return Err("storage snapshot report response required".into());
        };
        if storage_id != snapshot_id {
            return Err("storage snapshot report response identity".into());
        }
        let mut snapshot_chunks = std::collections::BTreeMap::new();
        for file in envelope
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &file.chunks {
                if snapshot_chunks
                    .insert(chunk.content_id.clone(), chunk.clone())
                    .is_some_and(|prior| prior != *chunk)
                {
                    return Err("snapshot conflicting chunk lengths".into());
                }
                if snapshot_chunks.len() + chunks.len()
                    > sync_extend_transport::MAX_ORIGINAL_CONTENT_CHUNKS
                {
                    return Err("snapshot transfer chunk count".into());
                }
            }
        }
        for chunk in snapshot_chunks.values() {
            // Chunks already sent from this exact page have the same CAS identity.
            if chunks.get(&chunk.content_id) == Some(chunk) {
                continue;
            }
            transferred = transferred
                .checked_add(u64::from(chunk.length))
                .ok_or("snapshot transfer sum")?;
            if transferred > sync_extend_transport::MAX_ORIGINAL_CONTENT_BYTES {
                return Err("snapshot transfer bounded request".into());
            }
            let bytes =
                StorageNode::local_snapshot_chunk(&local, &origin, &storage, &envelope, chunk)?;
            connection
                .send_json(&Request::SnapshotChunk {
                    storage_id: snapshot_id.clone(),
                    chunk: chunk.clone(),
                })
                .await?;
            connection.send_block(&chunk.content_id, &bytes).await?;
            let Response::SnapshotStored { storage_id } =
                connection.receive_json::<Response>().await?
            else {
                return Err("storage snapshot chunk response required".into());
            };
            if storage_id != snapshot_id {
                return Err("storage snapshot chunk response identity".into());
            }
        }
    }
    connection
        .send_json(&Request::Finish { storage_id: id })
        .await?;
    let Response::Stored { receipt } = connection.receive_json::<Response>().await? else {
        return Err("storage final signed receipt required".into());
    };
    receipt.verify(&storage, &signed.page)?;
    connection.finish().await?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
