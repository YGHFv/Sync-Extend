//! Authenticated bounded content requests; neither ownership nor native apply authority.
use crate::{PeerIdentity, Result, SignedOriginalOperationPage, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    limits::LocalLimits, Change, ChunkRef, ContentId, DeviceId, FileManifest, SpaceId,
    PROTOCOL_VERSION,
};

pub const MAX_ORIGINAL_CONTENT_CHUNKS: usize = 64;
pub const MAX_ORIGINAL_CONTENT_BYTES: u64 = 16 * 1024 * 1024;
const DOMAIN: &str = "SyncExtend original page target signed content request v1";

/// Obtained only after exact page/signature and current local limit checks.
pub struct VerifiedOriginalContentOffer {
    space: SpaceId,
    source: DeviceId,
    receiver: DeviceId,
    binding: ContentId,
    request: ContentId,
    files: Vec<FileManifest>,
    chunks: BTreeMap<ContentId, u32>,
    byte_limit: u64,
}

impl SignedOriginalOperationPage {
    pub fn verify_content_offer(
        &self,
        source: &PeerIdentity,
        receiver: &PeerIdentity,
        binding: &ContentId,
        after: u64,
        limits: &LocalLimits,
    ) -> Result<VerifiedOriginalContentOffer> {
        limits.validate()?;
        self.verify(source, receiver, binding, after)?;
        let mut files = Vec::new();
        let mut chunks = BTreeMap::new();
        let mut logical_bytes = 0u64;
        let mut references = 0usize;
        for signed in &self.page.operations {
            let Change::Put { entry } = &signed.operation.payload.change else {
                continue;
            };
            let Some(file) = &entry.content else {
                continue;
            };
            if file.length > limits.max_file_bytes {
                return Err(TransportError::Limit("original content file bytes"));
            }
            logical_bytes = logical_bytes
                .checked_add(file.length)
                .filter(|n| *n <= limits.max_scan_bytes)
                .ok_or(TransportError::Limit("original content aggregate bytes"))?;
            references = references
                .checked_add(file.chunks.len())
                .filter(|n| *n <= limits.max_scan_chunks)
                .ok_or(TransportError::Limit("original content chunk references"))?;
            for chunk in &file.chunks {
                if chunks
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|length| length != chunk.length)
                {
                    return Err(TransportError::Authorization(
                        "original content same hash conflicting length",
                    ));
                }
            }
            files.push(file.clone());
            if files.len() > limits.max_scan_entries {
                return Err(TransportError::Limit("original content offered files"));
            }
        }
        Ok(VerifiedOriginalContentOffer {
            space: self.page.space_id.clone(),
            source: source.device_id.clone(),
            receiver: receiver.device_id.clone(),
            binding: binding.clone(),
            request: self.page.request_id()?,
            files,
            chunks,
            byte_limit: limits.max_staging_bytes.min(MAX_ORIGINAL_CONTENT_BYTES),
        })
    }
}

impl VerifiedOriginalContentOffer {
    /// Original operation signatures remain attached to the independent source;
    /// content requests authorize only the current forwarding transport peer.
    pub fn from_verified_forward(
        page: &crate::VerifiedForwardedPage,
        limits: &LocalLimits,
    ) -> Result<Self> {
        limits.validate()?;
        let mut files = Vec::new();
        let mut chunks = BTreeMap::new();
        let mut logical = 0u64;
        let mut references = 0usize;
        for original in &page.page().operations {
            let Change::Put { entry } = &original.operation.payload.change else {
                continue;
            };
            let Some(file) = &entry.content else { continue };
            logical = logical
                .checked_add(file.length)
                .filter(|count| *count <= limits.max_scan_bytes)
                .ok_or(TransportError::Limit("forward offered logical bytes"))?;
            references = references
                .checked_add(file.chunks.len())
                .filter(|count| *count <= limits.max_scan_chunks)
                .ok_or(TransportError::Limit("forward offered references"))?;
            if file.length > limits.max_file_bytes || files.len() >= limits.max_scan_entries {
                return Err(TransportError::Limit("forward offered file bounds"));
            }
            for chunk in &file.chunks {
                if chunks
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|length| length != chunk.length)
                {
                    return Err(TransportError::Authorization(
                        "forward chunk conflicting length",
                    ));
                }
            }
            files.push(file.clone());
        }
        Ok(Self {
            space: page.page().space_id.clone(),
            source: page.forwarder().device_id.clone(),
            receiver: page.receiver().device_id.clone(),
            binding: page.page().channel_binding.clone(),
            request: page.request_id()?,
            files,
            chunks,
            byte_limit: limits.max_staging_bytes.min(MAX_ORIGINAL_CONTENT_BYTES),
        })
    }

    pub fn from_original_conflict(
        signed: &crate::SignedOriginalConflictOffer,
        source: &PeerIdentity,
        receiver: &PeerIdentity,
        binding: &ContentId,
        approved: &[PeerIdentity],
        limits: &LocalLimits,
    ) -> Result<Self> {
        limits.validate()?;
        signed.verify(
            source,
            receiver,
            binding,
            approved,
            sync_extend_core_model::conflict_resolution::ResolutionLimits {
                max_bytes: crate::MAX_RESOLUTION_WIRE_BYTES,
                ..Default::default()
            },
        )?;
        let mut files = Vec::new();
        let mut chunks = BTreeMap::new();
        let mut logical = 0u64;
        let mut references = 0usize;
        for original in signed
            .offer
            .resolution
            .payload
            .originals
            .iter()
            .chain(&signed.offer.resolution.payload.resolving)
        {
            if let Change::Put { entry } = &original.operation.payload.change {
                if let Some(file) = &entry.content {
                    logical = logical
                        .checked_add(file.length)
                        .filter(|n| *n <= limits.max_scan_bytes)
                        .ok_or(TransportError::Limit("conflict wire logical content bytes"))?;
                    references = references
                        .checked_add(file.chunks.len())
                        .filter(|n| *n <= limits.max_scan_chunks)
                        .ok_or(TransportError::Limit(
                            "conflict wire original reference count",
                        ))?;
                    if file.length > limits.max_file_bytes || files.len() >= limits.max_scan_entries
                    {
                        return Err(TransportError::Limit("conflict wire file inventory"));
                    }
                    for chunk in &file.chunks {
                        if chunks
                            .insert(chunk.content_id.clone(), chunk.length)
                            .is_some_and(|length| length != chunk.length)
                        {
                            return Err(TransportError::Authorization(
                                "conflict wire chunk length collision",
                            ));
                        }
                    }
                    files.push(file.clone());
                }
            }
        }
        Ok(Self {
            space: signed.offer.space_id.clone(),
            source: source.device_id.clone(),
            receiver: receiver.device_id.clone(),
            binding: binding.clone(),
            request: signed.request_id()?,
            files,
            chunks,
            byte_limit: limits.max_staging_bytes.min(MAX_ORIGINAL_CONTENT_BYTES),
        })
    }

    pub fn files(&self) -> &[FileManifest] {
        &self.files
    }

    pub fn request(&self, chunks: Vec<ChunkRef>) -> Result<OriginalContentRequest> {
        let request = OriginalContentRequest {
            protocol_version: PROTOCOL_VERSION,
            space_id: self.space.clone(),
            source_device: self.source.clone(),
            receiver_device: self.receiver.clone(),
            channel_binding: self.binding.clone(),
            page_request_id: self.request.clone(),
            chunks,
        };
        self.validate_request(&request)?;
        Ok(request)
    }

    fn validate_request(&self, request: &OriginalContentRequest) -> Result<()> {
        if request.protocol_version != PROTOCOL_VERSION
            || request.space_id != self.space
            || request.source_device != self.source
            || request.receiver_device != self.receiver
            || request.channel_binding != self.binding
            || request.page_request_id != self.request
            || request.chunks.is_empty()
            || request.chunks.len() > MAX_ORIGINAL_CONTENT_CHUNKS
        {
            return Err(TransportError::Authorization(
                "original content exact page/session/request",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for chunk in &request.chunks {
            if self.chunks.get(&chunk.content_id) != Some(&chunk.length)
                || !seen.insert(&chunk.content_id)
            {
                return Err(TransportError::Authorization(
                    "original content unoffered or duplicate chunk",
                ));
            }
            total = total
                .checked_add(u64::from(chunk.length))
                .filter(|n| *n <= self.byte_limit)
                .ok_or(TransportError::Limit("original content request byte bound"))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalContentRequest {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub source_device: DeviceId,
    pub receiver_device: DeviceId,
    pub channel_binding: ContentId,
    pub page_request_id: ContentId,
    pub chunks: Vec<ChunkRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOriginalContentRequest {
    pub request: OriginalContentRequest,
    pub signature: Vec<u8>,
}

impl SignedOriginalContentRequest {
    pub fn sign(
        target: &TransportIdentity,
        offer: &VerifiedOriginalContentOffer,
        request: OriginalContentRequest,
    ) -> Result<Self> {
        offer.validate_request(&request)?;
        if target.peer.space_id != request.space_id
            || target.peer.device_id != request.receiver_device
        {
            return Err(TransportError::Authorization(
                "original content request target signer",
            ));
        }
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&request)?);
        Ok(Self {
            request,
            signature: target.signing_key.sign(&digest).to_bytes().to_vec(),
        })
    }

    pub fn verify(
        &self,
        target: &PeerIdentity,
        offer: &VerifiedOriginalContentOffer,
    ) -> Result<()> {
        target.validate()?;
        offer.validate_request(&self.request)?;
        if target.space_id != self.request.space_id
            || target.device_id != self.request.receiver_device
        {
            return Err(TransportError::Authorization(
                "original content approved target identity",
            ));
        }
        let key = VerifyingKey::from_bytes(&target.public_key)
            .map_err(|_| TransportError::Authorization("original content target key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("original content signature width"))?;
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&self.request)?);
        key.verify_strict(&digest, &signature)
            .map_err(|_| TransportError::Authorization("original content signature invalid"))
    }

    /// Check a requested block; callers still need durable CAS ownership to import.
    pub fn verify_block(
        &self,
        target: &PeerIdentity,
        offer: &VerifiedOriginalContentOffer,
        id: &ContentId,
        bytes: &[u8],
    ) -> Result<()> {
        self.verify(target, offer)?;
        let chunk = self
            .request
            .chunks
            .iter()
            .find(|chunk| &chunk.content_id == id)
            .ok_or(TransportError::Authorization(
                "original content block not requested",
            ))?;
        if bytes.len() != chunk.length as usize || ContentId::hash(bytes) != *id {
            return Err(TransportError::Authorization(
                "original content block hash/length mismatch",
            ));
        }
        Ok(())
    }
}
