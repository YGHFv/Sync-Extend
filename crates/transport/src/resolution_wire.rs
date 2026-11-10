//! Session-bound signed conflict description and truthful target frontier.
use crate::{PeerIdentity, Result, SignedFileResolution, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    conflict_resolution::ResolutionLimits, ContentId, DeviceId, SnapshotId, SpaceId, VersionVector,
    PROTOCOL_VERSION,
};

pub const MAX_RESOLUTION_WIRE_BYTES: usize = 4 * 1024 * 1024;
const OFFER_DOMAIN: &str = "SyncExtend live original conflict offer v1";
const RECEIPT_DOMAIN: &str = "SyncExtend live original conflict target receipt v1";

fn sign(identity: &TransportIdentity, domain: &str, value: &impl Serialize) -> Result<Vec<u8>> {
    let digest = blake3::derive_key(domain, &serde_json::to_vec(value)?);
    Ok(identity.signing_key.sign(&digest).to_bytes().to_vec())
}
fn verify(peer: &PeerIdentity, domain: &str, value: &impl Serialize, bytes: &[u8]) -> Result<()> {
    let digest = blake3::derive_key(domain, &serde_json::to_vec(value)?);
    VerifyingKey::from_bytes(&peer.public_key)
        .map_err(|_| TransportError::Authorization("conflict wire key"))?
        .verify_strict(
            &digest,
            &Signature::from_slice(bytes)
                .map_err(|_| TransportError::Authorization("conflict wire signature length"))?,
        )
        .map_err(|_| TransportError::Authorization("conflict wire signature differs"))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalConflictOffer {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub source_device: DeviceId,
    pub receiver_device: DeviceId,
    pub channel_binding: ContentId,
    pub resolution: SignedFileResolution,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOriginalConflictOffer {
    pub offer: OriginalConflictOffer,
    pub signature: Vec<u8>,
}
impl SignedOriginalConflictOffer {
    pub fn sign(
        identity: &TransportIdentity,
        target: &PeerIdentity,
        binding: &ContentId,
        resolution: SignedFileResolution,
    ) -> Result<Self> {
        target.validate()?;
        if target.space_id != identity.peer.space_id
            || target.device_id == identity.peer.device_id
            || resolution.payload.resolver_device != identity.peer.device_id
            || resolution.payload.space_id != identity.peer.space_id
        {
            return Err(TransportError::Authorization(
                "conflict wire own resolver source",
            ));
        }
        let offer = OriginalConflictOffer {
            protocol_version: PROTOCOL_VERSION,
            space_id: identity.peer.space_id.clone(),
            source_device: identity.peer.device_id.clone(),
            receiver_device: target.device_id.clone(),
            channel_binding: binding.clone(),
            resolution,
        };
        if serde_json::to_vec(&offer)?.len().saturating_add(512) > MAX_RESOLUTION_WIRE_BYTES {
            return Err(TransportError::Limit("conflict wire envelope bytes"));
        }
        Ok(Self {
            signature: sign(identity, OFFER_DOMAIN, &offer)?,
            offer,
        })
    }
    pub fn request_id(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(self)?))
    }
    pub fn verify(
        &self,
        source: &PeerIdentity,
        target: &PeerIdentity,
        binding: &ContentId,
        approved: &[PeerIdentity],
        limits: ResolutionLimits,
    ) -> Result<sync_extend_core_model::conflict_resolution::FileResolutionPlan> {
        source.validate()?;
        target.validate()?;
        let offer = &self.offer;
        if offer.protocol_version != PROTOCOL_VERSION
            || source.device_id == target.device_id
            || offer.space_id != source.space_id
            || offer.space_id != target.space_id
            || offer.source_device != source.device_id
            || offer.receiver_device != target.device_id
            || offer.channel_binding != *binding
            || serde_json::to_vec(self)?.len() > MAX_RESOLUTION_WIRE_BYTES
        {
            return Err(TransportError::Authorization(
                "conflict wire current session scope",
            ));
        }
        verify(source, OFFER_DOMAIN, offer, &self.signature)?;
        offer.resolution.verify(source, approved, limits)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalConflictTargetReceipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub source_device: DeviceId,
    pub channel_binding: ContentId,
    pub request_id: ContentId,
    pub resolution_fingerprint: ContentId,
    pub received_vector: VersionVector,
    pub applied_snapshot: SnapshotId,
    pub applied_vector: VersionVector,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOriginalConflictTargetReceipt {
    pub receipt: OriginalConflictTargetReceipt,
    pub signature: Vec<u8>,
}
impl SignedOriginalConflictTargetReceipt {
    pub fn sign(
        identity: &TransportIdentity,
        receipt: OriginalConflictTargetReceipt,
    ) -> Result<Self> {
        if receipt.device_id != identity.peer.device_id
            || receipt.space_id != identity.peer.space_id
            || receipt.source_device == receipt.device_id
            || receipt.protocol_version != PROTOCOL_VERSION
            || !receipt.received_vector.dominates(&receipt.applied_vector)
            || receipt.received_vector.0.len() > 1024
            || receipt
                .received_vector
                .0
                .values()
                .any(|n| *n == 0 || *n > i64::MAX as u64)
        {
            return Err(TransportError::Authorization(
                "conflict wire truthful target frontier",
            ));
        }
        Ok(Self {
            signature: sign(identity, RECEIPT_DOMAIN, &receipt)?,
            receipt,
        })
    }
    pub fn verify(&self, target: &PeerIdentity, offer: &SignedOriginalConflictOffer) -> Result<()> {
        target.validate()?;
        let receipt = &self.receipt;
        if receipt.protocol_version != PROTOCOL_VERSION
            || receipt.device_id != target.device_id
            || receipt.space_id != target.space_id
            || receipt.space_id != offer.offer.space_id
            || receipt.source_device != offer.offer.source_device
            || receipt.device_id != offer.offer.receiver_device
            || receipt.channel_binding != offer.offer.channel_binding
            || receipt.request_id != offer.request_id()?
            || receipt.resolution_fingerprint != offer.offer.resolution.payload.plan_fingerprint
            || !receipt.received_vector.dominates(&receipt.applied_vector)
            || receipt.received_vector.0.len() > 1024
            || receipt
                .received_vector
                .0
                .values()
                .any(|n| *n == 0 || *n > i64::MAX as u64)
        {
            return Err(TransportError::Authorization(
                "conflict wire target receipt binding",
            ));
        }
        for signed in offer
            .offer
            .resolution
            .payload
            .originals
            .iter()
            .chain(&offer.offer.resolution.payload.resolving)
        {
            let payload = &signed.operation.payload;
            if receipt.applied_vector.get(&payload.origin_device_id) < payload.origin_seq {
                return Err(TransportError::Authorization(
                    "conflict wire incomplete applied frontier",
                ));
            }
        }
        if self
            .receipt
            .applied_vector
            .0
            .values()
            .any(|n| *n == 0 || *n > i64::MAX as u64)
        {
            return Err(TransportError::Authorization(
                "conflict wire applied vector bounds",
            ));
        }
        verify(target, RECEIPT_DOMAIN, receipt, &self.signature)
    }
}
