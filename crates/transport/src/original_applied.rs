//! Target-signed actual applied frontier; received metadata cannot create this claim.
use crate::{OriginalOperationPage, PeerIdentity, Result, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    ContentId, DeviceId, SnapshotId, SpaceId, VersionVector, PROTOCOL_VERSION,
};

const DOMAIN: &str = "SyncExtend original page actual target applied receipt v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPageAppliedReceipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub origin_device: DeviceId,
    pub channel_binding: ContentId,
    pub request_id: ContentId,
    pub last_offered_sequence: u64,
    pub applied_snapshot: SnapshotId,
    pub applied_vector: VersionVector,
}
impl OriginalPageAppliedReceipt {
    fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.device_id == self.origin_device
            || self.last_offered_sequence == 0
            || self.last_offered_sequence > i64::MAX as u64
            || self.applied_vector.0.len() > 1024
            || self
                .applied_vector
                .0
                .values()
                .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self.applied_vector.get(&self.origin_device) < self.last_offered_sequence
        {
            return Err(TransportError::Authorization(
                "original applied receipt actual scope/vector",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOriginalPageAppliedReceipt {
    pub receipt: OriginalPageAppliedReceipt,
    pub signature: Vec<u8>,
}
impl SignedOriginalPageAppliedReceipt {
    /// Cryptographic signer only; the native adapter must establish the actual claim.
    pub fn sign(identity: &TransportIdentity, receipt: OriginalPageAppliedReceipt) -> Result<Self> {
        receipt.validate()?;
        if receipt.device_id != identity.peer.device_id
            || receipt.space_id != identity.peer.space_id
        {
            return Err(TransportError::Authorization(
                "original applied receipt only target signs",
            ));
        }
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&receipt)?);
        Ok(Self {
            receipt,
            signature: identity.signing_key.sign(&digest).to_bytes().to_vec(),
        })
    }
    pub fn verify(&self, target: &PeerIdentity, page: &OriginalOperationPage) -> Result<()> {
        target.validate()?;
        page.validate()?;
        self.receipt.validate()?;
        let last = page
            .operations
            .last()
            .map_or(page.after_sequence, |s| s.operation.payload.origin_seq);
        if self.receipt.space_id != target.space_id
            || self.receipt.space_id != page.space_id
            || self.receipt.device_id != target.device_id
            || self.receipt.device_id != page.receiver_device
            || self.receipt.origin_device != page.origin_device
            || self.receipt.channel_binding != page.channel_binding
            || self.receipt.request_id != page.request_id()?
            || self.receipt.last_offered_sequence != last
        {
            return Err(TransportError::Authorization(
                "original applied receipt exact request/target",
            ));
        }
        let key = VerifyingKey::from_bytes(&target.public_key)
            .map_err(|_| TransportError::Authorization("original applied target key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("original applied signature width"))?;
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&self.receipt)?);
        key.verify_strict(&digest, &signature)
            .map_err(|_| TransportError::Authorization("original applied signature invalid"))
    }
    pub fn verify_forwarded(
        &self,
        target: &PeerIdentity,
        page: &crate::ForwardedOperationPage,
    ) -> Result<()> {
        target.validate()?;
        page.validate()?;
        self.receipt.validate()?;
        let last = page
            .operations
            .last()
            .map_or(page.after_sequence, |s| s.operation.payload.origin_seq);
        if self.receipt.space_id != target.space_id
            || self.receipt.space_id != page.space_id
            || self.receipt.device_id != target.device_id
            || self.receipt.device_id != page.receiver_device
            || self.receipt.origin_device != page.origin_device
            || self.receipt.channel_binding != page.channel_binding
            || self.receipt.request_id != page.request_id()?
            || self.receipt.last_offered_sequence != last
        {
            return Err(TransportError::Authorization(
                "original applied receipt exact request/target",
            ));
        }
        let key = VerifyingKey::from_bytes(&target.public_key)
            .map_err(|_| TransportError::Authorization("original applied target key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("original applied signature width"))?;
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&self.receipt)?);
        key.verify_strict(&digest, &signature)
            .map_err(|_| TransportError::Authorization("original applied signature invalid"))
    }
}
