//! Bounded individually signed own-origin metadata, not native apply authority.
use crate::{PeerIdentity, Result, SignedOperation, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    operation_batch::{MAX_OPERATION_BATCH, MAX_OPERATION_BATCH_BYTES},
    ContentId, DeviceId, SpaceId, VersionVector, PROTOCOL_VERSION,
};

pub const MAX_ORIGINAL_PAGE_BYTES: usize = MAX_OPERATION_BATCH_BYTES;
const DOMAIN: &str = "SyncExtend individually signed own-origin operation page v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalOperationPage {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub origin_device: DeviceId,
    pub receiver_device: DeviceId,
    pub channel_binding: ContentId,
    pub after_sequence: u64,
    pub tip_sequence: u64,
    pub operations: Vec<SignedOperation>,
}

impl OriginalOperationPage {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.origin_device == self.receiver_device
            || self.operations.len() > MAX_OPERATION_BATCH
            || self.after_sequence > self.tip_sequence
            || self.tip_sequence > i64::MAX as u64
            || (self.operations.is_empty() && self.after_sequence != self.tip_sequence)
        {
            return Err(TransportError::Authorization(
                "original page scope or bounds",
            ));
        }
        let mut sequence = self.after_sequence;
        for signed in &self.operations {
            signed.operation.validate()?;
            sequence = sequence
                .checked_add(1)
                .ok_or(TransportError::Limit("original page sequence overflow"))?;
            let payload = &signed.operation.payload;
            if payload.space_id != self.space_id
                || payload.origin_device_id != self.origin_device
                || payload.origin_seq != sequence
                || sequence > self.tip_sequence
                || signed.signature.len() != 64
            {
                return Err(TransportError::Authorization(
                    "original page exact contiguous identity",
                ));
            }
        }
        if serde_json::to_vec(self)?.len() > MAX_ORIGINAL_PAGE_BYTES - 256 {
            return Err(TransportError::Limit("original page encoded byte bound"));
        }
        Ok(())
    }

    pub fn request_id(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&serde_json::to_vec(&(DOMAIN, self))?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOriginalOperationPage {
    pub page: OriginalOperationPage,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPageReceiveReceipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub origin_device: DeviceId,
    pub channel_binding: ContentId,
    pub request_id: ContentId,
    pub after_sequence: u64,
    pub last_offered_sequence: u64,
    pub contiguous_received_sequence: u64,
    pub received_vector: VersionVector,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOriginalPageReceiveReceipt {
    pub receipt: OriginalPageReceiveReceipt,
    pub signature: Vec<u8>,
}

const RECEIVE_DOMAIN: &str = "SyncExtend individually signed page received-only receipt v1";

impl OriginalPageReceiveReceipt {
    fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.device_id == self.origin_device
            || self.after_sequence > self.last_offered_sequence
            || self.last_offered_sequence > i64::MAX as u64
            || self.contiguous_received_sequence < self.last_offered_sequence
            || self.contiguous_received_sequence > i64::MAX as u64
            || self.received_vector.0.len() > 1024
            || self
                .received_vector
                .0
                .values()
                .any(|n| *n == 0 || *n > i64::MAX as u64)
            || self.received_vector.get(&self.origin_device) != self.contiguous_received_sequence
        {
            return Err(TransportError::Authorization(
                "original received receipt vector/scope",
            ));
        }
        Ok(())
    }
}

impl SignedOriginalPageReceiveReceipt {
    pub fn sign(identity: &TransportIdentity, receipt: OriginalPageReceiveReceipt) -> Result<Self> {
        receipt.validate()?;
        if receipt.device_id != identity.peer.device_id
            || receipt.space_id != identity.peer.space_id
        {
            return Err(TransportError::Authorization(
                "original receive receipt target signer",
            ));
        }
        let digest = blake3::derive_key(RECEIVE_DOMAIN, &serde_json::to_vec(&receipt)?);
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
            || self.receipt.after_sequence != page.after_sequence
            || self.receipt.last_offered_sequence != last
        {
            return Err(TransportError::Authorization(
                "original receive receipt exact request/target",
            ));
        }
        let key = VerifyingKey::from_bytes(&target.public_key)
            .map_err(|_| TransportError::Authorization("original receive receipt target key"))?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| {
            TransportError::Authorization("original receive receipt signature width")
        })?;
        let digest = blake3::derive_key(RECEIVE_DOMAIN, &serde_json::to_vec(&self.receipt)?);
        key.verify_strict(&digest, &signature).map_err(|_| {
            TransportError::Authorization("original receive receipt signature invalid")
        })
    }
}

impl SignedOriginalOperationPage {
    pub fn sign(identity: &TransportIdentity, page: OriginalOperationPage) -> Result<Self> {
        page.validate()?;
        if page.space_id != identity.peer.space_id || page.origin_device != identity.peer.device_id
        {
            return Err(TransportError::Authorization(
                "original page source signer differs",
            ));
        }
        for operation in &page.operations {
            operation.verify(identity.peer_identity())?;
        }
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&page)?);
        let result = Self {
            page,
            signature: identity.signing_key.sign(&digest).to_bytes().to_vec(),
        };
        if serde_json::to_vec(&result)?.len() > MAX_ORIGINAL_PAGE_BYTES {
            return Err(TransportError::Limit(
                "signed original page encoded byte bound",
            ));
        }
        Ok(result)
    }

    pub fn verify(
        &self,
        source: &PeerIdentity,
        receiver: &PeerIdentity,
        binding: &ContentId,
        expected_after: u64,
    ) -> Result<()> {
        source.validate()?;
        receiver.validate()?;
        self.page.validate()?;
        if self.page.space_id != source.space_id
            || self.page.space_id != receiver.space_id
            || self.page.origin_device != source.device_id
            || self.page.receiver_device != receiver.device_id
            || &self.page.channel_binding != binding
            || self.page.after_sequence != expected_after
            || serde_json::to_vec(self)?.len() > MAX_ORIGINAL_PAGE_BYTES
        {
            return Err(TransportError::Authorization(
                "original page source/receiver/session/cursor",
            ));
        }
        let key = VerifyingKey::from_bytes(&source.public_key)
            .map_err(|_| TransportError::Authorization("original page approved key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("original page signature length"))?;
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(&self.page)?);
        key.verify_strict(&digest, &signature)
            .map_err(|_| TransportError::Authorization("original page signature invalid"))?;
        for operation in &self.page.operations {
            operation.verify(source)?;
        }
        Ok(())
    }
}
