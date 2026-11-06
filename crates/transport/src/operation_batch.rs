use crate::{PeerIdentity, Result, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    operation_batch::OperationBatch, ContentId, DeviceId, SpaceId, PROTOCOL_VERSION,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperationBatch {
    pub batch: OperationBatch,
    pub signature: Vec<u8>,
}

impl SignedOperationBatch {
    pub fn sign(identity: &TransportIdentity, batch: OperationBatch) -> Result<Self> {
        batch.validate()?;
        if batch.space_id != identity.peer.space_id
            || batch.origin_device != identity.peer.device_id
        {
            return Err(TransportError::Authorization(
                "operation batch signer mismatch",
            ));
        }
        let digest = blake3::derive_key(
            "SyncExtend signed own-origin operation batch v1",
            &serde_json::to_vec(&batch)?,
        );
        Ok(Self {
            batch,
            signature: identity.signing_key.sign(&digest).to_bytes().to_vec(),
        })
    }

    pub fn verify(&self, peer: &PeerIdentity) -> Result<()> {
        peer.validate()?;
        self.batch.validate()?;
        if self.batch.space_id != peer.space_id || self.batch.origin_device != peer.device_id {
            return Err(TransportError::Authorization(
                "operation batch peer mismatch",
            ));
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("operation batch signature length"))?;
        let key = VerifyingKey::from_bytes(&peer.public_key)
            .map_err(|_| TransportError::Authorization("operation batch signing key"))?;
        let digest = blake3::derive_key(
            "SyncExtend signed own-origin operation batch v1",
            &serde_json::to_vec(&self.batch)?,
        );
        key.verify_strict(&digest, &signature)
            .map_err(|_| TransportError::Authorization("operation batch signature mismatch"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBatchRequest {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub origin_device: DeviceId,
    pub after_sequence: u64,
}

impl OperationBatchRequest {
    pub fn validate(&self, local: &PeerIdentity) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.space_id != local.space_id
            || self.origin_device != local.device_id
            || self.after_sequence > i64::MAX as u64
        {
            return Err(TransportError::Authorization(
                "operation batch request scope",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceiveReceipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub origin_device: DeviceId,
    pub channel_binding: ContentId,
    pub request_id: ContentId,
    pub last_offered_sequence: u64,
    pub contiguous_received_sequence: u64,
    pub materialized: bool,
    pub backup_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperationReceiveReceipt {
    pub receipt: OperationReceiveReceipt,
    pub signature: Vec<u8>,
}

impl SignedOperationReceiveReceipt {
    pub fn sign(identity: &TransportIdentity, receipt: OperationReceiveReceipt) -> Result<Self> {
        if receipt.protocol_version != PROTOCOL_VERSION
            || receipt.space_id != identity.peer.space_id
            || receipt.device_id != identity.peer.device_id
            || receipt.origin_device == receipt.device_id
            || receipt.last_offered_sequence > i64::MAX as u64
            || receipt.contiguous_received_sequence > i64::MAX as u64
            || receipt.materialized
            || receipt.backup_complete
        {
            return Err(TransportError::Authorization(
                "operation receive receipt scope",
            ));
        }
        let digest = blake3::derive_key(
            "SyncExtend operation receive-only receipt v1",
            &serde_json::to_vec(&receipt)?,
        );
        Ok(Self {
            receipt,
            signature: identity.signing_key.sign(&digest).to_bytes().to_vec(),
        })
    }

    pub fn verify(
        &self,
        peer: &PeerIdentity,
        channel_binding: &ContentId,
        request_id: &ContentId,
        origin_device: &DeviceId,
        last_sequence: u64,
    ) -> Result<()> {
        peer.validate()?;
        if self.receipt.protocol_version != PROTOCOL_VERSION
            || self.receipt.space_id != peer.space_id
            || self.receipt.device_id != peer.device_id
            || self.receipt.origin_device == self.receipt.device_id
            || &self.receipt.origin_device != origin_device
            || &self.receipt.channel_binding != channel_binding
            || &self.receipt.request_id != request_id
            || self.receipt.last_offered_sequence != last_sequence
            || last_sequence > i64::MAX as u64
            || self.receipt.contiguous_received_sequence > i64::MAX as u64
            || self.receipt.materialized
            || self.receipt.backup_complete
        {
            return Err(TransportError::Authorization(
                "operation receive receipt binding",
            ));
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("operation receipt signature length"))?;
        let key = VerifyingKey::from_bytes(&peer.public_key)
            .map_err(|_| TransportError::Authorization("operation receipt signing key"))?;
        let digest = blake3::derive_key(
            "SyncExtend operation receive-only receipt v1",
            &serde_json::to_vec(&self.receipt)?,
        );
        key.verify_strict(&digest, &signature)
            .map_err(|_| TransportError::Authorization("operation receipt signature mismatch"))
    }
}
