use crate::{PeerIdentity, Result, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    ContentId, DeviceId, Operation, SnapshotId, SpaceId, VersionVector, PROTOCOL_VERSION,
};

fn sign<T: Serialize>(identity: &TransportIdentity, domain: &str, value: &T) -> Result<Vec<u8>> {
    let hash = blake3::derive_key(domain, &serde_json::to_vec(value)?);
    Ok(identity.signing_key.sign(&hash).to_bytes().to_vec())
}

fn verify<T: Serialize>(
    peer: &PeerIdentity,
    domain: &str,
    value: &T,
    signature: &[u8],
) -> Result<()> {
    peer.validate()?;
    let key = VerifyingKey::from_bytes(&peer.public_key)
        .map_err(|_| TransportError::Authorization("invalid signing key"))?;
    let signature = Signature::from_slice(signature)
        .map_err(|_| TransportError::Authorization("invalid signature length"))?;
    let hash = blake3::derive_key(domain, &serde_json::to_vec(value)?);
    key.verify_strict(&hash, &signature)
        .map_err(|_| TransportError::Authorization("signature verification failed"))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub certificate_fingerprint: ContentId,
    pub channel_binding: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHello {
    pub hello: Hello,
    pub signature: Vec<u8>,
}

impl SignedHello {
    pub fn sign(identity: &TransportIdentity, channel_binding: ContentId) -> Result<Self> {
        let hello = Hello {
            protocol_version: PROTOCOL_VERSION,
            space_id: identity.peer.space_id.clone(),
            device_id: identity.peer.device_id.clone(),
            certificate_fingerprint: identity.peer.certificate_fingerprint(),
            channel_binding,
        };
        Ok(Self {
            signature: sign(identity, "SyncExtend authenticated hello v1", &hello)?,
            hello,
        })
    }

    pub fn verify(&self, peer: &PeerIdentity, channel_binding: &ContentId) -> Result<()> {
        if self.hello.protocol_version != PROTOCOL_VERSION
            || self.hello.space_id != peer.space_id
            || self.hello.device_id != peer.device_id
            || self.hello.certificate_fingerprint != peer.certificate_fingerprint()
            || &self.hello.channel_binding != channel_binding
        {
            return Err(TransportError::Authorization("hello binding mismatch"));
        }
        verify(
            peer,
            "SyncExtend authenticated hello v1",
            &self.hello,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOperation {
    pub operation: Operation,
    pub signature: Vec<u8>,
}

impl SignedOperation {
    pub fn sign(identity: &TransportIdentity, operation: Operation) -> Result<Self> {
        operation.validate()?;
        if operation.payload.space_id != identity.peer.space_id
            || operation.payload.origin_device_id != identity.peer.device_id
        {
            return Err(TransportError::Authorization("operation signer mismatch"));
        }
        Ok(Self {
            signature: sign(identity, "SyncExtend signed operation v1", &operation)?,
            operation,
        })
    }

    pub fn verify(&self, peer: &PeerIdentity) -> Result<()> {
        self.operation.validate()?;
        if self.operation.payload.space_id != peer.space_id
            || self.operation.payload.origin_device_id != peer.device_id
        {
            return Err(TransportError::Authorization("operation origin mismatch"));
        }
        verify(
            peer,
            "SyncExtend signed operation v1",
            &self.operation,
            &self.signature,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Received,
    ContentClosed,
    Materialized,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub channel_binding: ContentId,
    pub request_id: ContentId,
    pub snapshot_id: SnapshotId,
    pub version_vector: VersionVector,
    pub state: ReceiptState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signature: Vec<u8>,
}

impl SignedReceipt {
    pub fn sign(identity: &TransportIdentity, receipt: Receipt) -> Result<Self> {
        if receipt.protocol_version != PROTOCOL_VERSION
            || receipt.space_id != identity.peer.space_id
            || receipt.device_id != identity.peer.device_id
            || receipt.version_vector.0.len() > 1024
            || receipt.version_vector.0.values().any(|value| *value == 0)
        {
            return Err(TransportError::Authorization("receipt issuer mismatch"));
        }
        Ok(Self {
            signature: sign(identity, "SyncExtend signed receipt v1", &receipt)?,
            receipt,
        })
    }

    pub fn verify(
        &self,
        peer: &PeerIdentity,
        channel_binding: &ContentId,
        request_id: &ContentId,
    ) -> Result<()> {
        if self.receipt.protocol_version != PROTOCOL_VERSION
            || self.receipt.space_id != peer.space_id
            || self.receipt.device_id != peer.device_id
            || &self.receipt.channel_binding != channel_binding
            || &self.receipt.request_id != request_id
            || self.receipt.version_vector.0.len() > 1024
            || self
                .receipt
                .version_vector
                .0
                .values()
                .any(|value| *value == 0)
        {
            return Err(TransportError::Authorization("receipt binding mismatch"));
        }
        verify(
            peer,
            "SyncExtend signed receipt v1",
            &self.receipt,
            &self.signature,
        )
    }
}
