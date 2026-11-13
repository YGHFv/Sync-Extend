//! A forwarding node authenticates the channel envelope, preserving each origin signature.
use crate::{PeerIdentity, Result, SignedOperation, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use sync_extend_core_model::{
    operation_batch::{MAX_OPERATION_BATCH, MAX_OPERATION_BATCH_BYTES},
    ContentId, DeviceId, SpaceId, PROTOCOL_VERSION,
};

const DOMAIN: &str = "SyncExtend independently signed origin forwarded page v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedOperationPage {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub origin_device: DeviceId,
    pub forwarding_device: DeviceId,
    pub receiver_device: DeviceId,
    pub channel_binding: ContentId,
    pub after_sequence: u64,
    pub tip_sequence: u64,
    pub operations: Vec<SignedOperation>,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > MAX_OPERATION_BATCH_BYTES {
                return Err(io::Error::other("forward page encoded byte limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, value)?;
    Ok(output.0)
}

impl ForwardedOperationPage {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.origin_device == self.forwarding_device
            || self.receiver_device == self.forwarding_device
            || self.receiver_device == self.origin_device
            || self.operations.len() > MAX_OPERATION_BATCH
            || self.after_sequence > self.tip_sequence
            || self.tip_sequence > i64::MAX as u64
            || (self.operations.is_empty() && self.after_sequence != self.tip_sequence)
        {
            return Err(TransportError::Authorization(
                "forward page exact three-device scope",
            ));
        }
        let mut sequence = self.after_sequence;
        for signed in &self.operations {
            signed.operation.validate()?;
            sequence = sequence
                .checked_add(1)
                .ok_or(TransportError::Limit("forward page sequence overflow"))?;
            if signed.operation.payload.space_id != self.space_id
                || signed.operation.payload.origin_device_id != self.origin_device
                || signed.operation.payload.origin_seq != sequence
                || sequence > self.tip_sequence
                || signed.signature.len() != 64
            {
                return Err(TransportError::Authorization(
                    "forward page original continuity",
                ));
            }
        }
        encode(self)?;
        Ok(())
    }

    pub fn request_id(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&encode(&(DOMAIN, self))?))
    }

    /// Durable storage ownership follows the original page and storage device.
    /// A new transport binding or forwarding hop does not reserve duplicate pins.
    pub fn storage_id(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&encode(&(
            "SyncExtend durable original forwarded storage page v1",
            &self.space_id,
            &self.origin_device,
            &self.receiver_device,
            self.after_sequence,
            &self.operations,
        ))?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedForwardedOperationPage {
    pub page: ForwardedOperationPage,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedPageEnvelope {
    pub origin: PeerIdentity,
    pub forwarder: PeerIdentity,
    pub receiver: PeerIdentity,
    pub signed_page: SignedForwardedOperationPage,
}

impl ForwardedPageEnvelope {
    /// Checks historical provenance only. Persisted keys do not approve themselves.
    pub fn validate(&self) -> Result<()> {
        self.signed_page.verify(
            &self.origin,
            &self.forwarder,
            &self.receiver,
            &self.signed_page.page.channel_binding,
            self.signed_page.page.after_sequence,
        )?;
        Ok(())
    }
}

/// Constructed only after current independent origin and channel-peer approval.
pub struct VerifiedForwardedPage {
    signed: SignedForwardedOperationPage,
    origin: PeerIdentity,
    forwarder: PeerIdentity,
    receiver: PeerIdentity,
}

impl SignedForwardedOperationPage {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_OPERATION_BATCH_BYTES {
            return Err(TransportError::Limit("forward page input bytes"));
        }
        let signed: Self = serde_json::from_slice(bytes)?;
        signed.page.validate()?;
        encode(&signed)?;
        Ok(signed)
    }

    pub fn sign(
        identity: &TransportIdentity,
        approved_origin: &PeerIdentity,
        page: ForwardedOperationPage,
    ) -> Result<Self> {
        page.validate()?;
        approved_origin.validate()?;
        if page.space_id != identity.peer.space_id
            || page.forwarding_device != identity.peer.device_id
            || page.origin_device != approved_origin.device_id
            || page.space_id != approved_origin.space_id
        {
            return Err(TransportError::Authorization(
                "forwarder or approved origin differs",
            ));
        }
        for original in &page.operations {
            original.verify(approved_origin)?;
        }
        let bytes = encode(&(DOMAIN, &page))?;
        let signed = Self {
            page,
            signature: identity
                .signing_key
                .sign(&blake3::derive_key(DOMAIN, &bytes))
                .to_bytes()
                .to_vec(),
        };
        encode(&signed)?;
        Ok(signed)
    }

    pub fn verify(
        &self,
        approved_origin: &PeerIdentity,
        authenticated_forwarder: &PeerIdentity,
        receiver: &PeerIdentity,
        binding: &ContentId,
        after: u64,
    ) -> Result<VerifiedForwardedPage> {
        for peer in [approved_origin, authenticated_forwarder, receiver] {
            peer.validate()?;
        }
        self.page.validate()?;
        encode(self)?;
        if self.page.space_id != approved_origin.space_id
            || self.page.space_id != authenticated_forwarder.space_id
            || self.page.space_id != receiver.space_id
            || self.page.origin_device != approved_origin.device_id
            || self.page.forwarding_device != authenticated_forwarder.device_id
            || self.page.receiver_device != receiver.device_id
            || &self.page.channel_binding != binding
            || self.page.after_sequence != after
        {
            return Err(TransportError::Authorization(
                "forwarded page current approval/channel/cursor",
            ));
        }
        for original in &self.page.operations {
            original.verify(approved_origin)?;
        }
        let key = VerifyingKey::from_bytes(&authenticated_forwarder.public_key)
            .map_err(|_| TransportError::Authorization("forwarder key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("forwarder signature length"))?;
        key.verify_strict(
            &blake3::derive_key(DOMAIN, &encode(&(DOMAIN, &self.page))?),
            &signature,
        )
        .map_err(|_| TransportError::Authorization("forwarder signature invalid"))?;
        Ok(VerifiedForwardedPage {
            signed: self.clone(),
            origin: approved_origin.clone(),
            forwarder: authenticated_forwarder.clone(),
            receiver: receiver.clone(),
        })
    }
}

impl VerifiedForwardedPage {
    pub fn page(&self) -> &ForwardedOperationPage {
        &self.signed.page
    }
    pub fn origin(&self) -> &PeerIdentity {
        &self.origin
    }
    pub fn forwarder(&self) -> &PeerIdentity {
        &self.forwarder
    }
    pub fn receiver(&self) -> &PeerIdentity {
        &self.receiver
    }
    pub fn request_id(&self) -> Result<ContentId> {
        self.signed.page.request_id()
    }
    pub fn storage_id(&self) -> Result<ContentId> {
        self.signed.page.storage_id()
    }
    pub fn envelope(&self) -> ForwardedPageEnvelope {
        ForwardedPageEnvelope {
            origin: self.origin.clone(),
            forwarder: self.forwarder.clone(),
            receiver: self.receiver.clone(),
            signed_page: self.signed.clone(),
        }
    }
    pub fn native_applied(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardStoreState {
    MetadataOnly,
    PartialStaging,
    ContentClosed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardStoreReceipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub origin_device: DeviceId,
    pub request_id: ContentId,
    pub channel_binding: ContentId,
    pub after_sequence: u64,
    pub received_sequence: u64,
    pub state: ForwardStoreState,
    pub verified_chunks: u32,
    pub verified_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedForwardStoreReceipt {
    pub receipt: ForwardStoreReceipt,
    pub signature: Vec<u8>,
}

const RECEIPT_DOMAIN: &str = "SyncExtend forwarded stored-only receipt v1";

impl ForwardStoreReceipt {
    fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.origin_device == self.storage_device
            || self.after_sequence > self.received_sequence
            || self.received_sequence > i64::MAX as u64
            || self.verified_chunks as usize > sync_extend_core_model::limits::MAX_CHUNKS
            || self.verified_bytes > i64::MAX as u64
            || (self.state == ForwardStoreState::MetadataOnly
                && (self.verified_chunks != 0 || self.verified_bytes != 0))
        {
            return Err(TransportError::Authorization("stored-only receipt bounds"));
        }
        Ok(())
    }
}

impl SignedForwardStoreReceipt {
    /// Caller must establish durable metadata/pins and content state before signing.
    pub fn sign(identity: &TransportIdentity, receipt: ForwardStoreReceipt) -> Result<Self> {
        receipt.validate()?;
        if receipt.storage_device != identity.peer.device_id
            || receipt.space_id != identity.peer.space_id
        {
            return Err(TransportError::Authorization("storage receipt signer"));
        }
        let signature = identity
            .signing_key
            .sign(&blake3::derive_key(RECEIPT_DOMAIN, &encode(&receipt)?))
            .to_bytes()
            .to_vec();
        Ok(Self { receipt, signature })
    }

    pub fn verify(&self, target: &PeerIdentity, page: &ForwardedOperationPage) -> Result<()> {
        target.validate()?;
        page.validate()?;
        self.receipt.validate()?;
        let last = page
            .operations
            .last()
            .map_or(page.after_sequence, |original| {
                original.operation.payload.origin_seq
            });
        if self.receipt.space_id != target.space_id
            || self.receipt.space_id != page.space_id
            || self.receipt.storage_device != target.device_id
            || self.receipt.storage_device != page.receiver_device
            || self.receipt.origin_device != page.origin_device
            || self.receipt.request_id != page.request_id()?
            || self.receipt.channel_binding != page.channel_binding
            || self.receipt.after_sequence != page.after_sequence
            || self.receipt.received_sequence != last
        {
            return Err(TransportError::Authorization(
                "stored receipt exact request/receiver/prefix",
            ));
        }
        let key = VerifyingKey::from_bytes(&target.public_key)
            .map_err(|_| TransportError::Authorization("storage receipt key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("storage receipt signature length"))?;
        key.verify_strict(
            &blake3::derive_key(RECEIPT_DOMAIN, &encode(&self.receipt)?),
            &signature,
        )
        .map_err(|_| TransportError::Authorization("storage receipt signature invalid"))
    }
}
