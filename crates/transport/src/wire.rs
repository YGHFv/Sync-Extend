use crate::{PeerIdentity, Result, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    ChunkRef, ContentId, DeviceId, EntryId, Manifest, PortablePath, SnapshotId, SpaceId,
    PROTOCOL_VERSION,
};

const OFFER_DOMAIN: &str = "SyncExtend authenticated file offer v1";
pub const MAX_OFFER_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOffer {
    pub protocol_version: u32,
    pub source_device: DeviceId,
    pub snapshot_id: SnapshotId,
    pub manifest: Manifest,
    pub entry_id: EntryId,
    pub snapshot_created_at_ms: u64,
}

impl FileOffer {
    pub fn validate(&self) -> Result<()> {
        let entry = self
            .manifest
            .entries
            .get(&self.entry_id)
            .ok_or(TransportError::Protocol("offered entry is absent"))?;
        if self.protocol_version != PROTOCOL_VERSION
            || self.manifest.root()? != self.snapshot_id
            || entry.kind != sync_extend_core_model::EntryKind::File
            || entry.content.is_none()
            || self.snapshot_created_at_ms > i64::MAX as u64
        {
            return Err(TransportError::Protocol("invalid file offer"));
        }
        if serde_json::to_vec(self)?.len() > MAX_OFFER_BYTES {
            return Err(TransportError::Limit("file offer metadata"));
        }
        Ok(())
    }

    pub fn request_id(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&blake3::derive_key(
            OFFER_DOMAIN,
            &serde_json::to_vec(self)?,
        )))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFileOffer {
    pub offer: FileOffer,
    pub signature: Vec<u8>,
}

impl SignedFileOffer {
    pub fn sign(identity: &TransportIdentity, offer: FileOffer) -> Result<Self> {
        offer.validate()?;
        if offer.manifest.space_id != identity.peer.space_id
            || offer.source_device != identity.peer.device_id
        {
            return Err(TransportError::Authorization("file offer signer scope"));
        }
        let hash = blake3::derive_key(OFFER_DOMAIN, &serde_json::to_vec(&offer)?);
        Ok(Self {
            offer,
            signature: identity.signing_key.sign(&hash).to_bytes().to_vec(),
        })
    }

    pub fn verify(&self, peer: &PeerIdentity) -> Result<()> {
        self.offer.validate()?;
        peer.validate()?;
        if self.offer.manifest.space_id != peer.space_id
            || self.offer.source_device != peer.device_id
        {
            return Err(TransportError::Authorization("file offer peer scope"));
        }
        let key = VerifyingKey::from_bytes(&peer.public_key)
            .map_err(|_| TransportError::Authorization("invalid offer public key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("invalid offer signature length"))?;
        key.verify_strict(
            &blake3::derive_key(OFFER_DOMAIN, &serde_json::to_vec(&self.offer)?),
            &signature,
        )
        .map_err(|_| TransportError::Authorization("invalid file offer signature"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileRequest {
    Offer {
        protocol_version: u32,
        space_id: SpaceId,
        path: PortablePath,
    },
    Chunk {
        request_id: ContentId,
        chunk: ChunkRef,
    },
    Finish {
        request_id: ContentId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FileResponse {
    Offer {
        offer: Box<SignedFileOffer>,
    },
    Chunk {
        request_id: ContentId,
        chunk: ChunkRef,
    },
    Finished {
        request_id: ContentId,
    },
    Refused {
        reason: String,
    },
}
