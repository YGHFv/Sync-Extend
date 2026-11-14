//! Signed stored-only snapshot status binds the exact original report and channel.
use crate::{
    ForwardStoreState, ForwardedSnapshotEnvelope, PeerIdentity, Result, TransportError,
    TransportIdentity,
};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{ContentId, DeviceId, SpaceId, PROTOCOL_VERSION};

const DOMAIN: &str = "SyncExtend exact stored-only snapshot receipt v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSnapshotReceipt {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub origin_device: DeviceId,
    pub storage_id: ContentId,
    pub report_id: ContentId,
    pub channel_binding: ContentId,
    pub state: ForwardStoreState,
    pub verified_chunks: u32,
    pub verified_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStorageSnapshotReceipt {
    pub receipt: StorageSnapshotReceipt,
    pub signature: Vec<u8>,
}

impl StorageSnapshotReceipt {
    fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.origin_device == self.storage_device
            || self.verified_chunks as usize > sync_extend_core_model::limits::MAX_CHUNKS
            || self.verified_bytes > i64::MAX as u64
            || (self.state == ForwardStoreState::MetadataOnly
                && (self.verified_chunks != 0 || self.verified_bytes != 0))
        {
            return Err(TransportError::Authorization(
                "stored-only snapshot receipt bounds",
            ));
        }
        Ok(())
    }
}

impl SignedStorageSnapshotReceipt {
    /// Caller must audit durable exact ownership and actual CAS content first.
    pub fn sign(identity: &TransportIdentity, receipt: StorageSnapshotReceipt) -> Result<Self> {
        receipt.validate()?;
        if receipt.storage_device != identity.peer.device_id
            || receipt.space_id != identity.peer.space_id
        {
            return Err(TransportError::Authorization(
                "stored-only snapshot receipt signer",
            ));
        }
        let signature = identity
            .signing_key
            .sign(&blake3::derive_key(DOMAIN, &serde_json::to_vec(&receipt)?))
            .to_bytes()
            .to_vec();
        Ok(Self { receipt, signature })
    }

    pub fn verify(
        &self,
        storage: &PeerIdentity,
        offered: &ForwardedSnapshotEnvelope,
    ) -> Result<()> {
        offered.verify(
            &offered.origin,
            &offered.forwarder,
            storage,
            &offered.channel_binding,
        )?;
        self.receipt.validate()?;
        if self.receipt.space_id != storage.space_id
            || self.receipt.storage_device != storage.device_id
            || self.receipt.origin_device != offered.origin.device_id
            || self.receipt.storage_id != offered.storage_id()?
            || self.receipt.report_id != offered.report_id()?
            || self.receipt.channel_binding != offered.channel_binding
        {
            return Err(TransportError::Authorization(
                "stored-only snapshot exact report/channel/storage",
            ));
        }
        let mut chunks = BTreeMap::new();
        for file in offered
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &file.chunks {
                if chunks
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|old| old != chunk.length)
                {
                    return Err(TransportError::Authorization(
                        "stored-only snapshot conflicting chunk lengths",
                    ));
                }
            }
        }
        let total_bytes = chunks.values().try_fold(0u64, |sum, length| {
            sum.checked_add(u64::from(*length))
                .ok_or(TransportError::Limit("snapshot receipt byte sum"))
        })?;
        if self.receipt.verified_chunks as usize > chunks.len()
            || self.receipt.verified_bytes > total_bytes
            || (self.receipt.state == ForwardStoreState::ContentClosed
                && (self.receipt.verified_chunks as usize != chunks.len()
                    || self.receipt.verified_bytes != total_bytes))
        {
            return Err(TransportError::Authorization(
                "stored-only snapshot exact unique content counts",
            ));
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("snapshot receipt signature length"))?;
        VerifyingKey::from_bytes(&storage.public_key)
            .map_err(|_| TransportError::Authorization("snapshot receipt storage key"))?
            .verify_strict(
                &blake3::derive_key(DOMAIN, &serde_json::to_vec(&self.receipt)?),
                &signature,
            )
            .map_err(|_| TransportError::Authorization("snapshot receipt signature changed"))
    }
}
