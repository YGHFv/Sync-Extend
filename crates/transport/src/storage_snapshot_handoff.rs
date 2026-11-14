//! Explicit replacement storage evidence for one exact original snapshot owner.
use crate::{
    ForwardStoreState, ForwardedSnapshotEnvelope, PeerIdentity, SignedStorageSnapshotReceipt,
    TransportError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{
    storage_node::StorageNodeConfig, ContentId, DeviceId, SpaceId, FORMAT_VERSION,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStorageHandoffPolicy {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub storage_id: ContentId,
    pub required_storage_targets: BTreeSet<DeviceId>,
    pub not_before_ms: u64,
}

impl SnapshotStorageHandoffPolicy {
    pub fn validate(&self) -> crate::Result<()> {
        if self.format_version != FORMAT_VERSION
            || self.required_storage_targets.is_empty()
            || self.required_storage_targets.len() > 1024
            || self.required_storage_targets.contains(&self.storage_device)
            || self.not_before_ms == 0
            || self.not_before_ms > i64::MAX as u64
        {
            return Err(TransportError::Authorization(
                "explicit exact snapshot replacement storage policy",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStorageHandoffEvidence {
    pub envelope: ForwardedSnapshotEnvelope,
    pub signed_receipt: SignedStorageSnapshotReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotStorageHandoffRecord {
    pub policy: SnapshotStorageHandoffPolicy,
    pub retained: ForwardedSnapshotEnvelope,
    pub evidence: Vec<SnapshotStorageHandoffEvidence>,
    pub handed_off_at_ms: u64,
}

pub struct VerifiedSnapshotStorageHandoff {
    record: SnapshotStorageHandoffRecord,
}
impl VerifiedSnapshotStorageHandoff {
    pub fn record(&self) -> &SnapshotStorageHandoffRecord {
        &self.record
    }
}

impl SnapshotStorageHandoffRecord {
    /// Immutable historical evidence remains auditable after approval changes.
    pub fn validate(&self) -> crate::Result<()> {
        self.policy.validate()?;
        self.retained.verify(
            &self.retained.origin,
            &self.retained.forwarder,
            &self.retained.receiver,
            &self.retained.channel_binding,
        )?;
        if self.policy.space_id != self.retained.origin.space_id
            || self.policy.storage_device != self.retained.receiver.device_id
            || self.policy.storage_id != self.retained.storage_id()?
            || self.handed_off_at_ms < self.policy.not_before_ms
            || self.handed_off_at_ms > i64::MAX as u64
            || self.evidence.len() != self.policy.required_storage_targets.len()
            || !self
                .retained
                .signed_report
                .report
                .manifest
                .entries
                .values()
                .any(|entry| entry.content.is_some())
        {
            return Err(TransportError::Authorization(
                "snapshot storage handoff exact record/owner/deadline",
            ));
        }
        let mut targets = BTreeSet::new();
        for evidence in &self.evidence {
            let offered = &evidence.envelope;
            if offered.origin != self.retained.origin
                || offered.forwarder != self.retained.receiver
                || offered.receiver.device_id.as_str() <= self.policy.storage_device.as_str()
                || offered.signed_report != self.retained.signed_report
                || evidence.signed_receipt.receipt.state != ForwardStoreState::ContentClosed
                || !targets.insert(offered.receiver.device_id.clone())
            {
                return Err(TransportError::Authorization(
                    "snapshot handoff exact original full acyclic replacement storage",
                ));
            }
            evidence.signed_receipt.verify(&offered.receiver, offered)?;
        }
        if targets != self.policy.required_storage_targets {
            return Err(TransportError::Authorization(
                "snapshot handoff all explicit replacement targets required",
            ));
        }
        Ok(())
    }

    pub fn verify_current(
        self,
        config: &StorageNodeConfig,
        storage: &PeerIdentity,
    ) -> crate::Result<VerifiedSnapshotStorageHandoff> {
        config.validate()?;
        storage.validate()?;
        self.validate()?;
        let key = |peer: &PeerIdentity| {
            peer.public_key
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        if !config.enabled
            || config.space_id != self.policy.space_id
            || self.retained.receiver != *storage
            || config
                .approved_origins
                .get(&self.retained.origin.device_id)
                .map(ContentId::as_str)
                != Some(key(&self.retained.origin).as_str())
            || config
                .approved_forwarders
                .get(&self.retained.forwarder.device_id)
                .map(ContentId::as_str)
                != Some(key(&self.retained.forwarder).as_str())
            || self.evidence.iter().any(|evidence| {
                config
                    .approved_forwarders
                    .get(&evidence.envelope.receiver.device_id)
                    .map(ContentId::as_str)
                    != Some(key(&evidence.envelope.receiver).as_str())
            })
        {
            return Err(TransportError::Authorization(
                "snapshot replacement storage independently current approved keys",
            ));
        }
        Ok(VerifiedSnapshotStorageHandoff { record: self })
    }
}
