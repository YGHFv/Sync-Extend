//! Target native-applied evidence binds exact original content, device and retained page.
use crate::{
    ForwardedPageEnvelope, PeerIdentity, SignedOriginalPageAppliedReceipt, TransportError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{
    storage_node::StorageNodeConfig,
    storage_retention::{
        StorageRetentionAssessment, StorageRetentionPolicy, StorageRetentionState,
    },
    DeviceId, Result as ModelResult,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedAppliedEvidence {
    pub envelope: ForwardedPageEnvelope,
    pub signed_receipt: SignedOriginalPageAppliedReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePageDeliveryRecord {
    pub policy: StorageRetentionPolicy,
    pub retained: ForwardedPageEnvelope,
    pub evidence: Vec<ForwardedAppliedEvidence>,
    pub handed_off_at_ms: u64,
}

/// Constructed only with exact current policy approvals and all required native receipts.
pub struct VerifiedStoragePageDelivery {
    record: StoragePageDeliveryRecord,
}

impl VerifiedStoragePageDelivery {
    pub fn record(&self) -> &StoragePageDeliveryRecord {
        &self.record
    }
}

impl StoragePageDeliveryRecord {
    /// Historical signature/identity verification remains possible after pairing changes.
    /// Current authorization is required separately when constructing a new handoff.
    pub fn validate(&self) -> crate::Result<()> {
        self.policy.validate()?;
        self.retained.validate()?;
        if self.policy.storage_device != self.retained.receiver.device_id
            || self.policy.space_id != self.retained.origin.space_id
            || self.policy.storage_id != self.retained.signed_page.page.storage_id()?
            || self.evidence.len() != self.policy.required_applied_targets.len()
            || self.handed_off_at_ms > i64::MAX as u64
            || self.retained.signed_page.page.operations.is_empty()
        {
            return Err(TransportError::Authorization(
                "storage page delivery exact durable record",
            ));
        }
        let mut targets = BTreeSet::new();
        for evidence in &self.evidence {
            evidence.verify(
                &self.retained.origin,
                &self.retained.receiver,
                &evidence.envelope.receiver,
            )?;
            evidence.matches_retained_page(&self.retained)?;
            if !targets.insert(evidence.envelope.receiver.device_id.clone()) {
                return Err(TransportError::Authorization(
                    "storage delivery duplicate target",
                ));
            }
        }
        if targets != self.policy.required_applied_targets
            || assess_storage_retention(&self.policy, &targets, self.handed_off_at_ms)?.state
                != StorageRetentionState::EligibleForExplicitOwnerHandoff
        {
            return Err(TransportError::Authorization(
                "storage delivery targets or retention deadline",
            ));
        }
        Ok(())
    }

    pub fn verify_current(
        self,
        config: &StorageNodeConfig,
        storage: &PeerIdentity,
    ) -> crate::Result<VerifiedStoragePageDelivery> {
        config.validate()?;
        storage.validate()?;
        self.validate()?;
        let key = |peer: &PeerIdentity| {
            peer.public_key
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        if config.space_id != self.policy.space_id
            || self.retained.receiver != *storage
            || config
                .approved_origins
                .get(&self.retained.origin.device_id)
                .map(|value| value.as_str())
                != Some(key(&self.retained.origin).as_str())
            || config
                .approved_forwarders
                .get(&self.retained.forwarder.device_id)
                .map(|value| value.as_str())
                != Some(key(&self.retained.forwarder).as_str())
            || self.evidence.iter().any(|evidence| {
                config
                    .approved_forwarders
                    .get(&evidence.envelope.receiver.device_id)
                    .map(|value| value.as_str())
                    != Some(key(&evidence.envelope.receiver).as_str())
            })
        {
            return Err(TransportError::Authorization(
                "storage delivery current independent policy keys",
            ));
        }
        Ok(VerifiedStoragePageDelivery { record: self })
    }
}

impl ForwardedAppliedEvidence {
    pub fn verify(
        &self,
        approved_origin: &PeerIdentity,
        approved_storage: &PeerIdentity,
        approved_target: &PeerIdentity,
    ) -> crate::Result<()> {
        let envelope = &self.envelope;
        if envelope.origin != *approved_origin
            || envelope.forwarder != *approved_storage
            || envelope.receiver != *approved_target
        {
            return Err(TransportError::Authorization(
                "delivery evidence independent current keys",
            ));
        }
        envelope.validate()?;
        self.signed_receipt
            .verify_forwarded(approved_target, &envelope.signed_page.page)
    }

    pub fn matches_retained_page(&self, retained: &ForwardedPageEnvelope) -> crate::Result<()> {
        retained.validate()?;
        self.envelope.validate()?;
        let offered = &self.envelope.signed_page.page;
        let original = &retained.signed_page.page;
        if self.envelope.origin != retained.origin
            || self.envelope.forwarder != retained.receiver
            || offered.space_id != original.space_id
            || offered.origin_device != original.origin_device
            || offered.after_sequence != original.after_sequence
            || offered.operations != original.operations
            || offered.operations.is_empty()
        {
            return Err(TransportError::Authorization(
                "delivery evidence exact retained originals",
            ));
        }
        Ok(())
    }
}

/// Verified target set comes only from the signature/native-evidence adapter.
/// This pure assessment cannot delete bytes or remove any durable reference.
pub fn assess_storage_retention(
    policy: &StorageRetentionPolicy,
    verified_targets: &BTreeSet<DeviceId>,
    now_ms: u64,
) -> ModelResult<StorageRetentionAssessment> {
    policy.validate()?;
    let missing = policy
        .required_applied_targets
        .difference(verified_targets)
        .cloned()
        .collect::<BTreeSet<_>>();
    let state = if now_ms < policy.not_before_ms || now_ms < policy.retain_until_ms {
        StorageRetentionState::RetainBeforeDeadline
    } else if !missing.is_empty() {
        StorageRetentionState::RetainMissingAppliedTargets
    } else {
        StorageRetentionState::EligibleForExplicitOwnerHandoff
    };
    Ok(StorageRetentionAssessment {
        storage_id: policy.storage_id.clone(),
        policy_id: policy.policy_id()?,
        state,
        missing_applied_targets: missing,
        reference_release_executed: false,
        physical_deletion_executed: false,
    })
}
