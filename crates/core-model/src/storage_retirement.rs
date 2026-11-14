//! Pure exact storage-only recovery descriptions; never durable or native authority.
use crate::{
    gc_recovery::{
        plan_gc_recovery, GcRecoveryEvidence, GcRecoveryPhase, GcRecoveryPlan, GcRecoveryStep,
    },
    storage_node::StorageNodeConfig,
    ContentId, DeviceId, EntryId, ModelError, Result, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};

/// Explicit operator request for one original retired chunk and one storage policy.
/// Every identity must be independently established by a future durable adapter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageRetirementRequest {
    pub format_version: u32,
    pub request_id: EntryId,
    pub storage_id: ContentId,
    pub original_owner_id: EntryId,
    pub content_id: ContentId,
    pub original_metadata_hash: ContentId,
    pub storage_device: DeviceId,
    pub storage_policy: ContentId,
    pub data_identity: ContentId,
    pub cas_identity: ContentId,
    pub objects_identity: ContentId,
    pub shard_identity: ContentId,
    pub object_identity: ContentId,
    pub length: u32,
    pub modified_at_ns: u64,
    pub requested_at_ms: u64,
    pub grace_until_ms: u64,
    pub expires_at_ms: u64,
}

impl StorageRetirementRequest {
    pub fn validate(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<()> {
        config.validate()?;
        let grace = self.grace_until_ms.checked_sub(self.requested_at_ms);
        if self.format_version != FORMAT_VERSION
            || self.storage_device != *device
            || self.storage_policy != config.fingerprint()?
            || !config.enabled
            || !(1..=4 * 1024 * 1024).contains(&self.length)
            || u64::from(self.length) > config.max_stored_bytes
            || self.request_id == self.original_owner_id
            || self.requested_at_ms > i64::MAX as u64
            || self.expires_at_ms > i64::MAX as u64
            || self.expires_at_ms <= self.grace_until_ms
            || grace.is_none_or(|value| !(1000..=604800000).contains(&value) || value % 1000 != 0)
            || !self
                .storage_id
                .as_str()
                .starts_with(self.original_owner_id.as_str())
        {
            return Err(ModelError::InvalidData(
                "exact bounded storage retirement request",
            ));
        }
        let identities = [
            &self.data_identity,
            &self.cas_identity,
            &self.objects_identity,
            &self.shard_identity,
            &self.object_identity,
        ];
        for (index, identity) in identities.iter().enumerate() {
            if identities[..index].contains(identity) {
                return Err(ModelError::InvalidData(
                    "storage retirement physical identity alias",
                ));
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<ContentId> {
        self.validate(config, device)?;
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend.storage-only-retirement-request.v1",
            &config.space_id,
            self,
        ))?))
    }
}

/// Independently supplied observations remain descriptions, including true booleans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorageRetirementEvidence {
    pub request_fingerprint: ContentId,
    pub retained_metadata_hash: ContentId,
    pub exact_retired_owner_handoff: bool,
    pub retained_original_signature_valid: bool,
    pub full_storage_role_audit: bool,
    pub complete_capacity_audit: bool,
    pub cas_exclusive_before_sql: bool,
    pub checked_at_ms: u64,
    pub clock_watermark_ms: u64,
    pub native: GcRecoveryEvidence,
}

/// A returned plan cannot be supplied as a native execution grant.
pub struct StorageRetirementPlan {
    request_fingerprint: ContentId,
    recovery: GcRecoveryPlan,
}

impl StorageRetirementPlan {
    pub fn request_fingerprint(&self) -> &ContentId {
        &self.request_fingerprint
    }
    pub fn step(&self) -> GcRecoveryStep {
        self.recovery.step()
    }
    pub fn phase_after_step(&self) -> GcRecoveryPhase {
        self.recovery.phase_after_step()
    }
    pub fn deletion_authorized(&self) -> bool {
        false
    }
    pub fn executor_available(&self) -> bool {
        false
    }
    pub fn backup_complete(&self) -> bool {
        false
    }
}

/// Describe one step after exact scope and provenance checks. No I/O or writes.
pub fn plan_storage_retirement(
    request: &StorageRetirementRequest,
    config: &StorageNodeConfig,
    device: &DeviceId,
    phase: GcRecoveryPhase,
    evidence: &StorageRetirementEvidence,
) -> Result<StorageRetirementPlan> {
    let fingerprint = request.fingerprint(config, device)?;
    if evidence.request_fingerprint != fingerprint
        || evidence.retained_metadata_hash != request.original_metadata_hash
        || !evidence.exact_retired_owner_handoff
        || !evidence.retained_original_signature_valid
        || !evidence.full_storage_role_audit
        || !evidence.complete_capacity_audit
        || !evidence.native.metadata_verified
        || evidence.checked_at_ms > i64::MAX as u64
        || evidence.clock_watermark_ms > i64::MAX as u64
        || evidence.checked_at_ms < evidence.clock_watermark_ms
        || evidence.clock_watermark_ms < request.requested_at_ms
    {
        return Err(ModelError::InvalidData(
            "storage retirement fresh exact audit",
        ));
    }
    // Metadata-only terminal replay has no access to a new occupant.
    let terminal = matches!(
        phase,
        GcRecoveryPhase::Deleted | GcRecoveryPhase::Restored | GcRecoveryPhase::Aborted
    );
    if !terminal && !evidence.cas_exclusive_before_sql {
        return Err(ModelError::InvalidData(
            "storage retirement requires exclusive CAS before SQL",
        ));
    }
    if !terminal && evidence.checked_at_ms < request.grace_until_ms {
        return Err(ModelError::InvalidData("storage retirement grace pending"));
    }
    let mut native = evidence.native;
    // Only existing generic recovery rules may describe recording a completed
    // pre-request action after expiry. New effects require fresh operator time.
    if !terminal
        && evidence.checked_at_ms >= request.expires_at_ms
        && native.authority == crate::gc_recovery::GcRecoveryAuthority::FreshIntent
    {
        native.authority = crate::gc_recovery::GcRecoveryAuthority::Denied;
    }
    Ok(StorageRetirementPlan {
        request_fingerprint: fingerprint,
        recovery: plan_gc_recovery(phase, native),
    })
}
