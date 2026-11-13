//! Explicit storage retention intent; expiry alone cannot authorize reference release.
use crate::{ContentId, DeviceId, ModelError, Result, SpaceId, FORMAT_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageRetentionPolicy {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub storage_id: ContentId,
    pub required_applied_targets: BTreeSet<DeviceId>,
    pub not_before_ms: u64,
    pub retain_until_ms: u64,
}

impl StorageRetentionPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || self.required_applied_targets.is_empty()
            || self.required_applied_targets.len() > 1024
            || self.required_applied_targets.contains(&self.storage_device)
            || self.not_before_ms == 0
            || self.retain_until_ms < self.not_before_ms
            || self.retain_until_ms > i64::MAX as u64
        {
            return Err(ModelError::InvalidConfig(
                "explicit exact storage retention policy",
            ));
        }
        Ok(())
    }

    pub fn policy_id(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-exact-storage-retention-policy-v1",
            self,
        ))?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageRetentionState {
    RetainBeforeDeadline,
    RetainMissingAppliedTargets,
    EligibleForExplicitOwnerHandoff,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRetentionAssessment {
    pub storage_id: ContentId,
    pub policy_id: ContentId,
    pub state: StorageRetentionState,
    pub missing_applied_targets: BTreeSet<DeviceId>,
    pub reference_release_executed: bool,
    pub physical_deletion_executed: bool,
}
