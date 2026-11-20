//! Conservative local-observation deletion age; no clock, database or deletion authority.
use crate::{Change, EntryId, Manifest, ModelError, Operation, OperationId, Result, SnapshotId, SpaceId, FORMAT_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const DELETION_CLOCK_REVISION: u64 = 1;
const MAX_PROTECTION_WORK: usize = 2_000_000;

pub fn retention_milliseconds(days: u64) -> Result<u64> {
    days.checked_mul(86_400_000)
        .ok_or(ModelError::InvalidConfig("deletion retention day overflow"))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionObservationBasis {
    LocalEffectiveCommit,
    LegacyLocalObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionObservation {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub operation_id: OperationId,
    pub entry_id: EntryId,
    pub effective_snapshot: SnapshotId,
    pub observed_at_ms: u64,
    pub clock_revision: u64,
    pub basis: DeletionObservationBasis,
}

impl DeletionObservation {
    pub fn validate(&self, operation: &Operation) -> Result<()> {
        operation.validate()?;
        if self.format_version != FORMAT_VERSION
            || self.space_id != operation.payload.space_id
            || self.operation_id != operation.op_id
            || self.clock_revision != DELETION_CLOCK_REVISION
            || operation.payload.change != (Change::Delete { entry_id: self.entry_id.clone() })
        {
            return Err(ModelError::InvalidData("deletion observation identity differs"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ObservedDeletion {
    pub operation: Operation,
    pub observation: Option<DeletionObservation>,
}

#[derive(Clone, Copy, Debug)]
pub struct RetentionClockView {
    pub now_ms: i64,
    pub watermark_ms: Option<u64>,
    pub revision: Option<u64>,
}

impl RetentionClockView {
    pub fn valid_now(self) -> Option<u64> {
        let now = u64::try_from(self.now_ms).ok().filter(|time| *time != 0)?;
        let watermark = self.watermark_ms.filter(|time| *time != 0)?;
        (self.revision == Some(DELETION_CLOCK_REVISION) && now >= watermark).then_some(now)
    }
}

pub struct DeletionRetentionSnapshot<'a> {
    pub snapshot_id: &'a SnapshotId,
    pub manifest: &'a Manifest,
}

fn age_reason(
    deletion: &ObservedDeletion,
    clock: RetentionClockView,
    minimum_ms: u64,
) -> Option<&'static str> {
    let Some(observation) = &deletion.observation else {
        return Some("deletion_age_unknown");
    };
    let Some(now) = clock.valid_now() else {
        return Some("deletion_clock_uncertain");
    };
    if observation.observed_at_ms == 0
        || observation.clock_revision != DELETION_CLOCK_REVISION
        || observation.observed_at_ms > now
        || clock.watermark_ms.is_none_or(|time| time < observation.observed_at_ms)
    {
        return Some("deletion_age_unknown");
    }
    match observation.observed_at_ms.checked_add(minimum_ms) {
        Some(expiry) if now >= expiry => None,
        Some(_) => Some("minimum_local_deletion_age"),
        None => Some("deletion_age_overflow"),
    }
}

/// Returns only additional protection. Existing current, count, lease, pin,
/// native/dependency and quota rules remain the caller's independent obligations.
/// Sender operation timestamps and snapshot creation timestamps are never used.
pub fn deletion_retention_protection(
    space: &SpaceId,
    snapshots: &[DeletionRetentionSnapshot<'_>],
    deletions: &BTreeMap<OperationId, ObservedDeletion>,
    days: u64,
    clock: RetentionClockView,
    max_entries: usize,
) -> Result<BTreeMap<SnapshotId, BTreeSet<&'static str>>> {
    let minimum_ms = retention_milliseconds(days)?;
    if max_entries == 0
        || max_entries > crate::limits::MAX_ENTRIES
        || snapshots.len() > max_entries
        || deletions.len() > max_entries
    {
        return Err(ModelError::InvalidData("deletion retention input limit"));
    }
    if days == 0 {
        return Ok(BTreeMap::new());
    }
    let mut seen = BTreeSet::new();
    for snapshot in snapshots {
        if snapshot.manifest.space_id != *space
            || snapshot.manifest.entries.len() > max_entries
            || snapshot.manifest.tombstones.len() > max_entries
            || snapshot.manifest.root()? != *snapshot.snapshot_id
            || !seen.insert(snapshot.snapshot_id)
        {
            return Err(ModelError::InvalidData("deletion retention snapshot differs"));
        }
    }
    let mut protection = BTreeMap::<SnapshotId, BTreeSet<&'static str>>::new();
    let mut work = 0usize;
    for (id, deletion) in deletions {
        deletion.operation.validate()?;
        let payload = &deletion.operation.payload;
        let Change::Delete { entry_id } = &payload.change else {
            return Err(ModelError::InvalidData("retention operation is not Delete"));
        };
        if id != &deletion.operation.op_id || payload.space_id != *space {
            return Err(ModelError::InvalidData("retention Delete identity differs"));
        }
        if let Some(observation) = &deletion.observation {
            observation.validate(&deletion.operation)?;
        }
        let age = age_reason(deletion, clock, minimum_ms);
        for snapshot in snapshots {
            work = work.checked_add(1).filter(|n| *n <= MAX_PROTECTION_WORK)
                .ok_or(ModelError::InvalidData("deletion retention work budget"))?;
            if !snapshot.manifest.entries.contains_key(entry_id) {
                continue;
            }
            let vector = &snapshot.manifest.version_vector;
            // The manifest vector proves global knowledge only. A concurrent
            // Put may remain live alongside a known Delete, and Entry carries
            // no Put provenance. A live post-Delete incarnation therefore
            // remains ambiguous until a separate bounded proof exists.
            let reason = if payload.causal.dominates(vector) {
                age
            } else {
                // A concurrent or unproven episode must not be aged by timestamps.
                Some("ambiguous_deletion_causal_history")
            };
            if let Some(reason) = reason {
                protection.entry(snapshot.snapshot_id.clone()).or_default().insert(reason);
            }
        }
    }
    Ok(protection)
}
