//! Persisted native byte/entry plan; no physical reservation or native authority.
use super::Stored;
use crate::{JournalError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, EntryKind, Manifest, PortablePath};

pub(super) const INTENT_LIMIT: u64 = 16 * 1024 * 1024;
const PAYLOAD_LIMIT: u64 = 64 * 1024 * 1024;
const RECORD_LIMIT: u64 = 4096;
const RECORD_COUNT: u64 = 8;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalNativeCreateFootprint {
    pub format_version: u32,
    pub target_path: PortablePath,
    pub payload_digest: ContentId,
    pub payload_bytes: u64,
    pub max_intent_bytes: u64,
    pub max_phase_record_bytes: u64,
    pub phase_record_count: u64,
    pub metadata_peak_bytes: u64,
    pub native_peak_bytes: u64,
    pub native_peak_entries: u64,
}

impl OriginalNativeCreateFootprint {
    /// The same bounded workload charged by the native history reservation.
    /// Provides preflight accounting only; it does not reserve storage.
    #[cfg(target_os = "linux")]
    pub fn plan_linux(
        baseline: &Manifest,
        manifest: &Manifest,
        path: &PortablePath,
        replacement: bool,
    ) -> Result<Self> {
        Self::plan_native(baseline, manifest, path, if replacement { 2 } else { 3 })
    }

    pub(super) fn plan_native(
        baseline: &Manifest,
        manifest: &Manifest,
        path: &PortablePath,
        version: u32,
    ) -> Result<Self> {
        let mut footprint = Self::plan(manifest, path)?;
        if matches!(version, 2 | 3) {
            footprint.format_version = version;
            footprint.phase_record_count = 14;
            footprint.metadata_peak_bytes = INTENT_LIMIT
                .checked_mul(4)
                .and_then(|bytes| bytes.checked_add(RECORD_LIMIT * footprint.phase_record_count))
                .ok_or(JournalError::Invariant(
                    "daemon native terminal metadata peak overflow",
                ))?;
            footprint.native_peak_bytes = footprint
                .metadata_peak_bytes
                .checked_add(footprint.payload_bytes)
                .ok_or(JournalError::Invariant(
                    "daemon native terminal peak overflow",
                ))?;
            footprint.native_peak_entries = 2 + footprint.phase_record_count;
        }
        if version == 2 {
            let prior = baseline
                .entries
                .values()
                .find(|entry| entry.path == *path)
                .and_then(|entry| entry.content.as_ref())
                .ok_or(JournalError::Invariant(
                    "replacement native footprint prior file absent",
                ))?;
            if prior.length > PAYLOAD_LIMIT {
                return Err(JournalError::Invariant(
                    "replacement retained original byte limit",
                ));
            }
            footprint.native_peak_bytes = footprint
                .native_peak_bytes
                .checked_add(prior.length)
                .ok_or(JournalError::Invariant("replacement native peak overflow"))?;
            footprint.native_peak_entries += 2;
        } else if !matches!(version, 1 | 3) {
            return Err(JournalError::Invariant("original native footprint version"));
        }
        Ok(footprint)
    }
    pub(super) fn plan(manifest: &Manifest, path: &PortablePath) -> Result<Self> {
        let entry = manifest
            .entries
            .values()
            .find(|entry| entry.path == *path)
            .ok_or(JournalError::Invariant(
                "original native footprint target absent",
            ))?;
        let content = entry.content.as_ref().ok_or(JournalError::Invariant(
            "original native footprint file content absent",
        ))?;
        if entry.kind != EntryKind::File || content.length > PAYLOAD_LIMIT {
            return Err(JournalError::Invariant(
                "original native footprint file byte limit",
            ));
        }
        let metadata_peak_bytes = RECORD_LIMIT
            .checked_mul(RECORD_COUNT)
            .and_then(|bytes| bytes.checked_add(INTENT_LIMIT))
            .ok_or(JournalError::Invariant(
                "original native metadata footprint overflow",
            ))?;
        let native_peak_bytes =
            metadata_peak_bytes
                .checked_add(content.length)
                .ok_or(JournalError::Invariant(
                    "original native footprint overflow",
                ))?;
        Ok(Self {
            format_version: 1,
            target_path: path.clone(),
            payload_digest: content.content_id.clone(),
            payload_bytes: content.length,
            max_intent_bytes: INTENT_LIMIT,
            max_phase_record_bytes: RECORD_LIMIT,
            phase_record_count: RECORD_COUNT,
            metadata_peak_bytes,
            native_peak_bytes,
            native_peak_entries: 2 + RECORD_COUNT,
        })
    }

    pub(super) fn validate(&self, stored: &Stored) -> Result<()> {
        if *self
            != Self::plan_native(
                &stored.baseline,
                &stored.planned,
                &stored.future_path,
                stored.version,
            )?
        {
            return Err(JournalError::Invariant(
                "original native footprint differs from full manifest",
            ));
        }
        Ok(())
    }
}

impl super::OriginalLocalHistoryReservation {
    /// Recompute against the full original live reservation. This is a
    /// descriptive budget projection; available disk blocks are not reserved.
    pub fn original_native_create_footprint(&self) -> Result<OriginalNativeCreateFootprint> {
        let stored: Stored = serde_json::from_str(&self.exact_json)?;
        stored.validate(sync_extend_core_model::limits::MAX_ENTRIES)?;
        if stored.attempt != self.attempt || serde_json::to_string(&stored)? != self.exact_json {
            return Err(JournalError::Invariant(
                "original live native footprint attempt differs",
            ));
        }
        Ok(stored.native_footprint)
    }
}
