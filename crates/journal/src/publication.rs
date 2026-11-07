use crate::{JournalError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Preparing,
    Ready,
    Published,
    Committed,
}

impl PublicationState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Ready => "ready",
            Self::Published => "published",
            Self::Committed => "committed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationIntent {
    pub format_version: u32,
    pub transaction_id: EntryId,
    pub space_id: SpaceId,
    pub entry_id: EntryId,
    pub requested_path: PortablePath,
    pub target_path: PortablePath,
    pub content: FileManifest,
    pub baseline_root: SnapshotId,
    pub requested_baseline: Option<Entry>,
    pub source_snapshot: Option<SnapshotId>,
    pub created_at_ms: u64,
    pub attempt: u32,
    #[serde(default)]
    pub root_identity: Option<ContentId>,
    #[serde(default)]
    pub parent_identity: Option<ContentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<PublicationCompletion>,
    /// Durable opt-in selection, including the interval before a native header.
    #[serde(default, skip_serializing_if = "is_false")]
    pub native_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<crate::RemotePublicationProof>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Exact pre-effect history continuation, not native creator or apply authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationCompletion {
    pub baseline: Manifest,
    pub manifest: Manifest,
    pub operations: Vec<Operation>,
    pub timestamp_ms: u64,
    pub protected_objects: std::collections::BTreeMap<ContentId, u32>,
}

impl PublicationCompletion {
    pub fn new(
        baseline: &Manifest,
        device: &DeviceId,
        entry: Entry,
        timestamp_ms: u64,
    ) -> Result<Self> {
        Self::from_observed(
            baseline,
            device,
            baseline.entries.clone(),
            entry,
            timestamp_ms,
        )
    }

    /// Native observations have their own operations; the owned publication Put
    /// is always last. No received operation is materialized by this plan.
    pub fn from_observed(
        baseline: &Manifest,
        device: &DeviceId,
        observed: std::collections::BTreeMap<EntryId, Entry>,
        entry: Entry,
        timestamp_ms: u64,
    ) -> Result<Self> {
        baseline.validate()?;
        entry.validate()?;
        if baseline.entries.contains_key(&entry.entry_id)
            || baseline.tombstones.contains_key(&entry.entry_id)
            || observed.contains_key(&entry.entry_id)
            || observed.len() >= limits::MAX_ENTRIES
            || timestamp_ms > i64::MAX as u64
        {
            return Err(JournalError::Invariant(
                "publication completion reused entry or limit",
            ));
        }
        let mut manifest = baseline.clone();
        manifest.entries = observed;
        for id in manifest.entries.keys() {
            manifest.tombstones.remove(id);
        }
        let mut changes = Vec::new();
        for observed in manifest.entries.values() {
            match baseline.entries.get(&observed.entry_id) {
                None => changes.push(Change::Put {
                    entry: observed.clone(),
                }),
                Some(old) => {
                    if old.path != observed.path {
                        changes.push(Change::Rename {
                            entry_id: observed.entry_id.clone(),
                            path: observed.path.clone(),
                        });
                    }
                    if old.kind != observed.kind || old.content != observed.content {
                        changes.push(Change::Put {
                            entry: observed.clone(),
                        });
                    }
                }
            }
        }
        for id in baseline.entries.keys() {
            if !manifest.entries.contains_key(id) {
                changes.push(Change::Delete {
                    entry_id: id.clone(),
                });
            }
        }
        changes.push(Change::Put {
            entry: entry.clone(),
        });
        if changes.len() > limits::MAX_ENTRIES {
            return Err(JournalError::Invariant(
                "publication observation operation limit",
            ));
        }
        let mut operations = Vec::new();
        for change in changes {
            let sequence = manifest
                .version_vector
                .get(device)
                .checked_add(1)
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or(JournalError::Invariant("publication sequence exhausted"))?;
            let operation = Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: baseline.space_id.clone(),
                origin_device_id: device.clone(),
                origin_seq: sequence,
                causal: manifest.version_vector.clone(),
                change,
                created_at_ms: timestamp_ms,
            })?;
            if let Change::Delete { entry_id } = &operation.payload.change {
                manifest
                    .tombstones
                    .insert(entry_id.clone(), operation.op_id.clone());
            }
            manifest.version_vector.observe(device.clone(), sequence);
            operations.push(operation);
        }
        manifest.entries.insert(entry.entry_id.clone(), entry);
        manifest.validate()?;
        let mut protected_objects = std::collections::BTreeMap::new();
        for content in manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &content.chunks {
                if protected_objects
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|length| length != chunk.length)
                {
                    return Err(JournalError::Invariant(
                        "publication conflicting chunk lengths",
                    ));
                }
            }
        }
        Ok(Self {
            baseline: baseline.clone(),
            manifest,
            operations,
            timestamp_ms,
            protected_objects,
        })
    }

    pub(crate) fn validate(&self, intent: &PublicationIntent) -> Result<()> {
        self.manifest.validate()?;
        self.baseline.validate()?;
        let operation = self.operations.last().ok_or(JournalError::Invariant(
            "publication completion operation missing",
        ))?;
        operation.validate()?;
        if self.timestamp_ms > i64::MAX as u64
            || self.timestamp_ms != intent.created_at_ms
            || operation.payload.created_at_ms != self.timestamp_ms
            || operation.payload.space_id != intent.space_id
            || self.manifest.space_id != intent.space_id
            || self.baseline.space_id != intent.space_id
            || operation.payload.change
                != (Change::Put {
                    entry: Entry {
                        entry_id: intent.entry_id.clone(),
                        path: intent.target_path.clone(),
                        kind: EntryKind::File,
                        content: Some(intent.content.clone()),
                    },
                })
        {
            return Err(JournalError::Invariant("publication completion scope"));
        }
        if let Some(proof) = &intent.remote {
            proof.verify()?;
            if !intent.native_only
                || self != &Self::from_remote(&self.baseline, proof)?
                || intent.requested_path != intent.target_path
                || intent.requested_baseline.is_some()
                || intent.source_snapshot.is_some()
            {
                return Err(JournalError::Invariant(
                    "remote publication original completion differs",
                ));
            }
            return Ok(());
        }
        let mut observed = self.manifest.entries.clone();
        observed
            .remove(&intent.entry_id)
            .ok_or(JournalError::Invariant(
                "publication completion entry missing",
            ))?;
        let mut rebuilt = Self::from_observed(
            &self.baseline,
            &operation.payload.origin_device_id,
            observed,
            self.manifest.entries[&intent.entry_id].clone(),
            self.timestamp_ms,
        )?;
        if rebuilt
            .protected_objects
            .iter()
            .any(|(id, length)| self.protected_objects.get(id) != Some(length))
            || self.protected_objects.len() > limits::MAX_CHUNKS
            || self
                .protected_objects
                .values()
                .any(|length| *length == 0 || *length > 4 * 1024 * 1024)
        {
            return Err(JournalError::Invariant(
                "publication observation protection scope",
            ));
        }
        rebuilt.protected_objects = self.protected_objects.clone();
        if self.baseline.root()? != intent.baseline_root || rebuilt != *self {
            return Err(JournalError::Invariant(
                "publication completion baseline mismatch",
            ));
        }
        Ok(())
    }

    /// Full independent history peak held until commit; old pins/map releases
    /// cannot finance this reservation. All sizes count actual UTF-8 SQL values.
    pub(crate) fn charge(&self) -> Result<tree_storage_capacity::TreeStorageCharge> {
        let chunks: std::collections::BTreeSet<_> = self
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| content.chunks.iter().map(|chunk| &chunk.content_id))
            .collect();
        let visits = self
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .try_fold(0usize, |n, content| n.checked_add(content.chunks.len()))
            .ok_or(JournalError::Invariant(
                "publication completion chunk overflow",
            ))?;
        let manifest = serde_json::to_vec(&self.manifest)?;
        let operation = self.operations.iter().try_fold(0u64, |bytes, operation| {
            let json = serde_json::to_vec(operation)?;
            if json.len() > crate::MAX_OPERATION_BYTES {
                return Err(JournalError::Invariant("publication operation byte limit"));
            }
            bytes
                .checked_add(json.len() as u64 + 180)
                .ok_or(JournalError::Invariant(
                    "publication operation bytes overflow",
                ))
        })?;
        if visits > limits::MAX_CHUNKS
            || manifest.len() > crate::MAX_OPERATION_BYTES
            || serde_json::to_vec(self)?.len() > crate::MAX_OPERATION_BYTES
        {
            return Err(JournalError::Invariant(
                "publication completion resource limit",
            ));
        }
        Ok(tree_storage_capacity::TreeStorageCharge {
            rows: 2 + self.operations.len() as u64 + chunks.len() as u64,
            logical_bytes: manifest.len() as u64
                + 124
                + operation
                + 104
                + chunks.len() as u64 * 128,
        })
    }
}

impl PublicationIntent {
    pub fn validate(&self) -> Result<()> {
        self.content.validate()?;
        if self.format_version != FORMAT_VERSION
            || self.attempt > 16
            || self.requested_path.parent() != self.target_path.parent()
            || self.root_identity.is_some() != self.parent_identity.is_some()
            || self.native_only && (self.completion.is_none() || self.attempt != 0)
            || self.remote.is_some() && !self.native_only
        {
            return Err(JournalError::Invariant("invalid publication intent"));
        }
        if let Some(completion) = &self.completion {
            completion.validate(self)?;
            completion.charge()?;
        }
        if let Some(entry) = &self.requested_baseline {
            entry.validate()?;
            if entry.path != self.requested_path {
                return Err(JournalError::Invariant(
                    "publication baseline path mismatch",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Publication {
    pub intent: PublicationIntent,
    pub state: PublicationState,
    pub committed_snapshot: Option<SnapshotId>,
    pub cleaned: bool,
}
