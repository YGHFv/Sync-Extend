use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VersionVector(pub BTreeMap<DeviceId, u64>);

impl VersionVector {
    pub fn get(&self, device: &DeviceId) -> u64 {
        self.0.get(device).copied().unwrap_or(0)
    }

    pub fn dominates(&self, other: &Self) -> bool {
        other.0.iter().all(|(device, seq)| self.get(device) >= *seq)
    }

    pub fn observe(&mut self, device: DeviceId, seq: u64) {
        if seq > 0 {
            self.0
                .entry(device)
                .and_modify(|value| *value = (*value).max(seq))
                .or_insert(seq);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRef {
    pub content_id: ContentId,
    pub length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileManifest {
    pub format_version: u32,
    pub chunking: String,
    pub hash_algorithm: String,
    pub compression: String,
    pub content_id: ContentId,
    pub length: u64,
    pub chunks: Vec<ChunkRef>,
}

impl FileManifest {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || self.chunking != "fastcdc-2020-v1"
            || self.hash_algorithm != "blake3"
            || self.compression != "none"
            || self.chunks.len() > limits::MAX_CHUNKS
        {
            return Err(ModelError::InvalidData("unsupported content format"));
        }
        let mut total = 0u64;
        for chunk in &self.chunks {
            if chunk.length == 0 || chunk.length > 4 * 1024 * 1024 {
                return Err(ModelError::InvalidData("invalid chunk length"));
            }
            total = total
                .checked_add(u64::from(chunk.length))
                .ok_or(ModelError::InvalidData("content length overflow"))?;
        }
        if total != self.length || (self.length == 0 && self.content_id != ContentId::hash(&[])) {
            return Err(ModelError::InvalidData(
                "content length or empty hash mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub entry_id: EntryId,
    pub path: PortablePath,
    pub kind: EntryKind,
    pub content: Option<FileManifest>,
}

impl Entry {
    pub fn validate(&self) -> Result<()> {
        match (self.kind, &self.content) {
            (EntryKind::File, Some(content)) => content.validate(),
            (EntryKind::Directory, None) => Ok(()),
            _ => Err(ModelError::InvalidData("entry kind/content mismatch")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Put {
        entry: Entry,
    },
    Rename {
        entry_id: EntryId,
        path: PortablePath,
    },
    Delete {
        entry_id: EntryId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPayload {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub origin_device_id: DeviceId,
    pub origin_seq: u64,
    pub causal: VersionVector,
    pub change: Change,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub op_id: OperationId,
    pub payload_hash: ContentId,
    pub payload: OperationPayload,
}

impl Operation {
    pub fn new(payload: OperationPayload) -> Result<Self> {
        let bytes = serde_json::to_vec(&payload)?;
        let result = Self {
            op_id: OperationId::hash(&bytes),
            payload_hash: ContentId::hash(&bytes),
            payload,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        let p = &self.payload;
        if p.format_version != FORMAT_VERSION
            || p.origin_seq == 0
            || p.causal.0.len() > 1024
            || p.causal.0.values().any(|seq| *seq == 0)
            || p.causal.get(&p.origin_device_id) != p.origin_seq - 1
        {
            return Err(ModelError::InvalidData("operation causal/format invariant"));
        }
        if let Change::Put { entry } = &p.change {
            entry.validate()?;
        }
        let bytes = serde_json::to_vec(p)?;
        if ContentId::hash(&bytes) != self.payload_hash || OperationId::hash(&bytes) != self.op_id {
            return Err(ModelError::InvalidData("operation hash mismatch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub policy_version: u64,
    pub version_vector: VersionVector,
    pub entries: BTreeMap<EntryId, Entry>,
    pub tombstones: BTreeMap<EntryId, OperationId>,
}

impl Manifest {
    pub fn empty(space_id: SpaceId) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            space_id,
            policy_version: 1,
            version_vector: VersionVector::default(),
            entries: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || self.policy_version == 0
            || self.version_vector.0.len() > 1024
            || self.version_vector.0.values().any(|seq| *seq == 0)
            || self.entries.len() > limits::MAX_ENTRIES
            || self.tombstones.len() > limits::MAX_ENTRIES
        {
            return Err(ModelError::InvalidData("unsupported manifest format"));
        }
        let mut paths = BTreeSet::new();
        let mut directories = BTreeSet::new();
        for (id, entry) in &self.entries {
            entry.validate()?;
            if id != &entry.entry_id
                || self.tombstones.contains_key(id)
                || !paths.insert(entry.path.collision_key())
            {
                return Err(ModelError::InvalidData(
                    "duplicate entry/path or live tombstone",
                ));
            }
            if entry.kind == EntryKind::Directory {
                directories.insert(entry.path.clone());
            }
        }
        for entry in self.entries.values() {
            if let Some(parent) = entry.path.parent() {
                if !directories.contains(&parent) {
                    return Err(ModelError::InvalidData("missing directory parent"));
                }
            }
        }
        Ok(())
    }

    pub fn root(&self) -> Result<SnapshotId> {
        self.validate()?;
        Ok(SnapshotId::hash(&serde_json::to_vec(self)?))
    }
}
