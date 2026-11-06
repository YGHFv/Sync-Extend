//! Bounded authenticated file-copy offers, not a causal conflict reducer.
use crate::*;
use serde::{Deserialize, Serialize};

pub const MAX_REMOTE_FILE_OFFER_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteFileOffer {
    pub format_version: u32,
    pub source_device: DeviceId,
    pub source_snapshot: SnapshotId,
    pub manifest: Manifest,
    pub entry_id: EntryId,
    pub created_at_ms: u64,
}

impl RemoteFileOffer {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || self.manifest.root()? != self.source_snapshot
            || self.created_at_ms > i64::MAX as u64
            || self.entry()?.kind != EntryKind::File
        {
            return Err(ModelError::InvalidData("invalid remote file offer"));
        }
        if serde_json::to_vec(self)?.len() > MAX_REMOTE_FILE_OFFER_BYTES {
            return Err(ModelError::InvalidData("remote file offer metadata limit"));
        }
        Ok(())
    }

    pub fn entry(&self) -> Result<&Entry> {
        self.manifest
            .entries
            .get(&self.entry_id)
            .ok_or(ModelError::InvalidData(
                "offered entry is absent from snapshot",
            ))
    }

    pub fn content(&self) -> Result<&FileManifest> {
        self.entry()?
            .content
            .as_ref()
            .ok_or(ModelError::InvalidData(
                "remote offer is not a regular file",
            ))
    }

    pub fn transfer_id(&self) -> Result<EntryId> {
        self.bound_id("SyncExtend remote file transfer v1")
    }

    pub fn publication_id(&self) -> Result<EntryId> {
        self.bound_id("SyncExtend remote file publication v1")
    }

    pub fn local_entry_id(&self) -> Result<EntryId> {
        self.bound_id("SyncExtend remote file local copy v1")
    }

    fn bound_id(&self, domain: &str) -> Result<EntryId> {
        self.validate()?;
        let hash = blake3::derive_key(domain, &serde_json::to_vec(self)?);
        hash[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            .parse()
    }
}
