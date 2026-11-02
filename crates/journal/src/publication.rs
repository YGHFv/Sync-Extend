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
}

impl PublicationIntent {
    pub fn validate(&self) -> Result<()> {
        self.content.validate()?;
        if self.format_version != FORMAT_VERSION
            || self.attempt > 16
            || self.requested_path.parent() != self.target_path.parent()
        {
            return Err(JournalError::Invariant("invalid publication intent"));
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
