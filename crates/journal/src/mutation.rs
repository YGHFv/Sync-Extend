use crate::{JournalError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationAction {
    Replace {
        content: FileManifest,
    },
    Delete,
    Move {
        destination: PortablePath,
        parent_identity: ContentId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationIntent {
    pub format_version: u32,
    pub transaction_id: EntryId,
    pub space_id: SpaceId,
    pub baseline_root: SnapshotId,
    pub baseline_entry: Entry,
    pub file_identity: ContentId,
    pub root_identity: ContentId,
    pub parent_identity: ContentId,
    pub action: MutationAction,
    pub created_at_ms: u64,
}

impl MutationIntent {
    pub fn validate(&self) -> Result<()> {
        self.baseline_entry.validate()?;
        if self.format_version != FORMAT_VERSION || self.baseline_entry.kind != EntryKind::File {
            return Err(JournalError::Invariant(
                "mutation requires a regular-file baseline",
            ));
        }
        match &self.action {
            MutationAction::Replace { content } => content.validate()?,
            MutationAction::Delete => {}
            MutationAction::Move { destination, .. } => {
                let source = self.baseline_entry.path.collision_key();
                let destination = destination.collision_key();
                if destination == source || destination.starts_with(&format!("{source}/")) {
                    return Err(JournalError::Invariant("invalid mutation move destination"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationState {
    Prepared,
    Cancelled,
}

#[derive(Clone, Debug, Serialize)]
pub struct Mutation {
    pub intent: MutationIntent,
    pub state: MutationState,
}
