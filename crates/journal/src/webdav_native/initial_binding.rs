//! Original binding descriptions only; decoding never reconstructs a native guard.
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, Entry, tree_restore_identity::TreeNativeIdentity};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum InitialBindingRole {
    WorktreeRoot,
    DataRoot,
    DataAncestor,
    WorktreeAncestor,
    MarkerDirectory,
    MarkerFile {
        space_id: sync_extend_core_model::SpaceId,
    },
    BaselineDirectory {
        entry: Entry,
        mutation_handle: bool,
    },
    BaselineFile {
        entry: Entry,
    },
    CasAncestor,
    CasChunk {
        content_id: ContentId,
        length: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitialHeldBinding {
    pub index: usize,
    pub plan_hash: ContentId,
    pub baseline_hash: sync_extend_core_model::SnapshotId,
    pub role: InitialBindingRole,
    pub absolute_path: String,
    pub identity: TreeNativeIdentity,
    pub parent_identity: Option<TreeNativeIdentity>,
}
