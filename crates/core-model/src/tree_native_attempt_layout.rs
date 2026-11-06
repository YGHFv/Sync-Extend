//! Private attempt sizing columns, never a committing or executable issuer.
use crate::{
    limits,
    tree_native_action_layout::{
        TreeNativeActionLayoutRecord, TreeNativeActionPayload, TreeNativeActionScope,
    },
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_storage_footprint::{
        hash, integer, json, row, scope_columns, text, TreeStorageRowValues, TreeStorageTable,
    },
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TreeNativeAttemptLayout {
    pub format_version: u32,
    pub scope: TreeNativeActionScope,
    pub layout_hash: ContentId,
    pub full_capacity_hash: ContentId,
    pub intended_record_hash: ContentId,
    pub attempt_id: EntryId,
    pub action_ordinal: usize,
    pub intended_record_index: usize,
    pub attempted_at_ms: u64,
}

pub(crate) fn tree_native_attempt_row_values(
    request: &TreeNativeAttemptLayout,
) -> Result<TreeStorageRowValues> {
    let mut columns = scope_columns(&request.scope);
    columns.extend([
        text("layout_hash", &request.layout_hash),
        text("full_capacity_hash", &request.full_capacity_hash),
        text("intended_record_hash", &request.intended_record_hash),
        text("attempt_id", &request.attempt_id),
        integer("action_ordinal", request.action_ordinal as u64),
        integer(
            "intended_record_index",
            request.intended_record_index as u64,
        ),
        integer("attempted_at_ms", request.attempted_at_ms),
        text("request_hash", hash(request)?),
        text("request", json(request)?),
    ]);
    row(
        TreeStorageTable::ActionAttempt,
        vec![
            request.scope.transaction_id.to_string(),
            request.action_ordinal.to_string(),
        ],
        columns,
    )
}

/// The supplied intention remains only a shape; this API does not persist,
/// allocate a generation, acquire a parent, or return an executable capability.
pub(crate) fn plan_tree_native_attempt_layout(
    intended: &TreeNativeActionLayoutRecord,
    layout_hash: &ContentId,
    full_capacity_hash: &ContentId,
    attempt_id: &EntryId,
    attempted_at_ms: u64,
    max_encoded_bytes: u64,
) -> Result<TreeNativeAttemptLayout> {
    if !matches!(intended.payload, TreeNativeActionPayload::Intended { .. })
        || intended.scope.format_version != 1
        || intended.record_index >= limits::MAX_ENTRIES
        || !intended.record_index.is_multiple_of(2)
        || intended.record_index / 2 != intended.action_ordinal
        || [
            &intended.scope.transaction_id,
            &intended.scope.coordinator_execution_id,
            &intended.scope.admission_id,
        ]
        .contains(&attempt_id)
        || attempted_at_ms < intended.recorded_at_ms
        || attempted_at_ms > i64::MAX as u64
        || max_encoded_bytes == 0
        || max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("native attempt layout bounds"));
    }
    let request = TreeNativeAttemptLayout {
        format_version: 1,
        scope: intended.scope.clone(),
        layout_hash: layout_hash.clone(),
        full_capacity_hash: full_capacity_hash.clone(),
        intended_record_hash: ContentId::hash(&encode_history_record(intended, max_encoded_bytes)?),
        attempt_id: attempt_id.clone(),
        action_ordinal: intended.action_ordinal,
        intended_record_index: intended.record_index,
        attempted_at_ms,
    };
    encode_history_record(&request, max_encoded_bytes)?;
    Ok(request)
}
