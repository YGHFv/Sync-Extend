//! Concrete owner cleanup columns, not stored observations or native authority.
use crate::{
    tree_owner_cleanup_layout::{TreeOwnerCleanupLayoutPlan, TreeOwnerCleanupRecordLayout},
    tree_storage_footprint::{
        hash, integer, json, row, scope_columns, text, TreeStorageRowValues, TreeStorageTable,
    },
    Result,
};

pub fn tree_owner_cleanup_intent_row_values(
    plan: &TreeOwnerCleanupLayoutPlan,
) -> Result<TreeStorageRowValues> {
    let i = plan.intent();
    let mut columns = scope_columns(&i.scope);
    columns.extend([
        text("finalization_id", &i.finalization_id),
        text("cleanup_id", &i.cleanup_id),
        text("owner_intent_hash", &i.owner_intent_hash),
        text("committed_hash", &i.committed_record_hash),
        text("input_release_hash", &i.input_release_hash),
        text("original_terminals_hash", &i.original_terminals_hash),
        text("intent_hash", plan.intent_hash()),
        integer("original_count", i.original_terminals.len() as u64),
        integer("intended_at_ms", i.intended_at_ms),
        text("intent", json(i)?),
    ]);
    row(
        TreeStorageTable::OwnerCleanupIntent,
        vec![i.scope.transaction_id.to_string()],
        columns,
    )
}

pub fn tree_owner_cleanup_record_row_values(
    record: &TreeOwnerCleanupRecordLayout,
) -> Result<TreeStorageRowValues> {
    let mut columns = scope_columns(&record.scope);
    columns.extend([
        text("finalization_id", &record.finalization_id),
        text("cleanup_id", &record.cleanup_id),
        text("intent_hash", &record.intent_hash),
        integer("record_index", record.record_index as u64),
        text("previous_hash", &record.previous_hash),
        text("record_hash", hash(record)?),
        integer("recorded_at_ms", record.recorded_at_ms),
        text("record", json(record)?),
    ]);
    row(
        TreeStorageTable::OwnerCleanupRecord,
        vec![
            record.scope.transaction_id.to_string(),
            record.record_index.to_string(),
        ],
        columns,
    )
}

pub fn tree_owner_cleanup_row_values(
    plan: &TreeOwnerCleanupLayoutPlan,
) -> Result<Vec<TreeStorageRowValues>> {
    let mut rows = vec![tree_owner_cleanup_intent_row_values(plan)?];
    for record in plan.records() {
        rows.push(tree_owner_cleanup_record_row_values(record)?);
    }
    Ok(rows)
}
