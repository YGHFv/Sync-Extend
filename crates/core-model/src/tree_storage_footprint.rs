//! Selected physical row VALUES, not SQLite allocation or durable provenance.
use crate::{
    tree_final_terminal_layout::TreeFinalTerminalLayoutPlan,
    tree_native_action_layout::{TreeNativeActionLayoutRecord, TreeNativeActionScope},
    tree_original_terminal_layout::{
        plan_tree_original_release_layout, TreeOriginalTerminalLayoutLimits,
        TreeOriginalTerminalLayoutPlan,
    },
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    ContentId, EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreeStorageTable {
    ActionHeader,
    ActionRecord,
    FinalIntent,
    FinalCommitted,
    FinalInputRelease,
    FinalRetainedOwner,
    OriginalIntent,
    OriginalAbsence,
    OriginalTerminal,
    Operation,
    Snapshot,
    SnapshotObject,
    CurrentSnapshot,
    Cursor,
    OriginalReference,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeStorageRowKey {
    pub table: TreeStorageTable,
    pub key: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TreeStorageColumnValue {
    Text(String),
    Integer(u64),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeStorageColumn {
    pub name: String,
    pub value: TreeStorageColumnValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeStorageRowValues {
    key: TreeStorageRowKey,
    columns: Vec<TreeStorageColumn>,
    logical_bytes: u64,
    fingerprint: ContentId,
}
impl TreeStorageRowValues {
    pub fn key(&self) -> &TreeStorageRowKey {
        &self.key
    }
    pub fn columns(&self) -> &[TreeStorageColumn] {
        &self.columns
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn is_new_history(&self) -> bool {
        matches!(
            self.key.table,
            TreeStorageTable::Operation
                | TreeStorageTable::Snapshot
                | TreeStorageTable::SnapshotObject
                | TreeStorageTable::CurrentSnapshot
                | TreeStorageTable::Cursor
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeStorageHeaderRequest {
    pub scope: TreeNativeActionScope,
    pub layout_hash: ContentId,
    pub capacity_hash: ContentId,
    pub created_at_ms: u64,
}

fn text(name: &str, value: impl ToString) -> TreeStorageColumn {
    TreeStorageColumn {
        name: name.into(),
        value: TreeStorageColumnValue::Text(value.to_string()),
    }
}
fn integer(name: &str, value: u64) -> TreeStorageColumn {
    TreeStorageColumn {
        name: name.into(),
        value: TreeStorageColumnValue::Integer(value),
    }
}
fn json<T: Serialize>(value: &T) -> Result<String> {
    String::from_utf8(encode_history_record(value, MAX_TREE_HISTORY_BYTES)?)
        .map_err(|_| ModelError::InvalidData("tree storage encoding"))
}
fn hash<T: Serialize>(value: &T) -> Result<ContentId> {
    Ok(ContentId::hash(json(value)?.as_bytes()))
}
fn scope_columns(s: &TreeNativeActionScope) -> Vec<TreeStorageColumn> {
    vec![
        text("space_id", &s.space_id),
        text("transaction_id", &s.transaction_id),
        text("coordinator_execution_id", &s.coordinator_execution_id),
        text("admission_id", &s.admission_id),
        text("admission_hash", &s.admission_hash),
        text("protocol_hash", &s.protocol_hash),
    ]
}
fn final_scope(s: &TreeNativeActionScope, id: &EntryId) -> Vec<TreeStorageColumn> {
    vec![
        text("transaction_id", &s.transaction_id),
        text("coordinator_execution_id", &s.coordinator_execution_id),
        text("admission_id", &s.admission_id),
        text("finalization_id", id),
    ]
}
fn row(
    table: TreeStorageTable,
    key: Vec<String>,
    columns: Vec<TreeStorageColumn>,
) -> Result<TreeStorageRowValues> {
    let mut names = BTreeSet::new();
    let logical_bytes = columns.iter().try_fold(0u64, |sum, column| {
        if !names.insert(&column.name) {
            return Err(ModelError::InvalidData("tree storage duplicate column"));
        }
        let bytes = match &column.value {
            TreeStorageColumnValue::Text(s) => s.len() as u64,
            TreeStorageColumnValue::Integer(n) if *n <= i64::MAX as u64 => 8,
            _ => return Err(ModelError::InvalidData("tree storage SQL integer")),
        };
        sum.checked_add(bytes)
            .ok_or(ModelError::InvalidData("tree storage byte overflow"))
    })?;
    let key = TreeStorageRowKey { table, key };
    let fingerprint = hash(&(
        "sync-extend.selected-physical-row-values.v1",
        &key,
        &columns,
    ))?;
    Ok(TreeStorageRowValues {
        key,
        columns,
        logical_bytes,
        fingerprint,
    })
}

/// Projects a distinct namespace. This does not persist a header or admit effects.
pub fn tree_native_header_row_values(
    request: &TreeNativeStorageHeaderRequest,
) -> Result<TreeStorageRowValues> {
    let mut c = scope_columns(&request.scope);
    c.extend([
        text("layout_hash", &request.layout_hash),
        text("capacity_hash", &request.capacity_hash),
        text("request_hash", hash(request)?),
        integer("created_at_ms", request.created_at_ms),
        text("request", json(request)?),
    ]);
    row(
        TreeStorageTable::ActionHeader,
        vec![request.scope.transaction_id.to_string()],
        c,
    )
}

/// Canonical JSON and every duplicated indexed value are charged independently.
pub fn tree_native_action_row_values(
    layout_hash: &ContentId,
    record: &TreeNativeActionLayoutRecord,
) -> Result<TreeStorageRowValues> {
    let mut c = scope_columns(&record.scope);
    c.extend([
        text("layout_hash", layout_hash),
        integer("record_index", record.record_index as u64),
        integer("action_ordinal", record.action_ordinal as u64),
        text("previous_hash", &record.previous_hash),
        text("record_hash", hash(record)?),
        integer("recorded_at_ms", record.recorded_at_ms),
        text("record", json(record)?),
    ]);
    row(
        TreeStorageTable::ActionRecord,
        vec![
            record.scope.transaction_id.to_string(),
            record.record_index.to_string(),
        ],
        c,
    )
}

pub fn tree_final_terminal_row_values(
    plan: &TreeFinalTerminalLayoutPlan,
) -> Result<Vec<TreeStorageRowValues>> {
    let r = plan.rows();
    let i = &r.intent;
    let key = vec![i.scope.transaction_id.to_string()];
    let mut result = Vec::new();
    let mut c = final_scope(&i.scope, &i.finalization_id);
    c.extend([
        text("intent_hash", hash(i)?),
        text("action_root", &i.action_last_record_hash),
        text("fresh_native_hash", &i.fresh_observation_hash),
        text("rows_hash", &i.exact_history_rows_hash),
        text("snapshot_id", &i.final_snapshot_id),
        text("input_closure_hash", &i.input_closure_hash),
        text("original_handoffs_hash", &i.original_handoffs_hash),
        integer("intended_at_ms", i.intended_at_ms),
        text("intent", json(i)?),
    ]);
    result.push(row(TreeStorageTable::FinalIntent, key.clone(), c)?);
    let committed = &r.committed;
    let mut c = final_scope(&committed.scope, &committed.finalization_id);
    c.extend([
        text("intent_hash", &committed.terminal_intent_hash),
        text("committed_hash", hash(committed)?),
        text("snapshot_id", &committed.final_snapshot_id),
        text("rows_hash", &committed.exact_history_rows_hash),
        integer("committed_at_ms", committed.committed_at_ms),
        text("record", json(committed)?),
    ]);
    result.push(row(TreeStorageTable::FinalCommitted, key.clone(), c)?);
    let release = &r.input_release;
    result.push(row(
        TreeStorageTable::FinalInputRelease,
        key,
        vec![
            text("transaction_id", &release.scope.transaction_id),
            text("finalization_id", &release.finalization_id),
            text("committed_hash", &release.committed_record_hash),
            text("input_closure_hash", &release.input_closure_hash),
            integer("reference_count", release.released_reference_count as u64),
            integer("released_at_ms", release.released_at_ms),
            text("record", json(release)?),
        ],
    )?);
    for (&index, retained) in &r.retained_owners {
        result.push(row(
            TreeStorageTable::FinalRetainedOwner,
            vec![retained.scope.transaction_id.to_string(), index.to_string()],
            vec![
                text("transaction_id", &retained.scope.transaction_id),
                text("finalization_id", &retained.finalization_id),
                integer("step_index", index as u64),
                text("step_execution_id", &retained.step_execution_id),
                text("committed_hash", &retained.committed_record_hash),
                text("handoff_hash", &retained.handoff_hash),
                text("retained_hash", hash(retained)?),
                text("record", json(retained)?),
            ],
        )?);
    }
    Ok(result)
}

/// Deletion predicates are intentionally NOT persisted row values.
pub fn tree_final_history_row_values(
    plan: &TreeFinalTerminalLayoutPlan,
) -> Result<Vec<TreeStorageRowValues>> {
    let r = plan.transaction().rows();
    let mut result = Vec::new();
    for op in &r.operations {
        result.push(row(
            TreeStorageTable::Operation,
            vec![op.op_id.to_string()],
            vec![
                text("op_id", &op.op_id),
                text("space_id", &op.space_id),
                text("origin_device_id", &op.origin_device_id),
                integer("origin_seq", op.origin_seq),
                text("payload", &op.payload),
                text("state", &op.state),
            ],
        )?);
    }
    let s = &r.snapshot;
    result.push(row(
        TreeStorageTable::Snapshot,
        vec![s.snapshot_id.to_string()],
        vec![
            text("snapshot_id", &s.snapshot_id),
            text("space_id", &s.space_id),
            text("manifest", &s.manifest),
            integer("created_at_ms", s.created_at_ms),
            text("state", &s.state),
            integer("locked", s.locked),
        ],
    )?);
    for object in &r.snapshot_objects {
        result.push(row(
            TreeStorageTable::SnapshotObject,
            vec![
                object.snapshot_id.to_string(),
                object.content_id.to_string(),
            ],
            vec![
                text("snapshot_id", &object.snapshot_id),
                text("content_id", &object.content_id),
            ],
        )?);
    }
    result.push(row(
        TreeStorageTable::CurrentSnapshot,
        vec![r.current.space_id.to_string()],
        vec![
            text("space_id", &r.current.space_id),
            text("snapshot_id", &r.current.snapshot_id),
        ],
    )?);
    result.push(row(
        TreeStorageTable::Cursor,
        vec![
            r.cursor.space_id.to_string(),
            r.cursor.device_id.to_string(),
        ],
        vec![
            text("space_id", &r.cursor.space_id),
            text("device_id", &r.cursor.device_id),
            integer("contiguous_seq", r.cursor.contiguous_seq),
        ],
    )?);
    let bytes = result.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.logical_bytes())
            .ok_or(ModelError::InvalidData("tree history byte overflow"))
    })?;
    let expected = plan.transaction().footprint();
    if bytes != expected.history_logical_bytes || result.len() as u64 != expected.history_value_rows
    {
        return Err(ModelError::InvalidData(
            "tree storage exact history recount",
        ));
    }
    for original in &r.retained_references {
        result.push(row(
            TreeStorageTable::OriginalReference,
            vec![
                original.transaction_id.to_string(),
                original.step_index.to_string(),
                original.content_id.to_string(),
            ],
            vec![
                text("transaction_id", &original.transaction_id),
                integer("step_index", original.step_index as u64),
                text("step_execution_id", &original.step_execution_id),
                text("content_id", &original.content_id),
                integer("length", original.length as u64),
            ],
        )?);
    }
    Ok(result)
}

pub fn tree_original_terminal_row_values(
    plan: &TreeOriginalTerminalLayoutPlan,
    observed_at_ms: u64,
    bounds: TreeOriginalTerminalLayoutLimits,
) -> Result<Vec<TreeStorageRowValues>> {
    let mut result = Vec::new();
    for (&index, i) in plan.intents() {
        let r = plan_tree_original_release_layout(plan, index, observed_at_ms, bounds)?;
        let key = vec![i.transaction_id.to_string(), index.to_string()];
        result.push(row(
            TreeStorageTable::OriginalIntent,
            key.clone(),
            vec![
                text("transaction_id", &i.transaction_id),
                integer("step_index", index as u64),
                text("step_execution_id", &i.step_execution_id),
                text("disposal_id", &i.disposal_id),
                text("finalization_id", &i.finalization_id),
                text("committed_hash", &i.committed_record_hash),
                text("retained_hash", &i.retained_owner_hash),
                text("intent_hash", hash(i)?),
                integer("intended_at_ms", i.intended_at_ms),
                text("intent", json(i)?),
            ],
        )?);
        result.push(row(
            TreeStorageTable::OriginalAbsence,
            key.clone(),
            vec![
                text("transaction_id", &i.transaction_id),
                integer("step_index", index as u64),
                text("disposal_id", &r.absence.disposal_id),
                text("intent_hash", &r.absence.intent_hash),
                text("absence_hash", hash(&r.absence)?),
                integer("observed_at_ms", r.absence.observed_at_ms),
                text("record", json(&r.absence)?),
            ],
        )?);
        result.push(row(
            TreeStorageTable::OriginalTerminal,
            key,
            vec![
                text("transaction_id", &i.transaction_id),
                integer("step_index", index as u64),
                text("disposal_id", &r.terminal.disposal_id),
                text("intent_hash", &r.terminal.intent_hash),
                text("absence_hash", &r.terminal.absence_hash),
                text("terminal_hash", hash(&r.terminal)?),
                text("own_closure_hash", &r.terminal.reference_closure_hash),
                integer(
                    "reference_count",
                    r.terminal.released_reference_count as u64,
                ),
                integer("released_at_ms", r.terminal.released_at_ms),
                text("record", json(&r.terminal)?),
            ],
        )?);
    }
    Ok(result)
}
