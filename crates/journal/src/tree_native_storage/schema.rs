// Exact schema32 native prewrite values, not future obligations.
use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    MAX_OPERATION_BYTES,
};

const fn column(name: &'static str, kind: ColumnKind, primary_key: usize) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key,
        not_null: true,
        default: None,
    }
}
pub(crate) const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "tree_native_capacity_admissions",
        columns: &[
            column("space_id", ColumnKind::Text(32), 0),
            column("transaction_id", ColumnKind::Text(32), 1),
            column("coordinator_execution_id", ColumnKind::Text(32), 0),
            column("admission_id", ColumnKind::Text(32), 0),
            column("admission_hash", ColumnKind::Text(64), 0),
            column("protocol_hash", ColumnKind::Text(64), 0),
            column("layout_hash", ColumnKind::Text(64), 0),
            column("inventory_hash", ColumnKind::Text(64), 0),
            column("request_hash", ColumnKind::Text(64), 0),
            column("capacity_hash", ColumnKind::Text(64), 0),
            column("created_at_ms", ColumnKind::Integer, 0),
            column("max_entries", ColumnKind::Integer, 0),
            column("prior_rows", ColumnKind::Integer, 0),
            column("prior_bytes", ColumnKind::Integer, 0),
            column("prior_budget_rows", ColumnKind::Integer, 0),
            column("prior_budget_bytes", ColumnKind::Integer, 0),
            column("stored_rows", ColumnKind::Integer, 0),
            column("stored_bytes", ColumnKind::Integer, 0),
            column("request", ColumnKind::Text(MAX_OPERATION_BYTES), 0),
            column("capacity", ColumnKind::Text(MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "tree_native_action_headers",
        columns: &[
            column("space_id", ColumnKind::Text(32), 0),
            column("transaction_id", ColumnKind::Text(32), 1),
            column("coordinator_execution_id", ColumnKind::Text(32), 0),
            column("admission_id", ColumnKind::Text(32), 0),
            column("admission_hash", ColumnKind::Text(64), 0),
            column("protocol_hash", ColumnKind::Text(64), 0),
            column("layout_hash", ColumnKind::Text(64), 0),
            column("capacity_hash", ColumnKind::Text(64), 0),
            column("request_hash", ColumnKind::Text(64), 0),
            column("created_at_ms", ColumnKind::Integer, 0),
            column("request", ColumnKind::Text(MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "tree_native_action_records",
        columns: &[
            column("space_id", ColumnKind::Text(32), 0),
            column("transaction_id", ColumnKind::Text(32), 1),
            column("coordinator_execution_id", ColumnKind::Text(32), 0),
            column("admission_id", ColumnKind::Text(32), 0),
            column("admission_hash", ColumnKind::Text(64), 0),
            column("protocol_hash", ColumnKind::Text(64), 0),
            column("layout_hash", ColumnKind::Text(64), 0),
            column("record_index", ColumnKind::Integer, 2),
            column("action_ordinal", ColumnKind::Integer, 0),
            column("previous_hash", ColumnKind::Text(64), 0),
            column("record_hash", ColumnKind::Text(64), 0),
            column("recorded_at_ms", ColumnKind::Integer, 0),
            column("record", ColumnKind::Text(MAX_OPERATION_BYTES), 0),
        ],
    },
];
