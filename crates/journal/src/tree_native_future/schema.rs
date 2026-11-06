use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    MAX_OPERATION_BYTES,
};
mod effects;
pub(crate) use effects::EFFECT_TABLES;
const fn c(name: &'static str, kind: ColumnKind, primary_key: usize) -> ColumnSpec {
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
        name: "tree_native_future_admissions",
        columns: &[
            c("space_id", ColumnKind::Text(32), 0),
            c("transaction_id", ColumnKind::Text(32), 1),
            c("coordinator_execution_id", ColumnKind::Text(32), 0),
            c("admission_id", ColumnKind::Text(32), 0),
            c("admission_hash", ColumnKind::Text(64), 0),
            c("protocol_hash", ColumnKind::Text(64), 0),
            c("layout_hash", ColumnKind::Text(64), 0),
            c("prewrite_capacity_hash", ColumnKind::Text(64), 0),
            c("initial_intended_hash", ColumnKind::Text(64), 0),
            c("inventory_hash", ColumnKind::Text(64), 0),
            c("request_hash", ColumnKind::Text(64), 0),
            c("capacity_hash", ColumnKind::Text(64), 0),
            c("created_at_ms", ColumnKind::Integer, 0),
            c("max_entries", ColumnKind::Integer, 0),
            c("action_count", ColumnKind::Integer, 0),
            c("original_count", ColumnKind::Integer, 0),
            c("prior_rows", ColumnKind::Integer, 0),
            c("prior_bytes", ColumnKind::Integer, 0),
            c("prior_budget_rows", ColumnKind::Integer, 0),
            c("prior_budget_bytes", ColumnKind::Integer, 0),
            c("stored_rows", ColumnKind::Integer, 0),
            c("stored_bytes", ColumnKind::Integer, 0),
            c("future_rows", ColumnKind::Integer, 0),
            c("future_bytes", ColumnKind::Integer, 0),
            c("new_rows", ColumnKind::Integer, 0),
            c("new_bytes", ColumnKind::Integer, 0),
            c("request", ColumnKind::Text(MAX_OPERATION_BYTES), 0),
            c("capacity", ColumnKind::Text(MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "tree_native_future_generations",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation_id", ColumnKind::Text(32), 0),
            c("purpose", ColumnKind::Utf8 { min: 12, max: 17 }, 2),
            c("ordinal", ColumnKind::Integer, 3),
            c("capacity_hash", ColumnKind::Text(64), 0),
        ],
    },
];
