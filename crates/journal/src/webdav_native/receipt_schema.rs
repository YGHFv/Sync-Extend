use crate::storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec};
const fn c(name: &'static str, kind: ColumnKind, pk: usize) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key: pk,
        not_null: true,
        default: None,
    }
}
pub(crate) const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "webdav_native_execution_templates",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("template_index", ColumnKind::Integer, 2),
            c("template_hash", ColumnKind::Text(64), 0),
            c("max_new_rows", ColumnKind::Integer, 0),
            c("max_new_bytes", ColumnKind::Integer, 0),
            c("issued_at_ms", ColumnKind::Integer, 0),
            c("template", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "webdav_native_execution_bindings",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("binding_index", ColumnKind::Integer, 2),
            c("binding_hash", ColumnKind::Text(64), 0),
            c("issued_at_ms", ColumnKind::Integer, 0),
            c("binding", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "webdav_native_execution_receipts",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("receipt_index", ColumnKind::Integer, 2),
            c("template_index", ColumnKind::Integer, 0),
            c("receipt_hash", ColumnKind::Text(64), 0),
            c("issued_at_ms", ColumnKind::Integer, 0),
            c("receipt", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "webdav_native_execution_manifests",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("manifest_hash", ColumnKind::Text(64), 0),
            c("template_count", ColumnKind::Integer, 0),
            c("binding_count", ColumnKind::Integer, 0),
            c("max_receipts", ColumnKind::Integer, 0),
            c("future_rows", ColumnKind::Integer, 0),
            c("future_bytes", ColumnKind::Integer, 0),
            c("admitted_at_ms", ColumnKind::Integer, 0),
            c("manifest", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
];
