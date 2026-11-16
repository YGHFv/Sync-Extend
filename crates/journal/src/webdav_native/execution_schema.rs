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
        name: "webdav_native_execution_admissions",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("description_hash", ColumnKind::Text(64), 0),
            c("request_hash", ColumnKind::Text(64), 0),
            c("plan_hash", ColumnKind::Text(64), 0),
            c("max_records", ColumnKind::Integer, 0),
            c("max_record_bytes", ColumnKind::Integer, 0),
            c("max_total_bytes", ColumnKind::Integer, 0),
            c("admitted_at_ms", ColumnKind::Integer, 0),
            c("admission_hash", ColumnKind::Text(64), 0),
        ],
    },
    TableSpec {
        name: "webdav_native_execution_records",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("record_index", ColumnKind::Integer, 2),
            c("record_hash", ColumnKind::Text(64), 0),
            c("recorded_at_ms", ColumnKind::Integer, 0),
            c("record", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
];
