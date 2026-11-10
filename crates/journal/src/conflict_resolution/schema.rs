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
        name: "conflict_resolution_equivalent_histories",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("base_transaction_id", ColumnKind::Text(32), 0),
            c("receiver_device", ColumnKind::Text(64), 0),
            c("resolver_device", ColumnKind::Text(64), 0),
            c("target_root", ColumnKind::Text(64), 0),
            c("record_hash", ColumnKind::Text(64), 0),
            c("record", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_equivalent_signatures",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("op_id", ColumnKind::Text(64), 2),
            c("proof", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_bindings",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("parent_hash", ColumnKind::Text(64), 0),
            c("binding_hash", ColumnKind::Text(64), 0),
            c("binding", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_admissions",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("space_id", ColumnKind::Text(32), 0),
            c("resolver_device", ColumnKind::Text(64), 0),
            c("plan_fingerprint", ColumnKind::Text(64), 0),
            c("baseline_root", ColumnKind::Text(64), 0),
            c("root_identity", ColumnKind::Text(64), 0),
            c("header_hash", ColumnKind::Text(64), 0),
            c("header", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_signatures",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("role", ColumnKind::Utf8 { min: 1, max: 16 }, 2),
            c("op_id", ColumnKind::Text(64), 3),
            c("proof", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_sequences",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("device_id", ColumnKind::Text(64), 0),
            c("first_sequence", ColumnKind::Integer, 0),
            c("last_sequence", ColumnKind::Integer, 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_objects",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("role", ColumnKind::Utf8 { min: 1, max: 16 }, 2),
            c("content_id", ColumnKind::Text(64), 3),
            c("length", ColumnKind::Integer, 0),
        ],
    },
];
