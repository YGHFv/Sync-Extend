// Future ledger schema pinned independently from physical SQLite columns.
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
        name: "conflict_resolution_native_activations",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("step", ColumnKind::Integer, 2),
            c("header_hash", ColumnKind::Text(64), 0),
            c("component", ColumnKind::Utf8 { min: 1, max: 256 }, 0),
            c("kind", ColumnKind::Utf8 { min: 1, max: 16 }, 0),
            c("parent_volume", ColumnKind::Text(16), 0),
            c("parent_id", ColumnKind::Text(32), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_branch_handoffs",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("owner_id", ColumnKind::Text(32), 2),
            c("intent_hash", ColumnKind::Text(64), 0),
            c("history_hash", ColumnKind::Text(64), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_creators",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("step", ColumnKind::Integer, 2),
            c("header_hash", ColumnKind::Text(64), 0),
            c("component", ColumnKind::Utf8 { min: 1, max: 256 }, 0),
            c("kind", ColumnKind::Utf8 { min: 1, max: 16 }, 0),
            c("parent_volume", ColumnKind::Text(16), 0),
            c("parent_id", ColumnKind::Text(32), 0),
            c("volume", ColumnKind::Text(16), 0),
            c("full_id", ColumnKind::Text(32), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_dispositions",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("header_hash", ColumnKind::Text(64), 0),
            c("component", ColumnKind::Utf8 { min: 1, max: 256 }, 2),
            c("stage", ColumnKind::Utf8 { min: 1, max: 32 }, 3),
            c("volume", ColumnKind::Text(16), 0),
            c("full_id", ColumnKind::Text(32), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_events",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("event_index", ColumnKind::Integer, 2),
            c("record_hash", ColumnKind::Text(64), 0),
            c("record", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_headers",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("parent_hash", ColumnKind::Text(64), 0),
            c("binding_hash", ColumnKind::Text(64), 0),
            c("generation", ColumnKind::Text(32), 0),
            c("header_hash", ColumnKind::Text(64), 0),
            c("layout_hash", ColumnKind::Text(64), 0),
            c("reserved_rows", ColumnKind::Integer, 0),
            c("reserved_bytes", ColumnKind::Integer, 0),
            c("native_peak", ColumnKind::Integer, 0),
            c("header", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_history",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("parent_hash", ColumnKind::Text(64), 0),
            c("target_root", ColumnKind::Text(64), 0),
            c("record_hash", ColumnKind::Text(64), 0),
            c("record", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_history_objects",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("role", ColumnKind::Utf8 { min: 1, max: 16 }, 2),
            c("content_id", ColumnKind::Text(64), 3),
            c("length", ColumnKind::Integer, 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_phases",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("header_hash", ColumnKind::Text(64), 0),
            c("phase", ColumnKind::Utf8 { min: 1, max: 32 }, 2),
            c("snapshot_id", ColumnKind::Text(64), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_steps",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("header_hash", ColumnKind::Text(64), 0),
            c("entry_id", ColumnKind::Text(32), 2),
            c("action", ColumnKind::Utf8 { min: 1, max: 32 }, 3),
            c("phase", ColumnKind::Utf8 { min: 1, max: 32 }, 4),
            c("volume", ColumnKind::Text(16), 0),
            c("full_id", ColumnKind::Text(32), 0),
        ],
    },
    TableSpec {
        name: "conflict_resolution_native_templates",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("name", ColumnKind::Utf8 { min: 1, max: 256 }, 2),
            c("template_hash", ColumnKind::Text(64), 0),
            c("reserved_rows", ColumnKind::Integer, 0),
            c("reserved_bytes", ColumnKind::Integer, 0),
            c("template", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
];
