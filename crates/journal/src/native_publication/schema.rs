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
        name: "native_publication_headers",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("space_id", ColumnKind::Text(32), 0),
            c("generation", ColumnKind::Text(32), 0),
            c("header_hash", ColumnKind::Text(64), 0),
            c("reserved_rows", ColumnKind::Integer, 0),
            c("reserved_bytes", ColumnKind::Integer, 0),
            c("header", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
        ],
    },
    TableSpec {
        name: "native_publication_activations",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("step", ColumnKind::Integer, 2),
            c("header_hash", ColumnKind::Text(64), 0),
            c("component", ColumnKind::Utf8 { min: 1, max: 255 }, 0),
            c("kind", ColumnKind::Utf8 { min: 1, max: 255 }, 0),
            c("parent_volume", ColumnKind::Text(16), 0),
            c("parent_id", ColumnKind::Text(32), 0),
        ],
    },
    TableSpec {
        name: "native_publication_creators",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("step", ColumnKind::Integer, 2),
            c("header_hash", ColumnKind::Text(64), 0),
            c("component", ColumnKind::Utf8 { min: 1, max: 255 }, 0),
            c("kind", ColumnKind::Utf8 { min: 1, max: 255 }, 0),
            c("parent_volume", ColumnKind::Text(16), 0),
            c("parent_id", ColumnKind::Text(32), 0),
            c("volume", ColumnKind::Text(16), 0),
            c("full_id", ColumnKind::Text(32), 0),
        ],
    },
    TableSpec {
        name: "native_publication_phases",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("attempt", ColumnKind::Integer, 2),
            c("header_hash", ColumnKind::Text(64), 0),
            c("phase", ColumnKind::Utf8 { min: 1, max: 255 }, 3),
            c("identity_hash", ColumnKind::Text(64), 0),
            c("content_id", ColumnKind::Text(64), 0),
            c("target_hash", ColumnKind::Text(64), 0),
            c("observed_at_ms", ColumnKind::Integer, 0),
            c("source_parent_volume", ColumnKind::Text(16), 0),
            c("source_parent_id", ColumnKind::Text(32), 0),
            c("target_parent_volume", ColumnKind::Text(16), 0),
            c("target_parent_id", ColumnKind::Text(32), 0),
            c("target_path", ColumnKind::Utf8 { min: 1, max: 4096 }, 0),
        ],
    },
    TableSpec {
        name: "native_publication_dispositions",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("generation", ColumnKind::Text(32), 0),
            c("step", ColumnKind::Integer, 2),
            c("header_hash", ColumnKind::Text(64), 0),
            c("stage", ColumnKind::Utf8 { min: 1, max: 255 }, 3),
            c("identity_hash", ColumnKind::Text(64), 0),
            c("observed_at_ms", ColumnKind::Integer, 0),
        ],
    },
];
