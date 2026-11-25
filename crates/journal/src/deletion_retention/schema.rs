use crate::storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec};

pub(super) const MAX_RECORD_BYTES: usize = 4096;

const fn column(name: &'static str, kind: ColumnKind, key: usize) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key: key,
        not_null: true,
        default: None,
    }
}

pub(crate) const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "deletion_retention_clock",
        columns: &[
            column("space_id", ColumnKind::Text(32), 1),
            column("clock_revision", ColumnKind::Integer, 0),
            column("watermark_ms", ColumnKind::Integer, 0),
            column(
                "record",
                ColumnKind::Utf8 {
                    min: 1,
                    max: MAX_RECORD_BYTES,
                },
                0,
            ),
            column("record_hash", ColumnKind::Text(64), 0),
        ],
    },
    TableSpec {
        name: "deletion_retention_policies",
        columns: &[
            column("space_id", ColumnKind::Text(32), 1),
            column("revision", ColumnKind::Integer, 2),
            column("minimum_days", ColumnKind::Integer, 0),
            column("observed_at_ms", ColumnKind::Integer, 0),
            column(
                "record",
                ColumnKind::Utf8 {
                    min: 1,
                    max: MAX_RECORD_BYTES,
                },
                0,
            ),
            column("record_hash", ColumnKind::Text(64), 0),
        ],
    },
    TableSpec {
        name: "deletion_retention_observations",
        columns: &[
            column("space_id", ColumnKind::Text(32), 1),
            column("operation_id", ColumnKind::Text(64), 2),
            column("entry_id", ColumnKind::Text(32), 0),
            column("effective_snapshot", ColumnKind::Text(64), 0),
            column("observed_at_ms", ColumnKind::Integer, 0),
            column("clock_revision", ColumnKind::Integer, 0),
            column(
                "record",
                ColumnKind::Utf8 {
                    min: 1,
                    max: MAX_RECORD_BYTES,
                },
                0,
            ),
            column("record_hash", ColumnKind::Text(64), 0),
        ],
    },
];
