//! Exact schema-70 persistence inventory for inert native history.
use crate::storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec};

const fn column(
    name: &'static str,
    kind: ColumnKind,
    primary_key: usize,
    not_null: bool,
    default: Option<&'static str>,
) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key,
        not_null,
        default,
    }
}

const BOUNDED_JSON: ColumnKind = ColumnKind::Utf8 {
    min: 1,
    max: 268_435_456,
};
const BOUNDED_KEY: ColumnKind = ColumnKind::Utf8 {
    min: 1,
    max: 65_536,
};

pub(crate) const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "native_history_sources",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("format_version", ColumnKind::Integer, 0, true, None),
            column("source_schema", ColumnKind::Integer, 0, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column(
                "image",
                ColumnKind::Blob {
                    min: 512,
                    max: 268_435_456,
                },
                0,
                true,
                None,
            ),
            column("image_digest", ColumnKind::Text(64), 0, true, None),
            column("catalog_digest", ColumnKind::Text(64), 0, true, None),
            column("rows_digest", ColumnKind::Text(64), 0, true, None),
            column("registry_digest", ColumnKind::Text(64), 0, true, None),
            column("table_count", ColumnKind::Integer, 0, true, None),
            column("row_count", ColumnKind::Integer, 0, true, None),
            column("hold_count", ColumnKind::Integer, 0, true, None),
            column("projection_row_count", ColumnKind::Integer, 0, true, None),
            column("root_mapping_count", ColumnKind::Integer, 0, true, None),
            column("logical_bytes", ColumnKind::Integer, 0, true, None),
            column("bound_max_entries", ColumnKind::Integer, 0, true, None),
            column("bound_inventory_rows", ColumnKind::Integer, 0, true, None),
            column(
                "bound_inventory_logical_bytes",
                ColumnKind::Integer,
                0,
                true,
                None,
            ),
            column("bound_rows", ColumnKind::Integer, 0, true, None),
            column("bound_logical_bytes", ColumnKind::Integer, 0, true, None),
            column("bound_vm_instructions", ColumnKind::Integer, 0, true, None),
            column("bound_query_nanos", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_source_tables",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("ordinal", ColumnKind::Integer, 2, true, None),
            column(
                "table_name",
                ColumnKind::Utf8 { min: 1, max: 128 },
                0,
                true,
                None,
            ),
            column("row_count", ColumnKind::Integer, 0, true, None),
            column("logical_bytes", ColumnKind::Integer, 0, true, None),
            column("digest", ColumnKind::Text(64), 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_source_rows",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("ordinal", ColumnKind::Integer, 2, true, None),
            column(
                "table_name",
                ColumnKind::Utf8 { min: 1, max: 128 },
                0,
                true,
                None,
            ),
            column("primary_key", BOUNDED_KEY, 0, true, None),
            column("columns_json", BOUNDED_JSON, 0, true, None),
            column("logical_bytes", ColumnKind::Integer, 0, true, None),
            column("fingerprint", ColumnKind::Text(64), 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_holds",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("ordinal", ColumnKind::Integer, 2, true, None),
            column(
                "family",
                ColumnKind::Utf8 { min: 1, max: 64 },
                0,
                true,
                None,
            ),
            column(
                "anchor_table",
                ColumnKind::Utf8 { min: 1, max: 128 },
                0,
                true,
                None,
            ),
            column("anchor_key", BOUNDED_KEY, 0, true, None),
            column("row_count", ColumnKind::Integer, 0, true, None),
            column("object_count", ColumnKind::Integer, 0, true, None),
            column("digest", ColumnKind::Text(64), 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_hold_rows",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("hold_ordinal", ColumnKind::Integer, 2, true, None),
            column("ordinal", ColumnKind::Integer, 3, true, None),
            column("row_ordinal", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_hold_objects",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("hold_ordinal", ColumnKind::Integer, 2, true, None),
            column("ordinal", ColumnKind::Integer, 3, true, None),
            column("kind", ColumnKind::Utf8 { min: 7, max: 32 }, 0, true, None),
            column("content_id", ColumnKind::Text(64), 0, true, None),
            column("length", ColumnKind::Integer, 0, true, None),
            column("source_row_ordinal", ColumnKind::Integer, 0, true, None),
            column(
                "source_column",
                ColumnKind::Utf8 { min: 1, max: 256 },
                0,
                true,
                None,
            ),
        ],
    },
    TableSpec {
        name: "native_history_projection_rows",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("ordinal", ColumnKind::Integer, 2, true, None),
            column("row_ordinal", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_projection_root_columns",
        columns: &[
            column("source_digest", ColumnKind::Text(64), 1, true, None),
            column("ordinal", ColumnKind::Integer, 2, true, None),
            column("row_ordinal", ColumnKind::Integer, 0, true, None),
            column(
                "column_name",
                ColumnKind::Utf8 { min: 1, max: 128 },
                0,
                true,
                None,
            ),
            column(
                "original_value",
                ColumnKind::Utf8 {
                    min: 1,
                    max: 32_768,
                },
                0,
                true,
                None,
            ),
            column(
                "projected_value",
                ColumnKind::Utf8 {
                    min: 1,
                    max: 32_768,
                },
                0,
                true,
                None,
            ),
        ],
    },
    TableSpec {
        name: "native_history_fresh_writers",
        columns: &[
            column("writer_id", ColumnKind::Text(32), 1, true, None),
            column("source_digest", ColumnKind::Text(64), 0, true, None),
            column("projection_digest", ColumnKind::Text(64), 0, true, None),
            column("image_digest", ColumnKind::Text(64), 0, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column("device_id", ColumnKind::Text(64), 0, true, None),
            column(
                "worktree",
                ColumnKind::Utf8 {
                    min: 1,
                    max: 32_768,
                },
                0,
                true,
                None,
            ),
            column("creator_id", ColumnKind::Text(32), 0, true, None),
            column("nonce_hash", ColumnKind::Text(64), 0, true, None),
            column("state", ColumnKind::Utf8 { min: 6, max: 8 }, 0, true, None),
            column("created_snapshot", ColumnKind::Text(64), 0, false, None),
            column("replaced_snapshot", ColumnKind::Text(64), 0, false, None),
            column("admitted_at_ms", ColumnKind::Integer, 0, true, None),
            column("updated_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "native_history_fresh_writer_events",
        columns: &[
            column("writer_id", ColumnKind::Text(32), 1, true, None),
            column("sequence", ColumnKind::Integer, 2, true, None),
            column(
                "event",
                ColumnKind::Utf8 { min: 1, max: 4096 },
                0,
                true,
                None,
            ),
            column("previous_hash", ColumnKind::Text(64), 0, true, None),
            column("event_hash", ColumnKind::Text(64), 0, true, None),
            column("observed_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
];

pub(crate) fn validate(connection: &rusqlite::Connection) -> crate::Result<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != crate::SCHEMA_VERSION {
        return Err(crate::JournalError::Invariant(
            "native history persistence schema version",
        ));
    }
    crate::storage_inventory::reader::validate_schema(
        connection,
        TABLES,
        crate::storage_inventory::reader::Namespace::NativeHistory,
    )
}
