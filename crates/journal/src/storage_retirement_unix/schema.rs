//! Independent compiled Unix family catalog. Historical JSON has no FD authority.
use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    JournalError, Result,
};
use rusqlite::Connection;

const fn c(name: &'static str, kind: ColumnKind, pk: usize, required: bool) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key: pk,
        not_null: required,
        default: None,
    }
}

pub(crate) const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "unix_storage_retirement_v1_requests",
        columns: &[
            c("request_id", ColumnKind::Text(32), 1, true),
            c("space_id", ColumnKind::Text(32), 0, true),
            c("storage_id", ColumnKind::Text(64), 0, true),
            c("owner_id", ColumnKind::Text(32), 0, true),
            c("device_id", ColumnKind::Text(64), 0, true),
            c("policy_hash", ColumnKind::Text(64), 0, true),
            c("content_id", ColumnKind::Text(64), 0, true),
            c("metadata_hash", ColumnKind::Text(64), 0, true),
            c("binding_hash", ColumnKind::Text(64), 0, true),
            c("request_hash", ColumnKind::Text(64), 0, true),
            c("requested_at_ms", ColumnKind::Integer, 0, true),
            c("grace_until_ms", ColumnKind::Integer, 0, true),
            c("expires_at_ms", ColumnKind::Integer, 0, true),
            c("admitted_at_ms", ColumnKind::Integer, 0, true),
            c("request", ColumnKind::Utf8 { min: 1, max: 16384 }, 0, true),
            c(
                "config",
                ColumnKind::Utf8 {
                    min: 1,
                    max: crate::MAX_OPERATION_BYTES,
                },
                0,
                true,
            ),
        ],
    },
    TableSpec {
        name: "unix_storage_retirement_v1_clock",
        columns: &[
            c("singleton", ColumnKind::Integer, 1, false),
            c("observed_at_ms", ColumnKind::Integer, 0, true),
        ],
    },
    TableSpec {
        name: "unix_storage_retirement_v1_cancellations",
        columns: &[
            c("request_id", ColumnKind::Text(32), 1, true),
            c("cancelled_at_ms", ColumnKind::Integer, 0, true),
        ],
    },
];

pub(crate) const REFERENCES: &[&str] = &[
    "snapshot_objects",
    "publication_objects",
    "mutation_objects",
    "read_lease_objects",
    "reference_reservation_objects",
    "tree_restore_objects",
    "tree_restore_original_objects",
    "remote_replace_objects",
    "conflict_resolution_objects",
    "conflict_resolution_native_history_objects",
    "gc_marks",
    "gc_executions",
];

pub(crate) fn validate(connection: &Connection) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
        Ok(connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema
                 WHERE instr(lower(name),'unix_storage_retirement_v1_')=1
                    OR instr(lower(tbl_name),'unix_storage_retirement_v1_')=1
                 ORDER BY type,name",
            )?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    static EXPECTED: std::sync::OnceLock<Vec<SchemaObject>> = std::sync::OnceLock::new();
    if EXPECTED.get().is_none() {
        let expected = Connection::open_in_memory()?;
        for table in REFERENCES {
            expected.execute_batch(&format!("CREATE TABLE {table}(content_id TEXT);"))?;
        }
        expected.execute_batch(include_str!("../migration-068.sql"))?;
        expected.execute_batch(include_str!("../migration-069.sql"))?;
        let _ = EXPECTED.set(objects(&expected)?);
    }
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE instr(lower(name),'unix_storage_retirement_v1_')=1
            OR instr(lower(tbl_name),'unix_storage_retirement_v1_')=1)",
        [],
        |row| row.get(0),
    )?;
    if shadow
        || objects(connection)?
            != *EXPECTED.get().ok_or(JournalError::Invariant(
                "compiled Unix retirement schema absent",
            ))?
    {
        return Err(JournalError::Invariant("Unix retirement exact schema"));
    }
    Ok(())
}
