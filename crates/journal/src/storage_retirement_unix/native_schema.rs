//! Exact independent native catalog, including the v1 cancellation guard.
use crate::{
    JournalError, Result,
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
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
        name: "unix_storage_retirement_native_v1_activations",
        columns: &[
            c("activation_id", ColumnKind::Text(32), 1, true),
            c("request_id", ColumnKind::Text(32), 0, true),
            c("binding_hash", ColumnKind::Text(64), 0, true),
            c("activation_hash", ColumnKind::Text(64), 0, true),
            c("activated_at_ms", ColumnKind::Integer, 0, true),
            c(
                "activation",
                ColumnKind::Utf8 { min: 1, max: 16384 },
                0,
                true,
            ),
        ],
    },
    TableSpec {
        name: "unix_storage_retirement_native_v1_events",
        columns: &[
            c("activation_id", ColumnKind::Text(32), 1, true),
            c("sequence", ColumnKind::Integer, 2, true),
            c("kind", ColumnKind::Utf8 { min: 1, max: 48 }, 0, true),
            c("observed_at_ms", ColumnKind::Integer, 0, true),
            c("previous_hash", ColumnKind::Text(64), 0, true),
            c("event_hash", ColumnKind::Text(64), 0, true),
            c("evidence", ColumnKind::Utf8 { min: 1, max: 4096 }, 0, true),
        ],
    },
    TableSpec {
        name: "unix_storage_retirement_native_v1_clock",
        columns: &[
            c("singleton", ColumnKind::Integer, 1, false),
            c("observed_at_ms", ColumnKind::Integer, 0, true),
        ],
    },
    TableSpec {
        name: "unix_storage_retirement_native_v1_releases",
        columns: &[
            c("activation_id", ColumnKind::Text(32), 1, true),
            c("request_id", ColumnKind::Text(32), 0, true),
            c("terminal_hash", ColumnKind::Text(64), 0, true),
            c("released_at_ms", ColumnKind::Integer, 0, true),
            c("release_hash", ColumnKind::Text(64), 0, true),
            c("release", ColumnKind::Utf8 { min: 1, max: 2048 }, 0, true),
        ],
    },
];

pub(crate) fn validate(connection: &Connection) -> Result<()> {
    type Object = (String, String, String, Option<String>);
    fn objects(connection: &Connection, namespace: &str) -> Result<Vec<Object>> {
        Ok(connection
            .prepare(&format!(
                "SELECT type,name,tbl_name,sql FROM {namespace}.sqlite_schema
             WHERE instr(lower(name),'unix_storage_retirement_native_v1_')=1
                OR instr(lower(tbl_name),'unix_storage_retirement_native_v1_')=1
             ORDER BY type,name"
            ))?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    static EXPECTED: std::sync::OnceLock<Vec<Object>> = std::sync::OnceLock::new();
    if EXPECTED.get().is_none() {
        let expected = Connection::open_in_memory()?;
        for table in super::schema::REFERENCES {
            expected.execute_batch(&format!("CREATE TABLE {table}(content_id TEXT);"))?;
        }
        expected.execute_batch(include_str!("../migration-068.sql"))?;
        expected.execute_batch(include_str!("../migration-069.sql"))?;
        let _ = EXPECTED.set(objects(&expected, "main")?);
    }
    if !objects(connection, "temp")?.is_empty()
        || objects(connection, "main")?
            != *EXPECTED.get().ok_or(JournalError::Invariant(
                "compiled original Unix native catalog missing",
            ))?
    {
        return Err(JournalError::Invariant("Unix native exact original schema"));
    }
    Ok(())
}
