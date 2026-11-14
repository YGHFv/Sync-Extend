use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    JournalError, Result,
};
use rusqlite::Connection;
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
        name: "webdav_native_admissions",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("space_id", ColumnKind::Text(32), 0),
            c("baseline_snapshot", ColumnKind::Text(64), 0),
            c("request_hash", ColumnKind::Text(64), 0),
            c("plan_hash", ColumnKind::Text(64), 0),
            c("admitted_at_ms", ColumnKind::Integer, 0),
            c(
                "description",
                ColumnKind::Text(crate::MAX_OPERATION_BYTES),
                0,
            ),
            c("future_rows", ColumnKind::Integer, 0),
            c("future_bytes", ColumnKind::Integer, 0),
        ],
    },
    TableSpec {
        name: "webdav_native_objects",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("content_id", ColumnKind::Text(64), 2),
            c("length", ColumnKind::Integer, 0),
        ],
    },
    TableSpec {
        name: "webdav_native_cancellations",
        columns: &[
            c("transaction_id", ColumnKind::Text(32), 1),
            c("cancelled_at_ms", ColumnKind::Integer, 0),
        ],
    },
    TableSpec {
        name: "webdav_native_clock",
        columns: &[
            ColumnSpec {
                name: "singleton",
                kind: ColumnKind::Integer,
                primary_key: 1,
                not_null: false,
                default: None,
            },
            c("observed_at_ms", ColumnKind::Integer, 0),
        ],
    },
];
pub(crate) fn validate(connection: &Connection) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
        Ok(connection.prepare("SELECT type,name,tbl_name,sql FROM main.sqlite_schema
            WHERE instr(name,'webdav_native_')=1 OR instr(tbl_name,'webdav_native_')=1 ORDER BY type,name")?
            .query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?.collect::<rusqlite::Result<_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(
        "CREATE TABLE snapshots(snapshot_id TEXT);
        CREATE TABLE current_manifests(space_id TEXT,snapshot_id TEXT);
        CREATE TABLE operations(space_id TEXT);
        CREATE TABLE publications(space_id TEXT);
        CREATE TABLE mutations(space_id TEXT);
        CREATE TABLE cleanup_plans(space_id TEXT,state TEXT);
        CREATE TABLE snapshot_prunings(snapshot_id TEXT);
        CREATE TABLE snapshot_objects(snapshot_id TEXT);",
    )?;
    expected.execute_batch(include_str!("../migration-064.sql"))?;
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
        WHERE instr(name,'webdav_native_')=1 OR instr(tbl_name,'webdav_native_')=1)",
        [],
        |r| r.get(0),
    )?;
    if shadow || objects(connection)? != objects(&expected)? {
        return Err(JournalError::Invariant(
            "exact retained DAV description schema",
        ));
    }
    Ok(())
}
