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
pub(crate) const TABLES: &[TableSpec] = &[TableSpec {
    name: "storage_retirement_payload_events",
    columns: &[
        c("request_id", ColumnKind::Text(32), 1),
        c("step", ColumnKind::Integer, 2),
        c("kind", ColumnKind::Utf8 { min: 1, max: 32 }, 0),
        c("event_hash", ColumnKind::Text(64), 0),
        c("recorded_at_ms", ColumnKind::Integer, 0),
    ],
}];
pub(crate) fn validate(connection: &Connection) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
        Ok(connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema
             WHERE (instr(name,'storage_retirement_payload_')=1
             OR instr(tbl_name,'storage_retirement_payload_')=1)
             AND instr(name,'storage_retirement_disposal_')!=1 ORDER BY type,name",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(
        "CREATE TABLE storage_retirement_requests(request_id TEXT);
         CREATE TABLE storage_retirement_owner_creations(request_id TEXT);
         CREATE TABLE storage_retirement_clock(singleton INTEGER,observed_at_ms INTEGER);
         CREATE TABLE storage_retirement_cancellations(request_id TEXT);",
    )?;
    expected.execute_batch(include_str!("../migration-061.sql"))?;
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE instr(name,'storage_retirement_payload_')=1
         OR instr(tbl_name,'storage_retirement_payload_')=1)",
        [],
        |r| r.get(0),
    )?;
    if shadow || objects(connection)? != objects(&expected)? {
        return Err(JournalError::Invariant(
            "storage retirement exact payload schema",
        ));
    }
    Ok(())
}
