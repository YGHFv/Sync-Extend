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
        name: "storage_retirement_requests",
        columns: &[
            c("request_id", ColumnKind::Text(32), 1, true),
            c("space_id", ColumnKind::Text(32), 0, true),
            c("storage_id", ColumnKind::Text(64), 0, true),
            c("owner_id", ColumnKind::Text(32), 0, true),
            c("device_id", ColumnKind::Text(64), 0, true),
            c("policy_hash", ColumnKind::Text(64), 0, true),
            c("content_id", ColumnKind::Text(64), 0, true),
            c("metadata_hash", ColumnKind::Text(64), 0, true),
            c("request_hash", ColumnKind::Text(64), 0, true),
            c("requested_at_ms", ColumnKind::Integer, 0, true),
            c("grace_until_ms", ColumnKind::Integer, 0, true),
            c("expires_at_ms", ColumnKind::Integer, 0, true),
            c("admitted_at_ms", ColumnKind::Integer, 0, true),
            c("request", ColumnKind::Utf8 { min: 1, max: 16384 }, 0, true),
            c(
                "config",
                ColumnKind::Text(crate::MAX_OPERATION_BYTES),
                0,
                true,
            ),
        ],
    },
    TableSpec {
        name: "storage_retirement_clock",
        columns: &[
            c("singleton", ColumnKind::Integer, 1, false),
            c("observed_at_ms", ColumnKind::Integer, 0, true),
        ],
    },
    TableSpec {
        name: "storage_retirement_cancellations",
        columns: &[
            c("request_id", ColumnKind::Text(32), 1, true),
            c("cancelled_at_ms", ColumnKind::Integer, 0, true),
        ],
    },
];

pub(crate) fn validate(connection: &Connection) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
        Ok(connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema
             WHERE (instr(name,'storage_retirement_')=1 OR instr(tbl_name,'storage_retirement_')=1)
             AND instr(name,'storage_retirement_owner_')!=1
             AND instr(tbl_name,'storage_retirement_owner_')!=1
             AND instr(name,'storage_retirement_payload_')!=1
             AND instr(tbl_name,'storage_retirement_payload_')!=1
             AND instr(name,'storage_retirement_disposal_')!=1
             AND instr(tbl_name,'storage_retirement_disposal_')!=1
             AND instr(name,'storage_retirement_terminal_')!=1
             AND instr(tbl_name,'storage_retirement_terminal_')!=1
             ORDER BY type,name",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch("CREATE TABLE snapshot_objects(content_id TEXT); CREATE TABLE publication_objects(content_id TEXT); CREATE TABLE mutation_objects(content_id TEXT); CREATE TABLE read_lease_objects(content_id TEXT); CREATE TABLE reference_reservation_objects(content_id TEXT); CREATE TABLE tree_restore_objects(content_id TEXT); CREATE TABLE tree_restore_original_objects(content_id TEXT); CREATE TABLE remote_replace_objects(content_id TEXT); CREATE TABLE conflict_resolution_objects(content_id TEXT); CREATE TABLE conflict_resolution_native_history_objects(content_id TEXT); CREATE TABLE gc_marks(content_id TEXT); CREATE TABLE gc_executions(content_id TEXT);")?;
    expected.execute_batch(include_str!("../migration-059.sql"))?;
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE (instr(name,'storage_retirement_')=1 OR instr(tbl_name,'storage_retirement_')=1)
         AND instr(name,'storage_retirement_owner_')!=1
         AND instr(tbl_name,'storage_retirement_owner_')!=1
         AND instr(name,'storage_retirement_payload_')!=1
         AND instr(tbl_name,'storage_retirement_payload_')!=1
         AND instr(name,'storage_retirement_disposal_')!=1
         AND instr(tbl_name,'storage_retirement_disposal_')!=1
             AND instr(name,'storage_retirement_terminal_')!=1
             AND instr(tbl_name,'storage_retirement_terminal_')!=1)",
        [],
        |r| r.get(0),
    )?;
    if shadow || objects(connection)? != objects(&expected)? {
        return Err(JournalError::Invariant("storage retirement exact schema"));
    }
    Ok(())
}
