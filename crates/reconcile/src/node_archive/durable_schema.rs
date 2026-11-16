//! Independent exact old/new ledger catalog, including an immutable completion table.
use rusqlite::Connection;
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_journal::{JournalError, Result};

pub(super) const COMPLETION_SCHEMA: &str = include_str!("schema.sql");

type Catalog = Vec<(String, String, String, Option<String>)>;

fn catalog(connection: &Connection) -> Result<Catalog> {
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name")?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        let item: (String, String, String, Option<String>) =
            (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
        bytes = bytes
            .checked_add(
                item.0.len() + item.1.len() + item.2.len() + item.3.as_ref().map_or(0, String::len),
            )
            .filter(|size| *size <= 65_536)
            .ok_or(JournalError::Invariant("completion ledger catalog bytes"))?;
        if result.len() >= 16 {
            return Err(JournalError::Invariant("completion ledger catalog count"));
        }
        result.push(item);
    }
    Ok(result)
}

pub(super) fn audit_current(
    connection: &Connection,
    archive: &ContentId,
    expected_ledger: &SpaceId,
    max_database_bytes: u64,
    require_delete_mode: bool,
) -> Result<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != 3 {
        return Err(JournalError::Invariant("completion exact ledger version"));
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(super::ledger::schema::SCHEMA)?;
    reference.execute_batch(COMPLETION_SCHEMA)?;
    if catalog(connection)? != catalog(&reference)? {
        return Err(JournalError::Invariant(
            "completion exact original reference catalog",
        ));
    }
    let scope: (u32, String, String, u32) = connection.query_row(
        "SELECT singleton,archive_digest,ledger_id,format_version FROM main.restore_scope",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if scope != (1, archive.to_string(), expected_ledger.to_string(), 2) {
        return Err(JournalError::Invariant(
            "completion immutable original scope differs",
        ));
    }
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if require_delete_mode && mode != "delete" {
        return Err(JournalError::Invariant(
            "completion ledger requires exact DELETE mode",
        ));
    }
    let pages: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let pages =
        u64::try_from(pages).map_err(|_| JournalError::Invariant("negative ledger page count"))?;
    let page_size = u64::try_from(page_size)
        .map_err(|_| JournalError::Invariant("negative ledger page size"))?;
    if pages
        .checked_mul(page_size)
        .is_none_or(|bytes| bytes > max_database_bytes)
    {
        return Err(JournalError::Invariant(
            "completion ledger physical page budget",
        ));
    }
    let mut statement = connection.prepare("PRAGMA main.integrity_check")?;
    let mut rows = statement.query([])?;
    if !rows
        .next()?
        .is_some_and(|row| row.get::<_, String>(0).is_ok_and(|value| value == "ok"))
        || rows.next()?.is_some()
    {
        return Err(JournalError::Invariant(
            "completion exact ledger integrity result",
        ));
    }
    Ok(())
}
