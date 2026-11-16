//! Exact independent reference catalog; hostile schema is never normalized.
use rusqlite::Connection;
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_journal::{JournalError, Result};

use super::bounds::LedgerBounds;

pub(in super::super) const SCHEMA: &str = r#"
CREATE TABLE restore_scope(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 archive_digest TEXT NOT NULL CHECK(length(archive_digest)=64),
 ledger_id TEXT NOT NULL CHECK(length(ledger_id)=32),
 format_version INTEGER NOT NULL CHECK(format_version=2)
) STRICT;
CREATE TABLE restore_records(
 record_index INTEGER PRIMARY KEY CHECK(record_index>=0),
 previous_hash TEXT NOT NULL CHECK(length(previous_hash)=64),
 record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) BETWEEN 1 AND 65536),
 record_hash TEXT NOT NULL CHECK(length(record_hash)=64)
) STRICT;
CREATE TRIGGER restore_scope_update BEFORE UPDATE ON restore_scope
BEGIN SELECT RAISE(ABORT,'restore scope immutable'); END;
CREATE TRIGGER restore_scope_delete BEFORE DELETE ON restore_scope
BEGIN SELECT RAISE(ABORT,'restore scope immutable'); END;
CREATE TRIGGER restore_records_update BEFORE UPDATE ON restore_records
BEGIN SELECT RAISE(ABORT,'restore records immutable'); END;
CREATE TRIGGER restore_records_delete BEFORE DELETE ON restore_records
BEGIN SELECT RAISE(ABORT,'restore records immutable'); END;
PRAGMA user_version=2;
"#;

type CatalogRow = (String, String, String, Option<String>);

pub(super) fn catalog(connection: &Connection) -> Result<Vec<CatalogRow>> {
    let mut statement = connection
        .prepare("SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name")?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        let entry: CatalogRow = (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?);
        bytes = bytes
            .checked_add(
                entry.0.len()
                    + entry.1.len()
                    + entry.2.len()
                    + entry.3.as_ref().map_or(0, String::len),
            )
            .filter(|bytes| *bytes <= 65_536)
            .ok_or(JournalError::Invariant("restore ledger catalog byte bound"))?;
        if result.len() >= 16 {
            return Err(JournalError::Invariant(
                "restore ledger catalog object bound",
            ));
        }
        result.push(entry);
    }
    Ok(result)
}

pub(in super::super) fn audit_image(
    connection: &Connection,
    archive: &ContentId,
    bounds: LedgerBounds,
) -> Result<SpaceId> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !matches!(version, 2 | 3) {
        return Err(JournalError::Invariant(
            "restore ledger exact known version",
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
        .is_none_or(|bytes| bytes > bounds.max_database_bytes)
    {
        return Err(JournalError::Invariant(
            "restore ledger database page byte bound",
        ));
    }
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA)?;
    if version == 3 {
        reference.execute_batch(super::super::durable_schema::COMPLETION_SCHEMA)?;
    }
    if catalog(connection)? != catalog(&reference)? {
        return Err(JournalError::Invariant(
            "restore ledger complete reference catalog differs",
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
            "restore ledger exact integrity result",
        ));
    }
    let mut scope_statement = connection.prepare(
        "SELECT singleton,archive_digest,ledger_id,format_version FROM main.restore_scope",
    )?;
    let mut scopes = scope_statement.query([])?;
    let row = scopes
        .next()?
        .ok_or(JournalError::Invariant("restore ledger scope absent"))?;
    let singleton: i64 = row.get(0)?;
    let digest: String = row.get(1)?;
    let ledger: String = row.get(2)?;
    let format: u32 = row.get(3)?;
    if singleton != 1 || digest != archive.as_str() || format != 2 || scopes.next()?.is_some() {
        return Err(JournalError::Invariant("restore ledger exact scope row"));
    }
    if version == 3 {
        let completed: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.restore_completions)",
            [],
            |row| row.get(0),
        )?;
        if completed {
            return Err(JournalError::Invariant(
                "completed ledger requires independent full completion evidence inspection",
            ));
        }
    }
    Ok(ledger.parse()?)
}

pub(in super::super) fn audit(
    connection: &Connection,
    archive: &ContentId,
    bounds: LedgerBounds,
) -> Result<SpaceId> {
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if mode != "delete" {
        return Err(JournalError::Invariant("restore ledger exact DELETE mode"));
    }
    audit_image(connection, archive, bounds)
}
