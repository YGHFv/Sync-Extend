//! Exact complete schema matching before accepting a Journal database image.
//! Migration SQL is supplied by the actual candidate's original Journal loader.
use super::{JournalError, Result};
use rusqlite::Connection;
use std::sync::OnceLock;

pub(super) type Definition = (String, String, String, Option<String>);

fn definitions(database: &Connection, max_count: usize) -> Result<Vec<Definition>> {
    let mut query = database.prepare(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema          ORDER BY type,name LIMIT ?1",
    )?;
    let limit = i64::try_from(max_count)
        .map_err(|_| JournalError::Invariant("backup schema object limit overflow"))?;
    let values = query.query_map([limit], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
    })?;
    Ok(values.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CatalogLineage {
    Canonical,
    HistoricalCrlf,
}

pub(super) fn validate_schema(database: &Connection, version: u32) -> Result<()> {
    select_lineage(database, version).map(|_| ())
}

/// Select one whole known catalog, never individual object aliases. Comparison
/// borrows observed text and bounds it against fixed expected bytes before copy.
pub(super) fn select_lineage(database: &Connection, version: u32) -> Result<CatalogLineage> {
    let actual: u32 = database.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if actual != version {
        return Err(JournalError::Invariant("backup exact catalog version"));
    }
    if matches_definitions(database, compiled_definitions(version)?)? {
        return Ok(CatalogLineage::Canonical);
    }
    if matches!(version, 73 | 74)
        && matches_definitions(
            database,
            definitions_for(version, CatalogLineage::HistoricalCrlf)?,
        )?
    {
        return Ok(CatalogLineage::HistoricalCrlf);
    }
    Err(JournalError::Invariant(
        "backup complete Journal schema differs",
    ))
}

pub(super) fn matches_definitions(database: &Connection, expected: &[Definition]) -> Result<bool> {
    use rusqlite::types::ValueRef;
    let mut query = database.prepare(
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name LIMIT ?1",
    )?;
    let mut rows = query.query([expected.len() as i64 + 1])?;
    for entry in expected {
        let Some(row) = rows.next()? else {
            return Ok(false);
        };
        for (index, text) in [(0, &entry.0), (1, &entry.1), (2, &entry.2)] {
            if !matches!(row.get_ref(index)?,ValueRef::Text(raw) if raw==text.as_bytes()) {
                return Ok(false);
            }
        }
        if !match (row.get_ref(3)?, entry.3.as_deref()) {
            (ValueRef::Null, None) => true,
            (ValueRef::Text(raw), Some(text)) => raw == text.as_bytes(),
            _ => false,
        } {
            return Ok(false);
        }
    }
    Ok(rows.next()?.is_none())
}

pub(super) fn definitions_for(
    version: u32,
    lineage: CatalogLineage,
) -> Result<&'static [Definition]> {
    if lineage == CatalogLineage::Canonical {
        return compiled_definitions(version);
    }
    static V73: OnceLock<Vec<Definition>> = OnceLock::new();
    static V74: OnceLock<Vec<Definition>> = OnceLock::new();
    let cached = match version {
        73 => &V73,
        74 => &V74,
        _ => {
            return Err(JournalError::Invariant(
                "unregistered historical SQL lineage",
            ));
        }
    };
    if cached.get().is_none() {
        let _ = cached.set(build_definitions(version, Some(version))?);
    }
    cached
        .get()
        .map(Vec::as_slice)
        .ok_or(JournalError::Invariant("historical SQL catalog absent"))
}

pub(super) fn compiled_definitions(version: u32) -> Result<&'static [Definition]> {
    // Only the immutable compiled migration result is cached. Every observed
    // database catalog and every typed source audit is still read and checked.
    static CATALOGS: [OnceLock<Vec<Definition>>; SCHEMA_SCRIPTS.len()] =
        [const { OnceLock::new() }; SCHEMA_SCRIPTS.len()];
    let index = usize::try_from(version)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .filter(|n| *n < CATALOGS.len())
        .ok_or(JournalError::Invariant(
            "backup schema catalog version absent",
        ))?;
    let cached = &CATALOGS[index];
    if cached.get().is_none() {
        let _ = cached.set(build_compiled_definitions(version)?);
    }
    cached
        .get()
        .map(Vec::as_slice)
        .ok_or(JournalError::Invariant(
            "backup compiled schema cache absent",
        ))
}

fn build_compiled_definitions(version: u32) -> Result<Vec<Definition>> {
    build_definitions(version, None)
}

fn build_definitions(version: u32, historical_crlf: Option<u32>) -> Result<Vec<Definition>> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SCRIPTS[0])?;
    let count = usize::try_from(version)
        .map_err(|_| JournalError::Invariant("backup schema version overflow"))?;
    if count == 0 || count > SCHEMA_SCRIPTS.len() {
        return Err(JournalError::Invariant(
            "backup schema catalog version absent",
        ));
    }
    for (index, script) in SCHEMA_SCRIPTS[1..count].iter().enumerate() {
        if historical_crlf == Some(index as u32 + 2) {
            // Trusted fixed historical input only. Never transform observed SQL.
            reference.execute_batch(&script.replace("\n", "\r\n"))?;
        } else {
            reference.execute_batch(script)?;
        }
    }
    let actual_version: u32 =
        reference.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if actual_version != version {
        return Err(JournalError::Invariant(
            "backup reference schema version differs",
        ));
    }
    let expected = definitions(&reference, 4097)?;
    if expected.is_empty() || expected.len() > 4096 {
        return Err(JournalError::Invariant(
            "backup schema object budget exceeded",
        ));
    }
    Ok(expected)
}

const SCHEMA_SCRIPTS: &[&str] = &[
    journal_sql!("schema.sql"),
    journal_sql!("migration-002.sql"),
    journal_sql!("migration-003.sql"),
    journal_sql!("migration-004.sql"),
    journal_sql!("migration-005.sql"),
    journal_sql!("migration-006.sql"),
    journal_sql!("migration-007.sql"),
    journal_sql!("migration-008.sql"),
    journal_sql!("migration-009.sql"),
    journal_sql!("migration-010.sql"),
    journal_sql!("migration-011.sql"),
    journal_sql!("migration-012.sql"),
    journal_sql!("migration-013.sql"),
    journal_sql!("migration-014.sql"),
    journal_sql!("migration-015.sql"),
    journal_sql!("migration-016.sql"),
    journal_sql!("migration-017.sql"),
    journal_sql!("migration-018.sql"),
    journal_sql!("migration-019.sql"),
    journal_sql!("migration-020.sql"),
    journal_sql!("migration-021.sql"),
    journal_sql!("migration-022.sql"),
    journal_sql!("migration-023.sql"),
    journal_sql!("migration-024.sql"),
    journal_sql!("migration-025.sql"),
    journal_sql!("migration-026.sql"),
    journal_sql!("migration-027.sql"),
    journal_sql!("migration-028.sql"),
    journal_sql!("migration-029.sql"),
    journal_sql!("migration-030.sql"),
    journal_sql!("migration-031.sql"),
    journal_sql!("migration-032.sql"),
    journal_sql!("migration-033.sql"),
    journal_sql!("migration-034.sql"),
    journal_sql!("migration-035.sql"),
    journal_sql!("migration-036.sql"),
    journal_sql!("migration-037.sql"),
    journal_sql!("migration-038.sql"),
    journal_sql!("migration-039.sql"),
    journal_sql!("migration-040.sql"),
    journal_sql!("migration-041.sql"),
    journal_sql!("migration-042.sql"),
    journal_sql!("migration-043.sql"),
    journal_sql!("migration-044.sql"),
    journal_sql!("migration-045.sql"),
    journal_sql!("migration-046.sql"),
    journal_sql!("migration-047.sql"),
    journal_sql!("migration-048.sql"),
    journal_sql!("migration-049.sql"),
    journal_sql!("migration-050.sql"),
    journal_sql!("migration-051.sql"),
    journal_sql!("migration-052.sql"),
    journal_sql!("migration-053.sql"),
    journal_sql!("migration-054.sql"),
    journal_sql!("migration-055.sql"),
    journal_sql!("migration-056.sql"),
    journal_sql!("migration-057.sql"),
    journal_sql!("migration-058.sql"),
    journal_sql!("migration-059.sql"),
    journal_sql!("migration-060.sql"),
    journal_sql!("migration-061.sql"),
    journal_sql!("migration-062.sql"),
    journal_sql!("migration-063.sql"),
    journal_sql!("migration-064.sql"),
    journal_sql!("migration-065.sql"),
    journal_sql!("migration-066.sql"),
    journal_sql!("migration-067.sql"),
    journal_sql!("migration-068.sql"),
    journal_sql!("migration-069.sql"),
    journal_sql!("migration-070.sql"),
    journal_sql!("migration-071.sql"),
    journal_sql!("migration-072.sql"),
    journal_sql!("migration-073.sql"),
    journal_sql!("migration-074.sql"),
];
