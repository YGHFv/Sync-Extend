//! Exact complete schema matching before accepting a Journal database image.
//! Migration SQL is supplied by the actual candidate's original Journal loader.
use super::{JournalError, Result};
use rusqlite::Connection;

type Definition = (String, String, String, Option<String>);

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

pub(super) fn validate_schema(database: &Connection, version: u32) -> Result<()> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(SCHEMA_SCRIPTS[0])?;
    let count = usize::try_from(version)
        .map_err(|_| JournalError::Invariant("backup schema version overflow"))?;
    if count == 0 || count > SCHEMA_SCRIPTS.len() {
        return Err(JournalError::Invariant(
            "backup schema catalog version absent",
        ));
    }
    for script in &SCHEMA_SCRIPTS[1..count] {
        reference.execute_batch(script)?;
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
    let observed = definitions(database, expected.len() + 1)?;
    if observed != expected {
        return Err(JournalError::Invariant(
            "backup complete Journal schema differs",
        ));
    }
    Ok(())
}

const SCHEMA_SCRIPTS: &[&str] = &[
    include_str!("../schema.sql"),
    include_str!("../migration-002.sql"),
    include_str!("../migration-003.sql"),
    include_str!("../migration-004.sql"),
    include_str!("../migration-005.sql"),
    include_str!("../migration-006.sql"),
    include_str!("../migration-007.sql"),
    include_str!("../migration-008.sql"),
    include_str!("../migration-009.sql"),
    include_str!("../migration-010.sql"),
    include_str!("../migration-011.sql"),
    include_str!("../migration-012.sql"),
    include_str!("../migration-013.sql"),
    include_str!("../migration-014.sql"),
    include_str!("../migration-015.sql"),
    include_str!("../migration-016.sql"),
    include_str!("../migration-017.sql"),
    include_str!("../migration-018.sql"),
    include_str!("../migration-019.sql"),
    include_str!("../migration-020.sql"),
    include_str!("../migration-021.sql"),
    include_str!("../migration-022.sql"),
    include_str!("../migration-023.sql"),
    include_str!("../migration-024.sql"),
    include_str!("../migration-025.sql"),
    include_str!("../migration-026.sql"),
    include_str!("../migration-027.sql"),
    include_str!("../migration-028.sql"),
    include_str!("../migration-029.sql"),
    include_str!("../migration-030.sql"),
    include_str!("../migration-031.sql"),
    include_str!("../migration-032.sql"),
    include_str!("../migration-033.sql"),
    include_str!("../migration-034.sql"),
    include_str!("../migration-035.sql"),
    include_str!("../migration-036.sql"),
    include_str!("../migration-037.sql"),
    include_str!("../migration-038.sql"),
    include_str!("../migration-039.sql"),
    include_str!("../migration-040.sql"),
    include_str!("../migration-041.sql"),
    include_str!("../migration-042.sql"),
    include_str!("../migration-043.sql"),
    include_str!("../migration-044.sql"),
    include_str!("../migration-045.sql"),
    include_str!("../migration-046.sql"),
    include_str!("../migration-047.sql"),
    include_str!("../migration-048.sql"),
    include_str!("../migration-049.sql"),
    include_str!("../migration-050.sql"),
    include_str!("../migration-051.sql"),
    include_str!("../migration-052.sql"),
    include_str!("../migration-053.sql"),
    include_str!("../migration-054.sql"),
    include_str!("../migration-055.sql"),
    include_str!("../migration-056.sql"),
    include_str!("../migration-057.sql"),
    include_str!("../migration-058.sql"),
    include_str!("../migration-059.sql"),
    include_str!("../migration-060.sql"),
    include_str!("../migration-061.sql"),
    include_str!("../migration-062.sql"),
    include_str!("../migration-063.sql"),
    include_str!("../migration-064.sql"),
    include_str!("../migration-065.sql"),
    include_str!("../migration-066.sql"),
    include_str!("../migration-067.sql"),
    include_str!("../migration-068.sql"),
];
