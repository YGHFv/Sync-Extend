use crate::{JournalError, Result, MAX_OPERATION_BYTES, SCHEMA_VERSION};
use rusqlite::{types::ValueRef, Connection};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::ContentId;

use super::{
    JournalStorageColumn, JournalStorageColumnValue, JournalStoredRow, JournalStoredTable,
};

#[derive(Clone, Copy)]
pub(crate) enum ColumnKind {
    Text(usize),
    Utf8 { min: usize, max: usize },
    Integer,
}
pub(crate) struct ColumnSpec {
    pub name: &'static str,
    pub kind: ColumnKind,
    pub primary_key: usize,
    pub not_null: bool,
    pub default: Option<&'static str>,
}
#[derive(Clone, Copy)]
pub(crate) struct TableSpec {
    pub name: &'static str,
    pub columns: &'static [ColumnSpec],
}

#[derive(Clone, Copy)]
pub(crate) enum Namespace {
    All,
    TreeRestore,
    TreeNative,
}
impl Namespace {
    fn predicate(self) -> &'static str {
        match self {
            Self::All => "lower(substr(name,1,7))!='sqlite_'",
            Self::TreeRestore => "lower(substr(name,1,13))='tree_restore_'",
            Self::TreeNative => "lower(substr(name,1,12))='tree_native_'",
        }
    }
}

pub(crate) fn invalid(message: &'static str) -> JournalError {
    JournalError::Invariant(message)
}
pub(crate) fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or(invalid("storage inventory arithmetic overflow"))
}
pub(crate) fn hash<T: Serialize>(value: &T) -> Result<ContentId> {
    Ok(ContentId::hash(&serde_json::to_vec(value)?))
}

// Every query names main explicitly; TEMP objects must not shadow typed audits.
pub(crate) fn validate_schema(
    connection: &Connection,
    tables: &[TableSpec],
    namespace: Namespace,
) -> Result<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version != SCHEMA_VERSION {
        return Err(invalid("storage inventory schema version"));
    }
    let mut list = connection.prepare(&format!(
        "SELECT name,type,ncol,wr,strict FROM pragma_table_list
         WHERE schema='main' AND {} ORDER BY name",
        namespace.predicate()
    ))?;
    let mut rows = list.query([])?;
    let mut seen = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let spec = tables
            .iter()
            .find(|table| table.name == name)
            .ok_or(invalid("storage inventory unknown table"))?;
        if !seen.insert(name)
            || row.get::<_, String>(1)? != "table"
            || row.get::<_, i64>(2)? != spec.columns.len() as i64
            || row.get::<_, i64>(3)? != 0
            || row.get::<_, i64>(4)? != 1
        {
            return Err(invalid("storage inventory table layout"));
        }
        let mut info = connection.prepare(
            "SELECT cid,name,type,\"notnull\",dflt_value,pk,hidden
             FROM pragma_table_xinfo(?1,'main') ORDER BY cid",
        )?;
        let mut columns = info.query([spec.name])?;
        for (index, expected) in spec.columns.iter().enumerate() {
            let actual = columns
                .next()?
                .ok_or(invalid("storage inventory missing column"))?;
            let declared = match expected.kind {
                ColumnKind::Text(_) | ColumnKind::Utf8 { .. } => "TEXT",
                ColumnKind::Integer => "INTEGER",
            };
            if actual.get::<_, i64>(0)? != index as i64
                || actual.get::<_, String>(1)? != expected.name
                || actual.get::<_, String>(2)? != declared
                || actual.get::<_, bool>(3)? != expected.not_null
                || actual.get::<_, Option<String>>(4)?.as_deref() != expected.default
                || actual.get::<_, i64>(5)? != expected.primary_key as i64
                || actual.get::<_, i64>(6)? != 0
            {
                return Err(invalid("storage inventory column layout"));
            }
        }
        if columns.next()?.is_some() {
            return Err(invalid("storage inventory extra column"));
        }
    }
    if seen.len() != tables.len() {
        return Err(invalid("storage inventory missing table"));
    }
    let shadow: bool = connection.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
             WHERE type IN ('table','view') AND {})",
            namespace.predicate()
        ),
        [],
        |r| r.get(0),
    )?;
    if shadow {
        return Err(invalid("storage inventory shadowed table"));
    }
    Ok(())
}

fn validity(column: &ColumnSpec) -> String {
    let name = column.name;
    match column.kind {
        ColumnKind::Text(n) if n == MAX_OPERATION_BYTES => format!(
            "typeof(\"{name}\")='text' AND length(CAST(\"{name}\" AS BLOB)) BETWEEN 1 AND {n}"
        ),
        ColumnKind::Text(n) => format!(
            "typeof(\"{name}\")='text' AND length(CAST(\"{name}\" AS BLOB))={n}
             AND \"{name}\" NOT GLOB '*[^0-9a-f]*'"
        ),
        ColumnKind::Utf8 { min, max } => format!(
            "typeof(\"{name}\")='text' AND length(CAST(\"{name}\" AS BLOB)) BETWEEN {min} AND {max}"
        ),
        ColumnKind::Integer => format!("typeof(\"{name}\")='integer' AND \"{name}\">=0"),
    }
}
fn nullable(column: &ColumnSpec) -> bool {
    // An INTEGER PRIMARY KEY aliases rowid despite PRAGMA notnull reporting 0.
    !column.not_null && column.primary_key == 0
}

// Length/type/count checks precede any JSON or large value copied into Rust.
pub(crate) fn preflight(
    connection: &Connection,
    specs: &[TableSpec],
    max_rows: usize,
    max_bytes: u64,
) -> Result<Vec<JournalStoredTable>> {
    let mut total_rows = 0;
    let mut total_bytes = 0;
    let mut tables = Vec::new();
    for table in specs {
        let remaining = max_rows as u64 - total_rows;
        let count: i64 = connection.query_row(
            &format!(
                "SELECT count(*) FROM (SELECT 1 FROM main.{} LIMIT ?1)",
                table.name
            ),
            [remaining as i64 + 1],
            |r| r.get(0),
        )?;
        let count = u64::try_from(count).map_err(|_| invalid("storage inventory row count"))?;
        total_rows = add(total_rows, count)?;
        if total_rows > max_rows as u64 {
            return Err(invalid("storage inventory row limit"));
        }
        let expressions: Vec<String> = table
            .columns
            .iter()
            .map(|c| {
                let bytes = match c.kind {
                    ColumnKind::Text(_) | ColumnKind::Utf8 { .. } => {
                        format!("length(CAST(\"{}\" AS BLOB))", c.name)
                    }
                    ColumnKind::Integer => "8".into(),
                };
                let null = if nullable(c) {
                    format!("WHEN \"{}\" IS NULL THEN 0 ", c.name)
                } else {
                    String::new()
                };
                format!("CASE {null}WHEN {} THEN {bytes} ELSE -1 END", validity(c))
            })
            .collect();
        let mut statement = connection.prepare(&format!(
            "SELECT {} FROM main.{}",
            expressions.join(","),
            table.name
        ))?;
        let mut rows = statement.query([])?;
        let mut actual_rows = 0;
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            for index in 0..table.columns.len() {
                let size = u64::try_from(row.get::<_, i64>(index)?)
                    .map_err(|_| invalid("storage inventory physical value type or bounds"))?;
                bytes = add(bytes, size)?;
                total_bytes = add(total_bytes, size)?;
                if total_bytes > max_bytes {
                    return Err(invalid("storage inventory byte limit"));
                }
            }
            actual_rows += 1;
        }
        if actual_rows != count {
            return Err(invalid("storage inventory row count changed"));
        }
        tables.push(JournalStoredTable {
            table: table.name,
            columns: table.columns.len(),
            rows: count,
            logical_bytes: bytes,
        });
    }
    Ok(tables)
}

fn validate_text(raw: &[u8], kind: ColumnKind) -> Result<&str> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid("storage inventory text encoding"))?;
    let valid = match kind {
        ColumnKind::Text(n) if n == MAX_OPERATION_BYTES => !raw.is_empty() && raw.len() <= n,
        ColumnKind::Text(n) => {
            raw.len() == n
                && raw
                    .iter()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        }
        ColumnKind::Utf8 { min, max } => (min..=max).contains(&raw.len()),
        ColumnKind::Integer => false,
    };
    if !valid {
        return Err(invalid("storage inventory text value bounds"));
    }
    Ok(text)
}

fn read_row(table: &TableSpec, row: &rusqlite::Row<'_>) -> Result<JournalStoredRow> {
    let mut columns = Vec::new();
    let mut key = BTreeMap::new();
    let mut bytes = 0;
    for (index, spec) in table.columns.iter().enumerate() {
        let (value, size, key_value) = match (spec.kind, row.get_ref(index)?) {
            (ColumnKind::Text(_) | ColumnKind::Utf8 { .. }, ValueRef::Text(raw)) => {
                let text = validate_text(raw, spec.kind)?.to_owned();
                let key_value = (spec.primary_key != 0).then(|| text.clone());
                (
                    JournalStorageColumnValue::Text(text),
                    raw.len() as u64,
                    key_value,
                )
            }
            (ColumnKind::Integer, ValueRef::Integer(n)) if n >= 0 => (
                JournalStorageColumnValue::Integer(n as u64),
                8,
                (spec.primary_key != 0).then(|| n.to_string()),
            ),
            (_, ValueRef::Null) if nullable(spec) => (JournalStorageColumnValue::Null, 0, None),
            _ => return Err(invalid("storage inventory value changed")),
        };
        if let Some(value) = key_value {
            key.insert(spec.primary_key, value);
        }
        bytes = add(bytes, size)?;
        columns.push(JournalStorageColumn {
            name: spec.name.into(),
            value,
        });
    }
    let primary_key: Vec<String> = key.into_values().collect();
    if primary_key.is_empty() {
        return Err(invalid("storage inventory primary key missing"));
    }
    let fingerprint = hash(&(
        "sync-extend.actual-journal-row-values.v1",
        table.name,
        &primary_key,
        &columns,
    ))?;
    Ok(JournalStoredRow {
        table: table.name,
        primary_key,
        columns,
        logical_bytes: bytes,
        fingerprint,
    })
}

pub(crate) fn read_table(
    connection: &Connection,
    table: &TableSpec,
    expected: &JournalStoredTable,
) -> Result<Vec<JournalStoredRow>> {
    let selected = table
        .columns
        .iter()
        .map(|c| format!("\"{}\"", c.name))
        .collect::<Vec<_>>()
        .join(",");
    let mut key_columns: Vec<_> = table
        .columns
        .iter()
        .filter(|c| c.primary_key != 0)
        .collect();
    key_columns.sort_by_key(|c| c.primary_key);
    let order = key_columns
        .iter()
        .map(|c| format!("\"{}\"", c.name))
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = connection.prepare(&format!(
        "SELECT {selected} FROM main.{} ORDER BY {order}",
        table.name
    ))?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    let mut keys = BTreeSet::new();
    let mut bytes = 0;
    while let Some(row) = rows.next()? {
        if result.len() as u64 >= expected.rows {
            return Err(invalid("storage inventory extra row"));
        }
        let row = read_row(table, row)?;
        if !keys.insert(row.primary_key.clone()) {
            return Err(invalid("storage inventory duplicate row"));
        }
        bytes = add(bytes, row.logical_bytes)?;
        if bytes > expected.logical_bytes {
            return Err(invalid("storage inventory extra bytes"));
        }
        result.push(row);
    }
    if result.len() as u64 != expected.rows || bytes != expected.logical_bytes {
        return Err(invalid("storage inventory projection mismatch"));
    }
    Ok(result)
}
