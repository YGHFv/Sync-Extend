//! Bounded actual legacy values. This report is not an execution admission.
use crate::{storage_metadata_budget_usage, Journal, JournalError, Result, MAX_OPERATION_BYTES};
use rusqlite::{types::ValueRef, Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    limits,
    tree_storage_footprint::{TreeStorageColumn, TreeStorageColumnValue},
    ContentId, EntryId, SpaceId,
};

mod schema;
use schema::TABLES;

#[derive(Clone, Copy)]
enum ColumnKind {
    Text(usize),
    Integer,
}
struct ColumnSpec {
    name: &'static str,
    kind: ColumnKind,
    primary_key: usize,
    not_null: bool,
}
struct TableSpec {
    name: &'static str,
    columns: &'static [ColumnSpec],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreInventoryLimits {
    pub max_rows: usize,
    pub max_logical_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreStoredRow {
    table: &'static str,
    owner: EntryId,
    primary_key: Vec<String>,
    columns: Vec<TreeStorageColumn>,
    logical_bytes: u64,
    fingerprint: ContentId,
}
impl TreeRestoreStoredRow {
    pub fn table(&self) -> &str {
        self.table
    }
    pub fn owner(&self) -> &EntryId {
        &self.owner
    }
    pub fn primary_key(&self) -> &[String] {
        &self.primary_key
    }
    pub fn columns(&self) -> &[TreeStorageColumn] {
        &self.columns
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreStoredTable {
    pub table: &'static str,
    pub columns: usize,
    pub rows: u64,
    pub logical_bytes: u64,
}

/// Persisted reservation counters, not an additive charge or a future release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreStoredReservation {
    pub table: &'static str,
    pub reserved_rows: u64,
    pub reserved_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreStoredOwner {
    pub transaction_id: EntryId,
    pub cancelled_at_ms: Option<u64>,
    pub rows: u64,
    pub logical_bytes: u64,
    pub stored_reservations: Vec<TreeRestoreStoredReservation>,
}

/// The unchanged whole-Journal conservative check, separate from actual values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreLegacyBudget {
    pub rows: u64,
    pub metadata_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreStorageInventory {
    accounting: &'static str,
    space_id: SpaceId,
    rows: Vec<TreeRestoreStoredRow>,
    tables: Vec<TreeRestoreStoredTable>,
    owners: Vec<TreeRestoreStoredOwner>,
    logical_bytes: u64,
    legacy_budget: TreeRestoreLegacyBudget,
    fingerprint: ContentId,
}
impl TreeRestoreStorageInventory {
    pub fn accounting(&self) -> &str {
        self.accounting
    }
    pub fn space_id(&self) -> &SpaceId {
        &self.space_id
    }
    pub fn rows(&self) -> &[TreeRestoreStoredRow] {
        &self.rows
    }
    pub fn tables(&self) -> &[TreeRestoreStoredTable] {
        &self.tables
    }
    pub fn owners(&self) -> &[TreeRestoreStoredOwner] {
        &self.owners
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn legacy_budget(&self) -> &TreeRestoreLegacyBudget {
        &self.legacy_budget
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
}

fn invalid(message: &'static str) -> JournalError {
    JournalError::Invariant(message)
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or(invalid("tree inventory arithmetic overflow"))
}

fn hash<T: Serialize>(value: &T) -> Result<ContentId> {
    Ok(ContentId::hash(&serde_json::to_vec(value)?))
}

fn validate_limits(max: usize, bounds: TreeRestoreInventoryLimits) -> Result<()> {
    if max == 0
        || max > limits::MAX_ENTRIES
        || bounds.max_rows == 0
        || bounds.max_rows > max
        || bounds.max_logical_bytes == 0
        || bounds.max_logical_bytes > max as u64 * 1024
    {
        return Err(invalid("tree inventory limits"));
    }
    Ok(())
}

// Qualify main throughout; a same-name TEMP table must never shadow the audit.
fn validate_schema(connection: &Connection) -> Result<()> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version != 31 {
        return Err(invalid("tree inventory schema version"));
    }
    let mut list = connection.prepare(
        "SELECT name,type,ncol,wr,strict FROM pragma_table_list
         WHERE schema='main' AND lower(substr(name,1,13))='tree_restore_' ORDER BY name",
    )?;
    let mut rows = list.query([])?;
    let mut seen = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let spec = TABLES
            .iter()
            .find(|table| table.name == name)
            .ok_or(invalid("tree inventory unknown table"))?;
        if !seen.insert(name)
            || row.get::<_, String>(1)? != "table"
            || row.get::<_, i64>(2)? != spec.columns.len() as i64
            || row.get::<_, i64>(3)? != 0
            || row.get::<_, i64>(4)? != 1
        {
            return Err(invalid("tree inventory table layout"));
        }
        let mut info = connection.prepare(
            "SELECT cid,name,type,\"notnull\",dflt_value,pk,hidden
             FROM pragma_table_xinfo(?1,'main') ORDER BY cid",
        )?;
        let mut columns = info.query([spec.name])?;
        for (index, expected) in spec.columns.iter().enumerate() {
            let actual = columns
                .next()?
                .ok_or(invalid("tree inventory missing column"))?;
            let declared = match expected.kind {
                ColumnKind::Text(_) => "TEXT",
                ColumnKind::Integer => "INTEGER",
            };
            if actual.get::<_, i64>(0)? != index as i64
                || actual.get::<_, String>(1)? != expected.name
                || actual.get::<_, String>(2)? != declared
                || actual.get::<_, bool>(3)? != expected.not_null
                || !matches!(actual.get_ref(4)?, ValueRef::Null)
                || actual.get::<_, i64>(5)? != expected.primary_key as i64
                || actual.get::<_, i64>(6)? != 0
            {
                return Err(invalid("tree inventory column layout"));
            }
        }
        if columns.next()?.is_some() {
            return Err(invalid("tree inventory extra column"));
        }
    }
    if seen.len() != TABLES.len() {
        return Err(invalid("tree inventory missing table"));
    }
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE type IN ('table','view') AND lower(substr(name,1,13))='tree_restore_')",
        [],
        |r| r.get(0),
    )?;
    if shadow {
        return Err(invalid("tree inventory shadowed table"));
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
        ColumnKind::Integer => format!("typeof(\"{name}\")='integer' AND \"{name}\">=0"),
    }
}

// Bound rows and every physical value before any legacy typed reader loads JSON.
fn preflight(
    connection: &Connection,
    bounds: TreeRestoreInventoryLimits,
) -> Result<Vec<TreeRestoreStoredTable>> {
    let mut total_rows = 0;
    let mut total_bytes = 0;
    let mut tables = Vec::new();
    for table in TABLES {
        let remaining = bounds.max_rows as u64 - total_rows;
        let count: i64 = connection.query_row(
            &format!(
                "SELECT count(*) FROM (SELECT 1 FROM main.{} LIMIT ?1)",
                table.name
            ),
            [remaining as i64 + 1],
            |r| r.get(0),
        )?;
        let count = u64::try_from(count).map_err(|_| invalid("tree inventory row count"))?;
        total_rows = add(total_rows, count)?;
        if total_rows > bounds.max_rows as u64 {
            return Err(invalid("tree inventory row limit"));
        }
        let expressions: Vec<String> = table
            .columns
            .iter()
            .map(|c| {
                let bytes = match c.kind {
                    ColumnKind::Text(_) => format!("length(CAST(\"{}\" AS BLOB))", c.name),
                    ColumnKind::Integer => "8".into(),
                };
                format!("CASE WHEN {} THEN {bytes} ELSE -1 END", validity(c))
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
                    .map_err(|_| invalid("tree inventory physical value type or bounds"))?;
                bytes = add(bytes, size)?;
                total_bytes = add(total_bytes, size)?;
                if total_bytes > bounds.max_logical_bytes {
                    return Err(invalid("tree inventory byte limit"));
                }
            }
            actual_rows += 1;
        }
        if actual_rows != count {
            return Err(invalid("tree inventory row count changed"));
        }
        tables.push(TreeRestoreStoredTable {
            table: table.name,
            columns: table.columns.len(),
            rows: count,
            logical_bytes: bytes,
        });
    }
    Ok(tables)
}

fn validate_text(raw: &[u8], bound: usize) -> Result<&str> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid("tree inventory text encoding"))?;
    if bound == MAX_OPERATION_BYTES {
        if raw.is_empty() || raw.len() > bound {
            return Err(invalid("tree inventory JSON size"));
        }
    } else if raw.len() != bound
        || !raw
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(invalid("tree inventory identifier encoding"));
    }
    Ok(text)
}

fn read_row(table: &TableSpec, row: &rusqlite::Row<'_>) -> Result<TreeRestoreStoredRow> {
    let mut columns = Vec::new();
    let mut key = BTreeMap::new();
    let mut bytes = 0;
    for (index, spec) in table.columns.iter().enumerate() {
        let (value, size, key_value) = match (spec.kind, row.get_ref(index)?) {
            (ColumnKind::Text(bound), ValueRef::Text(raw)) => {
                let text = validate_text(raw, bound)?.to_owned();
                let key_value = (spec.primary_key != 0).then(|| text.clone());
                (
                    TreeStorageColumnValue::Text(text),
                    raw.len() as u64,
                    key_value,
                )
            }
            (ColumnKind::Integer, ValueRef::Integer(n)) if n >= 0 => (
                TreeStorageColumnValue::Integer(n as u64),
                8,
                (spec.primary_key != 0).then(|| n.to_string()),
            ),
            _ => return Err(invalid("tree inventory value changed")),
        };
        if let Some(value) = key_value {
            key.insert(spec.primary_key, value);
        }
        bytes = add(bytes, size)?;
        columns.push(TreeStorageColumn {
            name: spec.name.into(),
            value,
        });
    }
    let primary_key: Vec<String> = key.into_values().collect();
    let owner: EntryId = primary_key
        .first()
        .ok_or(invalid("tree inventory missing owner key"))?
        .parse()?;
    let fingerprint = hash(&(
        "sync-extend.actual-tree-restore-row-values.v1",
        table.name,
        &primary_key,
        &columns,
    ))?;
    Ok(TreeRestoreStoredRow {
        table: table.name,
        owner,
        primary_key,
        columns,
        logical_bytes: bytes,
        fingerprint,
    })
}

fn integer(row: &TreeRestoreStoredRow, name: &str) -> Result<Option<u64>> {
    row.columns
        .iter()
        .find(|c| c.name == name)
        .map(|c| match c.value {
            TreeStorageColumnValue::Integer(n) => Ok(n),
            _ => Err(invalid("tree inventory reservation integer")),
        })
        .transpose()
}

impl Journal {
    /// Reads all schema31 tree-restore owners, including cancelled descriptions,
    /// in one SQL snapshot. Does not touch CAS bytes or inspect the native tree.
    pub fn tree_restore_storage_inventory(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: TreeRestoreInventoryLimits,
    ) -> Result<TreeRestoreStorageInventory> {
        validate_limits(max, bounds)?;
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let inventory = self.audit_tree_restore_storage_inventory(space, max, bounds)?;
            tx.commit()?;
            return Ok(inventory);
        }
        self.audit_tree_restore_storage_inventory(space, max, bounds)
    }

    fn audit_tree_restore_storage_inventory(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: TreeRestoreInventoryLimits,
    ) -> Result<TreeRestoreStorageInventory> {
        validate_schema(&self.connection)?;
        let tables = preflight(&self.connection, bounds)?;
        let preparations = self.tree_restore_preparations(space, max)?;
        let mut owners = BTreeMap::new();
        for p in preparations {
            let id = p.intent.transaction_id;
            if owners
                .insert(
                    id.clone(),
                    TreeRestoreStoredOwner {
                        transaction_id: id,
                        cancelled_at_ms: p.cancelled_at_ms,
                        rows: 0,
                        logical_bytes: 0,
                        stored_reservations: Vec::new(),
                    },
                )
                .is_some()
            {
                return Err(invalid("tree inventory duplicate owner"));
            }
        }
        let mut values = Vec::new();
        let mut keys = BTreeSet::new();
        let mut logical_bytes = 0;
        for (table, expected) in TABLES.iter().zip(&tables) {
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
            let mut statement = self.connection.prepare(&format!(
                "SELECT {selected} FROM main.{} ORDER BY {order}",
                table.name
            ))?;
            let mut rows = statement.query([])?;
            let mut count = 0;
            let mut bytes = 0;
            while let Some(row) = rows.next()? {
                let row = read_row(table, row)?;
                if !keys.insert((row.table, row.primary_key.clone())) {
                    return Err(invalid("tree inventory duplicate row"));
                }
                let owner = owners
                    .get_mut(&row.owner)
                    .ok_or(invalid("tree inventory orphan owner"))?;
                owner.rows = add(owner.rows, 1)?;
                owner.logical_bytes = add(owner.logical_bytes, row.logical_bytes)?;
                if let Some(reserved_rows) = integer(&row, "reserved_rows")? {
                    let reserved_bytes = integer(&row, "reserved_bytes")?
                        .ok_or(invalid("tree inventory missing reserved bytes"))?;
                    owner
                        .stored_reservations
                        .push(TreeRestoreStoredReservation {
                            table: row.table,
                            reserved_rows,
                            reserved_bytes,
                        });
                }
                count += 1;
                bytes = add(bytes, row.logical_bytes)?;
                logical_bytes = add(logical_bytes, row.logical_bytes)?;
                values.push(row);
            }
            if count != expected.rows || bytes != expected.logical_bytes {
                return Err(invalid("tree inventory projection mismatch"));
            }
        }
        if values.len() > bounds.max_rows || logical_bytes > bounds.max_logical_bytes {
            return Err(invalid("tree inventory projection limit"));
        }
        let owners: Vec<_> = owners.into_values().collect();
        let (rows, metadata_bytes) = storage_metadata_budget_usage(&self.connection)?;
        let legacy_budget = TreeRestoreLegacyBudget {
            rows,
            metadata_bytes,
        };
        let row_hashes: Vec<_> = values.iter().map(|r| &r.fingerprint).collect();
        let fingerprint = hash(&(
            "sync-extend.actual-tree-restore-inventory.v1",
            space,
            &tables,
            &owners,
            &row_hashes,
            logical_bytes,
            &legacy_budget,
        ))?;
        Ok(TreeRestoreStorageInventory {
            accounting:
                "all_schema31_tree_restore_values_not_complete_capacity_or_native_authority",
            space_id: space.clone(),
            rows: values,
            tables,
            owners,
            logical_bytes,
            legacy_budget,
            fingerprint,
        })
    }
}
