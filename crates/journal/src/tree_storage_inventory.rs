//! Bounded actual legacy values. This report is not an execution admission.
use crate::{storage_metadata_budget_usage, Journal, JournalError, Result};
use rusqlite::{Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    limits,
    tree_storage_footprint::{TreeStorageColumn, TreeStorageColumnValue},
    ContentId, EntryId, SpaceId,
};

pub(crate) mod schema;
use crate::storage_inventory::{
    reader::{add, hash, invalid, preflight, read_table, validate_schema, Namespace},
    JournalStorageColumnValue, JournalStoredRow,
};
use schema::TABLES;

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

pub(crate) fn validate_limits(max: usize, bounds: TreeRestoreInventoryLimits) -> Result<()> {
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

fn tree_row(row: JournalStoredRow) -> Result<TreeRestoreStoredRow> {
    let owner: EntryId = row
        .primary_key()
        .first()
        .ok_or(invalid("tree inventory missing owner key"))?
        .parse()?;
    let columns = row
        .columns()
        .iter()
        .map(|column| {
            let value = match &column.value {
                JournalStorageColumnValue::Text(text) => TreeStorageColumnValue::Text(text.clone()),
                JournalStorageColumnValue::Integer(n) => TreeStorageColumnValue::Integer(*n),
                JournalStorageColumnValue::Null => {
                    return Err(invalid("tree inventory null value"))
                }
            };
            Ok(TreeStorageColumn {
                name: column.name.clone(),
                value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let table = TABLES
        .iter()
        .find(|table| table.name == row.table())
        .ok_or(invalid("tree inventory unknown table"))?
        .name;
    let fingerprint = hash(&(
        "sync-extend.actual-tree-restore-row-values.v1",
        table,
        row.primary_key(),
        &columns,
    ))?;
    Ok(TreeRestoreStoredRow {
        table,
        owner,
        primary_key: row.primary_key().to_vec(),
        columns,
        logical_bytes: row.logical_bytes(),
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
    /// Reads all legacy tree-restore owners, including cancelled descriptions,
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
        validate_schema(&self.connection, TABLES, Namespace::TreeRestore)?;
        let physical_tables = preflight(
            &self.connection,
            TABLES,
            bounds.max_rows,
            bounds.max_logical_bytes,
        )
        .map_err(|error| match error {
            JournalError::Invariant("storage inventory row limit") => {
                invalid("tree inventory row limit")
            }
            JournalError::Invariant("storage inventory byte limit") => {
                invalid("tree inventory byte limit")
            }
            other => other,
        })?;
        let tables: Vec<_> = physical_tables
            .iter()
            .map(|t| TreeRestoreStoredTable {
                table: t.table,
                columns: t.columns,
                rows: t.rows,
                logical_bytes: t.logical_bytes,
            })
            .collect();
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
        let mut logical_bytes = 0;
        for (table, expected) in TABLES.iter().zip(&physical_tables) {
            for row in read_table(&self.connection, table, expected)? {
                let row = tree_row(row)?;
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
                logical_bytes = add(logical_bytes, row.logical_bytes)?;
                values.push(row);
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
