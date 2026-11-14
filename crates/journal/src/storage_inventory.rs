//! Exact persisted values, not future capacity or native execution authority.
use crate::{
    storage_metadata_budget_usage, Journal, Result, TreeRestoreInventoryLimits,
    TreeRestoreLegacyBudget, TreeRestorePreparation, SCHEMA_VERSION,
};
use rusqlite::{Transaction, TransactionBehavior};
use serde::Serialize;
use sync_extend_core_model::{ContentId, SpaceId};

pub(crate) mod reader;
mod schema;
use reader::{add, hash, invalid, preflight, read_table, validate_schema, Namespace, TableSpec};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum JournalStorageColumnValue {
    Null,
    Text(String),
    Integer(u64),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalStorageColumn {
    pub name: String,
    pub value: JournalStorageColumnValue,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalStoredRow {
    table: &'static str,
    primary_key: Vec<String>,
    columns: Vec<JournalStorageColumn>,
    logical_bytes: u64,
    fingerprint: ContentId,
}
impl JournalStoredRow {
    pub fn table(&self) -> &str {
        self.table
    }
    pub fn primary_key(&self) -> &[String] {
        &self.primary_key
    }
    pub fn columns(&self) -> &[JournalStorageColumn] {
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
pub struct JournalStoredTable {
    pub table: &'static str,
    pub columns: usize,
    pub rows: u64,
    pub logical_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalStorageInventory {
    accounting: &'static str,
    schema_version: u32,
    space_id: SpaceId,
    rows: Vec<JournalStoredRow>,
    tables: Vec<JournalStoredTable>,
    logical_bytes: u64,
    conservative_budget: TreeRestoreLegacyBudget,
    fingerprint: ContentId,
}
impl JournalStorageInventory {
    pub fn accounting(&self) -> &str {
        self.accounting
    }
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn space_id(&self) -> &SpaceId {
        &self.space_id
    }
    pub fn rows(&self) -> &[JournalStoredRow] {
        &self.rows
    }
    pub fn tables(&self) -> &[JournalStoredTable] {
        &self.tables
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn conservative_budget(&self) -> &TreeRestoreLegacyBudget {
        &self.conservative_budget
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
}

pub(crate) fn tables() -> Vec<TableSpec> {
    [
        schema::TABLES,
        crate::original_provenance::TABLES,
        crate::original_page_inbox::TABLES,
        crate::forwarded_page_inbox::TABLES,
        crate::storage_page_handoff::TABLES,
        crate::storage_snapshot_handoff::TABLES,
        crate::storage_retirement::schema::TABLES,
        crate::storage_retirement::owner_schema::TABLES,
        crate::storage_retirement::payload_schema::TABLES,
        crate::storage_retirement::disposal_schema::TABLES,
        crate::storage_retirement::terminal_schema::TABLES,
        crate::webdav_native::schema::TABLES,
        crate::tree_storage_inventory::schema::TABLES,
        crate::tree_native_storage::schema::TABLES,
        crate::tree_native_future::schema::TABLES,
        crate::tree_native_future::schema::EFFECT_TABLES,
        crate::native_publication::schema::TABLES,
        crate::remote_rename::schema::TABLES,
        crate::remote_delete::schema::TABLES,
        crate::remote_replace::schema::TABLES,
        crate::conflict_resolution::schema::TABLES,
        crate::conflict_resolution::native_future_schema::TABLES,
    ]
    .concat()
}

impl Journal {
    /// One bounded snapshot of every named main user-table value. NULL is zero,
    /// TEXT uses UTF8 length and INTEGER eight bytes, including alias-rowid PKs.
    /// This does not certify ordinary future obligations or native effects.
    pub fn storage_inventory(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: TreeRestoreInventoryLimits,
    ) -> Result<JournalStorageInventory> {
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let (inventory, _) = self.audit_storage_inventory(space, max, bounds)?;
            tx.commit()?;
            return Ok(inventory);
        }
        self.audit_storage_inventory(space, max, bounds)
            .map(|r| r.0)
    }

    pub(crate) fn audit_storage_inventory(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: TreeRestoreInventoryLimits,
    ) -> Result<(JournalStorageInventory, Vec<TreeRestorePreparation>)> {
        crate::tree_storage_inventory::validate_limits(max, bounds)?;
        let specs = tables();
        validate_schema(&self.connection, &specs, Namespace::All)?;
        let tables = preflight(
            &self.connection,
            &specs,
            bounds.max_rows,
            bounds.max_logical_bytes,
        )?;
        // The all-owner audit is deliberately after the whole-database preflight.
        let preparations = self.tree_restore_preparations(space, max)?;
        crate::webdav_native::audit(&self.connection)?;
        crate::tree_native_effects::validate_all(&self.connection, &preparations, max)?;
        let mut rows = Vec::new();
        let mut logical_bytes = 0;
        for (spec, expected) in specs.iter().zip(&tables) {
            let values = read_table(&self.connection, spec, expected)?;
            logical_bytes = add(logical_bytes, expected.logical_bytes)?;
            rows.extend(values);
        }
        if rows.len() > bounds.max_rows || logical_bytes > bounds.max_logical_bytes {
            return Err(invalid("storage inventory total bounds"));
        }
        crate::native_publication::validate_schema(&self.connection)?;
        crate::remote_rename::obligations(&rows, &self.connection)?;
        crate::remote_delete::obligations(&rows, &self.connection)?;
        crate::remote_replace::obligations(&rows, &self.connection)?;
        crate::conflict_resolution::obligations(&rows, &self.connection)?;
        crate::original_provenance::audit(&self.connection)?;
        crate::original_page_inbox::audit(&self.connection)?;
        crate::forwarded_page_inbox::audit(&self.connection)?;
        crate::storage_page_handoff::audit(&self.connection)?;
        crate::storage_snapshot_handoff::audit(&self.connection)?;
        if rows
            .iter()
            .any(|row| row.table() == "native_publication_headers")
        {
            crate::native_publication::scope(&rows, &self.connection)?;
            crate::native_publication::obligations(&rows, &self.read_view().publications(space)?)?;
        }
        let (budget_rows, metadata_bytes) = storage_metadata_budget_usage(&self.connection)?;
        let conservative_budget = TreeRestoreLegacyBudget {
            rows: budget_rows,
            metadata_bytes,
        };
        let hashes: Vec<_> = rows.iter().map(|r| &r.fingerprint).collect();
        let fingerprint = hash(&(
            "sync-extend.actual-journal-inventory.v1",
            SCHEMA_VERSION,
            space,
            &tables,
            &hashes,
            logical_bytes,
            &conservative_budget,
        ))?;
        Ok((
            JournalStorageInventory {
                accounting: "actual-main-user-column-values-v1;null=0;text=utf8;integer=8",
                schema_version: SCHEMA_VERSION,
                space_id: space.clone(),
                rows,
                tables,
                logical_bytes,
                conservative_budget,
                fingerprint,
            },
            preparations,
        ))
    }
}
