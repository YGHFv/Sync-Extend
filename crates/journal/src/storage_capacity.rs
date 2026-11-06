//! Actual Journal liabilities, not configured writer or native execution authority.
use crate::{
    storage_inventory::reader::{
        add, hash, invalid, preflight, read_table, validate_schema, Namespace,
    },
    Journal, JournalStoredRow, Result, TreeRestoreInventoryLimits, SCHEMA_VERSION,
};
use rusqlite::{Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, SpaceId};

mod audit;
mod ordinary;
mod tree;

enum OwnerAudit {
    Initialized,
    LeaseTransaction,
    HistoryTransaction,
}

pub(crate) struct CapacitySnapshot {
    pub(crate) report: JournalStorageCapacity,
    pub(crate) rows: Vec<JournalStoredRow>,
}

const ACCOUNTING: &str =
    "actual-main-plus-audited-state-liabilities-v1;not-global-writer-enforcement";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCapacityLimits {
    pub inventory: TreeRestoreInventoryLimits,
    pub max_rows: u64,
    pub max_logical_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalCapacityObligation {
    pub family: &'static str,
    pub owner_key: Vec<String>,
    pub charge: TreeStorageCharge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalCapacityGap {
    pub family: &'static str,
    pub owner_key: Vec<String>,
    pub missing_contract: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalCapacityRow {
    pub table: String,
    pub primary_key: Vec<String>,
    pub fingerprint: ContentId,
    pub logical_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalCapacityReservation {
    pub table: String,
    pub reserved_rows: u64,
    pub reserved_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalTreeCapacity {
    pub transaction_id: sync_extend_core_model::EntryId,
    pub native_future_covered: bool,
    pub immutable_actual: TreeStorageCharge,
    pub outstanding_metadata: TreeStorageCharge,
    pub reserved_new: TreeStorageCharge,
    pub actual_new: TreeStorageCharge,
    pub charged_new: TreeStorageCharge,
    pub legacy_residual: TreeStorageCharge,
    pub stored_reservations: Vec<JournalCapacityReservation>,
    pub attributed_new_rows: Vec<JournalCapacityRow>,
    pub total: TreeStorageCharge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JournalStorageCapacity {
    accounting: &'static str,
    schema_version: u32,
    space_id: SpaceId,
    limits: JournalCapacityLimits,
    physical_inventory_hash: ContentId,
    actual: TreeStorageCharge,
    ordinary_actual: TreeStorageCharge,
    ordinary_outstanding: TreeStorageCharge,
    ordinary_obligations: Vec<JournalCapacityObligation>,
    coverage_gaps: Vec<JournalCapacityGap>,
    tree_owners: Vec<JournalTreeCapacity>,
    accounted_total: TreeStorageCharge,
    fingerprint: ContentId,
}

impl JournalStorageCapacity {
    pub fn accounting(&self) -> &str {
        self.accounting
    }
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
    pub fn space_id(&self) -> &SpaceId {
        &self.space_id
    }
    pub fn limits(&self) -> JournalCapacityLimits {
        self.limits
    }
    pub fn physical_inventory_hash(&self) -> &ContentId {
        &self.physical_inventory_hash
    }
    pub fn actual(&self) -> TreeStorageCharge {
        self.actual
    }
    pub fn ordinary_actual(&self) -> TreeStorageCharge {
        self.ordinary_actual
    }
    pub fn ordinary_outstanding(&self) -> TreeStorageCharge {
        self.ordinary_outstanding
    }
    pub fn ordinary_obligations(&self) -> &[JournalCapacityObligation] {
        &self.ordinary_obligations
    }
    pub fn coverage_gaps(&self) -> &[JournalCapacityGap] {
        &self.coverage_gaps
    }
    pub fn tree_owners(&self) -> &[JournalTreeCapacity] {
        &self.tree_owners
    }
    pub fn accounted_total(&self) -> TreeStorageCharge {
        self.accounted_total
    }
    pub fn within_accounted_limits(&self) -> bool {
        self.accounted_total.rows <= self.limits.max_rows
            && self.accounted_total.logical_bytes <= self.limits.max_logical_bytes
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn journal_inventory_verified(&self) -> bool {
        true
    }
    pub fn full_capacity_verified(&self) -> bool {
        false
    }
    pub fn writer_enforcement_available(&self) -> bool {
        false
    }
    pub fn native_execution_available(&self) -> bool {
        false
    }
    pub fn reference_release_available(&self) -> bool {
        false
    }
}

fn plus(left: TreeStorageCharge, right: TreeStorageCharge) -> Result<TreeStorageCharge> {
    Ok(TreeStorageCharge {
        rows: add(left.rows, right.rows)?,
        logical_bytes: add(left.logical_bytes, right.logical_bytes)?,
    })
}

fn row_charge(row: &JournalStoredRow) -> TreeStorageCharge {
    TreeStorageCharge {
        rows: 1,
        logical_bytes: row.logical_bytes(),
    }
}

impl Journal {
    /// Read one bounded main-database snapshot. Known liabilities are reported
    /// even above the requested charge limits; physical traversal stays bounded.
    /// A report does not reserve capacity or enable a writer or native effect.
    pub fn storage_capacity(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: JournalCapacityLimits,
    ) -> Result<JournalStorageCapacity> {
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let report = self
                .read_view()
                .audit_storage_capacity(space, max, bounds)?;
            tx.commit()?;
            return Ok(report);
        }
        self.read_view().audit_storage_capacity(space, max, bounds)
    }
}

impl crate::JournalReadView<'_> {
    pub(crate) fn audit_storage_capacity(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: JournalCapacityLimits,
    ) -> Result<JournalStorageCapacity> {
        self.capacity_snapshot(space, max, bounds, OwnerAudit::Initialized)
            .map(|snapshot| snapshot.report)
    }

    pub(crate) fn audit_lease_capacity(
        &self,
        space: &SpaceId,
        bounds: JournalCapacityLimits,
    ) -> Result<CapacitySnapshot> {
        self.capacity_snapshot(
            space,
            sync_extend_core_model::limits::MAX_ENTRIES,
            bounds,
            OwnerAudit::LeaseTransaction,
        )
    }

    pub(crate) fn audit_history_capacity(
        &self,
        space: &SpaceId,
        bounds: JournalCapacityLimits,
    ) -> Result<CapacitySnapshot> {
        self.capacity_snapshot(
            space,
            sync_extend_core_model::limits::MAX_ENTRIES,
            bounds,
            OwnerAudit::HistoryTransaction,
        )
    }

    fn capacity_snapshot(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: JournalCapacityLimits,
        owners: OwnerAudit,
    ) -> Result<CapacitySnapshot> {
        crate::tree_storage_inventory::validate_limits(max, bounds.inventory)?;
        if bounds.max_rows == 0
            || bounds.max_rows > max as u64
            || bounds.max_logical_bytes == 0
            || bounds.max_logical_bytes > max as u64 * 1024
        {
            return Err(invalid("journal capacity target limits"));
        }
        if self.connection.is_autocommit() {
            return Err(invalid("journal capacity requires owned snapshot"));
        }
        let specs = crate::storage_inventory::tables();
        validate_schema(self.connection, &specs, Namespace::All)?;
        let tables = preflight(
            self.connection,
            &specs,
            bounds.inventory.max_rows,
            bounds.inventory.max_logical_bytes,
        )?;
        crate::tree_native_storage::preflight_all(self.connection, max)?;
        let audited = match owners {
            OwnerAudit::Initialized => audit::owners(self, space, max)?,
            OwnerAudit::LeaseTransaction => audit::lease_owners(self, space, max, &tables)?,
            OwnerAudit::HistoryTransaction => audit::history_owners(self, space, max, &tables)?,
        };
        let mut rows = Vec::new();
        let mut actual = TreeStorageCharge::default();
        for (spec, expected) in specs.iter().zip(&tables) {
            for row in read_table(self.connection, spec, expected)? {
                actual = plus(actual, row_charge(&row))?;
                rows.push(row);
            }
        }
        let row_hashes: Vec<_> = rows.iter().map(JournalStoredRow::fingerprint).collect();
        let physical_inventory_hash = hash(&(
            "sync-extend.journal-capacity-physical-values.v1",
            SCHEMA_VERSION,
            space,
            &tables,
            &row_hashes,
        ))?;
        let mut liabilities = ordinary::liabilities(&audited, &rows)?;
        let tree_owners = tree::owners(self.connection, &audited.trees, &rows, max)?;
        let mut attributed = BTreeSet::new();
        let mut accounted_total = TreeStorageCharge::default();
        for owner in &tree_owners {
            accounted_total = plus(accounted_total, owner.total)?;
            for row in &owner.attributed_new_rows {
                if !attributed.insert((row.table.as_str(), row.primary_key.as_slice())) {
                    return Err(invalid("journal capacity NEW multiply attributed"));
                }
            }
            if !owner.native_future_covered {
                liabilities.gaps.push(JournalCapacityGap {
                    family: "tree_restore",
                    owner_key: vec![owner.transaction_id.to_string()],
                    missing_contract: "legacy-conservative-residual-not-native-future-admission",
                });
            }
        }
        let mut ordinary_actual = TreeStorageCharge::default();
        for row in &rows {
            if !tree::is_tree_table(row.table())
                && !attributed.contains(&(row.table(), row.primary_key()))
            {
                ordinary_actual = plus(ordinary_actual, row_charge(row))?;
            }
        }
        let attributed_actual = tree_owners.iter().try_fold(ordinary_actual, |sum, owner| {
            plus(sum, plus(owner.immutable_actual, owner.actual_new)?)
        })?;
        if attributed_actual != actual {
            return Err(invalid("journal capacity exact actual partition"));
        }
        let ordinary_outstanding = liabilities
            .obligations
            .iter()
            .try_fold(TreeStorageCharge::default(), |sum, o| plus(sum, o.charge))?;
        accounted_total = plus(
            accounted_total,
            plus(ordinary_actual, ordinary_outstanding)?,
        )?;
        let fingerprint = hash(&(
            "sync-extend.journal-capacity-ledger.v1",
            ACCOUNTING,
            SCHEMA_VERSION,
            space,
            bounds,
            &physical_inventory_hash,
            actual,
            ordinary_actual,
            ordinary_outstanding,
            &liabilities.obligations,
            &liabilities.gaps,
            &tree_owners,
            accounted_total,
        ))?;
        let report = JournalStorageCapacity {
            accounting: ACCOUNTING,
            schema_version: SCHEMA_VERSION,
            space_id: space.clone(),
            limits: bounds,
            physical_inventory_hash,
            actual,
            ordinary_actual,
            ordinary_outstanding,
            ordinary_obligations: liabilities.obligations,
            coverage_gaps: liabilities.gaps,
            tree_owners,
            accounted_total,
            fingerprint,
        };
        Ok(CapacitySnapshot { report, rows })
    }
}
