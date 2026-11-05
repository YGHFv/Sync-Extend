//! Owner-attributed selected row accounting, never a Journal admission token.
use crate::{
    limits,
    tree_final_terminal_layout::TreeFinalTerminalLayoutPlan,
    tree_restore_history::MAX_TREE_HISTORY_BYTES,
    tree_storage_footprint::{
        tree_final_history_row_values, TreeStorageRowKey, TreeStorageRowValues, TreeStorageTable,
    },
    EntryId, ModelError, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeStorageCharge {
    pub rows: u64,
    pub logical_bytes: u64,
}
impl TreeStorageCharge {
    fn add(self, other: Self) -> Result<Self> {
        Ok(Self {
            rows: self
                .rows
                .checked_add(other.rows)
                .ok_or(ModelError::InvalidData("tree capacity row overflow"))?,
            logical_bytes: self
                .logical_bytes
                .checked_add(other.logical_bytes)
                .ok_or(ModelError::InvalidData("tree capacity byte overflow"))?,
        })
    }
    fn max(self, other: Self) -> Self {
        Self {
            rows: self.rows.max(other.rows),
            logical_bytes: self.logical_bytes.max(other.logical_bytes),
        }
    }
    fn from_row(row: &TreeStorageRowValues) -> Self {
        Self {
            rows: 1,
            logical_bytes: row.logical_bytes(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeStorageMetadataObligation {
    /// One exact future row, not a second copy of a persisted reservation row.
    pub key: TreeStorageRowKey,
    pub max_logical_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeStorageOwnerInput {
    owner_id: EntryId,
    immutable_metadata: Vec<TreeStorageRowValues>,
    future_metadata: Vec<TreeStorageMetadataObligation>,
    /// NEW values only. Immutable history request/reservation rows belong above.
    reserved_new: TreeStorageCharge,
    /// Exact copies of rows from the supplied global history inventory.
    actual_new: Vec<TreeStorageRowValues>,
}
impl TreeStorageOwnerInput {
    /// Ownership comes from the exact typed final projection, not an arbitrary
    /// attribution of another owner's row. Supplied keys select persisted values.
    pub fn from_final_layout(
        plan: &TreeFinalTerminalLayoutPlan,
        immutable_metadata: Vec<TreeStorageRowValues>,
        future_metadata: Vec<TreeStorageMetadataObligation>,
        reserved_new: TreeStorageCharge,
        actual_new_keys: &[TreeStorageRowKey],
    ) -> Result<Self> {
        let projection = tree_final_history_row_values(plan)?;
        let mut keys = BTreeSet::new();
        let mut actual_new = Vec::new();
        for key in actual_new_keys {
            if !keys.insert(key) {
                return Err(ModelError::InvalidData(
                    "tree capacity duplicate selected NEW",
                ));
            }
            let row = projection
                .iter()
                .find(|row| row.is_new_history() && row.key() == key)
                .ok_or(ModelError::InvalidData(
                    "tree capacity NEW outside owner projection",
                ))?;
            actual_new.push(row.clone());
        }
        Ok(Self {
            owner_id: plan.rows().intent.scope.transaction_id.clone(),
            immutable_metadata,
            future_metadata,
            reserved_new,
            actual_new,
        })
    }
    pub fn owner_id(&self) -> &EntryId {
        &self.owner_id
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeStorageCapacityLimits {
    pub max_owners: usize,
    pub max_inventory_rows: usize,
    pub max_rows: u64,
    pub max_logical_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeStorageOwnerCharge {
    pub immutable_metadata: TreeStorageCharge,
    pub outstanding_metadata: TreeStorageCharge,
    pub actual_new: TreeStorageCharge,
    pub reserved_new: TreeStorageCharge,
    pub charged_new: TreeStorageCharge,
    pub total: TreeStorageCharge,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeStorageCapacityPlan {
    owners: BTreeMap<EntryId, TreeStorageOwnerCharge>,
    ordinary_history: TreeStorageCharge,
    total: TreeStorageCharge,
}
impl TreeStorageCapacityPlan {
    pub fn owners(&self) -> &BTreeMap<EntryId, TreeStorageOwnerCharge> {
        &self.owners
    }
    pub fn ordinary_history(&self) -> TreeStorageCharge {
        self.ordinary_history
    }
    pub fn total(&self) -> TreeStorageCharge {
        self.total
    }
    pub fn journal_inventory_verified(&self) -> bool {
        false
    }
    pub fn full_capacity_verified(&self) -> bool {
        false
    }
    pub fn native_execution_available(&self) -> bool {
        false
    }
}

fn metadata_table(table: TreeStorageTable) -> bool {
    !matches!(
        table,
        TreeStorageTable::Operation
            | TreeStorageTable::Snapshot
            | TreeStorageTable::SnapshotObject
            | TreeStorageTable::CurrentSnapshot
            | TreeStorageTable::Cursor
    )
}
fn row_owner(row: &TreeStorageRowValues, owner: &EntryId) -> bool {
    row.key()
        .key
        .first()
        .is_some_and(|key| key == owner.as_str())
}

/// Metadata obligation replacement requires the same owner and exact row key.
/// Global history excludes ONLY exact, singly-attributed own NEW row values.
/// Missing legacy inventory cannot be certified by this selected-layout model.
pub fn plan_tree_storage_capacity(
    owners: &[TreeStorageOwnerInput],
    global_history: &[TreeStorageRowValues],
    bounds: TreeStorageCapacityLimits,
) -> Result<TreeStorageCapacityPlan> {
    if bounds.max_owners > limits::MAX_ENTRIES
        || bounds.max_inventory_rows > limits::MAX_ENTRIES
        || bounds.max_rows > limits::MAX_ENTRIES as u64
        || bounds.max_logical_bytes > MAX_TREE_HISTORY_BYTES
        || owners.len() > bounds.max_owners
        || global_history.len() > bounds.max_inventory_rows
    {
        return Err(ModelError::InvalidData("tree capacity bounds"));
    }
    let mut history = BTreeMap::new();
    for row in global_history {
        if !row.is_new_history() || history.insert(row.key(), row).is_some() {
            return Err(ModelError::InvalidData(
                "tree capacity duplicate/non-history row",
            ));
        }
    }
    let mut owner_charges = BTreeMap::new();
    let mut metadata_keys = BTreeSet::new();
    let mut attributed = BTreeSet::new();
    let mut all_future_keys = BTreeSet::new();
    let mut inventory_count = global_history.len();
    let mut total = TreeStorageCharge::default();
    for owner in owners {
        if owner_charges.contains_key(&owner.owner_id) {
            return Err(ModelError::InvalidData("tree capacity duplicate owner"));
        }
        inventory_count = inventory_count
            .checked_add(owner.immutable_metadata.len())
            .and_then(|n| n.checked_add(owner.future_metadata.len()))
            .and_then(|n| n.checked_add(owner.actual_new.len()))
            .ok_or(ModelError::InvalidData("tree capacity inventory overflow"))?;
        if inventory_count > bounds.max_inventory_rows {
            return Err(ModelError::InvalidData("tree capacity inventory bounds"));
        }
        let mut immutable = TreeStorageCharge::default();
        let mut actual_metadata = BTreeMap::new();
        for row in &owner.immutable_metadata {
            if !metadata_table(row.key().table)
                || !row_owner(row, &owner.owner_id)
                || !metadata_keys.insert(row.key())
            {
                return Err(ModelError::InvalidData(
                    "tree capacity metadata attribution",
                ));
            }
            actual_metadata.insert(row.key(), row);
            immutable = immutable.add(TreeStorageCharge::from_row(row))?;
        }
        let mut outstanding = TreeStorageCharge::default();
        for obligation in &owner.future_metadata {
            if !metadata_table(obligation.key.table)
                || obligation.key.key.first() != Some(&owner.owner_id.to_string())
                || obligation.max_logical_bytes == 0
                || obligation.max_logical_bytes > MAX_TREE_HISTORY_BYTES
                || !all_future_keys.insert(&obligation.key)
            {
                return Err(ModelError::InvalidData("tree capacity future attribution"));
            }
            if let Some(actual) = actual_metadata.get(&obligation.key) {
                if actual.logical_bytes() > obligation.max_logical_bytes {
                    return Err(ModelError::InvalidData(
                        "tree capacity obligation underreserved",
                    ));
                }
            } else {
                outstanding = outstanding.add(TreeStorageCharge {
                    rows: 1,
                    logical_bytes: obligation.max_logical_bytes,
                })?;
            }
        }
        let mut actual_new = TreeStorageCharge::default();
        for row in &owner.actual_new {
            if history.get(row.key()).copied() != Some(row) || !attributed.insert(row.key()) {
                return Err(ModelError::InvalidData(
                    "tree capacity exact NEW attribution",
                ));
            }
            actual_new = actual_new.add(TreeStorageCharge::from_row(row))?;
        }
        let charged_new = owner.reserved_new.max(actual_new);
        let owner_total = immutable.add(outstanding)?.add(charged_new)?;
        total = total.add(owner_total)?;
        owner_charges.insert(
            owner.owner_id.clone(),
            TreeStorageOwnerCharge {
                immutable_metadata: immutable,
                outstanding_metadata: outstanding,
                actual_new,
                reserved_new: owner.reserved_new,
                charged_new,
                total: owner_total,
            },
        );
    }
    let mut ordinary_history = TreeStorageCharge::default();
    for row in global_history {
        if !attributed.contains(row.key()) {
            ordinary_history = ordinary_history.add(TreeStorageCharge::from_row(row))?;
        }
    }
    total = total.add(ordinary_history)?;
    if total.rows > bounds.max_rows || total.logical_bytes > bounds.max_logical_bytes {
        return Err(ModelError::InvalidData(
            "tree capacity total exceeds limits",
        ));
    }
    Ok(TreeStorageCapacityPlan {
        owners: owner_charges,
        ordinary_history,
        total,
    })
}
