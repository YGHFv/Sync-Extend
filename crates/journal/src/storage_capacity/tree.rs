use super::{
    ordinary::{integer, text},
    plus, row_charge, JournalCapacityReservation, JournalCapacityRow, JournalTreeCapacity,
};
use crate::{
    storage_inventory::reader::invalid, JournalStorageColumnValue, JournalStoredRow, Result,
    TreeRestorePreparation,
};
use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    tree_native_future_obligations::plan_tree_native_future_obligations_with_observation,
    tree_storage_capacity::TreeStorageCharge,
    tree_storage_footprint::{TreeStorageColumnValue, TreeStorageRowValues, TreeStorageTable},
};

pub(super) fn is_tree_table(table: &str) -> bool {
    table.starts_with("tree_restore_") || table.starts_with("tree_native_")
}

fn difference(reserved: TreeStorageCharge, actual: TreeStorageCharge) -> TreeStorageCharge {
    TreeStorageCharge {
        rows: reserved.rows.saturating_sub(actual.rows),
        logical_bytes: reserved.logical_bytes.saturating_sub(actual.logical_bytes),
    }
}

fn group(rows: &[&JournalStoredRow], tables: &[&str]) -> Result<TreeStorageCharge> {
    rows.iter()
        .filter(|r| tables.contains(&r.table()))
        .try_fold(TreeStorageCharge::default(), |sum, row| {
            plus(sum, row_charge(row))
        })
}

fn named_table(table: TreeStorageTable) -> Result<&'static str> {
    Ok(match table {
        TreeStorageTable::Operation => "operations",
        TreeStorageTable::Snapshot => "snapshots",
        TreeStorageTable::SnapshotObject => "snapshot_objects",
        TreeStorageTable::CurrentSnapshot => "current_manifests",
        TreeStorageTable::Cursor => "receive_cursors",
        TreeStorageTable::ActionRecord => "tree_native_action_records",
        TreeStorageTable::ActionAttempt => "tree_native_action_attempts",
        TreeStorageTable::FinalIntent => "tree_native_final_intents",
        TreeStorageTable::FinalCommitted => "tree_native_final_commits",
        TreeStorageTable::FinalInputRelease => "tree_native_input_releases",
        TreeStorageTable::FinalRetainedOwner => "tree_native_retained_owners",
        TreeStorageTable::OriginalIntent => "tree_native_original_intents",
        TreeStorageTable::OriginalAbsence => "tree_native_original_absences",
        TreeStorageTable::OriginalTerminal => "tree_native_original_terminals",
        TreeStorageTable::OwnerCleanupIntent => "tree_native_cleanup_intents",
        TreeStorageTable::OwnerCleanupRecord => "tree_native_cleanup_records",
        _ => return Err(invalid("journal capacity unexpected future table")),
    })
}

fn exact(actual: &JournalStoredRow, expected: &TreeStorageRowValues) -> Result<bool> {
    if actual.table() != named_table(expected.key().table)?
        || actual.primary_key() != expected.key().key
        || actual.columns().len() != expected.columns().len()
        || actual.logical_bytes() != expected.logical_bytes()
    {
        return Ok(false);
    }
    Ok(expected.columns().iter().all(|expected| {
        actual.columns().iter().any(|actual| {
            actual.name == expected.name
                && match (&actual.value, &expected.value) {
                    (JournalStorageColumnValue::Text(a), TreeStorageColumnValue::Text(b)) => a == b,
                    (JournalStorageColumnValue::Integer(a), TreeStorageColumnValue::Integer(b)) => {
                        a == b
                    }
                    _ => false,
                }
        })
    }))
}

pub(super) fn owners(
    connection: &Connection,
    preparations: &[TreeRestorePreparation],
    rows: &[JournalStoredRow],
    max: usize,
) -> Result<Vec<JournalTreeCapacity>> {
    let mut grouped: BTreeMap<&str, Vec<&JournalStoredRow>> = BTreeMap::new();
    let mut inventory = BTreeMap::new();
    for row in rows {
        if inventory
            .insert((row.table(), row.primary_key()), row)
            .is_some()
        {
            return Err(invalid("journal capacity duplicate physical row"));
        }
        if is_tree_table(row.table()) {
            let owner = text(row, "transaction_id")?;
            if row.primary_key().first().map(String::as_str) != Some(owner) {
                return Err(invalid("journal capacity tree owner primary key"));
            }
            grouped.entry(owner).or_default().push(row);
        }
    }
    let mut result = Vec::new();
    let mut all_new = BTreeSet::new();
    for p in preparations {
        let owner_rows = grouped
            .remove(p.intent.transaction_id.as_str())
            .ok_or(invalid("journal capacity tree metadata missing"))?;
        let mut owner = JournalTreeCapacity {
            transaction_id: p.intent.transaction_id.clone(),
            native_future_covered: p.native_future_admission.is_some(),
            immutable_actual: owner_rows
                .iter()
                .try_fold(TreeStorageCharge::default(), |sum, row| {
                    plus(sum, row_charge(row))
                })?,
            outstanding_metadata: TreeStorageCharge::default(),
            reserved_new: TreeStorageCharge::default(),
            actual_new: TreeStorageCharge::default(),
            charged_new: TreeStorageCharge::default(),
            legacy_residual: TreeStorageCharge::default(),
            stored_reservations: Vec::new(),
            attributed_new_rows: Vec::new(),
            total: TreeStorageCharge::default(),
        };
        if let Some(future) = &p.native_future_admission {
            let prewrite = p
                .native_storage
                .as_ref()
                .ok_or(invalid("journal capacity prewrite missing"))?;
            let (projection, protocol, _) =
                crate::tree_native_storage::initial_layout(connection, p, prewrite.request(), max)?;
            let plan = plan_tree_native_future_obligations_with_observation(
                &projection.context(),
                &protocol,
                prewrite.intended(),
                future.generations(),
                future.request().layout_limits,
                future.prior_observation(),
            )?;
            if plan.obligations() != future.obligations()
                || plan.new_charge() != future.new_charge()
                || plan.future_charge() != future.future_charge()
            {
                return Err(invalid("journal capacity immutable future projection"));
            }
            let progress = crate::tree_native_effects::audit(connection, p, rows, max)?;
            let mut remaining = plan.future_charge();
            let mut seen_fulfilled = BTreeSet::new();
            for obligation in plan.obligations() {
                let key = (
                    named_table(obligation.key.table)?,
                    obligation.key.key.as_slice(),
                );
                if let Some(actual) = inventory.get(&key) {
                    let owned = (actual.table().to_owned(), actual.primary_key().to_vec());
                    if progress.fulfilled.get(&owned) != Some(&row_charge(actual))
                        || actual.logical_bytes() > obligation.max_logical_bytes
                        || !seen_fulfilled.insert(owned)
                    {
                        return Err(invalid("journal capacity unverified native fulfillment"));
                    }
                    remaining.rows = remaining
                        .rows
                        .checked_sub(1)
                        .ok_or(invalid("journal capacity native row underflow"))?;
                    remaining.logical_bytes = remaining
                        .logical_bytes
                        .checked_sub(obligation.max_logical_bytes)
                        .ok_or(invalid("journal capacity native byte underflow"))?;
                }
            }
            if seen_fulfilled.len() != progress.fulfilled.len() {
                return Err(invalid(
                    "journal capacity native fulfillment outside reservation",
                ));
            }
            owner.outstanding_metadata = remaining;
            owner.reserved_new = plan.new_charge();
            for expected in plan.exact_new_values() {
                if !expected.is_new_history() {
                    return Err(invalid("journal capacity non-NEW future value"));
                }
                let key = (
                    named_table(expected.key().table)?,
                    expected.key().key.as_slice(),
                );
                if let Some(actual) = inventory.get(&key) {
                    if exact(actual, expected)? {
                        let owned_key = (actual.table(), actual.primary_key());
                        if !all_new.insert(owned_key) {
                            return Err(invalid("journal capacity multiple NEW owners"));
                        }
                        owner.actual_new = plus(owner.actual_new, row_charge(actual))?;
                        owner.attributed_new_rows.push(JournalCapacityRow {
                            table: actual.table().to_owned(),
                            primary_key: actual.primary_key().to_vec(),
                            fingerprint: actual.fingerprint().clone(),
                            logical_bytes: actual.logical_bytes(),
                        });
                    }
                }
            }
            owner.charged_new = TreeStorageCharge {
                rows: owner.reserved_new.rows.max(owner.actual_new.rows),
                logical_bytes: owner
                    .reserved_new
                    .logical_bytes
                    .max(owner.actual_new.logical_bytes),
            };
            let finalized: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.tree_native_final_commits WHERE transaction_id=?1)",
                [p.intent.transaction_id.as_str()], |row| row.get(0),
            )?;
            if finalized {
                owner.charged_new = owner.actual_new;
            }
        }
        for row in &owner_rows {
            if row.columns().iter().any(|c| c.name == "reserved_rows") {
                let reserved = TreeStorageCharge {
                    rows: integer(row, "reserved_rows")?,
                    logical_bytes: integer(row, "reserved_bytes")?,
                };
                owner.stored_reservations.push(JournalCapacityReservation {
                    table: row.table().into(),
                    reserved_rows: reserved.rows,
                    reserved_bytes: reserved.logical_bytes,
                });
                let residual = residual(p, &owner_rows, row.table(), reserved)?;
                owner.legacy_residual = plus(owner.legacy_residual, residual)?;
            }
        }
        owner.total = plus(
            plus(owner.immutable_actual, owner.outstanding_metadata)?,
            plus(owner.charged_new, owner.legacy_residual)?,
        )?;
        result.push(owner);
    }
    if !grouped.is_empty() {
        return Err(invalid("journal capacity orphan tree metadata"));
    }
    Ok(result)
}

fn residual(
    preparation: &TreeRestorePreparation,
    rows: &[&JournalStoredRow],
    table: &str,
    reserved: TreeStorageCharge,
) -> Result<TreeStorageCharge> {
    let covered = preparation.native_future_admission.is_some();
    let tables: &[&str] = match table {
        // The audited native context already stores all prerequisite headers
        // and pins, excludes descriptive progress and permanently bars cancel.
        // Its exact future covers the remaining native/final/original/cleanup
        // rows; the old B1 counters remain actual, separately reported values.
        "tree_restore_preparations" if covered => return Ok(TreeStorageCharge::default()),
        "tree_restore_histories" if covered => return Ok(TreeStorageCharge::default()),
        "tree_restore_original_reservations" if covered => return Ok(TreeStorageCharge::default()),
        "tree_restore_preparations" => &[
            "tree_restore_preparations",
            "tree_restore_steps",
            "tree_restore_objects",
            "tree_restore_cancellations",
        ],
        "tree_restore_histories" => &["tree_restore_histories"],
        "tree_restore_native_reservations" => &["tree_restore_native_reservations"],
        "tree_restore_execution_intents" => &[
            "tree_restore_execution_intents",
            "tree_restore_execution_step_intents",
        ],
        "tree_restore_original_reservations" => &[
            "tree_restore_original_reservations",
            "tree_restore_original_owners",
            "tree_restore_original_objects",
        ],
        "tree_restore_disposition_reservations" => &[
            "tree_restore_disposition_reservations",
            "tree_restore_disposition_intents",
        ],
        _ => return Err(invalid("journal capacity unknown stored reservation")),
    };
    let actual = group(rows, tables)?;
    if table == "tree_restore_preparations" {
        let mut legacy_rows = 0u64;
        let mut legacy_bytes = 0u64;
        for row in rows {
            let charge = match row.table() {
                "tree_restore_preparations" => (1, text(row, "intent")?.len() as u64 + 4096),
                "tree_restore_steps" => (3, text(row, "step")?.len() as u64 + 4096),
                "tree_restore_objects" => (1, 128),
                "tree_restore_cancellations" => (1, 0),
                _ => (0, 0),
            };
            legacy_rows = super::add(legacy_rows, charge.0)?;
            legacy_bytes = super::add(legacy_bytes, charge.1)?;
        }
        return Ok(difference(
            TreeStorageCharge {
                rows: reserved.rows.max(legacy_rows),
                logical_bytes: reserved.logical_bytes.max(legacy_bytes),
            },
            actual,
        ));
    }
    Ok(difference(reserved, actual))
}
