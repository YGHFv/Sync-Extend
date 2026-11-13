//! Typed original release and cleanup accounting from actual Final lineage.
use super::*;
use sync_extend_core_model::{
    tree_native_final_layout::TreeNativeFinalLayoutPlan,
    tree_original_terminal_layout::{
        plan_tree_original_release_layout, plan_tree_original_terminal_layout,
        TreeOriginalTerminalLayoutInput, TreeOriginalTerminalLayoutLimits,
        TreeOriginalTerminalLayoutPlan, TreeOriginalTerminalRowsLayout,
    },
    tree_owner_cleanup_layout::{
        plan_tree_owner_cleanup_layout, TreeOwnerCleanupLayoutInput, TreeOwnerCleanupLayoutLimits,
        TreeOwnerCleanupLayoutPlan, TreeOwnerCleanupRecordLayout,
    },
    tree_owner_cleanup_values::tree_owner_cleanup_row_values,
    tree_storage_footprint::{
        tree_original_terminal_row_values, TreeStorageRowValues, TreeStorageTable,
    },
};

pub(crate) fn table(table: TreeStorageTable) -> Result<&'static str> {
    Ok(match table {
        TreeStorageTable::OriginalIntent => "tree_native_original_intents",
        TreeStorageTable::OriginalAbsence => "tree_native_original_absences",
        TreeStorageTable::OriginalTerminal => "tree_native_original_terminals",
        TreeStorageTable::OwnerCleanupIntent => "tree_native_cleanup_intents",
        TreeStorageTable::OwnerCleanupRecord => "tree_native_cleanup_records",
        _ => return Err(invalid("tree disposal unexpected table")),
    })
}

pub(crate) fn original_plan(
    final_plan: &TreeNativeFinalLayoutPlan,
    preparation: &TreeRestorePreparation,
) -> Result<(
    TreeOriginalTerminalLayoutPlan,
    TreeOriginalTerminalLayoutLimits,
)> {
    let future = preparation
        .native_future_admission
        .as_ref()
        .ok_or(invalid("tree disposal capacity"))?;
    let bounds = TreeOriginalTerminalLayoutLimits {
        max_owners: future.request().layout_limits.max_originals,
        max_reference_rows: future.request().layout_limits.max_reference_rows,
        max_input_bytes: future.request().layout_limits.max_input_bytes,
        max_encoded_bytes: future.request().layout_limits.max_encoded_bytes,
    };
    let plan = plan_tree_original_terminal_layout(
        final_plan,
        &TreeOriginalTerminalLayoutInput {
            final_terminal_layout_hash: final_plan.fingerprint().clone(),
            disposal_ids: future.generations().disposal_ids.clone(),
            intended_at_ms: final_plan.rows().committed.committed_at_ms,
        },
        bounds,
    )?;
    Ok((plan, bounds))
}

pub(crate) fn cleanup_plan(
    connection: &Connection,
    preparation: &TreeRestorePreparation,
    final_plan: &TreeNativeFinalLayoutPlan,
    originals: &TreeOriginalTerminalLayoutPlan,
    terminals: &BTreeMap<usize, TreeOriginalTerminalRowsLayout>,
    records: &[TreeOwnerCleanupRecordLayout],
    max: usize,
) -> Result<TreeOwnerCleanupLayoutPlan> {
    let prewrite = preparation
        .native_storage
        .as_ref()
        .ok_or(invalid("tree cleanup prewrite"))?;
    let future = preparation
        .native_future_admission
        .as_ref()
        .ok_or(invalid("tree cleanup capacity"))?;
    let (projection, _, _) = crate::tree_native_storage::initial_layout(
        connection,
        preparation,
        prewrite.request(),
        max,
    )?;
    Ok(plan_tree_owner_cleanup_layout(
        projection.context().owner,
        final_plan,
        originals,
        terminals,
        &TreeOwnerCleanupLayoutInput {
            cleanup_id: future.generations().cleanup_id.clone(),
            final_terminal_layout_hash: final_plan.fingerprint().clone(),
            original_terminal_layout_hash: originals.fingerprint().clone(),
            intended_at_ms: final_plan.rows().committed.committed_at_ms,
        },
        records,
        TreeOwnerCleanupLayoutLimits {
            max_originals: future.request().layout_limits.max_originals,
            max_reference_rows: future.request().layout_limits.max_reference_rows,
            max_records: 4,
            max_input_bytes: future.request().layout_limits.max_input_bytes,
            max_encoded_bytes: future.request().layout_limits.max_encoded_bytes,
        },
    )?)
}

fn exact(row: &JournalStoredRow, expected: &TreeStorageRowValues) -> Result<()> {
    let values: Vec<Value> = expected
        .columns()
        .iter()
        .map(|column| match &column.value {
            TreeStorageColumnValue::Text(value) => Ok(Value::Text(value.clone())),
            TreeStorageColumnValue::Integer(value) => {
                Ok(Value::Integer(crate::sql_integer(*value)?))
            }
        })
        .collect::<Result<_>>()?;
    if row.table() != table(expected.key().table)?
        || row.primary_key() != expected.key().key
        || row_values(row)? != values
    {
        return Err(invalid("tree disposal exact row values differ"));
    }
    Ok(())
}

pub(super) fn audit(
    connection: &Connection,
    preparation: &TreeRestorePreparation,
    records: &[TreeNativeActionLayoutRecord],
    layout: &TreeNativeActionLayoutPlan,
    rows: &[JournalStoredRow],
    max: usize,
    fulfilled: &mut BTreeMap<(String, Vec<String>), TreeStorageCharge>,
) -> Result<()> {
    let id = preparation.intent.transaction_id.as_str();
    let actual: Vec<_> = rows
        .iter()
        .filter(|row| {
            [
                "tree_native_original_intents",
                "tree_native_original_absences",
                "tree_native_original_terminals",
                "tree_native_cleanup_intents",
                "tree_native_cleanup_records",
            ]
            .contains(&row.table())
                && row.primary_key().first().map(String::as_str) == Some(id)
        })
        .collect();
    if actual.is_empty() {
        return Ok(());
    }
    if !rows.iter().any(|row| {
        row.table() == "tree_native_final_commits"
            && row.primary_key().first().map(String::as_str) == Some(id)
    }) {
        return Err(invalid("tree disposal before actual Final"));
    }
    let final_plan = super::final_state::plan(connection, preparation, records, layout, max)?;
    let (originals, bounds) = original_plan(&final_plan, preparation)?;
    let expected = tree_original_terminal_row_values(
        &originals,
        final_plan.rows().committed.committed_at_ms,
        bounds,
    )?;
    let mut seen = BTreeSet::new();
    let mut terminals = BTreeMap::new();
    for (&index, intent) in originals.intents() {
        let own: Vec<_> = actual
            .iter()
            .filter(|row| {
                row.table().starts_with("tree_native_original_")
                    && row.primary_key().get(1) == Some(&index.to_string())
            })
            .collect();
        if own.is_empty() {
            continue;
        }
        let present: BTreeSet<_> = own.iter().map(|row| row.table()).collect();
        if present != BTreeSet::from(["tree_native_original_intents"])
            && present
                != BTreeSet::from([
                    "tree_native_original_intents",
                    "tree_native_original_absences",
                    "tree_native_original_terminals",
                ])
        {
            return Err(invalid("tree original partial release transaction"));
        }
        for row in own {
            let expected = expected
                .iter()
                .find(|expected| {
                    table(expected.key().table).ok() == Some(row.table())
                        && expected.key().key == row.primary_key()
                })
                .ok_or(invalid("tree original unknown exact row"))?;
            exact(row, expected)?;
            seen.insert((row.table().to_owned(), row.primary_key().to_vec()));
        }
        if present.contains("tree_native_original_terminals") {
            terminals.insert(
                index,
                plan_tree_original_release_layout(
                    &originals,
                    index,
                    intent.intended_at_ms,
                    bounds,
                )?,
            );
        }
    }
    let cleanup_rows: Vec<_> = actual
        .iter()
        .filter(|row| row.table().starts_with("tree_native_cleanup_"))
        .collect();
    if !cleanup_rows.is_empty() {
        if terminals.len() != originals.intents().len() {
            return Err(invalid("tree cleanup original terminal closure incomplete"));
        }
        let mut cleanup_records = Vec::new();
        let mut sorted: Vec<_> = cleanup_rows
            .iter()
            .filter(|row| row.table() == "tree_native_cleanup_records")
            .collect();
        sorted.sort_by_key(|row| {
            row.primary_key()
                .get(1)
                .and_then(|value| value.parse::<usize>().ok())
        });
        for row in sorted {
            cleanup_records.push(serde_json::from_str::<TreeOwnerCleanupRecordLayout>(
                &text(row, "record")?,
            )?);
        }
        let cleanup = cleanup_plan(
            connection,
            preparation,
            &final_plan,
            &originals,
            &terminals,
            &cleanup_records,
            max,
        )?;
        let expected = tree_owner_cleanup_row_values(&cleanup)?;
        if expected.len() != cleanup_rows.len() {
            return Err(invalid("tree cleanup missing intent/record"));
        }
        for row in cleanup_rows {
            let value = expected
                .iter()
                .find(|expected| {
                    table(expected.key().table).ok() == Some(row.table())
                        && expected.key().key == row.primary_key()
                })
                .ok_or(invalid("tree cleanup unknown exact row"))?;
            exact(row, value)?;
            seen.insert((row.table().to_owned(), row.primary_key().to_vec()));
        }
    }
    if seen.len() != actual.len() {
        return Err(invalid("tree disposal orphan typed row"));
    }
    for row in actual {
        fulfilled.insert(
            (row.table().to_owned(), row.primary_key().to_vec()),
            TreeStorageCharge {
                rows: 1,
                logical_bytes: row.logical_bytes(),
            },
        );
    }
    Ok(())
}
