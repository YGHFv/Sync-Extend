//! Exact Final rows are reconstructed from real action records and immutable inputs.
use super::*;
use sync_extend_core_model::{
    tree_final_terminal_layout::TreeFinalTerminalLayoutLimits,
    tree_native_final_layout::{
        plan_tree_native_final_layout, TreeNativeFinalLayoutInput, TreeNativeFinalLayoutPlan,
    },
    tree_storage_footprint::tree_final_terminal_row_values,
    tree_storage_footprint::TreeStorageTable,
};

pub(crate) fn terminal_table(table: TreeStorageTable) -> Result<&'static str> {
    Ok(match table {
        TreeStorageTable::FinalIntent => "tree_native_final_intents",
        TreeStorageTable::FinalCommitted => "tree_native_final_commits",
        TreeStorageTable::FinalInputRelease => "tree_native_input_releases",
        TreeStorageTable::FinalRetainedOwner => "tree_native_retained_owners",
        _ => return Err(invalid("tree Final unexpected row table")),
    })
}

pub(crate) fn plan(
    connection: &Connection,
    preparation: &TreeRestorePreparation,
    records: &[TreeNativeActionLayoutRecord],
    layout: &TreeNativeActionLayoutPlan,
    max: usize,
) -> Result<TreeNativeFinalLayoutPlan> {
    let prewrite = preparation
        .native_storage
        .as_ref()
        .ok_or(invalid("tree Final prewrite absent"))?;
    let future = preparation
        .native_future_admission
        .as_ref()
        .ok_or(invalid("tree Final capacity absent"))?;
    let (projection, protocol, _) = crate::tree_native_storage::initial_layout(
        connection,
        preparation,
        prewrite.request(),
        max,
    )?;
    let complete = layout
        .completed_native_layout()
        .ok_or(invalid("tree Final native actions incomplete"))?;
    // Actual live executor checks the complete layout before calling this
    // constructor. The hash binds precisely the retained observed namespace.
    let fresh = hash(&(
        "sync-extend-tree-exact-complete-native-v1",
        &complete.owner_directory,
        &complete.owner_marker,
        &complete.entries,
        &complete.retained_originals,
    ))?;
    plan_tree_native_final_layout(
        &projection.context(),
        &protocol,
        records,
        &TreeNativeFinalLayoutInput {
            format_version: 1,
            scope: layout.scope().clone(),
            finalization_id: future.generations().finalization_id.clone(),
            native_action_layout_hash: layout.fingerprint().clone(),
            fresh_observation_hash: fresh,
            intended_at_ms: complete.last_recorded_at_ms,
            committed_at_ms: complete.last_recorded_at_ms,
            prior_observation: future.prior_observation().cloned(),
        },
        TreeFinalTerminalLayoutLimits {
            max_records: prewrite.request().layout_limits.max_records,
            max_reference_rows: future.request().layout_limits.max_reference_rows,
            max_rows: future.request().layout_limits.max_rows as u64,
            max_input_bytes: prewrite.request().layout_limits.max_input_bytes,
            max_encoded_bytes: prewrite.request().layout_limits.max_encoded_bytes,
            max_logical_bytes: future
                .request()
                .layout_limits
                .max_logical_bytes
                .min(MAX_OPERATION_BYTES as u64),
        },
    )
    .map_err(Into::into)
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
                "tree_native_final_intents",
                "tree_native_final_commits",
                "tree_native_input_releases",
                "tree_native_retained_owners",
            ]
            .contains(&row.table())
                && row.primary_key().first().map(String::as_str) == Some(id)
        })
        .collect();
    if actual.is_empty() {
        return Ok(());
    }
    let complete_cleanup: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.tree_native_cleanup_records
         WHERE transaction_id=?1 AND record_index=3)",
        [id],
        |row| row.get(0),
    )?;
    let expected = plan(connection, preparation, records, layout, max)?;
    let values = tree_final_terminal_row_values(&expected)?;
    if values.len() != actual.len() {
        return Err(invalid("tree Final partial terminal bundle"));
    }
    for expected in values {
        let table = terminal_table(expected.key().table)?;
        let actual = actual
            .iter()
            .find(|row| row.table() == table && row.primary_key() == expected.key().key)
            .ok_or(invalid("tree Final exact terminal row absent"))?;
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
        if row_values(actual)? != values {
            return Err(invalid("tree Final exact terminal values differ"));
        }
        fulfilled.insert(
            (table.to_owned(), actual.primary_key().to_vec()),
            TreeStorageCharge {
                rows: 1,
                logical_bytes: actual.logical_bytes(),
            },
        );
    }
    verify_new_history(connection, &expected, !complete_cleanup)?;
    Ok(())
}

pub(super) fn verify_new_history(
    connection: &Connection,
    plan: &TreeNativeFinalLayoutPlan,
    active: bool,
) -> Result<()> {
    let rows = plan.history().rows();
    for row in &rows.operations {
        let actual: Option<(String, String, i64, String, String)> = connection.query_row(
            "SELECT space_id,origin_device_id,origin_seq,payload,state FROM main.operations WHERE op_id=?1",
            [row.op_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        ).optional()?;
        if actual
            != Some((
                row.space_id.to_string(),
                row.origin_device_id.to_string(),
                crate::sql_integer(row.origin_seq)?,
                row.payload.clone(),
                row.state.clone(),
            ))
        {
            return Err(invalid("tree Final exact NEW operation missing"));
        }
    }
    let snapshot = &rows.snapshot;
    let actual: Option<(String,String,i64,String,i64)> = connection.query_row(
        "SELECT space_id,manifest,created_at_ms,state,locked FROM main.snapshots WHERE snapshot_id=?1",
        [snapshot.snapshot_id.as_str()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
    ).optional()?;
    if actual
        != Some((
            snapshot.space_id.to_string(),
            snapshot.manifest.clone(),
            crate::sql_integer(snapshot.created_at_ms)?,
            snapshot.state.clone(),
            snapshot.locked as i64,
        ))
    {
        return Err(invalid("tree Final exact NEW snapshot missing"));
    }
    let objects: BTreeSet<String> = connection
        .prepare(
            "SELECT content_id FROM main.snapshot_objects WHERE snapshot_id=?1 ORDER BY content_id",
        )?
        .query_map([snapshot.snapshot_id.as_str()], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    if objects
        != rows
            .snapshot_objects
            .iter()
            .map(|row| row.content_id.to_string())
            .collect()
    {
        return Err(invalid(
            "tree Final exact NEW snapshot object closure differs",
        ));
    }
    let current: Option<String> = connection
        .query_row(
            "SELECT snapshot_id FROM main.current_manifests WHERE space_id=?1",
            [rows.current.space_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    let cursor: Option<i64> = connection
        .query_row(
            "SELECT contiguous_seq FROM main.receive_cursors WHERE space_id=?1 AND device_id=?2",
            rusqlite::params![
                rows.cursor.space_id.as_str(),
                rows.cursor.device_id.as_str()
            ],
            |row| row.get(0),
        )
        .optional()?;
    if active
        && (current.as_deref() != Some(rows.current.snapshot_id.as_str())
            || cursor != Some(crate::sql_integer(rows.cursor.contiguous_seq)?))
    {
        return Err(invalid("tree Final exact current/cursor differs"));
    }
    if active
        && connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.rename_observations WHERE space_id=?1)",
            [rows.current.space_id.as_str()],
            |row| row.get::<_, bool>(0),
        )?
    {
        return Err(invalid(
            "tree Final prior observation invalidation incomplete",
        ));
    }
    for release in &rows.input_release {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.tree_restore_objects WHERE transaction_id=?1 AND content_id=?2)",
            rusqlite::params![release.transaction_id.as_str(),release.content_id.as_str()],
            |row| row.get(0),
        )?;
        if exists {
            return Err(invalid("tree Final input-only pin release incomplete"));
        }
    }
    Ok(())
}
