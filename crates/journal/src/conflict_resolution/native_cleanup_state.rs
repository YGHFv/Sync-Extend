//! Terminal authority requires the complete immutable ledger, not a phase flag.
use super::*;

pub(super) fn present(connection: &Connection, parent: &Header) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.conflict_resolution_native_phases WHERE transaction_id=?1 AND phase='cleanup')",
        [parent.transaction_id.as_str()], |r|r.get(0),
    )?)
}

pub(super) fn complete(connection: &Connection, parent: &Header) -> Result<bool> {
    if !present(connection, parent)? {
        return Ok(false);
    }
    let specs = all_tables();
    let counts = preflight(
        connection,
        &specs,
        sync_extend_core_model::limits::MAX_ENTRIES,
        sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let rows = specs
        .iter()
        .zip(&counts)
        .map(|(spec, count)| crate::storage_inventory::reader::read_table(connection, spec, count))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .filter(|row| {
            row.primary_key().first().map(String::as_str) == Some(parent.transaction_id.as_str())
        })
        .collect::<Vec<_>>();
    let header = native_ledger_storage::stored(connection, parent)?
        .ok_or(invalid("conflict cleanup original native header absent"))?;
    let binding = native_binding::stored(connection, parent)?
        .ok_or(invalid("conflict cleanup original binding absent"))?;
    let ledger = header.validate(parent, &binding)?;
    let effects = native_effects::audit(&header, &binding, &ledger, &rows)?;
    if !effects.remaining.is_empty() || !effects.fulfilled.contains("phase/cleanup") {
        return Err(invalid("conflict cleanup incomplete exact native terminal"));
    }
    let expected: RowMap = native_ledger_storage::values(&header, &ledger)?
        .into_iter()
        .chain(effects.values)
        .map(|(suffix, values)| value_columns(suffix, &values))
        .collect::<Result<_>>()?;
    let actual = row_map(
        &rows
            .into_iter()
            .filter(|row| {
                row.table().starts_with("conflict_resolution_native_")
                    && row.table() != "conflict_resolution_native_bindings"
            })
            .collect::<Vec<_>>(),
    );
    if actual != expected {
        return Err(invalid(
            "conflict cleanup exact permanent native ledger differs",
        ));
    }
    Ok(true)
}
