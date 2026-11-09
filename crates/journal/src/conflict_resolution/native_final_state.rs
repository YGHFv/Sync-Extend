//! Reconstruct exact whole Final from immutable original templates.
use super::native_templates::Cell;
use super::*;

pub(super) fn present(connection: &Connection, parent: &Header) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.conflict_resolution_native_phases WHERE transaction_id=?1 AND phase='final')",
        [parent.transaction_id.as_str()], |r|r.get(0),
    )?)
}

pub(super) fn exact_history(connection: &Connection, parent: &Header) -> Result<()> {
    if !present(connection, parent)? {
        return Err(invalid("conflict original Final absent"));
    }
    let plan = parent.plan()?;
    let terminal = native_cleanup_state::complete(connection, parent)?;
    for (name, expected) in [
        ("space_id", parent.target.space_id.as_str()),
        (
            "device_id",
            parent.intent.proof.payload.resolver_device.as_str(),
        ),
        ("worktree", parent.intent.worktree.as_str()),
    ] {
        let actual: String = connection.query_row(
            "SELECT value FROM main.local_state WHERE key=?1",
            [name],
            |r| r.get(0),
        )?;
        if actual != expected {
            return Err(invalid("conflict Final exact local identity differs"));
        }
    }
    let header = native_ledger_storage::stored(connection, parent)?
        .ok_or(invalid("conflict Final native original header absent"))?;
    let binding = native_binding::stored(connection, parent)?
        .ok_or(invalid("conflict Final original binding absent"))?;
    let ledger = header.validate(parent, &binding)?;
    for template in ledger
        .templates
        .iter()
        .filter(|t| t.name.starts_with("history/"))
    {
        // New ordinary work may advance current/cursors and install its own
        // rename observation; immutable original snapshots/history remain exact.
        if terminal
            && matches!(
                template.table.as_str(),
                "current_manifests" | "receive_cursors" | "rename_observations"
            )
        {
            continue;
        }
        let cells = template
            .future
            .as_ref()
            .or(template.prior.as_ref())
            .ok_or(invalid("conflict Final history template values absent"))?;
        let spec = crate::storage_inventory::tables()
            .into_iter()
            .find(|s| s.name == template.table)
            .ok_or(invalid("conflict Final history schema absent"))?;
        let primary: Vec<_> = spec
            .columns
            .iter()
            .zip(cells)
            .filter(|(c, _)| c.primary_key != 0)
            .collect();
        let predicate = primary
            .iter()
            .enumerate()
            .map(|(i, (c, _))| format!("{}=?{}", c.name, i + 1))
            .collect::<Vec<_>>()
            .join(" AND ");
        let key = primary
            .iter()
            .map(|(_, c)| match c {
                Cell::Text(s) => Ok(Value::Text(s.clone())),
                Cell::Integer(n) => Ok(Value::Integer(*n as i64)),
                _ => Err(invalid("conflict Final symbolic history key")),
            })
            .collect::<Result<Vec<_>>>()?;
        let mut stmt = connection.prepare(&format!(
            "SELECT * FROM main.{} WHERE {predicate}",
            template.table
        ))?;
        let mut rows = stmt.query(rusqlite::params_from_iter(key))?;
        let actual = if let Some(row) = rows.next()? {
            Some(
                (0..spec.columns.len())
                    .map(|i| row.get::<_, Value>(i))
                    .collect::<rusqlite::Result<Vec<_>>>()?,
            )
        } else {
            None
        };
        let expected = template
            .future
            .as_ref()
            .map(|values| native_effects::resolve(values, &BTreeMap::new()))
            .transpose()?;
        if actual != expected {
            return Err(invalid("conflict Final exact history DML differs"));
        }
    }
    let view = crate::JournalReadView { connection };
    if !terminal && view.current(&parent.target.space_id)?.as_ref() != Some(&parent.target) {
        return Err(invalid("conflict Final complete current target differs"));
    }
    let operations = parent
        .intent
        .proof
        .payload
        .originals
        .iter()
        .chain(&parent.intent.proof.payload.resolving)
        .map(|s| (&s.operation, "materialized"))
        .collect::<Vec<_>>();
    let count: i64 =
        connection.query_row("SELECT count(*) FROM main.operations", [], |r| r.get(0))?;
    if (!terminal && count != operations.len() as i64) || count < operations.len() as i64 {
        return Err(invalid("conflict Final complete original log count"));
    }
    for (op, state) in operations {
        let row:(String,String,i64,String,String)=connection.query_row(
            "SELECT space_id,origin_device_id,origin_seq,payload,state FROM main.operations WHERE op_id=?1",
            [op.op_id.as_str()], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
        )?;
        if row
            != (
                op.payload.space_id.to_string(),
                op.payload.origin_device_id.to_string(),
                op.payload.origin_seq as i64,
                serde_json::to_string(op)?,
                state.into(),
            )
        {
            return Err(invalid("conflict Final original signed operation differs"));
        }
    }
    let mut cursors = VersionVector::default();
    let mut statement =
        connection.prepare("SELECT space_id,device_id,contiguous_seq FROM main.receive_cursors")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(0)? != parent.target.space_id.as_str() {
            return Err(invalid("conflict Final cursor space"));
        }
        let device: sync_extend_core_model::DeviceId = row.get::<_, String>(1)?.parse()?;
        let seq = u64::try_from(row.get::<_, i64>(2)?)
            .map_err(|_| invalid("conflict Final negative cursor"))?;
        if cursors.get(&device) != 0 || seq == 0 {
            return Err(invalid("conflict Final duplicate cursor"));
        }
        cursors.observe(device, seq);
    }
    if ((!terminal && cursors != parent.target.version_vector)
        || !cursors.dominates(&parent.target.version_vector))
        || !parent
            .target
            .version_vector
            .dominates(&plan.received_vector)
    {
        return Err(invalid("conflict Final complete cursor vector differs"));
    }
    Ok(())
}
