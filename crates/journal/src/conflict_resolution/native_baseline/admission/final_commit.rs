//! Atomic complete original history Final, never partial materialization.
use super::super::super::native_templates::{Cell, Dml};
use super::*;

pub(super) fn row(table: &str, cells: &[Cell]) -> Result<(RowKey, RowValue)> {
    let specs = crate::storage_inventory::tables();
    let spec = specs
        .iter()
        .find(|s| s.name == table)
        .ok_or(invalid("conflict Final table absent"))?;
    let values = super::super::super::native_effects::resolve(cells, &BTreeMap::new())?;
    if values.len() != spec.columns.len() {
        return Err(invalid("conflict Final row width"));
    }
    let mut primary = BTreeMap::new();
    let columns = spec
        .columns
        .iter()
        .zip(&values)
        .map(|(c, v)| {
            let value = match v {
                Value::Text(s) => crate::JournalStorageColumnValue::Text(s.clone()),
                Value::Integer(n) if *n >= 0 => {
                    crate::JournalStorageColumnValue::Integer(*n as u64)
                }
                _ => return Err(invalid("conflict Final invalid value")),
            };
            if c.primary_key != 0 {
                primary.insert(
                    c.primary_key,
                    match v {
                        Value::Text(s) => s.clone(),
                        Value::Integer(n) => n.to_string(),
                        _ => unreachable!(),
                    },
                );
            }
            Ok(crate::JournalStorageColumn {
                name: c.name.into(),
                value,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(((table.into(), primary.into_values().collect()), columns))
}

impl Journal {
    pub fn finalize_conflict_native(
        &mut self,
        observed: ConflictNativeObservation,
    ) -> Result<SnapshotId> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict Final refuses caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let ready = &observed.held.held;
        let admission = &ready.admission;
        let parent = &admission.selected.header;
        let state = self.conflict_forward_state(&observed.held)?;
        if !state.contains("phase/observed") {
            return Err(invalid("conflict whole observed phase absent"));
        }
        observed.verify_content()?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        if state.contains("phase/final") {
            super::super::super::native_final_state::exact_history(&self.connection, parent)?;
            tx.commit()?;
            return parent.target.root().map_err(Into::into);
        }
        let ledger = admission
            .header
            .validate(parent, &admission.selected.binding()?)?;
        let mut fulfilled = state;
        let mut expected = row_map(&before.rows);
        for template in ledger
            .templates
            .iter()
            .filter(|t| t.name.starts_with("history/") || t.name == "phase/final")
        {
            if template
                .dependencies
                .iter()
                .any(|name| !fulfilled.contains(name))
            {
                return Err(invalid("conflict Final exact history dependency missing"));
            }
            let prior = template
                .prior
                .as_ref()
                .map(|v| row(&template.table, v))
                .transpose()?;
            let future = template
                .future
                .as_ref()
                .map(|v| row(&template.table, v))
                .transpose()?;
            match (&prior, &future) {
                (None, Some((key, columns))) if !expected.contains_key(key) => {
                    expected.insert(key.clone(), columns.clone());
                }
                (Some((key, columns)), Some((future_key, new)))
                    if expected.get(key) == Some(columns) && key == future_key =>
                {
                    expected.insert(key.clone(), new.clone());
                }
                (Some((key, columns)), None) if expected.get(key) == Some(columns) => {
                    expected.remove(key);
                }
                _ => {
                    return Err(invalid(
                        "conflict Final original exact DML precondition differs",
                    ))
                }
            }
            let old = template
                .prior
                .as_ref()
                .map(|v| super::super::super::native_effects::resolve(v, &ready.keys))
                .transpose()?;
            let new = template
                .future
                .as_ref()
                .map(|v| super::super::super::native_effects::resolve(v, &ready.keys))
                .transpose()?;
            let _permit = if let Some(suffix) = template.table.strip_prefix("conflict_resolution_")
            {
                let mut issued = vec![Value::Text(suffix.into())];
                issued.extend(
                    new.clone()
                        .ok_or(invalid("conflict Final native insertion values absent"))?,
                );
                self.conflict_resolution_issuance.permit(Some(issued))?
            } else {
                let mut issued = vec![
                    Value::Text(template.table.clone()),
                    Value::Text(
                        match template.dml {
                            Dml::Insert => "insert",
                            Dml::Update => "update",
                            Dml::Delete => "delete",
                        }
                        .into(),
                    ),
                ];
                issued.extend(old.clone().unwrap_or_default());
                issued.extend(new.clone().unwrap_or_default());
                let mut permits = vec![issued];
                // Original schema18 current trigger performs exact rename invalidation.
                if template.table == "current_manifests" {
                    for cascade in ledger
                        .templates
                        .iter()
                        .filter(|t| t.table == "rename_observations" && t.dml == Dml::Delete)
                    {
                        let mut issued = vec![
                            Value::Text("rename_observations".into()),
                            Value::Text("delete".into()),
                        ];
                        issued.extend(super::super::super::native_effects::resolve(
                            cascade
                                .prior
                                .as_ref()
                                .ok_or(invalid("conflict Final exact rename cascade prior"))?,
                            &ready.keys,
                        )?);
                        permits.push(issued);
                    }
                }
                self.conflict_resolution_issuance.final_permit(permits)?
            };
            let specs = crate::storage_inventory::tables();
            let spec = specs
                .iter()
                .find(|s| s.name == template.table)
                .ok_or(invalid("conflict Final exact DML schema"))?;
            let (sql, values) = match template.dml {
                Dml::Insert => {
                    let values = new.ok_or(invalid("conflict Final insert values absent"))?;
                    (
                        format!(
                            "INSERT INTO main.{} VALUES({})",
                            template.table,
                            (1..=values.len())
                                .map(|n| format!("?{n}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        values,
                    )
                }
                Dml::Update | Dml::Delete => {
                    let old = old.ok_or(invalid("conflict Final DML prior absent"))?;
                    let mut values = if template.dml == Dml::Update {
                        new.ok_or(invalid("conflict Final update future absent"))?
                    } else {
                        Vec::new()
                    };
                    let offset = values.len();
                    let where_clause = spec
                        .columns
                        .iter()
                        .enumerate()
                        .map(|(i, c)| format!("{}=?{}", c.name, offset + i + 1))
                        .collect::<Vec<_>>()
                        .join(" AND ");
                    let sql = if template.dml == Dml::Update {
                        format!(
                            "UPDATE main.{} SET {} WHERE {where_clause}",
                            template.table,
                            spec.columns
                                .iter()
                                .enumerate()
                                .map(|(i, c)| format!("{}=?{}", c.name, i + 1))
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    } else {
                        format!("DELETE FROM main.{} WHERE {where_clause}", template.table)
                    };
                    values.extend(old);
                    (sql, values)
                }
            };
            let count = tx.execute(&sql, rusqlite::params_from_iter(values))?;
            if count != 1 {
                let cascade_absent = template.table == "rename_observations"
                    && template.dml == Dml::Delete
                    && !tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM main.rename_observations WHERE space_id=?1)",
                        [parent.target.space_id.as_str()],
                        |r| r.get::<_, bool>(0),
                    )?;
                if !cascade_absent {
                    return Err(invalid("conflict Final exact original DML row count"));
                }
            }
            fulfilled.insert(template.name.clone());
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        if row_map(&after.rows) != expected
            || !after.report.within_accounted_limits()
            || after.report.accounted_total().rows > before.report.accounted_total().rows
            || after.report.accounted_total().logical_bytes
                > before.report.accounted_total().logical_bytes
        {
            return Err(invalid("conflict Final exact allmain capacity differs"));
        }
        observed.verify_content()?;
        self.verify_conflict_creator_cas(admission)?;
        tx.commit()?;
        parent.target.root().map_err(Into::into)
    }
}
