//! Narrow future conversion for original creators and whole Ready only.
use super::native_binding::{Binding, Key};
use super::native_ledger::NativeHeader;
use super::native_templates::{Cell, Dml, Ledger, Template};
use super::*;

pub(super) struct Effects<'a> {
    pub values: Vec<(&'static str, Vec<Value>)>,
    pub remaining: Vec<&'a Template>,
    pub creators: BTreeMap<u64, Key>,
    pub fulfilled: BTreeSet<String>,
}

fn key(template: &Template) -> Result<RowKey> {
    let specs = all_tables();
    let spec = specs
        .iter()
        .find(|spec| spec.name == template.table)
        .ok_or(invalid("conflict creator template table missing"))?;
    let cells = template
        .future
        .as_ref()
        .ok_or(invalid("conflict creator future cells missing"))?;
    if cells.len() != spec.columns.len() {
        return Err(invalid("conflict creator template column count"));
    }
    let mut primary = BTreeMap::new();
    for (column, cell) in spec.columns.iter().zip(cells) {
        if column.primary_key != 0 {
            let value = match cell {
                Cell::Text(text) => text.clone(),
                Cell::Integer(number) => number.to_string(),
                _ => return Err(invalid("conflict creator symbolic primary key")),
            };
            primary.insert(column.primary_key, value);
        }
    }
    Ok((template.table.clone(), primary.into_values().collect()))
}

pub(super) fn resolve(cells: &[Cell], creators: &BTreeMap<u64, Key>) -> Result<Vec<Value>> {
    cells
        .iter()
        .map(|cell| {
            Ok(match cell {
                Cell::Text(text) => Value::Text(text.clone()),
                Cell::Integer(number) => Value::Integer(
                    i64::try_from(*number)
                        .map_err(|_| invalid("conflict creator integer overflow"))?,
                ),
                Cell::CreatorVolume(step) => Value::Text(
                    creators
                        .get(step)
                        .ok_or(invalid("conflict creator original parent missing"))?
                        .volume
                        .clone(),
                ),
                Cell::CreatorId(step) => Value::Text(
                    creators
                        .get(step)
                        .ok_or(invalid("conflict creator original parent missing"))?
                        .id
                        .clone(),
                ),
            })
        })
        .collect()
}

fn field<'a>(columns: &'a [crate::JournalStorageColumn], name: &str) -> Result<&'a str> {
    columns
        .iter()
        .find_map(|column| match &column.value {
            crate::JournalStorageColumnValue::Text(text) if column.name == name => {
                Some(text.as_str())
            }
            _ => None,
        })
        .ok_or(invalid("conflict creator exact key column missing"))
}

pub(super) fn audit<'a>(
    header: &NativeHeader,
    binding: &Binding,
    ledger: &'a Ledger,
    rows: &[JournalStoredRow],
) -> Result<Effects<'a>> {
    let actual: RowMap = rows
        .iter()
        .filter(|row| row.table().starts_with("conflict_resolution_native_"))
        .map(|row| {
            (
                (row.table().into(), row.primary_key().to_vec()),
                row.columns().to_vec(),
            )
        })
        .collect();
    let final_present = actual.contains_key(&(
        "conflict_resolution_native_phases".into(),
        vec![header.transaction_id.to_string(), "final".into()],
    ));
    let handed_off = actual.contains_key(&(
        "conflict_resolution_native_phases".into(),
        vec![header.transaction_id.to_string(), "history_handoff".into()],
    ));
    let mut result = Effects {
        values: Vec::new(),
        remaining: Vec::new(),
        creators: BTreeMap::new(),
        fulfilled: BTreeSet::new(),
    };
    let mut native_keys: BTreeSet<_> = binding
        .ancestors
        .iter()
        .map(|ancestor| ancestor.key.clone())
        .chain(binding.existing_base.iter().cloned())
        .chain(std::iter::once(binding.marker_directory.clone()))
        .chain(std::iter::once(binding.marker_file.clone()))
        .chain(binding.originals.values().cloned())
        .chain(header.residue.directories.iter().map(|row| row.key.clone()))
        .chain(header.residue.files.iter().map(|row| row.key.clone()))
        .collect();
    for template in &ledger.templates {
        if handed_off && template.name.starts_with("release/") {
            if template
                .dependencies
                .iter()
                .any(|name| !result.fulfilled.contains(name))
            {
                return Err(invalid("conflict handoff exact release dependency absent"));
            }
            let cells = template
                .prior
                .as_ref()
                .ok_or(invalid("conflict handoff release prior absent"))?;
            let values = resolve(cells, &result.creators)?;
            let found = rows.iter().any(|row| {
                row.table() == template.table
                    && row
                        .columns()
                        .iter()
                        .zip(&values)
                        .all(|(c, v)| match (&c.value, v) {
                            (crate::JournalStorageColumnValue::Text(a), Value::Text(b)) => a == b,
                            (crate::JournalStorageColumnValue::Integer(a), Value::Integer(b)) => {
                                *a == *b as u64
                            }
                            _ => false,
                        })
            });
            if found {
                return Err(invalid("conflict handoff incomplete atomic release"));
            }
            result.fulfilled.insert(template.name.clone());
            continue;
        }
        if template.name.starts_with("history/") && final_present {
            if template
                .dependencies
                .iter()
                .any(|name| !result.fulfilled.contains(name))
            {
                return Err(invalid("conflict Final history dependency missing"));
            }
            if template.table.starts_with("conflict_resolution_native_") {
                let suffix = template
                    .table
                    .strip_prefix("conflict_resolution_")
                    .ok_or(invalid("conflict Final history namespace"))?;
                let stored = actual
                    .get(&key(template)?)
                    .ok_or(invalid("conflict Final history receipt absent"))?;
                let values = resolve(
                    template
                        .future
                        .as_ref()
                        .ok_or(invalid("conflict Final history future absent"))?,
                    &result.creators,
                )?;
                let (_, expected) = value_columns(suffix, &values)?;
                if *stored != expected {
                    return Err(invalid("conflict Final exact history receipt differs"));
                }
                let suffix = match suffix {
                    "native_history" => "native_history",
                    "native_events" => "native_events",
                    "native_history_objects" => "native_history_objects",
                    "native_branch_handoffs" => "native_branch_handoffs",
                    _ => return Err(invalid("conflict Final unsupported history receipt table")),
                };
                result.values.push((suffix, values));
            }
            result.fulfilled.insert(template.name.clone());
            continue;
        }
        let suffix = match template.table.as_str() {
            "conflict_resolution_native_activations" => "native_activations",
            "conflict_resolution_native_creators" => "native_creators",
            "conflict_resolution_native_steps" => "native_steps",
            "conflict_resolution_native_dispositions" => "native_dispositions",
            "conflict_resolution_native_phases"
                if matches!(
                    template.name.as_str(),
                    "phase/ready"
                        | "phase/quarantined"
                        | "phase/observed"
                        | "phase/final"
                        | "phase/history_handoff"
                        | "phase/files_cleaned"
                        | "phase/cleanup"
                ) =>
            {
                "native_phases"
            }
            _ => {
                result.remaining.push(template);
                continue;
            }
        };
        let Some(stored) = actual.get(&key(template)?) else {
            result.remaining.push(template);
            continue;
        };
        if template.dml != Dml::Insert
            || template.prior.is_some()
            || template
                .dependencies
                .iter()
                .any(|name| !result.fulfilled.contains(name))
        {
            return Err(invalid(
                "conflict creator original dependency or DML differs",
            ));
        }
        if suffix == "native_creators" {
            let Some(Cell::Integer(step)) = template.future.as_ref().and_then(|v| v.get(2)) else {
                return Err(invalid("conflict creator original ordinal missing"));
            };
            let native = Key {
                volume: field(stored, "volume")?.into(),
                id: field(stored, "full_id")?.into(),
            };
            if native.volume != binding.ancestors[0].key.volume
                || [&native.volume, &native.id]
                    .into_iter()
                    .zip([16, 32])
                    .any(|(value, width)| {
                        value.len() != width
                            || !value
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                || !native_keys.insert(native.clone())
                || result.creators.insert(*step, native).is_some()
            {
                return Err(invalid("conflict creator fullkey volume or alias differs"));
            }
        }
        let values = resolve(
            template
                .future
                .as_ref()
                .ok_or(invalid("conflict creator exact future missing"))?,
            &result.creators,
        )?;
        let (_, expected) = value_columns(suffix, &values)?;
        if &expected != stored {
            return Err(invalid("conflict creator exact fulfilled template differs"));
        }
        result.values.push((suffix, values));
        result.fulfilled.insert(template.name.clone());
    }
    Ok(result)
}
