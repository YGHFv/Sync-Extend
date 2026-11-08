//! actual schema-ordered future width/type validation; no SQL authority.
use super::native_templates::{Cell, Dml, Ledger, Template};
use super::*;
use crate::storage_inventory::reader::{ColumnKind, TableSpec};

const MAX_AGGREGATE_TEMPLATE_BYTES: usize = 64 * 1024 * 1024;

fn columns<'a>(template: &Template, specs: &'a [TableSpec]) -> Result<&'a TableSpec> {
    specs
        .iter()
        .find(|spec| spec.name == template.table)
        .ok_or(invalid("conflict future unknown physical template schema"))
}

fn key(spec: &TableSpec, values: &[Cell]) -> Result<Vec<Cell>> {
    let mut primary = BTreeMap::new();
    for (column, cell) in spec.columns.iter().zip(values) {
        if column.primary_key != 0 {
            primary.insert(column.primary_key, cell.clone());
        }
    }
    if primary.is_empty() {
        return Err(invalid("conflict future schema primary key missing"));
    }
    Ok(primary.into_values().collect())
}

fn verify_values(
    spec: &TableSpec,
    values: &[Cell],
    creators: &BTreeMap<u64, usize>,
    index: usize,
) -> Result<()> {
    if values.len() != spec.columns.len() {
        return Err(invalid("conflict future actual column count differs"));
    }
    for (column, cell) in spec.columns.iter().zip(values) {
        match (column.kind, cell) {
            (ColumnKind::Integer, Cell::Integer(n)) if *n <= i64::MAX as u64 => {}
            (ColumnKind::Text(n), Cell::Text(text))
                if n == crate::MAX_OPERATION_BYTES && !text.is_empty() && text.len() <= n => {}
            (ColumnKind::Text(n), Cell::Text(text))
                if text.len() == n
                    && text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) => {}
            (ColumnKind::Utf8 { min, max }, Cell::Text(text))
                if text.len() >= min && text.len() <= max => {}
            (ColumnKind::Text(16), Cell::CreatorVolume(step))
                if matches!(column.name, "parent_volume" | "volume")
                    && creators
                        .get(step)
                        .is_some_and(|position| *position <= index) => {}
            (ColumnKind::Text(32), Cell::CreatorId(step))
                if matches!(column.name, "parent_id" | "full_id")
                    && creators
                        .get(step)
                        .is_some_and(|position| *position <= index) => {}
            _ => return Err(invalid("conflict future actual column type/width differs")),
        }
    }
    Ok(())
}

pub(super) fn validate(ledger: &Ledger) -> Result<()> {
    let specs = crate::storage_inventory::tables();

    let mut names = BTreeSet::new();
    let mut creators = BTreeMap::new();
    for (index, template) in ledger.templates.iter().enumerate() {
        if template.table == "conflict_resolution_native_creators" {
            let values = template
                .future
                .as_ref()
                .ok_or(invalid("conflict future creator template values missing"))?;
            let Some(Cell::Integer(step)) = values.get(2) else {
                return Err(invalid("conflict future original creator ordinal differs"));
            };
            if creators.insert(*step, index).is_some() {
                return Err(invalid(
                    "conflict future duplicated original creator template",
                ));
            }
        }
    }
    let mut encoded_bytes = 0usize;
    let mut inserted = BTreeSet::new();
    let mut names_to_indices = BTreeMap::new();
    let mut graph_visits = 0usize;
    for (index, template) in ledger.templates.iter().enumerate() {
        let spec = columns(template, &specs)?;
        if template
            .dependencies
            .iter()
            .any(|name| !names.contains(name))
            || !names.insert(template.name.clone())
        {
            return Err(invalid(
                "conflict future ordered template dependency graph differs",
            ));
        }
        names_to_indices.insert(template.name.clone(), index);
        let symbols: BTreeSet<_> = template
            .prior
            .iter()
            .chain(template.future.iter())
            .flat_map(|values| values.iter())
            .filter_map(|cell| match cell {
                Cell::CreatorVolume(step) | Cell::CreatorId(step) => Some(*step),
                _ => None,
            })
            .collect();
        let mut needed: BTreeSet<_> = symbols
            .iter()
            .filter_map(|step| creators.get(step).copied())
            .filter(|source| *source != index)
            .map(|source| ledger.templates[source].name.clone())
            .collect();
        let mut reachable = template
            .dependencies
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut pending = template.dependencies.clone();
        while !needed.is_empty() {
            let Some(name) = pending.pop() else { break };
            graph_visits = graph_visits
                .checked_add(1)
                .filter(|visits| *visits <= 8_000_000)
                .ok_or(invalid("conflict future dependency traversal budget"))?;
            needed.remove(&name);
            let dependency = names_to_indices
                .get(&name)
                .map(|position| &ledger.templates[*position])
                .ok_or(invalid("conflict future missing graph dependency"))?;
            for parent in &dependency.dependencies {
                if reachable.insert(parent.clone()) {
                    pending.push(parent.clone());
                }
            }
        }
        for values in template.prior.iter().chain(template.future.iter()) {
            verify_values(spec, values, &creators, index)?;
            for cell in values {
                if let Cell::CreatorVolume(step) | Cell::CreatorId(step) = cell {
                    let source = creators
                        .get(step)
                        .ok_or(invalid("conflict future unknown creator symbol"))?;
                    if *source != index && !reachable.contains(&ledger.templates[*source].name) {
                        return Err(invalid(
                            "conflict future creator symbol not held by dependency",
                        ));
                    }
                }
            }
        }
        match template.dml {
            Dml::Insert => {
                let future = template
                    .future
                    .as_ref()
                    .ok_or(invalid("conflict future insert values missing"))?;
                let primary = key(spec, future)?;
                // Symbols cannot be primary keys in this finite future schema.
                let actual_primary: Vec<String> = primary
                    .iter()
                    .map(|cell| match cell {
                        Cell::Text(value) => Ok(value.clone()),
                        Cell::Integer(value) => Ok(value.to_string()),
                        _ => Err(invalid("conflict future symbolic primary key unavailable")),
                    })
                    .collect::<Result<_>>()?;
                if !inserted.insert((template.table.clone(), actual_primary)) {
                    return Err(invalid("conflict future duplicate physical row template"));
                }
            }
            Dml::Update => {
                let prior = template
                    .prior
                    .as_ref()
                    .ok_or(invalid("conflict future update prior missing"))?;
                let future = template
                    .future
                    .as_ref()
                    .ok_or(invalid("conflict future update future missing"))?;
                if key(spec, prior)? != key(spec, future)? {
                    return Err(invalid("conflict future update primary key changed"));
                }
            }
            Dml::Delete if template.prior.is_some() && template.future.is_none() => {}
            _ => return Err(invalid("conflict future DML physical row mismatch")),
        }
        let bytes = serde_json::to_vec(template)?.len();
        encoded_bytes = encoded_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_AGGREGATE_TEMPLATE_BYTES)
            .ok_or(invalid("conflict future aggregate encoded template budget"))?;
    }
    Ok(())
}
