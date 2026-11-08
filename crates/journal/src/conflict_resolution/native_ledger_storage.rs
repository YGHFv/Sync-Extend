//! exact persisted ledger receipt; rejects every unsupported effect row.
use super::native_ledger::NativeHeader;
use super::native_templates::Ledger;
use super::*;
use rusqlite::OptionalExtension;
use sync_extend_core_model::tree_storage_capacity::TreeStorageCharge;

fn text(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}
fn integer(value: u64) -> Result<Value> {
    Ok(Value::Integer(i64::try_from(value).map_err(|_| {
        invalid("conflict ledger stored integer overflow")
    })?))
}
pub(super) fn values(
    header: &NativeHeader,
    ledger: &Ledger,
) -> Result<Vec<(&'static str, Vec<Value>)>> {
    let mut result = vec![(
        "native_headers",
        vec![
            text(&header.transaction_id),
            text(&header.parent_hash),
            text(&header.binding_hash),
            text(&header.generation),
            text(hash(header)?),
            text(&header.layout_hash),
            integer(header.reserved.rows)?,
            integer(header.reserved.logical_bytes)?,
            integer(header.native_peak)?,
            text(serde_json::to_string(header)?),
        ],
    )];
    for template in &ledger.templates {
        let json = serde_json::to_string(template)?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(invalid("conflict future named template encoded budget"));
        }
        result.push((
            "native_templates",
            vec![
                text(&header.transaction_id),
                text(&template.name),
                text(ContentId::hash(json.as_bytes())),
                integer(template.charge.rows)?,
                integer(template.charge.logical_bytes)?,
                text(json),
            ],
        ));
    }
    Ok(result)
}

pub(super) fn stored(connection: &Connection, parent: &Header) -> Result<Option<NativeHeader>> {
    let row: Option<String> = connection
        .query_row(
            "SELECT header FROM main.conflict_resolution_native_headers WHERE transaction_id=?1",
            [parent.transaction_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    row.map(|json| {
        let header: NativeHeader = serde_json::from_str(&json)?;
        let binding = super::native_binding::stored(connection, parent)?
            .ok_or(invalid("conflict future exact original binding missing"))?;
        header.validate(parent, &binding)?;
        if serde_json::to_string(&header)? != json {
            return Err(invalid("conflict future header canonical JSON differs"));
        }
        Ok(header)
    })
    .transpose()
}

pub(super) fn require_fresh_generation(
    header: &NativeHeader,
    rows: &[JournalStoredRow],
    connection: &Connection,
) -> Result<()> {
    let ids = BTreeSet::from([&header.generation]);
    crate::tree_disposition_generations::audit_names(
        connection,
        &ids,
        sync_extend_core_model::limits::MAX_ENTRIES,
    )?;
    for row in rows.iter().filter(|row| {
        !row.table().starts_with("conflict_resolution_native_")
            || row.table() == "conflict_resolution_native_bindings"
    }) {
        if row
            .primary_key()
            .iter()
            .any(|key| key == header.generation.as_str())
            || row.columns().iter().any(|column| {
                matches!(&column.value, crate::JournalStorageColumnValue::Text(value)
                    if value == header.generation.as_str())
            })
        {
            return Err(invalid(
                "conflict future generation collides with retained namespace",
            ));
        }
    }
    Ok(())
}

pub(super) fn audit(
    rows: &[JournalStoredRow],
    connection: &Connection,
) -> Result<Vec<JournalCapacityObligation>> {
    let actual: RowMap = rows
        .iter()
        .filter(|row| {
            row.table().starts_with("conflict_resolution_native_")
                && row.table() != "conflict_resolution_native_bindings"
        })
        .map(|row| {
            (
                (row.table().into(), row.primary_key().to_vec()),
                row.columns().to_vec(),
            )
        })
        .collect();
    let mut expected = RowMap::new();
    let mut obligations = Vec::new();
    let owners: Vec<_> = rows
        .iter()
        .filter(|row| row.table() == "conflict_resolution_native_headers")
        .collect();
    if owners.len() > 1 {
        return Err(invalid("conflict future multiple immutable owners"));
    }
    for owner in owners {
        let json: String = connection.query_row(
            "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
            [owner.primary_key()[0].as_str()],
            |row| row.get(0),
        )?;
        let parent: Header = serde_json::from_str(&json)?;
        let header = stored(connection, &parent)?
            .ok_or(invalid("conflict future missing original native header"))?;
        let binding = super::native_binding::stored(connection, &parent)?.ok_or(invalid(
            "conflict future missing durable native original keys",
        ))?;
        let history =
            super::native_history_templates::HistorySelection::from_actual(&parent, rows)?;
        if history != header.history {
            return Err(invalid("conflict future selected actual history changed"));
        }
        let ledger = header.validate(&parent, &binding)?;
        require_fresh_generation(&header, rows, connection)?;
        for (suffix, values) in values(&header, &ledger)? {
            let (key, columns) = value_columns(suffix, &values)?;
            if expected.insert(key, columns).is_some() {
                return Err(invalid("conflict future duplicate exact actual row"));
            }
        }
        for template in &ledger.templates {
            obligations.push(JournalCapacityObligation {
                family: "original_conflict_native_future_template",
                owner_key: vec![parent.transaction_id.to_string(), template.name.clone()],
                charge: template.charge,
            });
            if template.ordinary_credit != TreeStorageCharge::default() {
                match template.table.as_str() {
                    "operations" => {
                        let cells = template
                            .prior
                            .as_ref()
                            .ok_or(invalid("conflict future received credit prior missing"))?;
                        if cells.len() != 6
                            || cells[5] != super::native_templates::Cell::Text("received".into())
                            || template.ordinary_credit
                                != (TreeStorageCharge {
                                    rows: 0,
                                    logical_bytes: 4,
                                })
                        {
                            return Err(invalid(
                                "conflict future original received credit differs",
                            ));
                        }
                    }
                    _ => return Err(invalid("conflict future unrelated ordinary credit")),
                }
            }
        }
    }
    if actual != expected {
        return Err(invalid(
            "conflict future missing/orphan/phase/effect/template actual row differs",
        ));
    }
    Ok(obligations)
}
