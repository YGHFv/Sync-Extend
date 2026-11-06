use super::{Capacity, TreeNativeFutureAdmissionAudit};
use crate::{
    sql_integer,
    storage_inventory::reader::{add, hash, invalid},
    Result, MAX_OPERATION_BYTES,
};
use rusqlite::{params_from_iter, types::Value, Connection};
use sync_extend_core_model::{
    tree_restore_history::encode_history_record,
    tree_storage_footprint::{TreeStorageColumn, TreeStorageColumnValue},
};

pub(super) struct StoredRow {
    table: &'static str,
    keys: &'static [usize],
    columns: Vec<TreeStorageColumn>,
}
impl StoredRow {
    pub(super) fn bytes(&self) -> Result<u64> {
        self.columns.iter().try_fold(0, |sum, column| {
            let n = match &column.value {
                TreeStorageColumnValue::Text(s) => s.len() as u64,
                TreeStorageColumnValue::Integer(n) => {
                    sql_integer(*n)?;
                    8
                }
            };
            add(sum, n)
        })
    }
    fn parameters(&self) -> Result<Vec<Value>> {
        self.columns
            .iter()
            .map(|column| match &column.value {
                TreeStorageColumnValue::Text(s) => Ok(Value::Text(s.clone())),
                TreeStorageColumnValue::Integer(n) => Ok(Value::Integer(sql_integer(*n)?)),
            })
            .collect()
    }
    fn selected(&self) -> String {
        self.columns
            .iter()
            .map(|column| format!("\"{}\"", column.name))
            .collect::<Vec<_>>()
            .join(",")
    }
    pub(super) fn insert(&self, connection: &Connection) -> Result<()> {
        let parameters = self.parameters()?;
        connection.execute(
            &format!(
                "INSERT INTO main.{} ({}) VALUES ({})",
                self.table,
                self.selected(),
                vec!["?"; parameters.len()].join(",")
            ),
            params_from_iter(parameters),
        )?;
        Ok(())
    }
    pub(super) fn require_exact(&self, connection: &Connection) -> Result<()> {
        let parameters = self.parameters()?;
        let predicates = self
            .keys
            .iter()
            .map(|&i| format!("\"{}\"=?", self.columns[i].name))
            .collect::<Vec<_>>()
            .join(" AND ");
        let mut query = connection.prepare(&format!(
            "SELECT {} FROM main.{} WHERE {predicates}",
            self.selected(),
            self.table
        ))?;
        let mut rows = query.query(params_from_iter(self.keys.iter().map(|&i| &parameters[i])))?;
        let row = rows.next()?.ok_or(invalid("tree future missing row"))?;
        for (i, expected) in parameters.iter().enumerate() {
            if row.get::<_, Value>(i)? != *expected {
                return Err(invalid("tree future exact physical values"));
            }
        }
        if rows.next()?.is_some() {
            return Err(invalid("tree future duplicate physical row"));
        }
        Ok(())
    }
}
fn text(name: &str, value: impl ToString) -> TreeStorageColumn {
    TreeStorageColumn {
        name: name.into(),
        value: TreeStorageColumnValue::Text(value.to_string()),
    }
}
fn integer(name: &str, value: u64) -> TreeStorageColumn {
    TreeStorageColumn {
        name: name.into(),
        value: TreeStorageColumnValue::Integer(value),
    }
}
fn json(value: &impl serde::Serialize) -> Result<String> {
    String::from_utf8(encode_history_record(value, MAX_OPERATION_BYTES as u64)?)
        .map_err(|_| invalid("tree future encoding"))
}

pub(super) fn rows(
    capacity: &Capacity,
    report: &TreeNativeFutureAdmissionAudit,
) -> Result<Vec<StoredRow>> {
    let s = &capacity.scope;
    let prior = &capacity.prior;
    let mut result = vec![StoredRow {
        table: "tree_native_future_admissions",
        keys: &[1],
        columns: vec![
            text("space_id", &s.space_id),
            text("transaction_id", &s.transaction_id),
            text("coordinator_execution_id", &s.coordinator_execution_id),
            text("admission_id", &s.admission_id),
            text("admission_hash", &s.admission_hash),
            text("protocol_hash", &s.protocol_hash),
            text("layout_hash", &capacity.layout_hash),
            text("prewrite_capacity_hash", &capacity.prewrite_capacity_hash),
            text("initial_intended_hash", &capacity.initial_intended_hash),
            text("inventory_hash", &prior.fingerprint),
            text("request_hash", hash(&capacity.request)?),
            text("capacity_hash", &report.capacity_hash),
            integer("created_at_ms", capacity.request.created_at_ms),
            integer("max_entries", capacity.max_entries as u64),
            integer("action_count", capacity.action_count as u64),
            integer("original_count", capacity.original_count as u64),
            integer("prior_rows", prior.rows),
            integer("prior_bytes", prior.logical_bytes),
            integer("prior_budget_rows", prior.conservative_rows),
            integer("prior_budget_bytes", prior.conservative_bytes),
            integer("stored_rows", report.stored_rows),
            integer("stored_bytes", 0),
            integer("future_rows", report.future_charge.rows),
            integer("future_bytes", report.future_charge.logical_bytes),
            integer("new_rows", capacity.new_charge.rows),
            integer("new_bytes", capacity.new_charge.logical_bytes),
            text("request", json(&capacity.request)?),
            text("capacity", json(capacity)?),
        ],
    }];
    for (purpose, ordinal, id) in [
        ("finalization", 0, &capacity.generations.finalization_id),
        ("owner_cleanup", 0, &capacity.generations.cleanup_id),
    ]
    .into_iter()
    .chain(
        capacity
            .generations
            .attempt_ids
            .iter()
            .map(|(&i, id)| ("action_attempt", i, id)),
    )
    .chain(
        capacity
            .generations
            .disposal_ids
            .iter()
            .map(|(&i, id)| ("original_disposal", i, id)),
    ) {
        result.push(StoredRow {
            table: "tree_native_future_generations",
            keys: &[0, 2, 3],
            columns: vec![
                text("transaction_id", &s.transaction_id),
                text("generation_id", id),
                text("purpose", purpose),
                integer("ordinal", ordinal as u64),
                text("capacity_hash", &report.capacity_hash),
            ],
        });
    }
    let bytes = result
        .iter()
        .try_fold(0, |sum, row| add(sum, row.bytes()?))?;
    // Indexed scalar outside hashed capacity JSON avoids self-referential size.
    result[0].columns[21] = integer("stored_bytes", bytes);
    Ok(result)
}
