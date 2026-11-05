//! Durable initial intention only. No syscall or externally supplied observation.
use crate::{
    check_storage_metadata_limit, sql_integer,
    storage_inventory::reader::{add, hash, invalid, preflight, validate_schema, Namespace},
    Journal, JournalStorageInventory, Result, TreeCoordinatorAdmissionInspection,
    TreeRestoreInventoryLimits, TreeRestorePreparation, MAX_OPERATION_BYTES,
};
use rusqlite::{
    params_from_iter, types::Value, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    tree_native_action_layout::{
        plan_tree_native_action_layout, TreeNativeActionLayoutLimits, TreeNativeActionLayoutPlan,
        TreeNativeActionLayoutRecord, TreeNativeActionPayload, TreeNativeActionScope,
    },
    tree_native_protocol::{
        plan_tree_native_protocol, TreeNativeAdmissionBinding, TreeNativeProtocolInput,
        TreeNativeProtocolLimits, TreeNativeProtocolPlan,
    },
    tree_restore_history::encode_history_record,
    tree_storage_footprint::{
        tree_native_action_row_values, tree_native_header_row_values,
        TreeNativeStorageHeaderRequest, TreeStorageColumn, TreeStorageColumnValue,
    },
    ContentId, EntryId, SpaceId,
};

pub(crate) mod schema;

const ACCOUNTING: &str = "intended-only-three-actual-rows-not-complete-future-capacity-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativePrewriteRequest {
    pub transaction_id: EntryId,
    pub created_at_ms: u64,
    pub layout_limits: TreeNativeActionLayoutLimits,
    pub inventory_limits: TreeRestoreInventoryLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PriorInventory {
    fingerprint: ContentId,
    rows: u64,
    logical_bytes: u64,
    conservative_rows: u64,
    conservative_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capacity {
    format_version: u32,
    accounting: String,
    scope: TreeNativeActionScope,
    layout_hash: ContentId,
    request: TreeNativePrewriteRequest,
    max_entries: usize,
    prior: PriorInventory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeNativePrewriteAudit {
    request: TreeNativePrewriteRequest,
    capacity_hash: ContentId,
    inventory_at_admission_hash: ContentId,
    header: TreeNativeStorageHeaderRequest,
    intended: TreeNativeActionLayoutRecord,
    stored_rows: u64,
    stored_logical_bytes: u64,
    accounting: &'static str,
}
impl TreeNativePrewriteAudit {
    pub fn request(&self) -> &TreeNativePrewriteRequest {
        &self.request
    }
    pub fn capacity_hash(&self) -> &ContentId {
        &self.capacity_hash
    }
    pub fn inventory_at_admission_hash(&self) -> &ContentId {
        &self.inventory_at_admission_hash
    }
    pub fn header(&self) -> &TreeNativeStorageHeaderRequest {
        &self.header
    }
    pub fn intended(&self) -> &TreeNativeActionLayoutRecord {
        &self.intended
    }
    pub fn stored_rows(&self) -> u64 {
        self.stored_rows
    }
    pub fn stored_logical_bytes(&self) -> u64 {
        self.stored_logical_bytes
    }
    pub fn accounting(&self) -> &str {
        self.accounting
    }
    pub fn full_capacity_verified(&self) -> bool {
        false
    }
    pub fn native_execution_available(&self) -> bool {
        false
    }
    pub fn durable_observation_available(&self) -> bool {
        false
    }
    pub fn history_commit_available(&self) -> bool {
        false
    }
    pub fn reference_release_available(&self) -> bool {
        false
    }
}

struct StoredValues {
    table: &'static str,
    columns: Vec<TreeStorageColumn>,
}
impl StoredValues {
    fn bytes(&self) -> Result<u64> {
        self.columns.iter().try_fold(0, |sum, c| {
            let n = match &c.value {
                TreeStorageColumnValue::Text(text) => text.len() as u64,
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
            .map(|c| match &c.value {
                TreeStorageColumnValue::Text(s) => Ok(Value::Text(s.clone())),
                TreeStorageColumnValue::Integer(n) => Ok(Value::Integer(sql_integer(*n)?)),
            })
            .collect()
    }
}
struct Projection {
    values: [StoredValues; 3],
    report: TreeNativePrewriteAudit,
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
fn json<T: Serialize>(value: &T) -> Result<String> {
    String::from_utf8(encode_history_record(value, MAX_OPERATION_BYTES as u64)?)
        .map_err(|_| invalid("tree native storage encoding"))
}
fn validate_request(request: &TreeNativePrewriteRequest, max: usize) -> Result<()> {
    crate::tree_storage_inventory::validate_limits(max, request.inventory_limits)?;
    sql_integer(request.created_at_ms)?;
    if request.layout_limits.max_records == 0
        || request.layout_limits.max_records > max
        || request.layout_limits.max_input_bytes == 0
        || request.layout_limits.max_input_bytes > MAX_OPERATION_BYTES as u64
        || request.layout_limits.max_encoded_bytes == 0
        || request.layout_limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
    {
        return Err(invalid("tree native prewrite limits"));
    }
    encode_history_record(request, MAX_OPERATION_BYTES as u64)?;
    Ok(())
}

fn initial_layout(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeNativePrewriteRequest,
    max: usize,
) -> Result<(
    TreeCoordinatorAdmissionInspection,
    TreeNativeProtocolPlan,
    TreeNativeActionLayoutPlan,
)> {
    validate_request(request, max)?;
    if request.transaction_id != p.intent.transaction_id
        || p.cancelled_at_ms.is_some()
        || !p.writer_gate_held
        || p.owner_description
            .as_ref()
            .is_some_and(|d| !d.records.is_empty())
        || p.execution_records
            .as_ref()
            .is_some_and(|d| !d.records.is_empty())
        || p.native_protocol_description
            .as_ref()
            .is_some_and(|d| !d.records.is_empty())
        || p.final_description.is_some()
        || p.disposition_description.is_some()
    {
        return Err(invalid("tree native prewrite namespace or owner"));
    }
    let admission = p
        .coordinator_admission
        .as_ref()
        .ok_or(invalid("tree native prewrite admission missing"))?;
    if request.created_at_ms < admission.request.input.admitted_at_ms {
        return Err(invalid("tree native prewrite time"));
    }
    let projection =
        crate::tree_coordinator_admission::project(connection, p, &admission.request, max)?;
    let context = projection.context();
    let protocol = plan_tree_native_protocol(
        &context,
        &TreeNativeProtocolInput {
            format_version: 1,
            admission: TreeNativeAdmissionBinding {
                input: admission.request.input.clone(),
                limits: admission.request.limits,
                intent_hash: admission.intent_hash.clone(),
                request_hash: admission.request_hash.clone(),
            },
        },
        TreeNativeProtocolLimits {
            max_records: request.layout_limits.max_records,
            max_input_bytes: request.layout_limits.max_input_bytes,
            max_encoded_bytes: request.layout_limits.max_encoded_bytes,
        },
    )?;
    let layout = plan_tree_native_action_layout(&context, &protocol, &[], request.layout_limits)?;
    if layout
        .action_count()
        .checked_mul(2)
        .is_none_or(|n| n > request.layout_limits.max_records)
    {
        return Err(invalid("tree native prewrite action inventory"));
    }
    Ok((projection, protocol, layout))
}

fn derive(
    connection: &Connection,
    p: &TreeRestorePreparation,
    capacity: &Capacity,
    max: usize,
) -> Result<Projection> {
    let request = &capacity.request;
    validate_request(request, capacity.max_entries)?;
    let (projection, protocol, layout) = initial_layout(connection, p, request, max)?;
    if layout.scope() != &capacity.scope
        || layout.layout_hash() != &capacity.layout_hash
        || capacity.format_version != 1
        || capacity.accounting != ACCOUNTING
    {
        return Err(invalid("tree native prewrite layout binding"));
    }
    let intended = TreeNativeActionLayoutRecord {
        scope: layout.scope().clone(),
        record_index: 0,
        action_ordinal: 0,
        previous_hash: layout.layout_hash().clone(),
        recorded_at_ms: request.created_at_ms,
        payload: TreeNativeActionPayload::Intended {
            intent: Box::new(
                layout
                    .next_intent()
                    .ok_or(invalid("tree native initial action missing"))?
                    .clone(),
            ),
        },
    };
    plan_tree_native_action_layout(
        &projection.context(),
        &protocol,
        std::slice::from_ref(&intended),
        request.layout_limits,
    )?;
    let capacity_hash = hash(capacity)?;
    let header = TreeNativeStorageHeaderRequest {
        scope: layout.scope().clone(),
        layout_hash: layout.layout_hash().clone(),
        capacity_hash: capacity_hash.clone(),
        created_at_ms: request.created_at_ms,
    };
    let s = &capacity.scope;
    let prior = &capacity.prior;
    let mut values = [
        StoredValues {
            table: "tree_native_capacity_admissions",
            columns: vec![
                text("space_id", &s.space_id),
                text("transaction_id", &s.transaction_id),
                text("coordinator_execution_id", &s.coordinator_execution_id),
                text("admission_id", &s.admission_id),
                text("admission_hash", &s.admission_hash),
                text("protocol_hash", &s.protocol_hash),
                text("layout_hash", &capacity.layout_hash),
                text("inventory_hash", &prior.fingerprint),
                text("request_hash", hash(request)?),
                text("capacity_hash", &capacity_hash),
                integer("created_at_ms", request.created_at_ms),
                integer("max_entries", capacity.max_entries as u64),
                integer("prior_rows", prior.rows),
                integer("prior_bytes", prior.logical_bytes),
                integer("prior_budget_rows", prior.conservative_rows),
                integer("prior_budget_bytes", prior.conservative_bytes),
                integer("stored_rows", 3),
                integer("stored_bytes", 0),
                text("request", json(request)?),
                text("capacity", json(capacity)?),
            ],
        },
        StoredValues {
            table: "tree_native_action_headers",
            columns: tree_native_header_row_values(&header)?.columns().to_vec(),
        },
        StoredValues {
            table: "tree_native_action_records",
            columns: tree_native_action_row_values(&capacity.layout_hash, &intended)?
                .columns()
                .to_vec(),
        },
    ];
    let bytes = values
        .iter()
        .try_fold(0, |sum, row| add(sum, row.bytes()?))?;
    // This computed value is outside the hashed JSON, so no self-referential size.
    values[0].columns[17] = integer("stored_bytes", bytes);
    if add(prior.rows, 3)? > request.inventory_limits.max_rows as u64
        || add(prior.logical_bytes, bytes)? > request.inventory_limits.max_logical_bytes
        || add(prior.conservative_rows, 3)? > capacity.max_entries as u64
        || add(prior.conservative_bytes, bytes)? > capacity.max_entries as u64 * 1024
    {
        return Err(invalid("tree native prewrite recorded capacity"));
    }
    Ok(Projection {
        values,
        report: TreeNativePrewriteAudit {
            request: request.clone(),
            capacity_hash,
            inventory_at_admission_hash: prior.fingerprint.clone(),
            header,
            intended,
            stored_rows: 3,
            stored_logical_bytes: bytes,
            accounting: ACCOUNTING,
        },
    })
}

pub(crate) fn preflight_all(connection: &Connection, max: usize) -> Result<()> {
    validate_schema(connection, schema::TABLES, Namespace::TreeNative)?;
    preflight(connection, schema::TABLES, max, max as u64 * 1024)?;
    let invalid_owner: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.tree_native_capacity_admissions c
            LEFT JOIN main.tree_restore_coordinator_admissions a USING(transaction_id)
            WHERE a.transaction_id IS NULL
            OR (SELECT count(*) FROM main.tree_native_action_headers WHERE transaction_id=c.transaction_id)!=1
            OR (SELECT count(*) FROM main.tree_native_action_records WHERE transaction_id=c.transaction_id)!=1)
        OR EXISTS(SELECT 1 FROM main.tree_native_action_headers h
            LEFT JOIN main.tree_native_capacity_admissions c USING(transaction_id) WHERE c.transaction_id IS NULL)
        OR EXISTS(SELECT 1 FROM main.tree_native_action_records r
            LEFT JOIN main.tree_native_action_headers h USING(transaction_id) WHERE h.transaction_id IS NULL)",
        [], |r| r.get(0),
    )?;
    if invalid_owner {
        return Err(invalid("tree native prewrite incomplete or orphan owner"));
    }
    Ok(())
}

fn require_exact(connection: &Connection, id: &EntryId, values: &StoredValues) -> Result<()> {
    let selected = values
        .columns
        .iter()
        .map(|c| format!("\"{}\"", c.name))
        .collect::<Vec<_>>()
        .join(",");
    let mut statement = connection.prepare(&format!(
        "SELECT {selected} FROM main.{} WHERE transaction_id=?1",
        values.table
    ))?;
    let mut rows = statement.query([id.as_str()])?;
    let row = rows
        .next()?
        .ok_or(invalid("tree native prewrite missing row"))?;
    for (index, expected) in values.parameters()?.iter().enumerate() {
        if &row.get::<_, Value>(index)? != expected {
            return Err(invalid("tree native prewrite exact physical values"));
        }
    }
    if rows.next()?.is_some() {
        return Err(invalid("tree native prewrite extra row"));
    }
    Ok(())
}

pub(crate) fn audit(
    connection: &Connection,
    p: &TreeRestorePreparation,
    max: usize,
) -> Result<Option<TreeNativePrewriteAudit>> {
    let raw: Option<String> = connection.query_row(
        "SELECT CASE WHEN length(CAST(capacity AS BLOB)) BETWEEN 1 AND 16777216 THEN capacity ELSE '' END
        FROM main.tree_native_capacity_admissions WHERE transaction_id=?1",
        [p.intent.transaction_id.as_str()], |r| r.get(0),
    ).optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let capacity: Capacity = serde_json::from_str(&raw)?;
    let expected = derive(connection, p, &capacity, max)?;
    for values in &expected.values {
        require_exact(connection, &p.intent.transaction_id, values)?;
    }
    Ok(Some(expected.report))
}

fn find<'a>(
    preparations: &'a [TreeRestorePreparation],
    id: &EntryId,
) -> Result<&'a TreeRestorePreparation> {
    preparations
        .iter()
        .find(|p| &p.intent.transaction_id == id)
        .ok_or(invalid("tree native prewrite owner missing"))
}
fn replay(
    p: &TreeRestorePreparation,
    request: &TreeNativePrewriteRequest,
) -> Result<Option<TreeNativePrewriteAudit>> {
    match &p.native_storage {
        Some(old) if old.request == *request => Ok(Some(old.clone())),
        Some(_) => Err(invalid("tree native prewrite immutable request collision")),
        None => Ok(None),
    }
}

impl Journal {
    /// Commit three exact rows, deriving the sole initial Intended internally.
    /// No native action, arbitrary record append, callback or Observed input exists.
    pub fn prepare_tree_native_storage(
        &self,
        space: &SpaceId,
        request: &TreeNativePrewriteRequest,
        max: usize,
    ) -> Result<TreeNativePrewriteAudit> {
        validate_request(request, max)?;
        if !self.connection.is_autocommit() {
            return Err(invalid("tree native prewrite requires own transaction"));
        }
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let (_, p) = self.audit_storage_inventory(space, max, request.inventory_limits)?;
            let old = replay(find(&p, &request.transaction_id)?, request)?;
            tx.commit()?;
            if let Some(old) = old {
                return Ok(old);
            }
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (before, p) = self.audit_storage_inventory(space, max, request.inventory_limits)?;
        self.audit_gc_owners(space, max)?;
        let p = find(&p, &request.transaction_id)?;
        if let Some(old) = replay(p, request)? {
            tx.commit()?;
            return Ok(old);
        }
        let capacity = initial_capacity(&tx, p, request, &before, max)?;
        let expected = derive(&tx, p, &capacity, max)?;
        check_storage_metadata_limit(&tx, max, 3, expected.report.stored_logical_bytes)?;
        for values in &expected.values {
            let columns = values
                .columns
                .iter()
                .map(|c| format!("\"{}\"", c.name))
                .collect::<Vec<_>>()
                .join(",");
            let parameters = values.parameters()?;
            let placeholders = vec!["?"; parameters.len()].join(",");
            tx.execute(
                &format!(
                    "INSERT INTO main.{} ({columns}) VALUES ({placeholders})",
                    values.table
                ),
                params_from_iter(parameters),
            )?;
        }
        let (after, p) = self.audit_storage_inventory(space, max, request.inventory_limits)?;
        self.audit_gc_owners(space, max)?;
        let after_rows: BTreeMap<_, _> = after
            .rows()
            .iter()
            .map(|row| ((row.table(), row.primary_key()), row.fingerprint()))
            .collect();
        if find(&p, &request.transaction_id)?.native_storage.as_ref() != Some(&expected.report)
            || after.rows().len() != before.rows().len() + 3
            || after.logical_bytes()
                != add(before.logical_bytes(), expected.report.stored_logical_bytes)?
            || before.rows().iter().any(|row| {
                after_rows.get(&(row.table(), row.primary_key())).copied()
                    != Some(row.fingerprint())
            })
        {
            return Err(invalid("tree native prewrite commit audit"));
        }
        tx.commit()?;
        Ok(expected.report)
    }
}

fn initial_capacity(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeNativePrewriteRequest,
    inventory: &JournalStorageInventory,
    max: usize,
) -> Result<Capacity> {
    let (_, _, layout) = initial_layout(connection, p, request, max)?;
    Ok(Capacity {
        format_version: 1,
        accounting: ACCOUNTING.into(),
        scope: layout.scope().clone(),
        layout_hash: layout.layout_hash().clone(),
        request: request.clone(),
        max_entries: max,
        prior: PriorInventory {
            fingerprint: inventory.fingerprint().clone(),
            rows: inventory.rows().len() as u64,
            logical_bytes: inventory.logical_bytes(),
            conservative_rows: inventory.conservative_budget().rows,
            conservative_bytes: inventory.conservative_budget().metadata_bytes,
        },
    })
}
