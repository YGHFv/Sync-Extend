//! Immutable TREE future component admission, not complete global capacity.
use crate::{
    check_storage_metadata_limit, sql_integer,
    storage_inventory::reader::{add, hash, invalid},
    Journal, JournalStorageInventory, Result, TreeRestoreInventoryLimits, TreeRestorePreparation,
    MAX_OPERATION_BYTES,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    tree_native_action_layout::TreeNativeActionScope,
    tree_native_future_obligations::{
        plan_tree_native_future_obligations, TreeNativeFutureGenerations, TreeNativeFutureLimits,
    },
    tree_restore_history::encode_history_record,
    tree_storage_capacity::{TreeStorageCharge, TreeStorageMetadataObligation},
    ContentId, EntryId, SpaceId,
};

mod generations;
pub(crate) mod schema;
mod values;

const ACCOUNTING: &str = "tree-future-component-only-not-global-capacity-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeFutureAdmissionRequest {
    pub transaction_id: EntryId,
    pub created_at_ms: u64,
    pub layout_limits: TreeNativeFutureLimits,
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
    prewrite_capacity_hash: ContentId,
    initial_intended_hash: ContentId,
    request: TreeNativeFutureAdmissionRequest,
    max_entries: usize,
    prior: PriorInventory,
    generations: TreeNativeFutureGenerations,
    action_count: usize,
    original_count: usize,
    obligations: Vec<TreeStorageMetadataObligation>,
    new_charge: TreeStorageCharge,
    new_values_hash: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeNativeFutureAdmissionAudit {
    request: TreeNativeFutureAdmissionRequest,
    capacity_hash: ContentId,
    prewrite_capacity_hash: ContentId,
    inventory_at_admission_hash: ContentId,
    generations: TreeNativeFutureGenerations,
    obligations: Vec<TreeStorageMetadataObligation>,
    new_charge: TreeStorageCharge,
    future_charge: TreeStorageCharge,
    stored_rows: u64,
    stored_logical_bytes: u64,
    accounting: &'static str,
}
impl TreeNativeFutureAdmissionAudit {
    pub fn request(&self) -> &TreeNativeFutureAdmissionRequest {
        &self.request
    }
    pub fn capacity_hash(&self) -> &ContentId {
        &self.capacity_hash
    }
    pub fn prewrite_capacity_hash(&self) -> &ContentId {
        &self.prewrite_capacity_hash
    }
    pub fn inventory_at_admission_hash(&self) -> &ContentId {
        &self.inventory_at_admission_hash
    }
    pub fn generations(&self) -> &TreeNativeFutureGenerations {
        &self.generations
    }
    pub fn obligations(&self) -> &[TreeStorageMetadataObligation] {
        &self.obligations
    }
    pub fn new_charge(&self) -> TreeStorageCharge {
        self.new_charge
    }
    pub fn future_charge(&self) -> TreeStorageCharge {
        self.future_charge
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
    pub fn tree_future_component_reserved(&self) -> bool {
        true
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

struct Projection {
    rows: Vec<values::StoredRow>,
    report: TreeNativeFutureAdmissionAudit,
}

fn validate_request(request: &TreeNativeFutureAdmissionRequest, max: usize) -> Result<()> {
    crate::tree_storage_inventory::validate_limits(max, request.inventory_limits)?;
    sql_integer(request.created_at_ms)?;
    let b = request.layout_limits;
    if b.max_records == 0
        || b.max_records > max
        || b.max_originals > max
        || b.max_reference_rows > max
        || b.max_rows == 0
        || b.max_rows > max
        || b.max_input_bytes == 0
        || b.max_input_bytes > MAX_OPERATION_BYTES as u64
        || b.max_encoded_bytes == 0
        || b.max_encoded_bytes > MAX_OPERATION_BYTES as u64
        || b.max_logical_bytes == 0
        || b.max_logical_bytes > max as u64 * 1024
    {
        return Err(invalid("tree future admission limits"));
    }
    encode_history_record(request, MAX_OPERATION_BYTES as u64)?;
    Ok(())
}

fn derive(
    connection: &Connection,
    p: &TreeRestorePreparation,
    capacity: &Capacity,
    max: usize,
) -> Result<Projection> {
    validate_request(&capacity.request, capacity.max_entries)?;
    let prewrite = p
        .native_storage
        .as_ref()
        .ok_or(invalid("tree future initial prewrite missing"))?;
    if capacity.format_version != 1
        || capacity.accounting != ACCOUNTING
        || capacity.request.transaction_id != p.intent.transaction_id
        || capacity.request.created_at_ms < prewrite.request().created_at_ms
        || capacity.scope != prewrite.header().scope
        || capacity.layout_hash != prewrite.header().layout_hash
        || &capacity.prewrite_capacity_hash != prewrite.capacity_hash()
        || capacity.initial_intended_hash != hash(prewrite.intended())?
    {
        return Err(invalid("tree future prewrite binding"));
    }
    let (projection, protocol, _) =
        crate::tree_native_storage::initial_layout(connection, p, prewrite.request(), max)?;
    let plan = plan_tree_native_future_obligations(
        &projection.context(),
        &protocol,
        prewrite.intended(),
        &capacity.generations,
        capacity.request.layout_limits,
    )?;
    let history = p
        .history_reservation
        .as_ref()
        .ok_or(invalid("tree future history reservation missing"))?;
    if capacity.action_count != plan.action_count()
        || capacity.original_count != plan.original_count()
        || capacity.obligations != plan.obligations()
        || capacity.new_charge != plan.new_charge()
        || capacity.new_values_hash != hash(&plan.exact_new_values())?
        || capacity.new_charge.rows != history.history_footprint.row_writes
        || capacity.new_charge.logical_bytes != history.history_footprint.metadata_bytes
    {
        return Err(invalid("tree future exact obligations or NEW charge"));
    }
    let stored_rows = add(
        3,
        add(plan.action_count() as u64, plan.original_count() as u64)?,
    )?;
    let mut report = TreeNativeFutureAdmissionAudit {
        request: capacity.request.clone(),
        capacity_hash: hash(capacity)?,
        prewrite_capacity_hash: capacity.prewrite_capacity_hash.clone(),
        inventory_at_admission_hash: capacity.prior.fingerprint.clone(),
        generations: capacity.generations.clone(),
        obligations: capacity.obligations.clone(),
        new_charge: capacity.new_charge,
        future_charge: plan.future_charge(),
        stored_rows,
        stored_logical_bytes: 0,
        accounting: ACCOUNTING,
    };
    let rows = values::rows(capacity, &report)?;
    report.stored_logical_bytes = rows.iter().try_fold(0, |sum, row| add(sum, row.bytes()?))?;
    if rows.len() as u64 != stored_rows {
        return Err(invalid("tree future actual row inventory"));
    }
    let extra_rows = add(stored_rows, report.future_charge.rows)?;
    let extra_bytes = add(
        report.stored_logical_bytes,
        report.future_charge.logical_bytes,
    )?;
    let prior = &capacity.prior;
    if add(add(prior.rows, extra_rows)?, capacity.new_charge.rows)?
        > capacity.request.inventory_limits.max_rows as u64
        || add(
            add(prior.logical_bytes, extra_bytes)?,
            capacity.new_charge.logical_bytes,
        )? > capacity.request.inventory_limits.max_logical_bytes
        || add(prior.conservative_rows, extra_rows)? > capacity.max_entries as u64
        || add(prior.conservative_bytes, extra_bytes)? > capacity.max_entries as u64 * 1024
    {
        return Err(invalid("tree future recorded component capacity"));
    }
    Ok(Projection { rows, report })
}

pub(crate) fn preflight_all(connection: &Connection, max: usize) -> Result<()> {
    let nonempty = schema::EFFECT_TABLES
        .iter()
        .map(|table| format!("EXISTS(SELECT 1 FROM main.{})", table.name))
        .collect::<Vec<_>>()
        .join(" OR ");
    if connection.query_row(&format!("SELECT {nonempty}"), [], |row| {
        row.get::<_, bool>(0)
    })? {
        return Err(invalid("tree future native effects remain unavailable"));
    }
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.tree_native_future_admissions f
         LEFT JOIN main.tree_native_capacity_admissions p USING(transaction_id)
         WHERE p.transaction_id IS NULL OR
         (SELECT count(*) FROM main.tree_native_future_generations g
          WHERE g.transaction_id=f.transaction_id)!=f.action_count+f.original_count+2)
         OR EXISTS(SELECT 1 FROM main.tree_native_future_generations g
         LEFT JOIN main.tree_native_future_admissions f USING(transaction_id)
         WHERE f.transaction_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if orphan {
        return Err(invalid("tree future incomplete or orphan bundle"));
    }
    generations::stored(connection, max)?;
    Ok(())
}

pub(crate) fn audit(
    connection: &Connection,
    p: &TreeRestorePreparation,
    max: usize,
) -> Result<Option<TreeNativeFutureAdmissionAudit>> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(capacity AS BLOB)) BETWEEN 1 AND 16777216
         THEN capacity ELSE '' END FROM main.tree_native_future_admissions
         WHERE transaction_id=?1",
            [p.intent.transaction_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let capacity: Capacity = serde_json::from_str(&raw)?;
    let expected = derive(connection, p, &capacity, max)?;
    for row in &expected.rows {
        row.require_exact(connection)?;
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
        .ok_or(invalid("tree future owner missing"))
}
fn replay(
    p: &TreeRestorePreparation,
    request: &TreeNativeFutureAdmissionRequest,
) -> Result<Option<TreeNativeFutureAdmissionAudit>> {
    match &p.native_future_admission {
        Some(old) if &old.request == request => Ok(Some(old.clone())),
        Some(_) => Err(invalid("tree future immutable request collision")),
        None => Ok(None),
    }
}

impl Journal {
    /// Reserve concrete TREE future columns without enabling any native effect.
    /// Replay is read-only and never issues an attempt or a continuation.
    pub fn admit_tree_native_future(
        &self,
        space: &SpaceId,
        request: &TreeNativeFutureAdmissionRequest,
        max: usize,
    ) -> Result<TreeNativeFutureAdmissionAudit> {
        validate_request(request, max)?;
        if !self.connection.is_autocommit() {
            return Err(invalid("tree future admission requires own transaction"));
        }
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let (_, preparations) =
                self.audit_storage_inventory(space, max, request.inventory_limits)?;
            let old = replay(find(&preparations, &request.transaction_id)?, request)?;
            tx.commit()?;
            if let Some(old) = old {
                return Ok(old);
            }
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (before, preparations) =
            self.audit_storage_inventory(space, max, request.inventory_limits)?;
        self.audit_gc_owners(space, max)?;
        let p = find(&preparations, &request.transaction_id)?;
        if let Some(old) = replay(p, request)? {
            tx.commit()?;
            return Ok(old);
        }
        let capacity = initial_capacity(&tx, p, request, &before, max)?;
        generations::admit(&tx, &capacity.generations, max)?;
        let expected = derive(&tx, p, &capacity, max)?;
        check_storage_metadata_limit(
            &tx,
            max,
            add(
                expected.report.stored_rows,
                expected.report.future_charge.rows,
            )?,
            add(
                expected.report.stored_logical_bytes,
                expected.report.future_charge.logical_bytes,
            )?,
        )?;
        for row in &expected.rows {
            row.insert(&tx)?;
        }
        let (after, preparations) =
            self.audit_storage_inventory(space, max, request.inventory_limits)?;
        self.audit_gc_owners(space, max)?;
        let after_rows: BTreeMap<_, _> = after
            .rows()
            .iter()
            .map(|row| ((row.table(), row.primary_key()), row.fingerprint()))
            .collect();
        if find(&preparations, &request.transaction_id)?
            .native_future_admission
            .as_ref()
            != Some(&expected.report)
            || after.rows().len() as u64
                != add(before.rows().len() as u64, expected.report.stored_rows)?
            || after.logical_bytes()
                != add(before.logical_bytes(), expected.report.stored_logical_bytes)?
            || before.rows().iter().any(|row| {
                after_rows.get(&(row.table(), row.primary_key())).copied()
                    != Some(row.fingerprint())
            })
        {
            return Err(invalid("tree future exact commit audit"));
        }
        tx.commit()?;
        Ok(expected.report)
    }
}

fn initial_capacity(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeNativeFutureAdmissionRequest,
    inventory: &JournalStorageInventory,
    max: usize,
) -> Result<Capacity> {
    let prewrite = p
        .native_storage
        .as_ref()
        .ok_or(invalid("tree future initial prewrite missing"))?;
    let (projection, protocol, action) =
        crate::tree_native_storage::initial_layout(connection, p, prewrite.request(), max)?;
    let context = projection.context();
    let originals = context.originals.intents().len();
    if request.transaction_id != p.intent.transaction_id
        || request.created_at_ms < prewrite.request().created_at_ms
        || action
            .action_count()
            .checked_mul(2)
            .is_none_or(|n| n > request.layout_limits.max_records)
        || originals > request.layout_limits.max_originals
        || action
            .action_count()
            .checked_mul(3)
            .and_then(|n| n.checked_add(7))
            .and_then(|n| n.checked_add(originals.checked_mul(4)?))
            .is_none_or(|n| n > request.layout_limits.max_rows)
    {
        return Err(invalid("tree future initial scope time or inventory"));
    }
    let generations = TreeNativeFutureGenerations {
        finalization_id: EntryId::random()?,
        cleanup_id: EntryId::random()?,
        attempt_ids: (0..action.action_count())
            .map(|i| Ok((i, EntryId::random()?)))
            .collect::<sync_extend_core_model::Result<_>>()?,
        disposal_ids: context
            .originals
            .intents()
            .keys()
            .map(|&i| Ok((i, EntryId::random()?)))
            .collect::<sync_extend_core_model::Result<_>>()?,
    };
    let plan = plan_tree_native_future_obligations(
        &context,
        &protocol,
        prewrite.intended(),
        &generations,
        request.layout_limits,
    )?;
    Ok(Capacity {
        format_version: 1,
        accounting: ACCOUNTING.into(),
        scope: prewrite.header().scope.clone(),
        layout_hash: prewrite.header().layout_hash.clone(),
        prewrite_capacity_hash: prewrite.capacity_hash().clone(),
        initial_intended_hash: hash(prewrite.intended())?,
        request: request.clone(),
        max_entries: max,
        prior: PriorInventory {
            fingerprint: inventory.fingerprint().clone(),
            rows: inventory.rows().len() as u64,
            logical_bytes: inventory.logical_bytes(),
            conservative_rows: inventory.conservative_budget().rows,
            conservative_bytes: inventory.conservative_budget().metadata_bytes,
        },
        generations,
        action_count: plan.action_count(),
        original_count: plan.original_count(),
        obligations: plan.obligations().to_vec(),
        new_charge: plan.new_charge(),
        new_values_hash: hash(&plan.exact_new_values())?,
    })
}
