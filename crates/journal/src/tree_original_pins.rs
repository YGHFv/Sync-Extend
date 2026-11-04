//! Exact original content references, not native ownership or action admission.
use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeExecutionDescriptionAudit, TreeRestoreHistoryReservation,
    TreeRestoreNativeReservation, TreeRestorePreparationIntent, MAX_OPERATION_BYTES,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    limits,
    tree_original_reference::{
        plan_tree_original_references, TreeOriginalReferenceIntent, TreeOriginalReferenceLimits,
        TreeOriginalReferencePlan,
    },
    tree_restore_history::encode_history_record,
    ContentId, EntryId, Manifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeOriginalPinRequest {
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub execution_intent_hash: ContentId,
    pub reserved_at_ms: u64,
    pub limits: TreeOriginalReferenceLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeOriginalPinsAudit {
    pub request: TreeOriginalPinRequest,
    pub originals: BTreeMap<usize, TreeOriginalReferenceIntent>,
    pub fingerprint: ContentId,
    pub original_count: usize,
    pub reference_count: usize,
    pub original_logical_bytes: u64,
    pub reserved_rows: u64,
    pub reserved_metadata_bytes: u64,
    pub exact_original_pins_verified: bool,
    pub active_reference_count: usize,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

struct Projection {
    core: TreeOriginalReferencePlan,
    request_json: String,
    owner_json: BTreeMap<usize, String>,
    audit: TreeOriginalPinsAudit,
}

impl TreeOriginalPinRequest {
    fn validate(&self, max: usize) -> Result<()> {
        sql_integer(self.reserved_at_ms)?;
        if max == 0
            || max > limits::MAX_ENTRIES
            || self.limits.max_owners == 0
            || self.limits.max_owners > max
            || self.limits.max_chunk_visits > max
            || self.limits.max_reference_rows > max
            || self.limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
        {
            return Err(JournalError::Invariant("tree original pin request bounds"));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn project(
    preparation: &TreeRestorePreparationIntent,
    history: &TreeRestoreHistoryReservation,
    native: &TreeRestoreNativeReservation,
    description: &TreeExecutionDescriptionAudit,
    baseline: &Manifest,
    target: &Manifest,
    request: &TreeOriginalPinRequest,
    max: usize,
) -> Result<Projection> {
    request.validate(max)?;
    if request.transaction_id != preparation.transaction_id
        || request.coordinator_execution_id != description.intent.input.execution_id
        || request.execution_intent_hash != description.intent_hash
        || request.reserved_at_ms < description.intent.input.created_at_ms
    {
        return Err(JournalError::Invariant(
            "tree original exact coordinator binding",
        ));
    }
    let execution = crate::tree_restore_execution_intent::project(
        preparation,
        history,
        native,
        baseline,
        target,
        &description.intent.input,
        max,
    )?;
    let core = plan_tree_original_references(&execution.plan, &execution.identity, request.limits)?;
    let request_json =
        String::from_utf8(encode_history_record(request, MAX_OPERATION_BYTES as u64)?)
            .map_err(|_| JournalError::Invariant("tree original request encoding"))?;
    // Header: two IDs, three hashes, six integers; owners and pins are separate values.
    let mut bytes = request_json.len() as u64 + 304;
    let mut owner_json = BTreeMap::new();
    for (index, intent) in core.intents() {
        let json = String::from_utf8(encode_history_record(intent, MAX_OPERATION_BYTES as u64)?)
            .map_err(|_| JournalError::Invariant("tree original owner encoding"))?;
        bytes = bytes
            .checked_add(json.len() as u64 + 264)
            .ok_or(JournalError::Invariant("tree original metadata overflow"))?;
        owner_json.insert(*index, json);
    }
    bytes = bytes
        .checked_add(144 * core.reference_rows() as u64)
        .filter(|n| *n <= max as u64 * 1024)
        .ok_or(JournalError::Invariant("tree original metadata byte limit"))?;
    let reserved_rows = 1 + core.intents().len() as u64 + core.reference_rows() as u64;
    if reserved_rows > max as u64 {
        return Err(JournalError::Invariant("tree original metadata row limit"));
    }
    let audit = TreeOriginalPinsAudit {
        request: request.clone(),
        originals: core.intents().clone(),
        fingerprint: core.fingerprint().clone(),
        original_count: core.intents().len(),
        reference_count: core.reference_rows(),
        original_logical_bytes: core.original_logical_bytes(),
        reserved_rows,
        reserved_metadata_bytes: bytes,
        exact_original_pins_verified: true,
        active_reference_count: core.reference_rows(),
        native_tree_verified: false,
        execution_admission_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    };
    Ok(Projection {
        core,
        request_json,
        owner_json,
        audit,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_originals(
    journal: &Journal,
    preparation: &TreeRestorePreparationIntent,
    history: Option<&TreeRestoreHistoryReservation>,
    native: Option<&TreeRestoreNativeReservation>,
    description: Option<&TreeExecutionDescriptionAudit>,
    baseline: &Manifest,
    target: &Manifest,
    cancelled: Option<u64>,
    max: usize,
) -> Result<Option<TreeOriginalPinsAudit>> {
    let connection = &journal.connection;
    let request: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216
         THEN request ELSE '' END FROM tree_restore_original_reservations WHERE transaction_id=?1",
            [preparation.transaction_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(json) = request else {
        return Ok(None);
    };
    let request: TreeOriginalPinRequest = serde_json::from_str(&json)?;
    let mut projection = project(
        preparation,
        history.ok_or(JournalError::Invariant("tree original history missing"))?,
        native.ok_or(JournalError::Invariant(
            "tree original native description missing",
        ))?,
        description.ok_or(JournalError::Invariant("tree original coordinator missing"))?,
        baseline,
        target,
        &request,
        max,
    )?;
    let a = &projection.audit;
    let exact: bool = connection.query_row(
        "SELECT coordinator_execution_id=?2 AND execution_intent_hash=?3 AND request=?4
         AND request_hash=?5 AND closure_hash=?6 AND reserved_at_ms=?7 AND owner_count=?8
         AND reference_count=?9 AND original_logical_bytes=?10 AND reserved_rows=?11 AND reserved_bytes=?12
         FROM tree_restore_original_reservations WHERE transaction_id=?1",
        params![preparation.transaction_id.as_str(), request.coordinator_execution_id.as_str(),
            request.execution_intent_hash.as_str(), projection.request_json,
            ContentId::hash(json.as_bytes()).as_str(), a.fingerprint.as_str(),
            sql_integer(request.reserved_at_ms)?, sql_integer(a.original_count as u64)?,
            sql_integer(a.reference_count as u64)?, sql_integer(a.original_logical_bytes)?,
            sql_integer(a.reserved_rows)?, sql_integer(a.reserved_metadata_bytes)?],
        |r| r.get(0),
    )?;
    if !exact
        || json != projection.request_json
        || cancelled.is_some_and(|t| t < request.reserved_at_ms)
    {
        return Err(JournalError::Invariant(
            "tree original header integrity mismatch",
        ));
    }
    let mut statement = connection.prepare(
        "SELECT step_index,
         CASE WHEN length(CAST(step_execution_id AS BLOB))=32 THEN step_execution_id ELSE '' END,
         CASE WHEN length(CAST(coordinator_execution_id AS BLOB))=32 THEN coordinator_execution_id ELSE '' END,
         CASE WHEN length(CAST(original_entry_id AS BLOB))=32 THEN original_entry_id ELSE '' END,
         CASE WHEN length(CAST(step_intent_hash AS BLOB))=64 THEN step_intent_hash ELSE '' END,
         CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216 THEN intent ELSE '' END,
         CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END FROM tree_restore_original_owners
         WHERE transaction_id=?1 ORDER BY step_index",
    )?;
    let mut owners = statement.query([preparation.transaction_id.as_str()])?;
    for (index, intent) in projection.core.intents() {
        let row = owners
            .next()?
            .ok_or(JournalError::Invariant("tree original owner missing"))?;
        let encoded = &projection.owner_json[index];
        if row.get::<_, i64>(0)? != sql_integer(*index as u64)?
            || row.get::<_, String>(1)? != intent.step_execution_id.as_str()
            || row.get::<_, String>(2)? != intent.coordinator_execution_id.as_str()
            || row.get::<_, String>(3)? != intent.original_entry_id.as_str()
            || row.get::<_, String>(4)? != intent.step_intent_hash.as_str()
            || row.get::<_, String>(5)? != *encoded
            || row.get::<_, String>(6)? != ContentId::hash(encoded.as_bytes()).as_str()
        {
            return Err(JournalError::Invariant(
                "tree original exact owner mismatch",
            ));
        }
    }
    if owners.next()?.is_some() {
        return Err(JournalError::Invariant("extra tree original owner"));
    }
    let mut statement = connection.prepare(
        "SELECT step_index,
         CASE WHEN length(CAST(step_execution_id AS BLOB))=32 THEN step_execution_id ELSE '' END,
         CASE WHEN length(CAST(content_id AS BLOB))=64 THEN content_id ELSE '' END,
         length FROM tree_restore_original_objects
         WHERE transaction_id=?1 ORDER BY step_index,content_id",
    )?;
    let mut pins = statement.query([preparation.transaction_id.as_str()])?;
    if cancelled.is_none() {
        for (index, closure) in projection.core.closures() {
            for (chunk, length) in closure {
                let row = pins
                    .next()?
                    .ok_or(JournalError::Invariant("tree original own pin missing"))?;
                if row.get::<_, i64>(0)? != sql_integer(*index as u64)?
                    || row.get::<_, String>(1)?
                        != projection.core.intents()[index].step_execution_id.as_str()
                    || row.get::<_, String>(2)? != chunk.as_str()
                    || row.get::<_, i64>(3)? != i64::from(*length)
                {
                    return Err(JournalError::Invariant(
                        "tree original exact own pin mismatch",
                    ));
                }
                journal.require_cas_access(chunk)?;
            }
        }
    }
    if pins.next()?.is_some() {
        return Err(JournalError::Invariant("extra tree original own pin"));
    }
    if cancelled.is_some() {
        projection.audit.exact_original_pins_verified = false;
        projection.audit.active_reference_count = 0;
    }
    Ok(Some(projection.audit))
}

impl Journal {
    /// Reserve immutable exact closures; inspection cannot authorize a native move.
    pub fn with_tree_original_pins<T, E>(
        &self,
        request: &TreeOriginalPinRequest,
        max: usize,
        inspect: impl FnOnce(&TreeOriginalReferencePlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeOriginalPinsAudit), E>
    where
        E: From<JournalError>,
    {
        request.validate(max)?;
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree original space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree original pin owner"))
        };
        let replay = |prior: &TreeOriginalPinsAudit| -> Result<()> {
            if prior.request != *request {
                return Err(JournalError::Invariant("tree original request collision"));
            }
            Ok(())
        };
        let old = find()?;
        if let Some(prior) = old.original_pins {
            replay(&prior)?;
            return Ok((None, prior));
        }
        if !old.writer_gate_held {
            return Err(JournalError::Invariant("cancelled tree original pin owner").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let preparation = find()?;
        if let Some(prior) = preparation.original_pins {
            replay(&prior)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, prior));
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("tree original owner cancelled").into());
        }
        let baseline =
            audit_snapshot(&tx, &space, &preparation.intent.scope.baseline_snapshot)?.manifest;
        let target =
            audit_snapshot(&tx, &space, &preparation.intent.scope.target_snapshot)?.manifest;
        let projected = project(
            &preparation.intent,
            preparation
                .history_reservation
                .as_ref()
                .ok_or(JournalError::Invariant("tree original history missing"))?,
            preparation
                .native_reservation
                .as_ref()
                .ok_or(JournalError::Invariant("tree original native missing"))?,
            preparation
                .execution_description
                .as_ref()
                .ok_or(JournalError::Invariant("tree original coordinator missing"))?,
            &baseline,
            &target,
            request,
            max,
        )?;
        let a = &projected.audit;
        check_storage_metadata_limit(&tx, max, a.reserved_rows, a.reserved_metadata_bytes)?;
        for closure in projected.core.closures().values() {
            for id in closure.keys() {
                self.require_cas_access(id)?;
            }
        }
        tx.execute(
            "INSERT INTO tree_restore_original_reservations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![request.transaction_id.as_str(), request.coordinator_execution_id.as_str(),
                request.execution_intent_hash.as_str(), projected.request_json,
                ContentId::hash(projected.request_json.as_bytes()).as_str(), a.fingerprint.as_str(),
                sql_integer(request.reserved_at_ms)?, sql_integer(a.original_count as u64)?,
                sql_integer(a.reference_count as u64)?, sql_integer(a.original_logical_bytes)?,
                sql_integer(a.reserved_rows)?, sql_integer(a.reserved_metadata_bytes)?],
        ).map_err(JournalError::from)?;
        for (index, intent) in projected.core.intents() {
            let json = &projected.owner_json[index];
            tx.execute(
                "INSERT INTO tree_restore_original_owners VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    request.transaction_id.as_str(),
                    sql_integer(*index as u64)?,
                    intent.step_execution_id.as_str(),
                    intent.coordinator_execution_id.as_str(),
                    intent.original_entry_id.as_str(),
                    intent.step_intent_hash.as_str(),
                    json,
                    ContentId::hash(json.as_bytes()).as_str()
                ],
            )
            .map_err(JournalError::from)?;
            for (id, length) in &projected.core.closures()[index] {
                tx.execute(
                    "INSERT INTO tree_restore_original_objects VALUES (?1,?2,?3,?4,?5)",
                    params![
                        request.transaction_id.as_str(),
                        sql_integer(*index as u64)?,
                        intent.step_execution_id.as_str(),
                        id.as_str(),
                        length
                    ],
                )
                .map_err(JournalError::from)?;
            }
        }
        self.audit_gc_owners(&space, max)?;
        let held = inspect(&projected.core)?;
        self.audit_gc_owners(&space, max)?;
        let final_audit = find()?.original_pins.ok_or(JournalError::Invariant(
            "tree original reservation disappeared",
        ))?;
        if final_audit != projected.audit {
            return Err(
                JournalError::Invariant("tree original pins changed during inspection").into(),
            );
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), final_audit))
    }
}
