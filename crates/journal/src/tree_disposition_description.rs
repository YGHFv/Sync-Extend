//! Persist original terminal descriptions only, never disposal or pin release.
use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeRestorePreparation, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    tree_original_disposition::{
        audit_tree_original_disposition_records, plan_tree_original_dispositions,
        TreeOriginalDispositionInput, TreeOriginalDispositionIntent, TreeOriginalDispositionLimits,
        TreeOriginalDispositionPlan, TreeOriginalDispositionRecord,
        TreeOriginalDispositionRecordAudit, TreeOriginalDispositionRecordLimits,
    },
    tree_restore_history::encode_history_record,
    ContentId,
};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeDispositionDescriptionRequest {
    pub input: TreeOriginalDispositionInput,
    pub limits: TreeOriginalDispositionLimits,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeDispositionDescriptionAudit {
    pub request: TreeDispositionDescriptionRequest,
    pub intents: BTreeMap<usize, TreeOriginalDispositionIntent>,
    pub fingerprint: ContentId,
    pub intent_hashes: BTreeMap<usize, ContentId>,
    pub records: BTreeMap<usize, Vec<TreeOriginalDispositionRecord>>,
    pub terminal_descriptions: BTreeSet<usize>,
    pub records_fingerprint: ContentId,
    pub metadata_bytes: u64,
    pub description_rows: u64,
    pub native_disposition_available: bool,
    pub native_absence_verified: bool,
    pub original_reference_release_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}
fn project(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeDispositionDescriptionRequest,
    max: usize,
) -> Result<TreeOriginalDispositionPlan> {
    if request.limits.max_owners > max
        || request.limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
    {
        return Err(JournalError::Invariant(
            "tree disposition description inventory",
        ));
    }
    let final_description = p.final_description.as_ref().ok_or(JournalError::Invariant(
        "tree disposition final description missing",
    ))?;
    if request.input.final_description_hash != final_description.intent_hash {
        return Err(JournalError::Invariant(
            "tree disposition actual final hash mismatch",
        ));
    }
    let final_plan =
        crate::tree_final_description::project(connection, p, &final_description.request, max)?;
    let baseline = audit_snapshot(
        connection,
        &p.intent.scope.space_id,
        &p.intent.scope.baseline_snapshot,
    )?
    .manifest;
    let target = audit_snapshot(
        connection,
        &p.intent.scope.space_id,
        &p.intent.scope.target_snapshot,
    )?
    .manifest;
    let execution = p
        .execution_description
        .as_ref()
        .ok_or(JournalError::Invariant(
            "tree disposition execution missing",
        ))?;
    let history = p
        .history_reservation
        .as_ref()
        .ok_or(JournalError::Invariant("tree disposition history missing"))?;
    let native = p
        .native_reservation
        .as_ref()
        .ok_or(JournalError::Invariant("tree disposition native missing"))?;
    let execution = crate::tree_restore_execution_intent::project(
        &p.intent,
        history,
        native,
        &baseline,
        &target,
        &execution.intent.input,
        max,
    )?;
    Ok(plan_tree_original_dispositions(
        &execution.plan,
        &final_plan,
        &request.input,
        request.limits,
        &baseline,
        &target,
    )?)
}
fn record_bounds(max: usize) -> TreeOriginalDispositionRecordLimits {
    TreeOriginalDispositionRecordLimits {
        max_records: max,
        max_encoded_bytes: MAX_OPERATION_BYTES as u64,
    }
}
fn report(
    request: &TreeDispositionDescriptionRequest,
    plan: &TreeOriginalDispositionPlan,
    records: &TreeOriginalDispositionRecordAudit,
    bytes: u64,
) -> TreeDispositionDescriptionAudit {
    TreeDispositionDescriptionAudit {
        request: request.clone(),
        intents: plan.intents().clone(),
        fingerprint: plan.fingerprint().clone(),
        intent_hashes: plan.intent_hashes().clone(),
        records: records.records().clone(),
        terminal_descriptions: records.terminals().clone(),
        records_fingerprint: records.fingerprint().clone(),
        metadata_bytes: bytes,
        description_rows: 1
            + plan.intents().len() as u64
            + records
                .records()
                .values()
                .map(|r| r.len() as u64)
                .sum::<u64>(),
        native_disposition_available: false,
        native_absence_verified: false,
        original_reference_release_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    }
}
fn reserved_values(
    request: &TreeDispositionDescriptionRequest,
    plan: &TreeOriginalDispositionPlan,
) -> Result<u64> {
    let mut bytes = encode_history_record(request, MAX_OPERATION_BYTES as u64)?.len() as u64 + 288;
    for intent in plan.intents().values() {
        bytes = bytes
            .checked_add(
                encode_history_record(intent, MAX_OPERATION_BYTES as u64)?.len() as u64 + 336,
            )
            .ok_or(JournalError::Invariant(
                "tree disposition description bytes overflow",
            ))?;
    }
    Ok(bytes)
}

pub(crate) fn audit_dispositions(
    connection: &Connection,
    p: &TreeRestorePreparation,
    max: usize,
) -> Result<Option<TreeDispositionDescriptionAudit>> {
    let transaction = p.intent.transaction_id.as_str();
    let json:Option<String>=connection.query_row(
        "SELECT CASE WHEN length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216 THEN request ELSE '' END
        FROM tree_restore_disposition_reservations WHERE transaction_id=?1",[transaction],|r|r.get(0)).optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let request: TreeDispositionDescriptionRequest = serde_json::from_str(&json)?;
    let (owners, records): (i64, i64) = connection.query_row(
        "SELECT (SELECT count(*) FROM tree_restore_disposition_intents WHERE transaction_id=?1),
        (SELECT count(*) FROM tree_restore_disposition_records WHERE transaction_id=?1)",
        [transaction],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if owners < 0 || records < 0 || owners as u64 + records as u64 + 1 > max as u64 {
        return Err(JournalError::Invariant("tree disposition row inventory"));
    }
    let plan = project(connection, p, &request, max)?;
    let reserve = reserved_values(&request, &plan)?;
    let input = &request.input;
    let exact:bool=connection.query_row(
        "SELECT coordinator_execution_id=?2 AND final_description_hash=?3 AND request_hash=?4
        AND plan_hash=?5 AND request=?6 AND described_at_ms=?7 AND owner_count=?8 AND reserved_rows=?9
        AND reserved_bytes=?10 FROM tree_restore_disposition_reservations WHERE transaction_id=?1",
        params![transaction,input.coordinator_execution_id.as_str(),input.final_description_hash.as_str(),
            ContentId::hash(json.as_bytes()).as_str(),plan.fingerprint().as_str(),serde_json::to_string(&request)?,
            sql_integer(input.described_at_ms)?,sql_integer(plan.intents().len() as u64)?,
            sql_integer(1+plan.intents().len() as u64)?,sql_integer(reserve)?],|r|r.get(0))?;
    if !exact || p.cancelled_at_ms.is_some_and(|t| t < input.described_at_ms) {
        return Err(JournalError::Invariant(
            "tree disposition exact header mismatch",
        ));
    }
    let mut statement=connection.prepare(
        "SELECT step_index,coordinator_execution_id,step_execution_id,disposition_id,final_description_hash,
        retained_description_hash,intent_hash,described_at_ms,
        CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216 THEN intent ELSE '' END
        FROM tree_restore_disposition_intents WHERE transaction_id=?1 ORDER BY step_index")?;
    let mut rows = statement.query([transaction])?;
    for (index, intent) in plan.intents() {
        let row = rows.next()?.ok_or(JournalError::Invariant(
            "tree disposition owner intent missing",
        ))?;
        if row.get::<_, i64>(0)? != sql_integer(*index as u64)?
            || row.get::<_, String>(1)? != input.coordinator_execution_id.as_str()
            || row.get::<_, String>(2)? != intent.retained.original.step_execution_id.as_str()
            || row.get::<_, String>(3)? != intent.disposition_id.as_str()
            || row.get::<_, String>(4)? != input.final_description_hash.as_str()
            || row.get::<_, String>(5)? != intent.retained_description_hash.as_str()
            || row.get::<_, String>(6)? != plan.intent_hashes()[index].as_str()
            || row.get::<_, i64>(7)? != sql_integer(input.described_at_ms)?
            || row.get::<_, String>(8)? != serde_json::to_string(intent)?
        {
            return Err(JournalError::Invariant(
                "tree disposition exact owner intent mismatch",
            ));
        }
    }
    if rows.next()?.is_some() {
        return Err(JournalError::Invariant(
            "tree disposition extra owner intent",
        ));
    }
    let mut statement=connection.prepare(
        "SELECT step_index,record_index,coordinator_execution_id,disposition_id,intent_hash,previous_hash,
        record_hash,recorded_at_ms,CASE WHEN length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216 THEN record ELSE '' END
        FROM tree_restore_disposition_records WHERE transaction_id=?1 ORDER BY step_index,record_index")?;
    let mut rows = statement.query([transaction])?;
    let mut records = BTreeMap::<usize, Vec<TreeOriginalDispositionRecord>>::new();
    let mut bytes = reserve;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .filter(|n| *n <= max)
            .ok_or(JournalError::Invariant("tree disposition record inventory"))?;
        let json: String = row.get(8)?;
        let record: TreeOriginalDispositionRecord = serde_json::from_str(&json)?;
        bytes = bytes
            .checked_add(json.len() as u64 + 312)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant(
                "tree disposition record byte inventory",
            ))?;
        if record.transaction_id.as_str() != transaction
            || sql_integer(record.step_index as u64)? != row.get::<_, i64>(0)?
            || sql_integer(record.record_index as u64)? != row.get::<_, i64>(1)?
            || record.coordinator_execution_id.as_str() != row.get::<_, String>(2)?
            || record.disposition_id.as_str() != row.get::<_, String>(3)?
            || record.intent_hash.as_str() != row.get::<_, String>(4)?
            || record.previous_hash.as_str() != row.get::<_, String>(5)?
            || ContentId::hash(json.as_bytes()).as_str() != row.get::<_, String>(6)?
            || sql_integer(record.recorded_at_ms)? != row.get::<_, i64>(7)?
            || json != serde_json::to_string(&record)?
            || p.cancelled_at_ms.is_some_and(|t| t < record.recorded_at_ms)
        {
            return Err(JournalError::Invariant(
                "tree disposition exact record row mismatch",
            ));
        }
        records.entry(record.step_index).or_default().push(record);
    }
    if 1 + plan.intents().len() + count > max || bytes > max as u64 * 1024 {
        return Err(JournalError::Invariant(
            "tree disposition exact row byte inventory",
        ));
    }
    let core = audit_tree_original_disposition_records(&plan, &records, record_bounds(max))?;
    Ok(Some(report(&request, &plan, &core, bytes)))
}

impl Journal {
    /// Metadata only: even a complete chain grants no disposition or release.
    pub fn with_tree_disposition_description<T, E>(
        &self,
        request: &TreeDispositionDescriptionRequest,
        max: usize,
        inspect: impl FnOnce(&TreeOriginalDispositionPlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeDispositionDescriptionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree disposition space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.input.transaction_id)
                .ok_or(JournalError::Invariant("tree disposition owner unknown"))
        };
        let replay = |prior: &TreeDispositionDescriptionAudit| -> Result<()> {
            if prior.request != *request {
                return Err(JournalError::Invariant(
                    "tree disposition request collision",
                ));
            }
            Ok(())
        };
        let p = find()?;
        if let Some(prior) = p.disposition_description {
            replay(&prior)?;
            return Ok((None, prior));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("tree disposition owner cancelled").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let p = find()?;
        if let Some(prior) = p.disposition_description {
            replay(&prior)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, prior));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("tree disposition owner cancelled").into());
        }
        let plan = project(&tx, &p, request, max)?;
        // MUST independently audit all generation namespaces before ANY insertion.
        crate::tree_disposition_generations::admit(&tx, &plan, max)?;
        let bytes = reserved_values(request, &plan)?;
        let rows = 1 + plan.intents().len() as u64;
        check_storage_metadata_limit(&tx, max, rows, bytes)?;
        let expected = report(
            request,
            &plan,
            &audit_tree_original_disposition_records(&plan, &BTreeMap::new(), record_bounds(max))
                .map_err(JournalError::from)?,
            bytes,
        );
        let input = &request.input;
        let json = serde_json::to_string(request).map_err(JournalError::from)?;
        tx.execute("INSERT INTO tree_restore_disposition_reservations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![input.transaction_id.as_str(),input.coordinator_execution_id.as_str(),input.final_description_hash.as_str(),
                ContentId::hash(json.as_bytes()).as_str(),plan.fingerprint().as_str(),json,sql_integer(input.described_at_ms)?,
                sql_integer(plan.intents().len() as u64)?,sql_integer(rows)?,sql_integer(bytes)?]).map_err(JournalError::from)?;
        for (index, intent) in plan.intents() {
            tx.execute("INSERT INTO tree_restore_disposition_intents VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![input.transaction_id.as_str(),input.coordinator_execution_id.as_str(),intent.retained.original.step_execution_id.as_str(),
                    intent.disposition_id.as_str(),sql_integer(*index as u64)?,sql_integer(input.described_at_ms)?,
                    input.final_description_hash.as_str(),intent.retained_description_hash.as_str(),plan.intent_hashes()[index].as_str(),
                    serde_json::to_string(intent).map_err(JournalError::from)?]).map_err(JournalError::from)?;
        }
        let held = inspect(&plan)?;
        self.audit_gc_owners(&space, max)?;
        let audit = find()?
            .disposition_description
            .ok_or(JournalError::Invariant(
                "tree disposition description disappeared",
            ))?;
        if audit != expected {
            return Err(
                JournalError::Invariant("tree disposition changed during inspection").into(),
            );
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }
    pub fn with_tree_disposition_record_description<T, E>(
        &self,
        record: &TreeOriginalDispositionRecord,
        max: usize,
        inspect: impl FnOnce(&TreeOriginalDispositionRecordAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeDispositionDescriptionAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant(
                "tree disposition record space missing",
            ))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == record.transaction_id)
                .ok_or(JournalError::Invariant(
                    "tree disposition record owner unknown",
                ))
        };
        let replay = |prior: &TreeDispositionDescriptionAudit| -> Result<bool> {
            if let Some(p) = prior
                .records
                .get(&record.step_index)
                .and_then(|r| r.get(record.record_index))
            {
                if p != record {
                    return Err(JournalError::Invariant("tree disposition record collision"));
                }
                return Ok(true);
            }
            Ok(false)
        };
        let p = find()?;
        let prior = p
            .disposition_description
            .as_ref()
            .ok_or(JournalError::Invariant(
                "tree disposition reservation missing",
            ))?;
        if replay(prior)? {
            return Ok((None, prior.clone()));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("tree disposition record owner cancelled").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let p = find()?;
        let prior = p
            .disposition_description
            .as_ref()
            .ok_or(JournalError::Invariant(
                "tree disposition reservation missing",
            ))?;
        if replay(prior)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, prior.clone()));
        }
        if !p.writer_gate_held {
            return Err(JournalError::Invariant("tree disposition record owner cancelled").into());
        }
        let plan = project(&tx, &p, &prior.request, max)?;
        let json = String::from_utf8(
            encode_history_record(record, MAX_OPERATION_BYTES as u64)
                .map_err(JournalError::from)?,
        )
        .map_err(|_| JournalError::Invariant("tree disposition record encoding"))?;
        check_storage_metadata_limit(&tx, max, 1, json.len() as u64 + 312)?;
        if prior.description_rows >= max as u64 {
            return Err(JournalError::Invariant("tree disposition description row limit").into());
        }
        let bytes = prior
            .metadata_bytes
            .checked_add(json.len() as u64 + 312)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant(
                "tree disposition record byte limit",
            ))?;
        let mut records = prior.records.clone();
        records
            .entry(record.step_index)
            .or_default()
            .push(record.clone());
        let core = audit_tree_original_disposition_records(&plan, &records, record_bounds(max))
            .map_err(JournalError::from)?;
        let expected = report(&prior.request, &plan, &core, bytes);
        tx.execute(
            "INSERT INTO tree_restore_disposition_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                record.transaction_id.as_str(),
                record.coordinator_execution_id.as_str(),
                record.disposition_id.as_str(),
                sql_integer(record.step_index as u64)?,
                sql_integer(record.record_index as u64)?,
                sql_integer(record.recorded_at_ms)?,
                record.intent_hash.as_str(),
                record.previous_hash.as_str(),
                ContentId::hash(json.as_bytes()).as_str(),
                json
            ],
        )
        .map_err(JournalError::from)?;
        let held = inspect(&core)?;
        self.audit_gc_owners(&space, max)?;
        let audit = find()?
            .disposition_description
            .ok_or(JournalError::Invariant(
                "tree disposition records disappeared",
            ))?;
        if audit != expected {
            return Err(JournalError::Invariant(
                "tree disposition records changed during inspection",
            )
            .into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), audit))
    }
}
