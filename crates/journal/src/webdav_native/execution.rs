//! D01 draft: durable reservation and activation only. No public observation issuer.
//! Bind this child module to an actually accepted published parent before runtime.
use super::{advance_clock, invalid, prepare, scope, unchanged, WebDavNativeAdmission};
use crate::{
    storage_inventory::reader::{add, preflight},
    Journal, Result,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    tree_restore_history::encode_history_record,
    tree_storage_capacity::TreeStorageCharge,
    webdav_native_execution::{
        audit_webdav_execution_prefix, WebDavExecutionLimits, WebDavExecutionPhase,
        WebDavExecutionRecord, WebDavExecutionScope, WebDavExecutionState,
    },
    ContentId, EntryId, SpaceId, FORMAT_VERSION,
};

const ADMISSION_BYTES: u64 = 320; // 32 + 4*64 + 4*8.
const RECORD_FIXED_BYTES: u64 = 112; // 32 + 8 + 64 + 8, excluding JSON.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavDurableExecutionLimits {
    pub max_records: usize,
    pub max_record_bytes: u64,
    pub max_total_bytes: u64,
}

impl From<WebDavDurableExecutionLimits> for WebDavExecutionLimits {
    fn from(value: WebDavDurableExecutionLimits) -> Self {
        Self {
            max_records: value.max_records,
            max_record_bytes: value.max_record_bytes,
            max_total_bytes: value.max_total_bytes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WebDavDurableExecution {
    pub transaction_id: EntryId,
    pub description_hash: ContentId,
    pub request_hash: ContentId,
    pub plan_hash: ContentId,
    pub limits: WebDavDurableExecutionLimits,
    pub admitted_at_ms: u64,
    pub admission_hash: ContentId,
    pub records: Vec<WebDavExecutionRecord>,
    pub future_rows: u64,
    pub future_bytes: u64,
    pub cancelled: bool,
    pub unresolved_activation: bool,
    pub completed_actions: usize,
    pub native_receipts_issued: bool,
    pub final_committed: bool,
    pub cleanup_authorized: bool,
}

pub(super) fn admission_hash(
    description: &WebDavNativeAdmission,
    request: &ContentId,
    limits: WebDavDurableExecutionLimits,
    time: u64,
) -> Result<ContentId> {
    Ok(ContentId::hash(&serde_json::to_vec(&(
        "sync-extend.webdav.durable-execution-admission.v1",
        &description.description.request.transaction_id,
        &description.description_hash,
        request,
        &description.plan_hash,
        limits,
        time,
    ))?))
}

pub(super) fn build(
    connection: &Connection,
    description: &WebDavNativeAdmission,
    limits: WebDavDurableExecutionLimits,
    time: u64,
    records: Vec<WebDavExecutionRecord>,
) -> Result<WebDavDurableExecution> {
    crate::sql_integer(time)?;
    let request = &description.description.request;
    let prepared = prepare(
        connection,
        &description.description,
        &request_space(connection)?,
        description.admitted_at_ms,
        description.writer_gate_held,
    )?;
    let required = prepared
        .plan
        .steps()
        .len()
        .checked_mul(2)
        .ok_or_else(invalid)?;
    let peak_record_bytes = (required as u64)
        .checked_mul(limits.max_record_bytes)
        .ok_or_else(invalid)?;
    if limits.max_records != required
        || limits.max_total_bytes < peak_record_bytes
        || time < description.admitted_at_ms
        || records
            .first()
            .is_some_and(|record| record.recorded_at_ms < time)
    {
        return Err(invalid());
    }
    let audited = audit_webdav_execution_prefix(
        request,
        &prepared.plan,
        &description.description_hash,
        &records,
        limits.into(),
    )?;
    let native_receipts_issued =
        super::ordered_records::audit(connection, &prepared.plan, &records, limits)?;
    let cancelled = description.cancelled_at_ms.is_some();
    if cancelled && !records.is_empty() {
        return Err(invalid());
    }
    let terminal = super::reference_handoff::terminal(connection, &request.transaction_id)?;
    let final_committed=records.iter().any(|record|matches!(
        record.phase,WebDavExecutionPhase::Observed {
            observation:sync_extend_core_model::webdav_native_execution::WebDavExecutionObservation::HistoryCommitted{..},..
        }));
    let future_rows = if cancelled || terminal {
        0
    } else {
        (required - records.len()) as u64
    };
    let future_bytes = if cancelled || terminal {
        0
    } else {
        add(
            future_rows
                .checked_mul(RECORD_FIXED_BYTES)
                .ok_or_else(invalid)?,
            limits
                .max_total_bytes
                .checked_sub(audited.encoded_bytes())
                .ok_or_else(invalid)?,
        )?
    };
    Ok(WebDavDurableExecution {
        transaction_id: request.transaction_id.clone(),
        description_hash: description.description_hash.clone(),
        request_hash: prepared.plan.request_hash().clone(),
        plan_hash: description.plan_hash.clone(),
        limits,
        admitted_at_ms: time,
        admission_hash: admission_hash(description, prepared.plan.request_hash(), limits, time)?,
        records,
        future_rows,
        future_bytes,
        cancelled,
        unresolved_activation: matches!(
            audited.state(),
            WebDavExecutionState::UnresolvedActivation { .. }
        ),
        completed_actions: audited.completed_actions(),
        native_receipts_issued,
        final_committed,
        cleanup_authorized: final_committed,
    })
}

fn request_space(connection: &Connection) -> Result<SpaceId> {
    Ok(connection
        .query_row(
            "SELECT value FROM main.local_state WHERE key='space_id'",
            [],
            |row| row.get::<_, String>(0),
        )?
        .parse()?)
}

/// Parent descriptions audit must remain separate to prevent budget/audit recursion.
pub(super) fn audit(connection: &Connection) -> Result<Vec<WebDavDurableExecution>> {
    let descriptions = super::read_phase::VerifiedDescriptions::read(connection)?;
    audit_verified(&descriptions)
}

/// Reuse this read phase's complete, private description audit only.
/// Every execution row, record, plan, receipt and scope check remains below.
pub(super) fn audit_verified(
    verified: &super::read_phase::VerifiedDescriptions<'_>,
) -> Result<Vec<WebDavDurableExecution>> {
    let connection = verified.connection()?;
    super::schema::validate(connection)?;
    preflight(
        connection,
        super::execution_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let descriptions = verified.values(connection)?;
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.webdav_native_execution_records r
         LEFT JOIN main.webdav_native_execution_admissions e USING(transaction_id)
         WHERE e.transaction_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if orphan {
        return Err(invalid());
    }
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.webdav_native_clock WHERE singleton=1",
            [],
            |row| crate::sql_u64(row, 0),
        )
        .optional()?;
    let mut statement = connection.prepare(
        "SELECT transaction_id,description_hash,request_hash,plan_hash,max_records,
         max_record_bytes,max_total_bytes,admitted_at_ms,admission_hash
         FROM main.webdav_native_execution_admissions ORDER BY transaction_id",
    )?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let description = descriptions
            .iter()
            .find(|description| description.description.request.transaction_id.as_str() == id)
            .ok_or_else(invalid)?;
        let records: Vec<(u64, String, u64, String)> = connection.prepare(
            "SELECT record_index,record_hash,recorded_at_ms,record
             FROM main.webdav_native_execution_records WHERE transaction_id=?1 ORDER BY record_index",
        )?.query_map([&id], |row| Ok((crate::sql_u64(row, 0)?, row.get(1)?, crate::sql_u64(row, 2)?, row.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut parsed = Vec::new();
        for (index, hash, time, json) in records {
            let record: WebDavExecutionRecord = serde_json::from_str(&json)?;
            if record.record_index as u64 != index
                || record.recorded_at_ms != time
                || serde_json::to_string(&record)? != json
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || clock.is_none_or(|clock| time > clock)
            {
                return Err(invalid());
            }
            // D01 alone has no native observation issuer: persisted observations
            // must remain rejected until a real retained D02/D03 receipt is bound.

            parsed.push(record);
        }
        let execution = build(
            connection,
            description,
            WebDavDurableExecutionLimits {
                max_records: usize::try_from(crate::sql_u64(row, 4)?).map_err(|_| invalid())?,
                max_record_bytes: crate::sql_u64(row, 5)?,
                max_total_bytes: crate::sql_u64(row, 6)?,
            },
            crate::sql_u64(row, 7)?,
            parsed,
        )?;
        if execution.description_hash.as_str() != row.get::<_, String>(1)?
            || execution.request_hash.as_str() != row.get::<_, String>(2)?
            || execution.plan_hash.as_str() != row.get::<_, String>(3)?
            || execution.admission_hash.as_str() != row.get::<_, String>(8)?
            || clock.is_none_or(|clock| execution.admitted_at_ms > clock)
        {
            return Err(invalid());
        }
        result.push(execution);
    }
    verified.verify(connection)?;
    Ok(result)
}

pub(super) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    audit(connection)?
        .iter()
        .try_fold(TreeStorageCharge::default(), |total, row| {
            Ok(TreeStorageCharge {
                rows: add(total.rows, row.future_rows)?,
                logical_bytes: add(total.logical_bytes, row.future_bytes)?,
            })
        })
}

pub(super) fn exact_insert(
    before: &crate::storage_capacity::CapacitySnapshot,
    after: &crate::storage_capacity::CapacitySnapshot,
    table: &'static str,
    primary_key: Vec<String>,
    values: Vec<crate::JournalStorageColumnValue>,
    time: u64,
) -> Result<()> {
    use crate::JournalStorageColumnValue as Value;
    let map = |snapshot: &crate::storage_capacity::CapacitySnapshot| {
        snapshot
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.columns()
                        .iter()
                        .map(|column| column.value.clone())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let mut expected = map(before);
    if expected
        .insert((table.into(), primary_key), values)
        .is_some()
    {
        return Err(invalid());
    }
    let clock_key = ("webdav_native_clock".to_owned(), vec!["1".into()]);
    let clock = expected.get_mut(&clock_key).ok_or_else(invalid)?;
    if clock.len() != 2
        || clock[0] != Value::Integer(1)
        || !matches!(clock[1], Value::Integer(old) if old <= time)
    {
        return Err(invalid());
    }
    clock[1] = Value::Integer(time);
    if map(after) != expected {
        return Err(invalid());
    }
    unchanged(before, after)
}

impl Journal {
    pub fn webdav_durable_executions(&self) -> Result<Vec<WebDavDurableExecution>> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let _dav_read_scope = self.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let verified = self.webdav_native_read_charges.read(&tx)?;
        let rows = verified.executions(&tx)?.to_vec();
        tx.commit()?;
        Ok(rows)
    }

    pub fn reserve_webdav_execution(
        &self,
        space: &SpaceId,
        id: &EntryId,
        limits: WebDavDurableExecutionLimits,
        time: u64,
    ) -> Result<WebDavDurableExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let _dav_read_scope = self.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let verified = self.webdav_native_read_charges.read(&tx)?;
        let description = verified
            .descriptions(&tx)?
            .iter()
            .find(|description| &description.description.request.transaction_id == id)
            .cloned()
            .ok_or_else(invalid)?;
        scope(&tx, space, &description.description.request.origin_device)?;
        if let Some(old) = verified
            .executions(&tx)?
            .iter()
            .find(|row| &row.transaction_id == id)
            .cloned()
        {
            if old.limits != limits {
                return Err(invalid());
            }
            tx.commit()?;
            return Ok(old);
        }
        if description.cancelled_at_ms.is_some() {
            return Err(invalid());
        }
        let prepared = build(&tx, &description, limits, time, Vec::new())?;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let before = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        if !before.report.within_accounted_limits()
            || !before.report.coverage_gaps().is_empty()
            || add(
                before.report.accounted_total().rows,
                add(1, prepared.future_rows)?,
            )? > bounds.max_rows
            || add(
                before.report.accounted_total().logical_bytes,
                add(ADMISSION_BYTES, prepared.future_bytes)?,
            )? > bounds.max_logical_bytes
        {
            return Err(invalid());
        }
        advance_clock(&tx, time)?;
        self.webdav_native_execution_admission_issue.issue(prepared.admission_hash.to_string(), time, || {
            tx.execute("INSERT INTO main.webdav_native_execution_admissions VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![id.as_str(), prepared.description_hash.as_str(), prepared.request_hash.as_str(),
                        prepared.plan_hash.as_str(), crate::sql_integer(limits.max_records as u64)?,
                        crate::sql_integer(limits.max_record_bytes)?, crate::sql_integer(limits.max_total_bytes)?,
                        crate::sql_integer(time)?, prepared.admission_hash.as_str()])?;
            Ok(())
        })?;
        let after = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        exact_insert(
            &before,
            &after,
            "webdav_native_execution_admissions",
            vec![id.to_string()],
            vec![
                crate::JournalStorageColumnValue::Text(id.to_string()),
                crate::JournalStorageColumnValue::Text(prepared.description_hash.to_string()),
                crate::JournalStorageColumnValue::Text(prepared.request_hash.to_string()),
                crate::JournalStorageColumnValue::Text(prepared.plan_hash.to_string()),
                crate::JournalStorageColumnValue::Integer(limits.max_records as u64),
                crate::JournalStorageColumnValue::Integer(limits.max_record_bytes),
                crate::JournalStorageColumnValue::Integer(limits.max_total_bytes),
                crate::JournalStorageColumnValue::Integer(time),
                crate::JournalStorageColumnValue::Text(prepared.admission_hash.to_string()),
            ],
            time,
        )?;
        let accepted_read = self.webdav_native_read_charges.read(&tx)?;
        let accepted = accepted_read
            .executions(&tx)?
            .iter()
            .find(|row| &row.transaction_id == id)
            .cloned()
            .ok_or_else(invalid)?;
        super::checkpoint("webdav_execution_reserve_before_commit");
        tx.commit()?;
        super::checkpoint("webdav_execution_reserve_after_commit");
        Ok(accepted)
    }

    /// Persist the exact first attempt. Any unresolved activation forbids another.
    /// This intent performs no filesystem operation and proves no native effect.
    pub fn activate_webdav_execution(
        &self,
        space: &SpaceId,
        id: &EntryId,
        attempt: &EntryId,
        time: u64,
    ) -> Result<WebDavDurableExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let _dav_read_scope = self.webdav_native_read_charges.scope();
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let verified = self.webdav_native_read_charges.read(&tx)?;
        let description = verified
            .descriptions(&tx)?
            .iter()
            .find(|description| &description.description.request.transaction_id == id)
            .cloned()
            .ok_or_else(invalid)?;
        scope(&tx, space, &description.description.request.origin_device)?;
        let old = verified
            .executions(&tx)?
            .iter()
            .find(|row| &row.transaction_id == id)
            .cloned()
            .ok_or_else(invalid)?;
        if old.cancelled {
            return Err(invalid());
        }
        if !old.records.is_empty() {
            if old.records.len() == 1
                && old.records[0].attempt_id == *attempt
                && old.records[0].recorded_at_ms == time
            {
                tx.commit()?;
                return Ok(old);
            }
            return Err(invalid());
        }
        if time < old.admitted_at_ms {
            return Err(invalid());
        }
        let record = WebDavExecutionRecord {
            scope: WebDavExecutionScope {
                format_version: FORMAT_VERSION,
                transaction_id: id.clone(),
                request_hash: old.request_hash.clone(),
                plan_hash: old.plan_hash.clone(),
                description_hash: old.description_hash.clone(),
            },
            record_index: 0,
            action_index: 0,
            attempt_id: attempt.clone(),
            previous_hash: old.description_hash.clone(),
            recorded_at_ms: time,
            phase: WebDavExecutionPhase::Activated,
        };
        let bytes = encode_history_record(&record, old.limits.max_record_bytes)?;
        let hash = ContentId::hash(&bytes);
        build(
            &tx,
            &description,
            old.limits,
            old.admitted_at_ms,
            vec![record],
        )?;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let before = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        advance_clock(&tx, time)?;
        self.webdav_native_execution_record_issue
            .issue(hash.to_string(), time, || {
                tx.execute(
                    "INSERT INTO main.webdav_native_execution_records VALUES(?1,0,?2,?3,?4)",
                    params![
                        id.as_str(),
                        hash.as_str(),
                        crate::sql_integer(time)?,
                        std::str::from_utf8(&bytes).map_err(|_| invalid())?
                    ],
                )?;
                Ok(())
            })?;
        let after = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        exact_insert(
            &before,
            &after,
            "webdav_native_execution_records",
            vec![id.to_string(), "0".into()],
            vec![
                crate::JournalStorageColumnValue::Text(id.to_string()),
                crate::JournalStorageColumnValue::Integer(0),
                crate::JournalStorageColumnValue::Text(hash.to_string()),
                crate::JournalStorageColumnValue::Integer(time),
                crate::JournalStorageColumnValue::Text(
                    std::str::from_utf8(&bytes).map_err(|_| invalid())?.into(),
                ),
            ],
            time,
        )?;
        let accepted_read = self.webdav_native_read_charges.read(&tx)?;
        let accepted = accepted_read
            .executions(&tx)?
            .iter()
            .find(|row| &row.transaction_id == id)
            .cloned()
            .ok_or_else(invalid)?;
        super::checkpoint("webdav_execution_activate_before_commit");
        tx.commit()?;
        super::checkpoint("webdav_execution_activate_after_commit");
        Ok(accepted)
    }
}
