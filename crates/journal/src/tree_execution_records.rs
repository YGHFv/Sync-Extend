//! Persist descriptive phase chains only, never native action admission.
use crate::{
    check_storage_metadata_limit, snapshot_retention::audit_snapshot, sql_integer, CasAccessGuard,
    Journal, JournalError, Result, TreeExecutionDescriptionAudit, TreeRestoreHistoryReservation,
    TreeRestoreNativeReservation, TreeRestorePreparationIntent,
};
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::Serialize;
use std::collections::BTreeMap;
use sync_extend_core_model::{
    tree_execution_records::{
        audit_tree_execution_records, TreeExecutionRecord, TreeExecutionRecordAudit,
        TreeExecutionRecordLimits, TreeExecutionTerminal,
    },
    tree_restore_history::encode_history_record,
    ContentId, Manifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeExecutionRecordsAudit {
    pub records: BTreeMap<usize, Vec<TreeExecutionRecord>>,
    pub terminals: BTreeMap<usize, TreeExecutionTerminal>,
    pub fingerprint: ContentId,
    pub record_count: usize,
    pub metadata_bytes: u64,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn audit_records(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    history: Option<&TreeRestoreHistoryReservation>,
    native: Option<&TreeRestoreNativeReservation>,
    description: Option<&TreeExecutionDescriptionAudit>,
    baseline: &Manifest,
    target: &Manifest,
    cancelled: Option<u64>,
    max: usize,
) -> Result<Option<TreeExecutionRecordsAudit>> {
    let Some(description) = description else {
        return Ok(None);
    };
    let projection = crate::tree_restore_execution_intent::project(
        preparation,
        history.ok_or(JournalError::Invariant("phase description history missing"))?,
        native.ok_or(JournalError::Invariant("phase description native missing"))?,
        baseline,
        target,
        &description.intent.input,
        max,
    )?;
    let mut statement = connection.prepare(
        "SELECT step_index,record_index,coordinator_execution_id,step_execution_id,
         step_intent_hash,previous_hash,
         CASE WHEN length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216 THEN record ELSE '' END,
         record_hash,recorded_at_ms FROM tree_restore_execution_records
         WHERE transaction_id=?1 ORDER BY step_index,record_index",
    )?;
    let mut rows = statement.query([preparation.transaction_id.as_str()])?;
    let mut records = BTreeMap::<usize, Vec<TreeExecutionRecord>>::new();
    let mut bytes = 0u64;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        count = count
            .checked_add(1)
            .filter(|n| *n <= max)
            .ok_or(JournalError::Invariant(
                "phase description record inventory",
            ))?;
        let json: String = row.get(6)?;
        bytes = bytes
            .checked_add(json.len() as u64 + 312)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant("phase description byte inventory"))?;
        let record: TreeExecutionRecord = serde_json::from_str(&json)?;
        if serde_json::to_string(&record)? != json
            || record.transaction_id != preparation.transaction_id
            || sql_integer(record.step_index as u64)? != row.get::<_, i64>(0)?
            || sql_integer(record.record_index as u64)? != row.get::<_, i64>(1)?
            || record.coordinator_execution_id.as_str() != row.get::<_, String>(2)?
            || record.step_execution_id.as_str() != row.get::<_, String>(3)?
            || record.step_intent_hash.as_str() != row.get::<_, String>(4)?
            || record.previous_hash.as_str() != row.get::<_, String>(5)?
            || ContentId::hash(json.as_bytes()).as_str() != row.get::<_, String>(7)?
            || sql_integer(record.recorded_at_ms)? != row.get::<_, i64>(8)?
            || cancelled.is_some_and(|t| t < record.recorded_at_ms)
        {
            return Err(JournalError::Invariant(
                "phase description exact row mismatch",
            ));
        }
        records.entry(record.step_index).or_default().push(record);
    }
    let core = audit_tree_execution_records(
        &projection.plan,
        &projection.identity,
        &records,
        bounds(max),
    )?;
    Ok(Some(report(&core, bytes)))
}

fn bounds(max: usize) -> TreeExecutionRecordLimits {
    TreeExecutionRecordLimits {
        max_records: max,
        max_encoded_bytes: crate::MAX_OPERATION_BYTES as u64,
    }
}

fn report(core: &TreeExecutionRecordAudit, bytes: u64) -> TreeExecutionRecordsAudit {
    TreeExecutionRecordsAudit {
        records: core.records().clone(),
        terminals: core.terminals().clone(),
        fingerprint: core.fingerprint().clone(),
        record_count: core.record_count(),
        metadata_bytes: bytes,
        native_tree_verified: false,
        execution_admission_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    }
}

impl Journal {
    /// Append a description, not an action. Replay never renews native authority.
    pub fn with_tree_execution_record_description<T, E>(
        &self,
        record: &TreeExecutionRecord,
        max: usize,
        inspect: impl FnOnce(&TreeExecutionRecordAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeExecutionRecordsAudit), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("phase description space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == record.transaction_id)
                .ok_or(JournalError::Invariant("unknown phase description owner"))
        };
        let replay = |audit: &TreeExecutionRecordsAudit| -> Result<bool> {
            if let Some(prior) = audit
                .records
                .get(&record.step_index)
                .and_then(|chain| chain.get(record.record_index))
            {
                if prior != record {
                    return Err(JournalError::Invariant("phase description collision"));
                }
                return Ok(true);
            }
            Ok(false)
        };
        let preparation = find()?;
        let audit = preparation
            .execution_records
            .as_ref()
            .ok_or(JournalError::Invariant(
                "phase description coordinator missing",
            ))?;
        if replay(audit)? {
            return Ok((None, audit.clone()));
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("cancelled phase description owner").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let preparation = find()?;
        let audit = preparation
            .execution_records
            .as_ref()
            .ok_or(JournalError::Invariant(
                "phase description coordinator missing",
            ))?;
        if replay(audit)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, audit.clone()));
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("phase description owner cancelled").into());
        }
        let description = preparation
            .execution_description
            .as_ref()
            .ok_or(JournalError::Invariant("phase description intent missing"))?;
        let baseline =
            audit_snapshot(&tx, &space, &preparation.intent.scope.baseline_snapshot)?.manifest;
        let target =
            audit_snapshot(&tx, &space, &preparation.intent.scope.target_snapshot)?.manifest;
        let projection = crate::tree_restore_execution_intent::project(
            &preparation.intent,
            preparation
                .history_reservation
                .as_ref()
                .ok_or(JournalError::Invariant("phase description history missing"))?,
            preparation
                .native_reservation
                .as_ref()
                .ok_or(JournalError::Invariant("phase description native missing"))?,
            &baseline,
            &target,
            &description.intent.input,
            max,
        )?;
        if audit.record_count >= max {
            return Err(JournalError::Invariant("phase description record inventory").into());
        }
        let json = String::from_utf8(
            encode_history_record(record, crate::MAX_OPERATION_BYTES as u64)
                .map_err(JournalError::from)?,
        )
        .map_err(|_| JournalError::Invariant("phase description encoding"))?;
        let bytes = audit
            .metadata_bytes
            .checked_add(json.len() as u64 + 312)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant("phase description byte inventory"))?;
        check_storage_metadata_limit(&tx, max, 1, json.len() as u64 + 312)?;
        let mut records = audit.records.clone();
        records
            .entry(record.step_index)
            .or_default()
            .push(record.clone());
        let core = audit_tree_execution_records(
            &projection.plan,
            &projection.identity,
            &records,
            bounds(max),
        )
        .map_err(JournalError::from)?;
        let expected = report(&core, bytes);
        tx.execute(
            "INSERT INTO tree_restore_execution_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                record.transaction_id.as_str(),
                sql_integer(record.step_index as u64)?,
                sql_integer(record.record_index as u64)?,
                record.coordinator_execution_id.as_str(),
                record.step_execution_id.as_str(),
                record.step_intent_hash.as_str(),
                record.previous_hash.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(record.recorded_at_ms)?
            ],
        )
        .map_err(JournalError::from)?;
        let held = inspect(&core)?;
        self.audit_gc_owners(&space, max)?;
        let final_audit = find()?
            .execution_records
            .ok_or(JournalError::Invariant("phase descriptions disappeared"))?;
        if final_audit != expected {
            return Err(
                JournalError::Invariant("phase descriptions changed during inspection").into(),
            );
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), final_audit))
    }
}
