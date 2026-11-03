use crate::{
    GcAuthorizationState, GcDisposalState, GcExecutionState, GcQuarantineState, GcState, Journal,
    JournalError, Result,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use std::collections::BTreeMap;
use sync_extend_core_model::{Operation, SpaceId};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcDiagnostics {
    pub accounting: &'static str,
    pub clock_basis: &'static str,
    pub gc_clock_watermark_ms: Option<u64>,
    pub mark_states: BTreeMap<&'static str, usize>,
    pub authorization_states: BTreeMap<&'static str, usize>,
    pub execution_states: BTreeMap<&'static str, usize>,
    pub quarantine_states: BTreeMap<&'static str, usize>,
    pub disposal_states: BTreeMap<&'static str, usize>,
    pub active_execution_fences: usize,
    pub pending_disposals: usize,
    pub deleted_payload_logical_bytes: u64,
    pub content_hashes_verified: bool,
    pub realtime_authority_verified: bool,
    pub disposition_executor_available: bool,
    pub deletion_authorized: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

impl Journal {
    pub fn diagnostic_operation_count(&self, space: &SpaceId, max: usize) -> Result<usize> {
        let (count, bytes): (i64, i64) = self.connection.query_row(
            "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM operations WHERE space_id=?1",
            [space.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let budget = (max as u64)
            .checked_mul(1024)
            .ok_or(JournalError::Invariant(
                "diagnostic operation budget overflow",
            ))?;
        if count < 0 || bytes < 0 || count as u64 > max as u64 || bytes as u64 > budget {
            return Err(JournalError::Invariant(
                "diagnostic operation inventory limit",
            ));
        }
        let mut statement = self.connection.prepare(
            "SELECT op_id,origin_device_id,origin_seq,
                CASE WHEN length(CAST(payload AS BLOB))<=16777216 THEN payload ELSE '' END
             FROM operations WHERE space_id=?1 ORDER BY origin_device_id,origin_seq",
        )?;
        let rows = statement.query_map([space.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for row in rows {
            let (id, device, sequence, json) = row?;
            let op: Operation = serde_json::from_str(&json)?;
            op.validate()?;
            if op.op_id.as_str() != id
                || op.payload.space_id != *space
                || op.payload.origin_device_id.as_str() != device
                || crate::sql_integer(op.payload.origin_seq)? != sequence
            {
                return Err(JournalError::Invariant(
                    "diagnostic operation integrity mismatch",
                ));
            }
        }
        usize::try_from(count)
            .map_err(|_| JournalError::Invariant("diagnostic operation count overflow"))
    }

    pub fn gc_diagnostics(&self, space: &SpaceId, max: usize) -> Result<GcDiagnostics> {
        self.with_gc_diagnostics(space, max, |summary| Ok(summary.clone()))
    }

    /// A deferred read snapshot spans the bounded audit and the caller's index reads.
    /// No authority clock, fence or physical state is advanced.
    pub fn with_gc_diagnostics<T, E>(
        &self,
        space: &SpaceId,
        max: usize,
        inspect: impl FnOnce(&GcDiagnostics) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E>
    where
        E: From<JournalError>,
    {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
            .map_err(JournalError::from)?;
        self.check_storage_metadata_limit(max)?;
        crate::rename_observation::audit_observation(&tx, space, max)?;
        self.audit_gc_owners(space, max)?;
        let marks = self.gc_marks(space, max)?;
        let authorizations = self.gc_authorizations(space, max)?;
        let executions = self.gc_executions(space, max)?;
        let quarantines = self.audit_gc_quarantines(&executions, max)?;
        let disposals = self.audit_gc_disposals(&quarantines, &executions, max)?;
        let watermark: Option<i64> = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(JournalError::from)?;
        let mut summary = GcDiagnostics {
            accounting: "immutable_record_states_not_physical_inventory_or_freed_space",
            clock_basis: "persisted_gc_watermark_not_current_wall_clock",
            gc_clock_watermark_ms: watermark
                .map(|w| u64::try_from(w).map_err(|_| JournalError::Invariant("negative GC clock")))
                .transpose()?,
            mark_states: counters(&["marked", "cancelled", "invalidated"]),
            authorization_states: counters(&[
                "active_intent",
                "consumed",
                "revoked",
                "mark_cancelled",
                "invalidated",
                "expired",
            ]),
            execution_states: counters(&["fenced", "aborted", "deleted"]),
            quarantine_states: counters(&[
                "prepared",
                "quarantined",
                "restore_pending",
                "restored",
                "deleted",
            ]),
            disposal_states: counters(&[
                "delete_pending",
                "restore_pending",
                "restored",
                "deleted",
            ]),
            active_execution_fences: executions.iter().filter(|e| e.content_fenced).count(),
            pending_disposals: disposals.iter().filter(|d| d.content_fenced).count(),
            deleted_payload_logical_bytes: 0,
            content_hashes_verified: false,
            realtime_authority_verified: false,
            disposition_executor_available: cfg!(windows),
            deletion_authorized: false,
            sweep_available: false,
            gc_enabled: false,
        };
        for m in marks {
            increment(
                &mut summary.mark_states,
                match m.state {
                    GcState::Marked => "marked",
                    GcState::Cancelled => "cancelled",
                    GcState::Invalidated => "invalidated",
                },
            );
        }
        for a in authorizations {
            increment(
                &mut summary.authorization_states,
                match a.state {
                    GcAuthorizationState::ActiveIntent => "active_intent",
                    GcAuthorizationState::Consumed => "consumed",
                    GcAuthorizationState::Revoked => "revoked",
                    GcAuthorizationState::MarkCancelled => "mark_cancelled",
                    GcAuthorizationState::Invalidated => "invalidated",
                    GcAuthorizationState::Expired => "expired",
                },
            );
        }
        for e in executions {
            increment(
                &mut summary.execution_states,
                match e.state {
                    GcExecutionState::Fenced => "fenced",
                    GcExecutionState::Aborted => "aborted",
                    GcExecutionState::Deleted => "deleted",
                },
            );
            if e.state == GcExecutionState::Deleted {
                summary.deleted_payload_logical_bytes = summary
                    .deleted_payload_logical_bytes
                    .checked_add(u64::from(e.intent.authorization.mark.observation.length))
                    .ok_or(JournalError::Invariant("GC diagnostic byte count overflow"))?;
            }
        }
        for q in quarantines {
            increment(
                &mut summary.quarantine_states,
                match q.state {
                    GcQuarantineState::Prepared => "prepared",
                    GcQuarantineState::Quarantined => "quarantined",
                    GcQuarantineState::RestorePending => "restore_pending",
                    GcQuarantineState::Restored => "restored",
                    GcQuarantineState::Deleted => "deleted",
                },
            );
        }
        for d in disposals {
            increment(
                &mut summary.disposal_states,
                match d.state {
                    GcDisposalState::DeletePending => "delete_pending",
                    GcDisposalState::RestorePending => "restore_pending",
                    GcDisposalState::Restored => "restored",
                    GcDisposalState::Deleted => "deleted",
                },
            );
        }
        let value = inspect(&summary)?;
        tx.commit().map_err(JournalError::from)?;
        Ok(value)
    }
}

fn counters(keys: &[&'static str]) -> BTreeMap<&'static str, usize> {
    keys.iter().map(|key| (*key, 0)).collect()
}

fn increment(counts: &mut BTreeMap<&'static str, usize>, key: &'static str) {
    *counts.entry(key).or_default() += 1;
}
