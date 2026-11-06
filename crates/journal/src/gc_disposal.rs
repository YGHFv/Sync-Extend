use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, GcExecutionAudit, GcExecutionState,
    GcQuarantineAudit, GcQuarantineIntent, GcQuarantineState, Journal, JournalError, Result,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcDisposalIntent {
    pub format_version: u32,
    pub disposal_id: EntryId,
    pub execution_id: EntryId,
    pub execution_hash: ContentId,
    pub quarantine: GcQuarantineIntent,
    pub quarantine_hash: ContentId,
    pub admitted_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcDisposalState {
    DeletePending,
    RestorePending,
    Restored,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcDisposalAudit {
    pub intent: GcDisposalIntent,
    pub state: GcDisposalState,
    pub restored_at_watermark_ms: Option<u64>,
    pub deleted_at_watermark_ms: Option<u64>,
    pub content_fenced: bool,
    pub deletion_authorized: bool,
    pub disposition_executor_available: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcDisposalStep {
    Deleted,
    RestorePending,
    Pending,
}

impl Journal {
    pub fn gc_disposals(&self, space: &SpaceId, max: usize) -> Result<Vec<GcDisposalAudit>> {
        let quarantines = self.gc_quarantines(space, max)?;
        let executions = self.gc_executions(space, max)?;
        self.audit_gc_disposals(&quarantines, &executions, max)
    }

    pub(crate) fn audit_gc_disposals(
        &self,
        quarantines: &[GcQuarantineAudit],
        executions: &[GcExecutionAudit],
        max: usize,
    ) -> Result<Vec<GcDisposalAudit>> {
        check_storage_metadata_limit(&self.connection, max, 0, 0)?;
        self.read_view().audit_gc_disposals(quarantines, executions)
    }

    /// Denied authority selects restoration; clock rollback still defers new deletion.
    pub fn gc_disposition_requires_restore<E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
    ) -> std::result::Result<bool, E>
    where
        E: From<JournalError>,
    {
        self.audit_gc_owners(space, max)?;
        let e = self
            .gc_executions(space, max)?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("unknown GC execution"))?;
        if !e.content_fenced {
            return Err(JournalError::Invariant("GC execution is terminal").into());
        }
        let revoked: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM gc_revocations WHERE authorization_id=?1)",
                [e.intent.authorization.authorization_id.as_str()],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        let mark = self
            .gc_marks(space, max)?
            .into_iter()
            .find(|m| m.intent.mark_id == e.intent.authorization.mark.mark_id)
            .ok_or(JournalError::Invariant("GC execution mark missing"))?;
        if revoked || mark.state != crate::GcState::Marked {
            return Ok(true);
        }
        let time = now()?;
        self.gc_observe_clock(time, max)?;
        if time >= e.intent.authorization.expires_at_ms {
            return Ok(true);
        }
        self.recheck_gc_execution_authority(space, id, max, now)?;
        Ok(false)
    }

    /// Apply one explicit pending step while retaining namespace and CAS guards.
    /// Deleted is caller evidence of exact absence, never request-success evidence.
    pub fn with_gc_disposition<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        inspect: impl FnOnce(&GcExecutionAudit, &GcDisposalAudit) -> std::result::Result<T, E>,
        steps: (
            impl FnOnce(&mut T, &GcDisposalAudit) -> std::result::Result<GcDisposalStep, E>,
            impl FnOnce(&mut T, &GcDisposalAudit) -> std::result::Result<(), E>,
        ),
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, GcDisposalAudit), E>
    where
        E: From<JournalError>,
    {
        let (apply, verify_absence) = steps;
        let mut coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let d = self
            .gc_disposals(space, max)?
            .into_iter()
            .find(|d| d.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC disposal preparation missing"))?;
        if matches!(
            d.state,
            GcDisposalState::Restored | GcDisposalState::Deleted
        ) {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, d));
        }
        if d.state != GcDisposalState::DeletePending {
            return Err(
                JournalError::Invariant("GC disposal requires explicit restoration").into(),
            );
        }
        self.audit_gc_owners(space, max)?;
        let e = self
            .gc_executions(space, max)?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC disposal execution missing"))?;
        let mut guards = inspect(&e, &d)?;
        coordination.try_exclusive()?;
        match apply(&mut guards, &d)? {
            GcDisposalStep::Deleted => {
                self.audit_gc_owners(space, max)?;
                verify_absence(&mut guards, &d)?;
                tx.execute("INSERT INTO gc_execution_deletions SELECT ?1,observed_at_ms FROM gc_clock WHERE singleton=1",[id.as_str()])
                    .map_err(JournalError::from)?;
            }
            GcDisposalStep::RestorePending => {
                tx.execute("UPDATE gc_quarantines SET state='restore_pending' WHERE execution_id=?1 AND state='quarantined'",[id.as_str()])
                    .map_err(JournalError::from)?;
            }
            GcDisposalStep::Pending => {}
        }
        let audit = self
            .gc_disposals(space, max)?
            .into_iter()
            .find(|d| d.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC disposal disappeared"))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), audit))
    }

    /// Commit a single-use pre-disposition record only; caller performs no deletion.
    pub fn prepare_gc_disposal<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcExecutionAudit, &GcQuarantineAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, GcDisposalAudit), E>
    where
        E: From<JournalError>,
    {
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(JournalError::from)?;
            if let Some(old) = self
                .gc_disposals(space, max)?
                .into_iter()
                .find(|d| d.intent.execution_id == *id)
            {
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, old));
            }
        }
        let mut coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        if let Some(old) = self
            .gc_disposals(space, max)?
            .into_iter()
            .find(|d| d.intent.execution_id == *id)
        {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let q = self
            .gc_quarantines(space, max)?
            .into_iter()
            .find(|q| q.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC disposal quarantine missing"))?;
        if q.state != GcQuarantineState::Quarantined {
            return Err(JournalError::Invariant("GC disposal requires quarantined object").into());
        }
        self.recheck_gc_execution_authority(space, id, max, &now)?;
        let e = self
            .gc_executions(space, max)?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC disposal execution missing"))?;
        let guards = inspect(&e, &q)?;
        coordination.try_exclusive()?;
        self.recheck_gc_execution_authority(space, id, max, &now)?;
        let time: i64 = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        let intent = GcDisposalIntent {
            format_version: FORMAT_VERSION,
            disposal_id: EntryId::random().map_err(JournalError::from)?,
            execution_id: id.clone(),
            execution_hash: ContentId::hash(
                serde_json::to_string(&e.intent)
                    .map_err(JournalError::from)?
                    .as_bytes(),
            ),
            quarantine_hash: ContentId::hash(
                serde_json::to_string(&q.intent)
                    .map_err(JournalError::from)?
                    .as_bytes(),
            ),
            quarantine: q.intent,
            admitted_at_ms: time as u64,
        };
        let json = serde_json::to_string(&intent).map_err(JournalError::from)?;
        // Reserve the immutable restoration row; no physical action is admitted here.
        check_storage_metadata_limit(&tx, max, 2, json.len() as u64)?;
        tx.execute(
            "INSERT INTO gc_disposals VALUES (?1,?2,?3,?4,?5)",
            params![
                id.as_str(),
                intent.disposal_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                time
            ],
        )
        .map_err(JournalError::from)?;
        let audit = self
            .gc_disposals(space, max)?
            .into_iter()
            .find(|d| d.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC disposal disappeared"))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), audit))
    }
}

impl crate::JournalReadView<'_> {
    pub(crate) fn audit_gc_disposals(
        &self,
        quarantines: &[GcQuarantineAudit],
        executions: &[GcExecutionAudit],
    ) -> Result<Vec<GcDisposalAudit>> {
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_disposal_restorations r LEFT JOIN gc_disposals d USING(execution_id) WHERE d.execution_id IS NULL)",
            [], |r| r.get(0))?;
        if orphan {
            return Err(JournalError::Invariant("orphan GC disposal restoration"));
        }
        if executions.iter().any(|e| {
            e.state == GcExecutionState::Deleted
                && !quarantines
                    .iter()
                    .any(|q| q.intent.execution_id == e.intent.execution_id)
        }) {
            return Err(JournalError::Invariant(
                "deleted GC execution quarantine missing",
            ));
        }
        let missing_disposal: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_execution_deletions t LEFT JOIN gc_disposals d USING(execution_id) WHERE d.execution_id IS NULL)",
            [], |r|r.get(0))?;
        if missing_disposal {
            return Err(JournalError::Invariant("deleted GC disposal missing"));
        }
        let mut statement = self.connection.prepare(
            "SELECT execution_id,disposal_id,CASE WHEN length(CAST(intent AS BLOB))<=4096 THEN intent ELSE '' END,intent_hash,admitted_at_ms FROM gc_disposals ORDER BY admitted_at_ms,execution_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })?;
        let mut audits = Vec::new();
        for row in rows {
            let (id, disposal, json, hash, time) = row?;
            let intent: GcDisposalIntent = serde_json::from_str(&json)?;
            let e = executions
                .iter()
                .find(|e| e.intent.execution_id.as_str() == id)
                .ok_or(JournalError::Invariant("GC disposal execution missing"))?;
            let q = quarantines
                .iter()
                .find(|q| q.intent.execution_id.as_str() == id)
                .ok_or(JournalError::Invariant("GC disposal quarantine missing"))?;
            let restored: Option<i64> = self.connection.query_row(
                "SELECT restored_at_watermark_ms FROM gc_disposal_restorations WHERE execution_id=?1",
                [&id], |r| r.get(0)).optional()?;
            let watermark: i64 = self.connection.query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if intent.format_version != FORMAT_VERSION
                || intent.execution_id.as_str() != id
                || intent.disposal_id.as_str() != disposal
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || intent.execution_hash
                    != ContentId::hash(serde_json::to_string(&e.intent)?.as_bytes())
                || intent.quarantine != q.intent
                || intent.quarantine_hash
                    != ContentId::hash(serde_json::to_string(&q.intent)?.as_bytes())
                || sql_integer(intent.admitted_at_ms)? != time
                || intent.admitted_at_ms < q.intent.prepared_at_watermark_ms
                || intent.admitted_at_ms >= e.intent.authorization.expires_at_ms
                || watermark < time
                || q.state == GcQuarantineState::Prepared
                || (restored.is_some() != (q.state == GcQuarantineState::Restored))
                || (restored.is_some() != (e.state == GcExecutionState::Aborted))
                || (q.state == GcQuarantineState::Deleted) != (e.state == GcExecutionState::Deleted)
                || e.deleted_at_watermark_ms
                    .is_some_and(|t| t < intent.admitted_at_ms)
                || restored.is_some_and(|r| {
                    r < time || r > watermark || Some(r as u64) != e.aborted_at_watermark_ms
                })
            {
                return Err(JournalError::Invariant("GC disposal integrity mismatch"));
            }
            audits.push(GcDisposalAudit {
                intent,
                state: if e.state == GcExecutionState::Deleted {
                    GcDisposalState::Deleted
                } else if restored.is_some() {
                    GcDisposalState::Restored
                } else if q.state == GcQuarantineState::RestorePending {
                    GcDisposalState::RestorePending
                } else {
                    GcDisposalState::DeletePending
                },
                restored_at_watermark_ms: restored.map(|r| r as u64),
                deleted_at_watermark_ms: e.deleted_at_watermark_ms,
                content_fenced: e.content_fenced,
                deletion_authorized: false,
                disposition_executor_available: cfg!(windows),
                sweep_available: false,
                gc_enabled: false,
            });
        }
        Ok(audits)
    }
}
