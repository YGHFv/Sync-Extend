use crate::{
    check_storage_metadata_limit, CasAccessGuard, GcExecutionAudit, GcExecutionState, GcState,
    Journal, JournalError, Result,
};
use rusqlite::{params, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcQuarantineIntent {
    pub format_version: u32,
    pub execution_id: EntryId,
    pub plan_id: EntryId,
    pub tmp_identity: ContentId,
    pub owner_identity: ContentId,
    pub prepared_at_watermark_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcQuarantineState {
    Prepared,
    Quarantined,
    RestorePending,
    Restored,
}

impl GcQuarantineState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Quarantined => "quarantined",
            Self::RestorePending => "restore_pending",
            Self::Restored => "restored",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcQuarantineAudit {
    pub intent: GcQuarantineIntent,
    pub state: GcQuarantineState,
    pub deletion_authorized: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

impl Journal {
    pub fn recheck_gc_execution_authority<E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
    ) -> std::result::Result<(), E>
    where
        E: From<JournalError>,
    {
        let e = self.selected_gc_execution(space, id, max)?;
        self.require_gc_execution_live(&e, now()?, max)?;
        // Caller retains SQLite writer exclusion: authority cannot change, but
        // a bounded metadata audit may itself cross the fixed deadline.
        let time = now()?;
        self.gc_observe_clock(time, max)?;
        if time >= e.intent.authorization.expires_at_ms {
            return Err(JournalError::Invariant("GC execution authority expired").into());
        }
        Ok(())
    }
    pub fn gc_quarantines(
        &self,
        space: &SpaceId,
        max_entries: usize,
    ) -> Result<Vec<GcQuarantineAudit>> {
        let executions = self.gc_executions(space, max_entries)?;
        let mut statement = self.connection.prepare(
            "SELECT execution_id,plan_id,CASE WHEN length(CAST(intent AS BLOB))<=2048 THEN intent ELSE '' END,intent_hash,state FROM gc_quarantines ORDER BY execution_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut audits = Vec::new();
        for row in rows {
            let (id, plan, json, hash, state) = row?;
            let intent: GcQuarantineIntent = serde_json::from_str(&json)?;
            let execution = executions
                .iter()
                .find(|e| e.intent.execution_id.as_str() == id)
                .ok_or(JournalError::Invariant("orphan GC quarantine"))?;
            let watermark: i64 = self.connection.query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            let state = match state.as_str() {
                "prepared" => GcQuarantineState::Prepared,
                "quarantined" => GcQuarantineState::Quarantined,
                "restore_pending" => GcQuarantineState::RestorePending,
                "restored" => GcQuarantineState::Restored,
                _ => return Err(JournalError::Invariant("invalid GC quarantine state")),
            };
            if intent.format_version != FORMAT_VERSION
                || intent.execution_id.as_str() != id
                || intent.plan_id.as_str() != plan
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || intent.prepared_at_watermark_ms < execution.intent.admitted_at_ms
                || intent.prepared_at_watermark_ms >= execution.intent.authorization.expires_at_ms
                || intent.prepared_at_watermark_ms > watermark as u64
                || execution
                    .aborted_at_watermark_ms
                    .is_some_and(|time| time < intent.prepared_at_watermark_ms)
                || (state == GcQuarantineState::Restored)
                    != (execution.state == GcExecutionState::Aborted)
            {
                return Err(JournalError::Invariant("GC quarantine integrity mismatch"));
            }
            audits.push(GcQuarantineAudit {
                intent,
                state,
                deletion_authorized: false,
                sweep_available: false,
                gc_enabled: false,
            });
        }
        Ok(audits)
    }

    fn selected_gc_execution(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
    ) -> Result<GcExecutionAudit> {
        self.gc_executions(space, max)?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("unknown GC execution"))
    }

    fn require_gc_execution_live(&self, e: &GcExecutionAudit, now: u64, max: usize) -> Result<()> {
        if e.state != GcExecutionState::Fenced || now >= e.intent.authorization.expires_at_ms {
            return Err(JournalError::Invariant(
                "GC execution authority expired or terminal",
            ));
        }
        let audit = self
            .gc_authorizations(&e.intent.authorization.mark.space_id, max)?
            .into_iter()
            .find(|a| a.intent.authorization_id == e.intent.authorization.authorization_id)
            .ok_or(JournalError::Invariant(
                "GC execution authorization missing",
            ))?;
        if audit.revoked_at_ms.is_some() {
            return Err(JournalError::Invariant("GC execution revoked"));
        }
        self.require_gc_preflight(
            &e.intent.authorization.mark.space_id,
            &e.intent.authorization.mark.mark_id,
            now,
            max,
        )?;
        Ok(())
    }

    pub fn prepare_gc_quarantine<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcExecutionAudit, u64) -> std::result::Result<(T, GcQuarantineIntent), E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, GcQuarantineAudit), E>
    where
        E: From<JournalError>,
    {
        let mut coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        if let Some(old) = self
            .gc_quarantines(space, max)?
            .into_iter()
            .find(|q| q.intent.execution_id == *id)
        {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let e = self.selected_gc_execution(space, id, max)?;
        self.require_gc_execution_live(&e, now()?, max)?;
        let watermark: i64 = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        let (guards, intent) = inspect(&e, watermark as u64)?;
        if intent.execution_id != *id
            || intent.format_version != FORMAT_VERSION
            || intent.prepared_at_watermark_ms != watermark as u64
        {
            return Err(JournalError::Invariant("invalid quarantine observation").into());
        }
        coordination.try_exclusive()?;
        self.require_gc_execution_live(&e, now()?, max)?;
        let json = serde_json::to_string(&intent).map_err(JournalError::from)?;
        check_storage_metadata_limit(&tx, max, 1, json.len() as u64)?;
        tx.execute(
            "INSERT INTO gc_quarantines VALUES (?1,?2,?3,?4,'prepared')",
            params![
                id.as_str(),
                intent.plan_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str()
            ],
        )
        .map_err(JournalError::from)?;
        let q = self
            .gc_quarantines(space, max)?
            .into_iter()
            .find(|q| q.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("quarantine disappeared"))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), q))
    }

    /// Inspect under shared admission, then apply one guarded step under exclusive
    /// CAS and SQLite exclusion. Caller retains native guards through commit.
    pub fn with_gc_quarantine_step<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        policy: (usize, bool),
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcExecutionAudit, &GcQuarantineAudit) -> std::result::Result<T, E>,
        apply: impl FnOnce(&T, &GcQuarantineAudit, bool) -> std::result::Result<GcQuarantineState, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, GcQuarantineAudit), E>
    where
        E: From<JournalError>,
    {
        let (max, restore) = policy;
        let mut coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let old = self
            .gc_quarantines(space, max)?
            .into_iter()
            .find(|q| q.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("unknown GC quarantine"))?;
        if old.state == GcQuarantineState::Restored {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let e = self.selected_gc_execution(space, id, max)?;
        self.audit_gc_owners(space, max)?;
        let guards = inspect(&e, &old)?;
        coordination.try_exclusive()?;
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
            .ok_or(JournalError::Invariant("GC quarantine mark missing"))?;
        let restoring = if restore
            || old.state == GcQuarantineState::RestorePending
            || revoked
            || mark.state != GcState::Marked
        {
            true
        } else {
            let time = now()?;
            self.gc_observe_clock(time, max)?;
            time >= e.intent.authorization.expires_at_ms
        };
        let next = apply(&guards, &old, restoring)?;
        if (restoring
            && old.state != GcQuarantineState::RestorePending
            && next != GcQuarantineState::RestorePending)
            || (!restoring
                && old.state == GcQuarantineState::Prepared
                && next != GcQuarantineState::Quarantined)
            || (old.state == GcQuarantineState::RestorePending
                && next != GcQuarantineState::Restored)
            || (old.state == GcQuarantineState::Quarantined && !restoring && next != old.state)
        {
            return Err(JournalError::Invariant("invalid GC quarantine recovery step").into());
        }
        if next != old.state {
            tx.execute(
                "UPDATE gc_quarantines SET state=?1 WHERE execution_id=?2 AND state=?3",
                params![next.as_str(), id.as_str(), old.state.as_str()],
            )
            .map_err(JournalError::from)?;
            if next == GcQuarantineState::Restored {
                tx.execute("INSERT INTO gc_execution_aborts SELECT ?1,observed_at_ms FROM gc_clock WHERE singleton=1",[id.as_str()]).map_err(JournalError::from)?;
            }
        }
        let q = self
            .gc_quarantines(space, max)?
            .into_iter()
            .find(|q| q.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("quarantine disappeared"))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), q))
    }
}
