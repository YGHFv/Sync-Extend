use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, GcAuthorization, Journal,
    JournalError, Result,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcExecutionIntent {
    pub format_version: u32,
    pub execution_id: EntryId,
    pub authorization: GcAuthorization,
    pub authorization_hash: ContentId,
    pub admitted_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcExecutionState {
    Fenced,
    Aborted,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcExecutionAudit {
    pub intent: GcExecutionIntent,
    pub state: GcExecutionState,
    pub aborted_at_watermark_ms: Option<u64>,
    pub deleted_at_watermark_ms: Option<u64>,
    pub content_fenced: bool,
    pub deletion_authorized: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

impl Journal {
    pub fn require_cas_access(&self, content: &ContentId) -> Result<()> {
        let fenced: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_executions e WHERE e.content_id=?1
                AND NOT EXISTS (SELECT 1 FROM gc_execution_aborts WHERE execution_id=e.execution_id)
                AND NOT EXISTS (SELECT 1 FROM gc_execution_deletions WHERE execution_id=e.execution_id))",
            [content.as_str()], |r| r.get(0),
        )?;
        if fenced {
            return Err(JournalError::Invariant("CAS object fenced by GC execution"));
        }
        Ok(())
    }

    pub fn gc_executions(
        &self,
        space: &SpaceId,
        max_entries: usize,
    ) -> Result<Vec<GcExecutionAudit>> {
        let authorizations = self.gc_authorizations(space, max_entries)?;
        let watermark: Option<i64> = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_execution_aborts b LEFT JOIN gc_executions e USING(execution_id)
                WHERE e.execution_id IS NULL)", [], |r| r.get(0))?;
        if orphan {
            return Err(JournalError::Invariant("orphan GC execution abort"));
        }
        let orphan_deleted: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_execution_deletions d LEFT JOIN gc_executions e USING(execution_id) WHERE e.execution_id IS NULL)",
            [], |r| r.get(0))?;
        if orphan_deleted {
            return Err(JournalError::Invariant("orphan GC deletion terminal"));
        }
        let mut statement = self.connection.prepare(
            "SELECT execution_id,authorization_id,content_id,
                CASE WHEN length(CAST(intent AS BLOB))<=16384 THEN intent ELSE '' END,
                intent_hash,admitted_at_ms FROM gc_executions ORDER BY admitted_at_ms,execution_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut audits = Vec::new();
        let mut active = std::collections::BTreeSet::new();
        for row in rows {
            let (id, authorization_id, content, json, hash, time) = row?;
            let intent: GcExecutionIntent = serde_json::from_str(&json)?;
            let authorization = authorizations
                .iter()
                .find(|a| a.intent.authorization_id.as_str() == authorization_id)
                .ok_or(JournalError::Invariant(
                    "GC execution authorization missing",
                ))?;
            if intent.format_version != FORMAT_VERSION
                || intent.execution_id.as_str() != id
                || intent.authorization != authorization.intent
                || intent.authorization.mark.content_id.as_str() != content
                || intent.authorization_hash
                    != ContentId::hash(serde_json::to_string(&authorization.intent)?.as_bytes())
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || sql_integer(intent.admitted_at_ms)? != time
                || intent.admitted_at_ms < intent.authorization.authorized_at_ms
                || intent.admitted_at_ms >= intent.authorization.expires_at_ms
                || watermark.is_none_or(|w| w < time)
            {
                return Err(JournalError::Invariant("GC execution integrity mismatch"));
            }
            let aborted: Option<i64> = self
                .connection
                .query_row(
                    "SELECT aborted_at_watermark_ms FROM gc_execution_aborts WHERE execution_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            let deleted: Option<i64> = self.connection.query_row(
                "SELECT deleted_at_watermark_ms FROM gc_execution_deletions WHERE execution_id=?1",
                [&id], |r| r.get(0)).optional()?;
            if (deleted.is_some() && aborted.is_some())
                || deleted.is_some_and(|t| t < time || watermark.is_none_or(|w| t > w))
            {
                return Err(JournalError::Invariant(
                    "GC deletion terminal time mismatch",
                ));
            }
            if aborted.is_some_and(|t| t < time || watermark.is_none_or(|w| t > w)) {
                return Err(JournalError::Invariant("GC execution abort time mismatch"));
            }
            if aborted.is_none()
                && deleted.is_none()
                && (!active.insert(content.clone())
                    || self.gc_protected(&intent.authorization.mark.content_id)?)
            {
                return Err(JournalError::Invariant(
                    "GC execution fence/reference mismatch",
                ));
            }
            audits.push(GcExecutionAudit {
                intent,
                state: if aborted.is_some() {
                    GcExecutionState::Aborted
                } else if deleted.is_some() {
                    GcExecutionState::Deleted
                } else {
                    GcExecutionState::Fenced
                },
                aborted_at_watermark_ms: aborted.map(|t| t as u64),
                deleted_at_watermark_ms: deleted.map(|t| t as u64),
                content_fenced: aborted.is_none() && deleted.is_none(),
                deletion_authorized: false,
                sweep_available: false,
                gc_enabled: false,
            });
        }
        self.audit_gc_quarantines(&audits, max_entries)?;
        Ok(audits)
    }

    /// Consume one explicit intent into a durable fence without moving CAS content.
    pub fn with_gc_execution_admission<T, E>(
        &self,
        space: &SpaceId,
        authorization_id: &EntryId,
        max_entries: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcAuthorization) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, GcExecutionAudit), E>
    where
        E: From<JournalError>,
    {
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(JournalError::from)?;
            if let Some(old) = self
                .gc_executions(space, max_entries)?
                .into_iter()
                .find(|e| e.intent.authorization.authorization_id == *authorization_id)
            {
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, old));
            }
        }
        let mut coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        if let Some(old) = self
            .gc_executions(space, max_entries)?
            .into_iter()
            .find(|e| e.intent.authorization.authorization_id == *authorization_id)
        {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let authorization =
            self.require_gc_authorization(space, authorization_id, now()?, max_entries)?;
        let guards = inspect(&authorization)?;
        let time = now()?;
        if self.require_gc_authorization(space, authorization_id, time, max_entries)?
            != authorization
        {
            return Err(JournalError::Invariant("GC admission authorization changed").into());
        }
        coordination.try_exclusive()?;
        let time = now()?;
        if self.require_gc_authorization(space, authorization_id, time, max_entries)?
            != authorization
        {
            return Err(JournalError::Invariant(
                "GC admission authorization changed after CAS exclusion",
            )
            .into());
        }
        let intent = GcExecutionIntent {
            format_version: FORMAT_VERSION,
            execution_id: EntryId::random().map_err(JournalError::from)?,
            authorization_hash: ContentId::hash(
                serde_json::to_string(&authorization)
                    .map_err(JournalError::from)?
                    .as_bytes(),
            ),
            authorization,
            admitted_at_ms: time,
        };
        let json = serde_json::to_string(&intent).map_err(JournalError::from)?;
        // Reserve the terminal abort row so cancellation does not grow admission usage.
        check_storage_metadata_limit(&tx, max_entries, 2, json.len() as u64)?;
        tx.execute(
            "INSERT INTO gc_executions VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                intent.execution_id.as_str(),
                authorization_id.as_str(),
                intent.authorization.mark.content_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(time)?
            ],
        )
        .map_err(JournalError::from)?;
        let audit = self
            .gc_executions(space, max_entries)?
            .into_iter()
            .find(|e| e.intent.execution_id == intent.execution_id)
            .ok_or(JournalError::Invariant("GC execution disappeared"))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), audit))
    }

    /// Abort only a non-displacing execution or replay an already restored terminal.
    /// SQL rejects active physical plans until guarded restoration completes.
    pub fn abort_gc_execution(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max_entries: usize,
    ) -> Result<GcExecutionAudit> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.gc_quarantines(space, max_entries)?;
        let old = self
            .gc_executions(space, max_entries)?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("unknown GC execution"))?;
        if old.state == GcExecutionState::Aborted {
            tx.commit()?;
            return Ok(old);
        }
        if old.state == GcExecutionState::Deleted {
            return Err(JournalError::Invariant("deleted GC execution cannot abort"));
        }
        self.connection.execute(
            "INSERT INTO gc_execution_aborts SELECT ?1,observed_at_ms FROM gc_clock WHERE singleton=1",
            [id.as_str()],
        )?;
        let audit = self
            .gc_executions(space, max_entries)?
            .into_iter()
            .find(|e| e.intent.execution_id == *id)
            .ok_or(JournalError::Invariant("GC execution disappeared"))?;
        tx.commit()?;
        Ok(audit)
    }
}
