use crate::{
    check_storage_metadata_limit, sql_integer, GcMark, GcState, Journal, JournalError, Result,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcBoundary {
    pub worktree: ContentId,
    pub cas: ContentId,
    pub objects: ContentId,
    pub shard: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcAuthorization {
    pub format_version: u32,
    pub authorization_id: EntryId,
    pub mark: GcMark,
    pub mark_hash: ContentId,
    pub boundary: GcBoundary,
    pub authorized_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcAuthorizationState {
    ActiveIntent,
    Revoked,
    MarkCancelled,
    Invalidated,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcAuthorizationAudit {
    pub intent: GcAuthorization,
    pub state: GcAuthorizationState,
    pub revoked_at_ms: Option<u64>,
    pub evaluated_at_watermark_ms: u64,
    pub deletion_authorized: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

pub fn gc_authorization_expiry(now: u64, ttl_secs: u64) -> Result<u64> {
    if !(1..=3600).contains(&ttl_secs) {
        return Err(JournalError::Invariant(
            "GC authorization TTL must be 1..3600 seconds",
        ));
    }
    sql_integer(now)?;
    let expiry = now
        .checked_add(ttl_secs * 1000)
        .ok_or(JournalError::Invariant("GC authorization expiry overflow"))?;
    sql_integer(expiry)?;
    Ok(expiry)
}

impl Journal {
    pub fn gc_authorizations(
        &self,
        space: &SpaceId,
        max_entries: usize,
    ) -> Result<Vec<GcAuthorizationAudit>> {
        let marks = self.gc_marks(space, max_entries)?;
        let marks: std::collections::BTreeMap<_, _> = marks
            .iter()
            .map(|mark| (mark.intent.mark_id.as_str(), mark))
            .collect();
        let watermark: Option<i64> = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_revocations r LEFT JOIN gc_authorizations a USING(authorization_id)
                WHERE a.authorization_id IS NULL)", [], |r| r.get(0))?;
        if orphan {
            return Err(JournalError::Invariant("orphan GC revocation"));
        }
        let mut statement = self.connection.prepare(
            "SELECT authorization_id,mark_id,
                CASE WHEN length(CAST(intent AS BLOB))<=8192 THEN intent ELSE '' END,
                intent_hash,authorized_at_ms,expires_at_ms FROM gc_authorizations
                ORDER BY authorized_at_ms,authorization_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        let mut audits = Vec::new();
        for row in rows {
            let (id, mark_id, json, hash, time, expiry) = row?;
            let intent: GcAuthorization = serde_json::from_str(&json)?;
            let mark = marks
                .get(mark_id.as_str())
                .ok_or(JournalError::Invariant("authorization mark missing"))?;
            let duration = intent.expires_at_ms.checked_sub(intent.authorized_at_ms);
            let canonical = serde_json::to_string(&mark.intent)?;
            if intent.format_version != FORMAT_VERSION
                || intent.authorization_id.as_str() != id
                || intent.mark != mark.intent
                || intent.mark.space_id != *space
                || intent.mark_hash != ContentId::hash(canonical.as_bytes())
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || sql_integer(intent.authorized_at_ms)? != time
                || sql_integer(intent.expires_at_ms)? != expiry
                || intent.authorized_at_ms < intent.mark.grace_until_ms
                || duration.is_none_or(|n| !(1000..=3600000).contains(&n) || n % 1000 != 0)
                || watermark.is_none_or(|n| n < time)
            {
                return Err(JournalError::Invariant(
                    "GC authorization integrity mismatch",
                ));
            }
            let revoked: Option<i64> = self
                .connection
                .query_row(
                    "SELECT revoked_at_ms FROM gc_revocations WHERE authorization_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            if revoked.is_some_and(|t| t < time || watermark.is_none_or(|w| t > w)) {
                return Err(JournalError::Invariant("GC revocation time mismatch"));
            }
            let watermark = watermark.ok_or(JournalError::Invariant("GC clock missing"))? as u64;
            let state = if revoked.is_some() {
                GcAuthorizationState::Revoked
            } else if mark.state == GcState::Cancelled {
                GcAuthorizationState::MarkCancelled
            } else if mark.state == GcState::Invalidated {
                GcAuthorizationState::Invalidated
            } else if watermark >= intent.expires_at_ms {
                GcAuthorizationState::Expired
            } else {
                GcAuthorizationState::ActiveIntent
            };
            audits.push(GcAuthorizationAudit {
                intent,
                state,
                revoked_at_ms: revoked.map(|t| t as u64),
                evaluated_at_watermark_ms: watermark,
                deletion_authorized: false,
                sweep_available: false,
                gc_enabled: false,
            });
        }
        Ok(audits)
    }

    pub fn revoke_gc_authorization(
        &self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
        max_entries: usize,
    ) -> Result<GcAuthorizationAudit> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let audit = self
            .gc_authorizations(space, max_entries)?
            .into_iter()
            .find(|a| a.intent.authorization_id == *id)
            .ok_or(JournalError::Invariant("unknown GC authorization"))?;
        if audit.revoked_at_ms.is_some() {
            tx.commit()?;
            return Ok(audit);
        }
        self.gc_observe_clock(now, max_entries)?;
        check_storage_metadata_limit(&tx, max_entries, 1, 0)?;
        tx.execute(
            "INSERT INTO gc_revocations VALUES (?1,?2)",
            params![id.as_str(), sql_integer(now)?],
        )?;
        let audit = self
            .gc_authorizations(space, max_entries)?
            .into_iter()
            .find(|a| a.intent.authorization_id == *id)
            .ok_or(JournalError::Invariant("GC authorization disappeared"))?;
        tx.commit()?;
        Ok(audit)
    }

    pub fn with_gc_authorization<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        ttl_secs: u64,
        max_entries: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcMark) -> std::result::Result<(T, GcBoundary), E>,
    ) -> std::result::Result<(T, GcAuthorizationAudit), E>
    where
        E: From<JournalError>,
    {
        gc_authorization_expiry(0, ttl_secs)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        if self
            .gc_authorizations(space, max_entries)?
            .iter()
            .any(|a| a.intent.mark.mark_id == *id)
        {
            return Err(JournalError::Invariant("GC mark already has an authorization").into());
        }
        let mark = self.require_gc_preflight(space, id, now()?, max_entries)?;
        let (guards, boundary) = inspect(&mark)?;
        let time = now()?;
        if self.require_gc_preflight(space, id, time, max_entries)? != mark {
            return Err(JournalError::Invariant("GC authorization mark changed").into());
        }
        let intent = GcAuthorization {
            format_version: FORMAT_VERSION,
            authorization_id: EntryId::random().map_err(JournalError::from)?,
            mark_hash: ContentId::hash(
                serde_json::to_string(&mark)
                    .map_err(JournalError::from)?
                    .as_bytes(),
            ),
            mark,
            boundary,
            authorized_at_ms: time,
            expires_at_ms: gc_authorization_expiry(time, ttl_secs)?,
        };
        let json = serde_json::to_string(&intent).map_err(JournalError::from)?;
        check_storage_metadata_limit(&tx, max_entries, 1, json.len() as u64)?;
        tx.execute(
            "INSERT INTO gc_authorizations VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                intent.authorization_id.as_str(),
                id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(time)?,
                sql_integer(intent.expires_at_ms)?
            ],
        )
        .map_err(JournalError::from)?;
        let audit = self
            .gc_authorizations(space, max_entries)?
            .into_iter()
            .find(|a| a.intent.authorization_id == intent.authorization_id)
            .ok_or(JournalError::Invariant(
                "GC authorization missing after insert",
            ))?;
        tx.commit().map_err(JournalError::from)?;
        Ok((guards, audit))
    }

    pub fn with_gc_authorization_check<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max_entries: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcAuthorization) -> std::result::Result<T, E>,
    ) -> std::result::Result<(T, u64), E>
    where
        E: From<JournalError>,
    {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let intent = self.require_gc_authorization(space, id, now()?, max_entries)?;
        let guards = inspect(&intent)?;
        let time = now()?;
        if self.require_gc_authorization(space, id, time, max_entries)? != intent {
            return Err(JournalError::Invariant("GC authorization changed").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((guards, time))
    }

    fn require_gc_authorization(
        &self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
        max_entries: usize,
    ) -> Result<GcAuthorization> {
        let audit = self
            .gc_authorizations(space, max_entries)?
            .into_iter()
            .find(|a| a.intent.authorization_id == *id)
            .ok_or(JournalError::Invariant("unknown GC authorization"))?;
        if audit.state != GcAuthorizationState::ActiveIntent || now >= audit.intent.expires_at_ms {
            return Err(JournalError::Invariant(
                "GC authorization revoked, expired or invalidated",
            ));
        }
        self.require_gc_preflight(space, &audit.intent.mark.mark_id, now, max_entries)?;
        Ok(audit.intent)
    }
}
