use crate::{check_storage_metadata_limit, sql_integer, Journal, JournalError, Result};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

const MAX_GC_INTENT_BYTES: i64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcObservation {
    pub physical_identity: ContentId,
    pub length: u32,
    pub modified_at_ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcMark {
    pub format_version: u32,
    pub mark_id: EntryId,
    pub space_id: SpaceId,
    pub content_id: ContentId,
    pub observation: GcObservation,
    pub marked_at_ms: u64,
    pub grace_until_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcState {
    Marked,
    Cancelled,
    Invalidated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GcMarkAudit {
    pub intent: GcMark,
    pub state: GcState,
    pub cancelled_at_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcCheck {
    PendingGrace,
    UnreferencedAfterGraceObservationOnly,
    Referenced,
    Invalidated,
    Cancelled,
    Missing,
    Changed,
    Corrupt,
}

pub fn gc_grace_until(now_ms: u64, grace_secs: u64) -> Result<u64> {
    sql_integer(now_ms)?;
    if !(1..=604800).contains(&grace_secs) {
        return Err(JournalError::Invariant(
            "GC grace must be 1 second through 7 days",
        ));
    }
    let until = now_ms
        .checked_add(grace_secs * 1000)
        .ok_or(JournalError::Invariant("GC grace overflow"))?;
    sql_integer(until)?;
    Ok(until)
}

impl GcMark {
    fn validate(&self) -> Result<()> {
        let duration = self.grace_until_ms.checked_sub(self.marked_at_ms);
        if self.format_version != FORMAT_VERSION
            || duration.is_none_or(|n| !(1000..=604800000).contains(&n) || n % 1000 != 0)
            || !(1..=4 * 1024 * 1024).contains(&self.observation.length)
        {
            return Err(JournalError::Invariant("invalid GC mark intent"));
        }
        sql_integer(self.marked_at_ms)?;
        sql_integer(self.grace_until_ms)?;
        Ok(())
    }
}

impl Journal {
    pub fn gc_marks(&self, space: &SpaceId, max_entries: usize) -> Result<Vec<GcMarkAudit>> {
        self.check_storage_metadata_limit(max_entries)?;
        self.read_view().gc_marks(space)
    }

    pub(crate) fn gc_protected(&self, id: &ContentId) -> Result<bool> {
        self.read_view().gc_protected(id)
    }

    pub(crate) fn gc_observe_clock(&self, now: u64, max_entries: usize) -> Result<()> {
        let now = sql_integer(now)?;
        let old: Option<i64> = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if old.is_some_and(|old| now < old) {
            return Err(JournalError::Invariant("GC clock moved backward"));
        }
        check_storage_metadata_limit(&self.connection, max_entries, u64::from(old.is_none()), 0)?;
        if old.is_some() {
            self.connection.execute(
                "UPDATE gc_clock SET observed_at_ms=?1 WHERE singleton=1",
                [now],
            )?;
        } else {
            self.connection
                .execute("INSERT INTO gc_clock VALUES (1,?1)", [now])?;
        }
        Ok(())
    }

    pub fn mark_gc_object(&mut self, intent: &GcMark, max_entries: usize) -> Result<GcMarkAudit> {
        intent.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_gc_owners(&intent.space_id, max_entries)?;
        let marks = self.gc_marks(&intent.space_id, max_entries)?;
        self.gc_observe_clock(intent.marked_at_ms, max_entries)?;
        if let Some(old) = marks
            .iter()
            .find(|m| m.state == GcState::Marked && m.intent.content_id == intent.content_id)
        {
            if old.intent.observation != intent.observation
                || old.intent.grace_until_ms - old.intent.marked_at_ms
                    != intent.grace_until_ms - intent.marked_at_ms
            {
                return Err(JournalError::Invariant(
                    "existing GC mark observation/grace mismatch",
                ));
            }
            tx.commit()?;
            return Ok(old.clone());
        }
        let json = serde_json::to_string(intent)?;
        if json.len() > MAX_GC_INTENT_BYTES as usize {
            return Err(JournalError::Invariant("GC intent byte limit"));
        }
        // Reserve an invalidation slot so new pins never need extra metadata admission.
        check_storage_metadata_limit(&tx, max_entries, 2, json.len() as u64)?;
        tx.execute(
            "INSERT INTO gc_marks VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                intent.mark_id.as_str(),
                intent.space_id.as_str(),
                intent.content_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(intent.marked_at_ms)?,
                sql_integer(intent.grace_until_ms)?,
            ],
        )?;
        let audit = self
            .gc_marks(&intent.space_id, max_entries)?
            .into_iter()
            .find(|m| m.intent.mark_id == intent.mark_id)
            .ok_or(JournalError::Invariant("GC mark missing after admission"))?;
        tx.commit()?;
        Ok(audit)
    }

    pub fn cancel_gc_mark(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
        max_entries: usize,
    ) -> Result<GcMarkAudit> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let audit = self
            .gc_marks(space, max_entries)?
            .into_iter()
            .find(|m| m.intent.mark_id == *id)
            .ok_or(JournalError::Invariant("unknown GC mark"))?;
        self.gc_observe_clock(now, max_entries)?;
        if audit.state != GcState::Cancelled {
            check_storage_metadata_limit(&tx, max_entries, 1, 0)?;
            tx.execute(
                "INSERT INTO gc_cancellations VALUES (?1,?2)",
                params![id.as_str(), sql_integer(now)?],
            )?;
        }
        let audit = self
            .gc_marks(space, max_entries)?
            .into_iter()
            .find(|m| m.intent.mark_id == *id)
            .ok_or(JournalError::Invariant("GC mark disappeared"))?;
        tx.commit()?;
        Ok(audit)
    }

    pub fn revalidate_gc_mark(
        &mut self,
        space: &SpaceId,
        id: &EntryId,
        observation: GcCheck,
        now: u64,
        max_entries: usize,
    ) -> Result<GcCheck> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.audit_gc_owners(space, max_entries)?;
        let audit = self
            .gc_marks(space, max_entries)?
            .into_iter()
            .find(|m| m.intent.mark_id == *id)
            .ok_or(JournalError::Invariant("unknown GC mark"))?;
        self.gc_observe_clock(now, max_entries)?;
        let check = if audit.state == GcState::Cancelled {
            GcCheck::Cancelled
        } else if self.gc_protected(&audit.intent.content_id)? {
            GcCheck::Referenced
        } else if audit.state == GcState::Invalidated {
            GcCheck::Invalidated
        } else if observation != GcCheck::UnreferencedAfterGraceObservationOnly {
            observation
        } else if now < audit.intent.grace_until_ms {
            GcCheck::PendingGrace
        } else {
            GcCheck::UnreferencedAfterGraceObservationOnly
        };
        tx.commit()?;
        Ok(check)
    }

    pub(crate) fn audit_gc_owners(&self, space: &SpaceId, max_entries: usize) -> Result<()> {
        self.snapshot_audit(space, max_entries)?;
        self.current(space)?;
        self.read_leases(space, max_entries)?;
        for mutation in self.mutations(space)? {
            self.verify_mutation_references(&mutation.intent.transaction_id)?;
        }
        self.publications(space, max_entries)?;
        self.cleanup_plans(space)?;
        self.reference_reservations(space, max_entries)?;
        self.original_disposals(space, max_entries)?;
        self.tree_restore_preparations(space, max_entries)?;
        let conflict_owner: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.conflict_resolution_admissions)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_signatures)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_sequences)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_objects)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_bindings)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_headers)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_templates)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_activations)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_creators)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_phases)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_steps)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_dispositions)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_history)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_events)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_history_objects)
             OR EXISTS(SELECT 1 FROM main.conflict_resolution_native_branch_handoffs)",
            [],
            |row| row.get(0),
        )?;
        if conflict_owner {
            self.conflict_resolution_admissions(space)?;
        }
        Ok(())
    }

    /// Observe under SQLite writer exclusion. Returned guards survive clock commit;
    /// neither the callback nor this method grants permission to delete content.
    pub fn with_gc_preflight<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max_entries: usize,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(&GcMark) -> std::result::Result<T, E>,
    ) -> std::result::Result<(T, u64), E>
    where
        E: From<JournalError>,
    {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        let mark = self.require_gc_preflight(space, id, now()?, max_entries)?;
        let guards = inspect(&mark)?;
        let checked_at_ms = now()?;
        let final_mark = self.require_gc_preflight(space, id, checked_at_ms, max_entries)?;
        if final_mark != mark {
            return Err(JournalError::Invariant("GC preflight mark changed").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((guards, checked_at_ms))
    }

    pub(crate) fn require_gc_preflight(
        &self,
        space: &SpaceId,
        id: &EntryId,
        now: u64,
        max_entries: usize,
    ) -> Result<GcMark> {
        self.audit_gc_owners(space, max_entries)?;
        let audit = self
            .gc_marks(space, max_entries)?
            .into_iter()
            .find(|m| m.intent.mark_id == *id)
            .ok_or(JournalError::Invariant("unknown GC mark"))?;
        if audit.state != GcState::Marked || self.gc_protected(&audit.intent.content_id)? {
            return Err(JournalError::Invariant(
                "GC preflight mark is terminal or referenced",
            ));
        }
        if now < audit.intent.grace_until_ms {
            return Err(JournalError::Invariant("GC preflight grace pending"));
        }
        self.gc_observe_clock(now, max_entries)?;
        Ok(audit.intent)
    }
}

impl crate::JournalReadView<'_> {
    pub(crate) fn gc_marks(&self, space: &SpaceId) -> Result<Vec<GcMarkAudit>> {
        if self.state("space_id")?.as_deref() != Some(space.as_str()) {
            return Err(JournalError::Invariant("GC space mismatch"));
        }
        let clock: Option<i64> = self
            .connection
            .query_row(
                "SELECT observed_at_ms FROM gc_clock WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if clock.is_some_and(|c| c < 0) {
            return Err(JournalError::Invariant("negative GC clock"));
        }
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gc_cancellations c LEFT JOIN gc_marks m USING(mark_id)
                WHERE m.mark_id IS NULL)
             OR EXISTS(SELECT 1 FROM gc_invalidations i LEFT JOIN gc_marks m USING(mark_id)
                WHERE m.mark_id IS NULL)",
            [],
            |r| r.get(0),
        )?;
        if orphan {
            return Err(JournalError::Invariant("orphan GC terminal record"));
        }
        let mut statement = self.connection.prepare(
            "SELECT mark_id,space_id,content_id,
             CASE WHEN length(CAST(intent AS BLOB))<=4096 THEN intent ELSE '' END,
             intent_hash,marked_at_ms,grace_until_ms
             FROM gc_marks ORDER BY marked_at_ms,mark_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut audits = Vec::new();
        let mut live = std::collections::BTreeSet::new();
        for row in rows {
            let (id, stored_space, content, json, hash, time, until) = row?;
            let intent: GcMark = serde_json::from_str(&json)?;
            intent.validate()?;
            if intent.mark_id.as_str() != id
                || intent.space_id != *space
                || stored_space != space.as_str()
                || intent.content_id.as_str() != content
                || ContentId::hash(json.as_bytes()).as_str() != hash
                || sql_integer(intent.marked_at_ms)? != time
                || sql_integer(intent.grace_until_ms)? != until
                || clock.is_none_or(|c| c < time)
            {
                return Err(JournalError::Invariant("GC mark integrity mismatch"));
            }
            let cancelled: Option<i64> = self
                .connection
                .query_row(
                    "SELECT cancelled_at_ms FROM gc_cancellations WHERE mark_id=?1",
                    [&id],
                    |r| r.get(0),
                )
                .optional()?;
            if cancelled.is_some_and(|c| c < time || clock.is_none_or(|t| t < c)) {
                return Err(JournalError::Invariant("GC cancellation time mismatch"));
            }
            let invalidated: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM gc_invalidations WHERE mark_id=?1)",
                [&id],
                |r| r.get(0),
            )?;
            let state = if cancelled.is_some() {
                GcState::Cancelled
            } else if invalidated {
                GcState::Invalidated
            } else {
                GcState::Marked
            };
            if state == GcState::Marked
                && (!live.insert(intent.content_id.clone())
                    || self.gc_protected(&intent.content_id)?)
            {
                return Err(JournalError::Invariant(
                    "live GC mark has duplicate or protected content",
                ));
            }
            audits.push(GcMarkAudit {
                intent,
                state,
                cancelled_at_ms: cancelled.map(|c| c as u64),
            });
        }
        Ok(audits)
    }

    pub(crate) fn gc_protected(&self, id: &ContentId) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM snapshot_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM publication_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM remote_replace_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM conflict_resolution_native_history_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM conflict_resolution_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM mutation_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM read_lease_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM reference_reservation_objects WHERE content_id=?1)
             OR EXISTS(SELECT 1 FROM tree_restore_objects WHERE content_id=?1)",
            [id.as_str()],
            |r| r.get(0),
        )?)
    }
}
