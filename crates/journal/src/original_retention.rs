use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, Journal, JournalError,
    MutationAction, MutationState, Result,
};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    original_retention::{OriginalRetentionScope, RetainedOriginalAction},
    ContentId, EntryId, SpaceId,
};

const MAX_INTENT_BYTES: usize = 16 * 1024 * 1024;
const TERMINAL_RESERVATION_BYTES: u64 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalDisposalIntent {
    pub plan_id: EntryId,
    pub scope: OriginalRetentionScope,
    pub base_identity: ContentId,
    pub original_length: u64,
    pub modified_at_ns: u64,
    pub prepared_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OriginalDisposalAudit {
    pub intent: OriginalDisposalIntent,
    pub state: &'static str,
    pub completed_at_ms: Option<u64>,
    pub historical_snapshot_pins_verified: bool,
    pub content_hashes_verified: bool,
    pub disposition_executor_available: bool,
    pub automatic_cleanup_available: bool,
    pub physical_space_reclaimed: bool,
    pub remote_backup_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalDisposalStep {
    Pending,
    ActualAbsence,
}

impl Journal {
    fn validate_original_disposal(&self, intent: &OriginalDisposalIntent) -> Result<()> {
        let scope = &intent.scope;
        scope.validate()?;
        sql_integer(intent.prepared_at_ms)?;
        let mutation = self.mutation(&scope.transaction_id)?;
        self.verify_mutation_references(&scope.transaction_id)?;
        let action = match &mutation.intent.action {
            MutationAction::Delete => RetainedOriginalAction::Delete,
            MutationAction::Replace { .. } => RetainedOriginalAction::Replace,
            MutationAction::Move { .. } => {
                return Err(JournalError::Invariant("Move has no retained original"));
            }
        };
        let execution = mutation.execution.as_ref().ok_or(JournalError::Invariant(
            "original preparation execution missing",
        ))?;
        let baseline = self.retained_snapshot(&scope.space_id, &scope.baseline_snapshot)?;
        let completed = self.retained_snapshot(&scope.space_id, &scope.committed_snapshot)?;
        if mutation.state != MutationState::Committed
            || mutation.intent.space_id != scope.space_id
            || mutation.intent.baseline_root != scope.baseline_snapshot
            || mutation.committed_snapshot.as_ref() != Some(&scope.committed_snapshot)
            || execution.execution_id != scope.execution_id
            || action != scope.action
            || ContentId::hash(serde_json::to_string(&mutation.intent)?.as_bytes())
                != scope.mutation_intent_hash
            || ContentId::hash(serde_json::to_string(execution)?.as_bytes()) != scope.execution_hash
            || mutation.intent.file_identity != scope.original_identity
            || mutation.intent.baseline_entry.content.as_ref() != Some(&scope.content)
            || baseline.state != "materialized"
            || completed.state != "materialized"
            || intent.original_length != scope.content.length
            || intent.prepared_at_ms < mutation.intent.created_at_ms
            || intent.prepared_at_ms < baseline.created_at_ms
            || intent.prepared_at_ms < completed.created_at_ms
        {
            return Err(JournalError::Invariant(
                "original preparation committed generation mismatch",
            ));
        }
        for chunk in &scope.content.chunks {
            self.require_cas_access(&chunk.content_id)?;
        }
        Ok(())
    }

    /// Metadata-only, bounded own-snapshot pin audit. No native or CAS hash proof.
    /// Reuse a caller's transaction so GC callbacks cannot begin nested snapshots.
    pub fn original_disposals(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Vec<OriginalDisposalAudit>> {
        if !self.connection.is_autocommit() {
            return self.audit_original_disposals(space, max);
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let audits = self.audit_original_disposals(space, max)?;
        tx.commit()?;
        Ok(audits)
    }

    fn audit_original_disposals(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Vec<OriginalDisposalAudit>> {
        self.check_storage_metadata_limit(max)?;
        if self.state("space_id")?.as_deref() != Some(space.as_str()) {
            return Err(JournalError::Invariant(
                "original preparation space mismatch",
            ));
        }
        let orphan: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM original_disposal_completions c
                LEFT JOIN original_disposals p USING(transaction_id) WHERE p.transaction_id IS NULL)",
            [],
            |r| r.get(0),
        )?;
        if orphan {
            return Err(JournalError::Invariant("orphan original completion"));
        }
        let mut statement = self.connection.prepare(
            "SELECT transaction_id,execution_id,plan_id,space_id,
                CASE WHEN length(CAST(intent AS BLOB))<=16777216 THEN intent ELSE '' END,
                intent_hash,prepared_at_ms FROM original_disposals ORDER BY transaction_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut audits = Vec::new();
        let mut visits = 0usize;
        for row in rows {
            let (transaction, execution, plan, stored_space, json, hash, time) = row?;
            let intent: OriginalDisposalIntent = serde_json::from_str(&json)?;
            visits = visits
                .checked_add(intent.scope.content.chunks.len())
                .filter(|n| *n <= max)
                .ok_or(JournalError::Invariant("original preparation chunk budget"))?;
            if intent.scope.transaction_id.as_str() != transaction
                || intent.scope.execution_id.as_str() != execution
                || intent.plan_id.as_str() != plan
                || intent.scope.space_id != *space
                || stored_space != space.as_str()
                || sql_integer(intent.prepared_at_ms)? != time
                || serde_json::to_string(&intent)? != json
                || ContentId::hash(json.as_bytes()).as_str() != hash
            {
                return Err(JournalError::Invariant(
                    "original preparation integrity mismatch",
                ));
            }
            self.validate_original_disposal(&intent)?;
            let completion: Option<(String, String, i64)> = self
                .connection
                .query_row(
                    "SELECT CASE WHEN length(CAST(plan_id AS BLOB))=32 THEN plan_id ELSE '' END,
                        CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END,
                        completed_at_ms
                     FROM original_disposal_completions WHERE transaction_id=?1",
                    [&transaction],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let completed_at_ms = if let Some((plan_id, intent_hash, completed)) = completion {
                if plan_id != plan || intent_hash != hash || completed < time {
                    return Err(JournalError::Invariant(
                        "original completion integrity mismatch",
                    ));
                }
                Some(
                    u64::try_from(completed)
                        .map_err(|_| JournalError::Invariant("invalid original completion time"))?,
                )
            } else {
                None
            };
            audits.push(OriginalDisposalAudit {
                intent,
                state: if completed_at_ms.is_some() {
                    "disposed"
                } else {
                    "delete_pending"
                },
                completed_at_ms,
                historical_snapshot_pins_verified: true,
                content_hashes_verified: false,
                disposition_executor_available: cfg!(windows),
                automatic_cleanup_available: false,
                physical_space_reclaimed: false,
                remote_backup_complete: false,
            });
        }
        Ok(audits)
    }

    /// Persist one single-use pending, not a native disposition request.
    /// Trusted adapters verify exact native/CAS content with retained guards,
    /// then recheck those guards AFTER the final owner audit through commit.
    pub fn prepare_original_disposal<T, E>(
        &self,
        intent: &OriginalDisposalIntent,
        max: usize,
        inspect: impl FnOnce(&OriginalDisposalIntent) -> std::result::Result<T, E>,
        recheck: impl FnOnce(&mut T, &OriginalDisposalIntent) -> std::result::Result<(), E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, OriginalDisposalAudit), E>
    where
        E: From<JournalError>,
    {
        let space = &intent.scope.space_id;
        let old = self.original_disposals(space, max)?;
        if let Some(old) = old
            .into_iter()
            .find(|old| old.intent.scope.transaction_id == intent.scope.transaction_id)
        {
            if old.intent != *intent {
                return Err(JournalError::Invariant("original preparation already exists").into());
            }
            return Ok((None, old));
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.require_no_tree_restore(space, max)?;
        self.audit_gc_owners(space, max)?;
        self.validate_original_disposal(intent)?;
        if intent.scope.content.chunks.len() > max {
            return Err(JournalError::Invariant("original preparation chunk budget").into());
        }
        let json = serde_json::to_string(intent).map_err(JournalError::from)?;
        if json.len() > MAX_INTENT_BYTES {
            return Err(JournalError::Invariant("original preparation metadata limit").into());
        }
        check_storage_metadata_limit(&tx, max, 2, json.len() as u64 + TERMINAL_RESERVATION_BYTES)?;
        let mut guards = inspect(intent)?;
        self.audit_gc_owners(space, max)?;
        self.validate_original_disposal(intent)?;
        tx.execute(
            "INSERT INTO original_disposals VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                intent.scope.transaction_id.as_str(),
                intent.scope.execution_id.as_str(),
                intent.plan_id.as_str(),
                space.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str(),
                sql_integer(intent.prepared_at_ms)?,
            ],
        )
        .map_err(JournalError::from)?;
        let audit = self
            .original_disposals(space, max)?
            .into_iter()
            .find(|audit| audit.intent.scope.transaction_id == intent.scope.transaction_id)
            .ok_or(JournalError::Invariant("original preparation disappeared"))?;
        // Reading the inserted row may itself take time; retain final native proof.
        recheck(&mut guards, intent)?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), audit))
    }

    /// Journal side of one explicit pending step, not a native executor.
    /// ActualAbsence is trusted adapter evidence, never request-success evidence.
    /// A final absence callback runs AFTER the fresh owner audit before terminal.
    pub fn with_original_disposition<T, E>(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        completed_at_ms: u64,
        inspect: impl FnOnce(&OriginalDisposalAudit) -> std::result::Result<T, E>,
        steps: (
            impl FnOnce(&mut T, &OriginalDisposalAudit) -> std::result::Result<OriginalDisposalStep, E>,
            impl FnOnce(&mut T, &OriginalDisposalAudit) -> std::result::Result<(), E>,
        ),
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, OriginalDisposalAudit), E>
    where
        E: From<JournalError>,
    {
        let (apply, final_absence) = steps;
        let selected = |audits: Vec<OriginalDisposalAudit>| {
            audits
                .into_iter()
                .find(|a| a.intent.scope.transaction_id == *id)
                .ok_or(JournalError::Invariant(
                    "original pending preparation missing",
                ))
        };
        let old = selected(self.original_disposals(space, max)?)?;
        if old.completed_at_ms.is_some() {
            return Ok((None, old));
        }
        sql_integer(completed_at_ms)?;
        if completed_at_ms < old.intent.prepared_at_ms {
            return Err(
                JournalError::Invariant("original completion clock precedes preparation").into(),
            );
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.require_no_tree_restore(space, max)?;
        self.audit_gc_owners(space, max)?;
        let pending = selected(self.original_disposals(space, max)?)?;
        // Another writer can finish between the optimistic read and write admission.
        if pending.completed_at_ms.is_some() {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, pending));
        }
        let mut guards = inspect(&pending)?;
        if apply(&mut guards, &pending)? == OriginalDisposalStep::ActualAbsence {
            self.audit_gc_owners(space, max)?;
            self.validate_original_disposal(&pending.intent)?;
            final_absence(&mut guards, &pending)?;
            tx.execute(
                "INSERT INTO original_disposal_completions VALUES (?1,?2,?3,?4)",
                params![
                    id.as_str(),
                    pending.intent.plan_id.as_str(),
                    ContentId::hash(
                        serde_json::to_string(&pending.intent)
                            .map_err(JournalError::from)?
                            .as_bytes()
                    )
                    .as_str(),
                    sql_integer(completed_at_ms)?,
                ],
            )
            .map_err(JournalError::from)?;
        }
        let audit = selected(self.original_disposals(space, max)?)?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, guards)), audit))
    }
}
