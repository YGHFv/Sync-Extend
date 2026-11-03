//! Immutable descriptive native binding, never executable or current native proof.

use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, Journal, JournalError, Result,
    TreeRestoreHistoryReservation, TreeRestorePreparationIntent, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    limits,
    tree_restore::{plan_tree_restore, TreeRestorePlan},
    tree_restore_history::encode_history_record,
    tree_restore_identity::{
        plan_tree_restore_identities, TreeIdentityLimits, TreeIdentityPlan, TreeNativeInventory,
    },
    ContentId, EntryId, Manifest,
};

const ROW_BYTES: u64 = 384;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreNativeRequest {
    pub transaction_id: EntryId,
    pub preparation_hash: ContentId,
    pub history_intent_hash: ContentId,
    pub history_projection_hash: ContentId,
    pub captured_at_ms: u64,
    pub limits: TreeIdentityLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeRestoreNativeIntent {
    pub request: TreeRestoreNativeRequest,
    pub inventory: TreeNativeInventory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeRestoreNativeReservation {
    pub accounting: &'static str,
    pub intent: TreeRestoreNativeIntent,
    pub identity_fingerprint: ContentId,
    pub binding_count: usize,
    pub reserved_rows: u64,
    pub reserved_metadata_bytes: u64,
    pub native_tree_verified: bool,
    pub execution_admission_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

fn validate_request(
    request: &TreeRestoreNativeRequest,
    preparation: &TreeRestorePreparationIntent,
    history: &TreeRestoreHistoryReservation,
    max: usize,
) -> Result<()> {
    sql_integer(request.captured_at_ms)?;
    if request.transaction_id != preparation.transaction_id
        || request.preparation_hash != ContentId::hash(&serde_json::to_vec(preparation)?)
        || request.history_intent_hash != ContentId::hash(&serde_json::to_vec(&history.intent)?)
        || request.history_projection_hash != history.projection_hash
        || request.captured_at_ms < history.intent.history.created_at_ms
        || request.limits.max_bindings == 0
        || request.limits.max_bindings > max
        || request.limits.max_bindings > limits::MAX_ENTRIES
        || request.limits.max_metadata_bytes > MAX_OPERATION_BYTES as u64
    {
        return Err(JournalError::Invariant(
            "tree native exact request binding or limits",
        ));
    }
    Ok(())
}

fn project(
    intent: &TreeRestoreNativeIntent,
    preparation: &TreeRestorePreparationIntent,
    history: &TreeRestoreHistoryReservation,
    tree: &TreeRestorePlan,
    baseline: &Manifest,
    max: usize,
) -> Result<(String, TreeIdentityPlan, TreeRestoreNativeReservation)> {
    validate_request(&intent.request, preparation, history, max)?;
    let r = &intent.request;
    let plan = plan_tree_restore_identities(
        tree,
        baseline,
        &r.transaction_id,
        &r.preparation_hash,
        &intent.inventory,
        r.limits,
    )?;
    let json = String::from_utf8(encode_history_record(intent, r.limits.max_metadata_bytes)?)
        .map_err(|_| JournalError::Invariant("tree native intent encoding"))?;
    let binding_count = intent
        .inventory
        .entries
        .len()
        .checked_add(tree.steps().len())
        .and_then(|n| n.checked_add(3))
        .ok_or(JournalError::Invariant(
            "tree native binding count overflow",
        ))?;
    let reserved_metadata_bytes = (json.len() as u64)
        .checked_add(ROW_BYTES)
        .filter(|n| *n <= max as u64 * 1024)
        .ok_or(JournalError::Invariant("tree native metadata budget"))?;
    let audit = TreeRestoreNativeReservation {
        accounting: "logical_native_description_row_values_not_current_proof_or_sqlite_allocation",
        intent: intent.clone(),
        identity_fingerprint: plan.fingerprint().clone(),
        binding_count,
        reserved_rows: 1,
        reserved_metadata_bytes,
        native_tree_verified: false,
        execution_admission_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    };
    Ok((json, plan, audit))
}

pub(crate) fn audit_native(
    connection: &Connection,
    preparation: &TreeRestorePreparationIntent,
    history: Option<&TreeRestoreHistoryReservation>,
    tree: &TreeRestorePlan,
    baseline: &Manifest,
    cancelled_at_ms: Option<u64>,
    max: usize,
) -> Result<Option<TreeRestoreNativeReservation>> {
    type Stored = (
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        i64,
        i64,
    );
    let stored: Option<Stored> =
        connection.query_row(
            "SELECT CASE WHEN length(CAST(preparation_hash AS BLOB))=64 THEN preparation_hash ELSE '' END,
                CASE WHEN length(CAST(history_intent_hash AS BLOB))=64 THEN history_intent_hash ELSE '' END,
                CASE WHEN length(CAST(history_projection_hash AS BLOB))=64 THEN history_projection_hash ELSE '' END,
                CASE WHEN length(CAST(intent AS BLOB)) BETWEEN 1 AND 16777216 THEN intent ELSE '' END,
                CASE WHEN length(CAST(intent_hash AS BLOB))=64 THEN intent_hash ELSE '' END,
                CASE WHEN length(CAST(identity_fingerprint AS BLOB))=64 THEN identity_fingerprint ELSE '' END,
                captured_at_ms,binding_count,reserved_rows,reserved_bytes
             FROM tree_restore_native_reservations WHERE transaction_id=?1",
            [preparation.transaction_id.as_str()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,
                r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)),
        ).optional()?;
    let Some(row) = stored else {
        return Ok(None);
    };
    let history = history.ok_or(JournalError::Invariant("tree native history missing"))?;
    let intent: TreeRestoreNativeIntent = serde_json::from_str(&row.3)?;
    let (json, _, audit) = project(&intent, preparation, history, tree, baseline, max)?;
    let request = &intent.request;
    if json != row.3
        || request.preparation_hash.as_str() != row.0
        || request.history_intent_hash.as_str() != row.1
        || request.history_projection_hash.as_str() != row.2
        || ContentId::hash(json.as_bytes()).as_str() != row.4
        || audit.identity_fingerprint.as_str() != row.5
        || sql_integer(request.captured_at_ms)? != row.6
        || sql_integer(audit.binding_count as u64)? != row.7
        || sql_integer(audit.reserved_rows)? != row.8
        || sql_integer(audit.reserved_metadata_bytes)? != row.9
        || cancelled_at_ms.is_some_and(|t| t < request.captured_at_ms)
    {
        return Err(JournalError::Invariant(
            "tree native immutable description mismatch",
        ));
    }
    Ok(Some(audit))
}

impl Journal {
    /// Store an exact description returned by a fresh retained read-only inspection.
    /// Generic callers supply descriptions, not native authority or executable proof.
    /// Exact replay never calls inspection or reacquires CAS; cancellations stay terminal.
    pub fn with_tree_restore_native_identity<T, E>(
        &self,
        request: &TreeRestoreNativeRequest,
        max: usize,
        inspect: impl FnOnce(
            &TreeRestorePreparationIntent,
            &TreeRestorePlan,
            &Manifest,
            &Manifest,
        ) -> std::result::Result<(T, TreeNativeInventory), E>,
        recheck: impl FnOnce(&T, &TreeIdentityPlan) -> std::result::Result<(), E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, TreeRestoreNativeReservation), E>
    where
        E: From<JournalError>,
    {
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree native space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree native owner"))
        };
        let replay = |old: TreeRestoreNativeReservation| {
            if old.intent.request != *request {
                Err(JournalError::Invariant("tree native request collision"))
            } else {
                Ok((None, old))
            }
        };
        let preparation = find()?;
        if let Some(old) = preparation.native_reservation {
            return replay(old).map_err(E::from);
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("cancelled tree native owner").into());
        }
        if max == 0 || max > limits::MAX_ENTRIES {
            return Err(JournalError::Invariant("tree native shared inventory limit").into());
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let preparation = find()?;
        if let Some(old) = preparation.native_reservation {
            let result = replay(old)?;
            tx.commit().map_err(JournalError::from)?;
            return Ok(result);
        }
        if !preparation.writer_gate_held {
            return Err(JournalError::Invariant("tree native owner cancelled").into());
        }
        let history = preparation
            .history_reservation
            .as_ref()
            .ok_or(JournalError::Invariant(
                "tree native requires exact history",
            ))?;
        validate_request(request, &preparation.intent, history, max)?;
        let baseline = self.snapshot(&space, &preparation.intent.scope.baseline_snapshot)?;
        let target = self.snapshot(&space, &preparation.intent.scope.target_snapshot)?;
        let tree = plan_tree_restore(
            &preparation.intent.scope,
            &baseline,
            &target,
            preparation.intent.limits,
        )
        .map_err(JournalError::from)?;
        let (held, inventory) = inspect(&preparation.intent, &tree, &baseline, &target)?;
        let intent = TreeRestoreNativeIntent {
            request: request.clone(),
            inventory,
        };
        let (json, plan, audit) =
            project(&intent, &preparation.intent, history, &tree, &baseline, max)?;
        let aggregate: i64 = tx
            .query_row(
                "SELECT coalesce(sum(binding_count),0) FROM tree_restore_native_reservations",
                [],
                |r| r.get(0),
            )
            .map_err(JournalError::from)?;
        if aggregate < 0
            || (aggregate as u64)
                .checked_add(audit.binding_count as u64)
                .is_none_or(|n| n > max as u64)
        {
            return Err(JournalError::Invariant("tree native aggregate reservation limit").into());
        }
        check_storage_metadata_limit(&tx, max, audit.reserved_rows, audit.reserved_metadata_bytes)?;
        tx.execute(
            "INSERT INTO tree_restore_native_reservations VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                request.transaction_id.as_str(), request.preparation_hash.as_str(),
                request.history_intent_hash.as_str(), request.history_projection_hash.as_str(),
                json, ContentId::hash(json.as_bytes()).as_str(), audit.identity_fingerprint.as_str(),
                sql_integer(request.captured_at_ms)?, sql_integer(audit.binding_count as u64)?,
                sql_integer(audit.reserved_rows)?, sql_integer(audit.reserved_metadata_bytes)?,
            ],
        ).map_err(JournalError::from)?;
        recheck(&held, &plan)?;
        self.audit_gc_owners(&space, max)?;
        let final_audit = find()?.native_reservation.ok_or(JournalError::Invariant(
            "tree native reservation disappeared",
        ))?;
        if final_audit != audit {
            return Err(JournalError::Invariant("tree native changed during inspection").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), final_audit))
    }
}
