use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{config::HistoryPolicy, ContentId, SnapshotId};
use sync_extend_journal::{ReadLeaseState, RetainedSnapshot};

#[derive(Debug, Serialize)]
pub struct SnapshotLockResult {
    pub snapshot_id: SnapshotId,
    pub locked: bool,
    pub history_pruning_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct SnapshotRetention {
    pub snapshot_id: SnapshotId,
    pub created_at_ms: u64,
    pub locked: bool,
    pub current: bool,
    pub proposed_retained: bool,
    pub protection_reasons: BTreeSet<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct RetentionReport {
    pub accounting: &'static str,
    pub proposal_only: bool,
    pub content_hashes_verified: bool,
    pub policy: HistoryPolicy,
    pub snapshots: Vec<SnapshotRetention>,
    pub retained_historical_snapshots: usize,
    pub proposed_historical_snapshots: usize,
    pub historical_additional_chunk_bytes: u64,
    pub proposed_historical_additional_chunk_bytes: u64,
    pub snapshot_only_potential_unreferenced_chunk_bytes: u64,
    pub candidate_snapshots: Vec<SnapshotId>,
    pub count_target_exceeded: bool,
    pub budget_target_exceeded: bool,
    pub ordering_blockers: Vec<&'static str>,
    pub execution_blockers: Vec<&'static str>,
    pub durable_snapshot_locks_available: bool,
    pub history_pruning_enabled: bool,
    pub gc_enabled: bool,
    pub pruned_snapshots: usize,
    pub explicit_snapshot_pruning_available: bool,
}

impl LocalSpace {
    pub fn lock_snapshot(&mut self, id: &SnapshotId) -> Result<SnapshotLockResult> {
        self.verify_root()?;
        self.journal
            .check_storage_metadata_limit(self.limits.max_storage_entries)?;
        let snapshot = self.journal.retained_snapshot(&self.space_id, id)?;
        if snapshot.state != "materialized" {
            return Err(ReconcileError::Invariant("snapshot is not materialized"));
        }
        if snapshot.manifest.entries.len() > self.limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit("snapshot lock entry budget"));
        }
        let mut bytes = 0u64;
        let mut chunks = 0usize;
        for content in snapshot
            .manifest
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
        {
            bytes = bytes
                .checked_add(content.length)
                .ok_or(ReconcileError::ResourceLimit("snapshot lock byte overflow"))?;
            chunks =
                chunks
                    .checked_add(content.chunks.len())
                    .ok_or(ReconcileError::ResourceLimit(
                        "snapshot lock reference overflow",
                    ))?;
            if content.length > self.limits.max_file_bytes
                || bytes > self.limits.max_scan_bytes
                || chunks > self.limits.max_scan_chunks
            {
                return Err(ReconcileError::ResourceLimit(
                    "snapshot lock content budget",
                ));
            }
        }
        checkpoint("before_snapshot_lock");
        for content in snapshot
            .manifest
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
        {
            self.cas.verify(content)?;
        }
        self.verify_root()?;
        let snapshot = self.journal.set_snapshot_locked(&self.space_id, id, true)?;
        checkpoint("after_snapshot_lock");
        Ok(SnapshotLockResult {
            snapshot_id: snapshot.snapshot_id,
            locked: snapshot.locked,
            history_pruning_enabled: false,
        })
    }

    pub fn unlock_snapshot(&mut self, id: &SnapshotId) -> Result<SnapshotLockResult> {
        self.verify_root()?;
        checkpoint("before_snapshot_unlock");
        let snapshot = self
            .journal
            .set_snapshot_locked(&self.space_id, id, false)?;
        checkpoint("after_snapshot_unlock");
        Ok(SnapshotLockResult {
            snapshot_id: snapshot.snapshot_id,
            locked: snapshot.locked,
            history_pruning_enabled: false,
        })
    }

    pub fn retention_report(&self, policy: HistoryPolicy) -> Result<RetentionReport> {
        self.verify_root()?;
        self.journal.integrity_check()?;
        let pruned_snapshots = self
            .snapshot_audit()?
            .iter()
            .filter(|s| !s.content_retained)
            .count();
        if policy.deleted_min_retention_days != 0 {
            return Err(ReconcileError::Invariant(
                "minimum-days retention is not implemented",
            ));
        }
        let snapshots = self
            .journal
            .retained_snapshots(&self.space_id, self.limits.max_storage_entries)?;
        let by_id: BTreeMap<_, _> = snapshots.iter().map(|s| (&s.snapshot_id, s)).collect();
        let mut reasons: BTreeMap<_, BTreeSet<_>> = snapshots
            .iter()
            .map(|snapshot| {
                let mut reasons = BTreeSet::new();
                if snapshot.locked {
                    reasons.insert("user_locked");
                }
                if snapshot.state != "materialized" {
                    reasons.insert("not_materialized");
                }
                (snapshot.snapshot_id.clone(), reasons)
            })
            .collect();
        self.journal.cleanup_plans(&self.space_id)?;
        for lease in self
            .journal
            .read_leases(&self.space_id, self.limits.max_storage_entries)?
        {
            protect(
                &mut reasons,
                &lease.intent.snapshot_id,
                if lease.state == ReadLeaseState::Active {
                    "active_read_lease"
                } else {
                    "read_lease_audit_dependency"
                },
            )?;
        }
        for mutation in self.journal.mutations(&self.space_id)? {
            self.journal
                .verify_mutation_references(&mutation.intent.transaction_id)?;
            protect(
                &mut reasons,
                &mutation.intent.baseline_root,
                "mutation_baseline_dependency",
            )?;
            if let Some(id) = &mutation.committed_snapshot {
                protect(&mut reasons, id, "mutation_completion_dependency")?;
            }
        }
        for publication in self
            .journal
            .publications(&self.space_id, self.limits.max_storage_entries)?
        {
            let intent = &publication.intent;
            let baseline = by_id
                .get(&intent.baseline_root)
                .ok_or(ReconcileError::Invariant("publication baseline missing"))?;
            if baseline
                .manifest
                .entries
                .values()
                .find(|e| e.path == intent.requested_path)
                != intent.requested_baseline.as_ref()
                || baseline.manifest.entries.contains_key(&intent.entry_id)
            {
                return Err(ReconcileError::Invariant("publication baseline mismatch"));
            }
            protect(
                &mut reasons,
                &intent.baseline_root,
                "publication_baseline_dependency",
            )?;
            if let Some(id) = &intent.source_snapshot {
                let source = by_id
                    .get(id)
                    .ok_or(ReconcileError::Invariant("publication source missing"))?;
                if !source
                    .manifest
                    .entries
                    .values()
                    .any(|e| e.content.as_ref() == Some(&intent.content))
                {
                    return Err(ReconcileError::Invariant("publication source mismatch"));
                }
                protect(&mut reasons, id, "publication_source_dependency")?;
            }
            if let Some(id) = &publication.committed_snapshot {
                let completed = by_id
                    .get(id)
                    .ok_or(ReconcileError::Invariant("publication completion missing"))?;
                let entry = completed.manifest.entries.get(&intent.entry_id).ok_or(
                    ReconcileError::Invariant("publication completed entry missing"),
                )?;
                if entry.path != intent.target_path
                    || entry.content.as_ref() != Some(&intent.content)
                {
                    return Err(ReconcileError::Invariant("publication completion mismatch"));
                }
                protect(&mut reasons, id, "publication_completion_dependency")?;
            }
        }
        let current = self.manifest()?.map(|m| m.root()).transpose()?;
        if let Some(id) = &current {
            protect(&mut reasons, id, "current")?;
        } else if !snapshots.is_empty() {
            return Err(ReconcileError::Invariant(
                "retained history has no current snapshot",
            ));
        }
        let mut report = proposal(
            snapshots,
            current,
            reasons,
            policy,
            self.limits.max_storage_entries,
        )?;
        report.pruned_snapshots = pruned_snapshots;
        self.verify_root()?;
        Ok(report)
    }
}

fn protect(
    reasons: &mut BTreeMap<SnapshotId, BTreeSet<&'static str>>,
    id: &SnapshotId,
    reason: &'static str,
) -> Result<()> {
    reasons
        .get_mut(id)
        .ok_or(ReconcileError::Invariant("snapshot dependency missing"))?
        .insert(reason);
    Ok(())
}

fn proposal(
    snapshots: Vec<RetainedSnapshot>,
    current: Option<SnapshotId>,
    reasons: BTreeMap<SnapshotId, BTreeSet<&'static str>>,
    policy: HistoryPolicy,
    limit: usize,
) -> Result<RetentionReport> {
    let mut lengths = BTreeMap::<ContentId, u64>::new();
    let mut refs = BTreeMap::<SnapshotId, BTreeSet<ContentId>>::new();
    let by_id: BTreeMap<_, _> = snapshots.iter().map(|s| (&s.snapshot_id, s)).collect();
    let mut visits = 0usize;
    let mut ordered = Vec::new();
    for snapshot in &snapshots {
        let mut ids = BTreeSet::new();
        for chunk in snapshot
            .manifest
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .flat_map(|content| &content.chunks)
        {
            visits = visits
                .checked_add(1)
                .filter(|n| *n <= limit)
                .ok_or(ReconcileError::ResourceLimit("retention reference count"))?;
            if lengths
                .insert(chunk.content_id.clone(), u64::from(chunk.length))
                .is_some_and(|old| old != u64::from(chunk.length))
            {
                return Err(ReconcileError::Invariant(
                    "conflicting retention chunk lengths",
                ));
            }
            ids.insert(chunk.content_id.clone());
        }
        refs.insert(snapshot.snapshot_id.clone(), ids);
        let rank = snapshot
            .manifest
            .version_vector
            .0
            .values()
            .try_fold(0u64, |sum, seq| sum.checked_add(*seq))
            .ok_or(ReconcileError::ResourceLimit(
                "snapshot causal rank overflow",
            ))?;
        ordered.push((
            rank,
            &snapshot.snapshot_id,
            &snapshot.manifest.version_vector,
        ));
    }
    ordered.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let mut ordering_blockers = Vec::new();
    if ordered
        .windows(2)
        .any(|pair| pair[1].2 == pair[0].2 || !pair[1].2.dominates(pair[0].2))
    {
        ordering_blockers.push("snapshot_history_is_not_a_strict_causal_chain");
    }
    if current.as_ref() != ordered.last().map(|s| s.1) {
        ordering_blockers.push("current_snapshot_is_not_causal_tip");
    }
    let current_refs = current
        .as_ref()
        .and_then(|id| refs.get(id))
        .cloned()
        .unwrap_or_default();
    let all: BTreeSet<_> = refs.values().flat_map(|set| set.iter().cloned()).collect();
    let bytes = |ids: &BTreeSet<ContentId>| -> Result<u64> {
        ids.difference(&current_refs).try_fold(0u64, |sum, id| {
            sum.checked_add(
                *lengths
                    .get(id)
                    .ok_or(ReconcileError::Invariant("retention chunk length missing"))?,
            )
            .ok_or(ReconcileError::ResourceLimit("retention byte overflow"))
        })
    };
    let historical: Vec<_> = ordered
        .iter()
        .map(|s| s.1)
        .filter(|id| Some(*id) != current.as_ref())
        .collect();
    let mut selected: BTreeSet<_> = reasons
        .iter()
        .filter(|(_, set)| !set.is_empty())
        .map(|(id, _)| id.clone())
        .collect();
    selected.extend(
        historical
            .iter()
            .rev()
            .take(policy.history_snapshots as usize)
            .map(|id| (*id).clone()),
    );
    if !ordering_blockers.is_empty() {
        selected.extend(refs.keys().cloned());
    }
    let mut ref_counts = BTreeMap::<ContentId, usize>::new();
    for id in &selected {
        for chunk in &refs[id] {
            *ref_counts.entry(chunk.clone()).or_default() += 1;
        }
    }
    let mut proposed_refs: BTreeSet<_> = ref_counts.keys().cloned().collect();
    let mut projected = bytes(&proposed_refs)?;
    // Remove oldest eligible histories; shared chunks remain until the last selected owner leaves.
    if ordering_blockers.is_empty() {
        for id in &historical {
            if projected <= policy.history_budget_bytes {
                break;
            }
            if !selected.contains(*id) || !reasons[*id].is_empty() {
                continue;
            }
            selected.remove(*id);
            for chunk in &refs[*id] {
                let n = ref_counts
                    .get_mut(chunk)
                    .ok_or(ReconcileError::Invariant("retention owner missing"))?;
                *n -= 1;
                if *n == 0 {
                    proposed_refs.remove(chunk);
                    if !current_refs.contains(chunk) {
                        projected = projected
                            .checked_sub(lengths[chunk])
                            .ok_or(ReconcileError::Invariant("retention byte underflow"))?;
                    }
                }
            }
        }
    }
    let history_bytes = bytes(&all)?;
    let proposed_count = selected
        .iter()
        .filter(|id| Some(*id) != current.as_ref())
        .count();
    let candidates = historical
        .iter()
        .filter(|id| !selected.contains(**id))
        .map(|id| (*id).clone())
        .collect();
    let report_snapshots = ordered
        .iter()
        .map(|(_, id, _)| {
            let snapshot = by_id[*id];
            SnapshotRetention {
                snapshot_id: (*id).clone(),
                created_at_ms: snapshot.created_at_ms,
                locked: snapshot.locked,
                current: Some(*id) == current.as_ref(),
                proposed_retained: selected.contains(*id),
                protection_reasons: reasons[*id].clone(),
            }
        })
        .collect();
    Ok(RetentionReport {
        accounting: "unique_snapshot_chunk_logical_lengths_minus_current_not_allocated_blocks",
        proposal_only: true,
        content_hashes_verified: false,
        retained_historical_snapshots: historical.len(),
        proposed_historical_snapshots: proposed_count,
        historical_additional_chunk_bytes: history_bytes,
        proposed_historical_additional_chunk_bytes: projected,
        snapshot_only_potential_unreferenced_chunk_bytes: history_bytes
            .checked_sub(projected)
            .ok_or(ReconcileError::Invariant("retention delta underflow"))?,
        candidate_snapshots: candidates,
        count_target_exceeded: proposed_count > policy.history_snapshots as usize,
        budget_target_exceeded: projected > policy.history_budget_bytes,
        policy,
        snapshots: report_snapshots,
        ordering_blockers,
        execution_blockers: vec![
            "automatic_retention_and_terminal_audit_decoupling_not_implemented",
            "conflict_offline_transfer_protection_not_implemented",
            "gc_sweep_and_deletion_authorization_not_implemented",
        ],
        durable_snapshot_locks_available: true,
        history_pruning_enabled: false,
        gc_enabled: false,
        pruned_snapshots: 0,
        explicit_snapshot_pruning_available: true,
    })
}
