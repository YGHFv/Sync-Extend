use crate::{
    check_ancestors,
    fault::checkpoint,
    filesystem::{ObservedFile, PathIdentity},
    LocalSpace, ReconcileError, Result,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use sync_extend_cas::is_reparse;
use sync_extend_core_model::{ChunkRef, ContentId, FileManifest};
use sync_extend_journal::{MutationAction, PublicationState, ReadLeaseState};

#[derive(Debug, Serialize)]
pub struct StorageReport {
    pub accounting: &'static str,
    pub content_hashes_verified: bool,
    pub current_unique_chunk_bytes: u64,
    pub historical_additional_chunk_bytes: u64,
    pub transaction_only_chunk_bytes: u64,
    pub protected_chunk_bytes: u64,
    pub protected_objects: usize,
    pub active_read_leases: usize,
    pub read_lease_unique_chunk_bytes: u64,
    pub durable_read_leases_available: bool,
    pub durable_worker_reservations_available: bool,
    pub worker_reservation_records: usize,
    pub active_worker_reservations: usize,
    pub worker_snapshot_handoff_records: usize,
    pub explicit_local_snapshot_handoff_available: bool,
    pub worker_reservation_unique_chunk_bytes: u64,
    pub worker_reservation_release_available: bool,
    pub tree_restore_preparation_records: usize,
    pub tree_restore_writer_gate_held: bool,
    pub tree_restore_reserved_metadata_bytes: u64,
    pub tree_restore_history_reserved_metadata_bytes: u64,
    pub tree_restore_native_reserved_metadata_bytes: u64,
    pub tree_restore_execution_description_metadata_bytes: u64,
    pub tree_restore_execution_record_description_metadata_bytes: u64,
    pub tree_restore_reserved_worktree_logical_bytes: u64,
    pub tree_restore_input_unique_chunk_bytes: u64,
    pub tree_restore_execution_available: bool,
    pub tree_atomic: bool,
    pub locked_snapshots: usize,
    pub durable_snapshot_locks_available: bool,
    pub missing_protected_objects: usize,
    pub mismatched_protected_lengths: usize,
    pub cas_logical_bytes: u64,
    pub cas_object_paths: usize,
    pub cas_temporary_paths: usize,
    pub unreferenced_cas_objects: usize,
    pub unreferenced_cas_logical_bytes: u64,
    pub internal_worktree_logical_bytes: u64,
    pub internal_worktree_file_paths: usize,
    pub internal_worktree_limit_bytes: u64,
    pub internal_worktree_limit_exceeded: bool,
    pub history_pruning_enabled: bool,
    pub cleanup_enabled: bool,
    pub explicit_move_marker_cleanup_available: bool,
    pub original_disposal_preparation_records: usize,
    pub disposed_original_records: usize,
    pub explicit_original_preparation_available: bool,
    pub original_disposition_executor_available: bool,
    pub gc_enabled: bool,
    pub persistent_gc_marks_available: bool,
    pub gc_mark_records: usize,
    pub guarded_gc_preflight_available: bool,
    pub durable_gc_authorizations_available: bool,
    pub gc_authorization_records: usize,
    pub durable_gc_execution_fences_available: bool,
    pub gc_execution_records: usize,
    pub active_gc_execution_fences: usize,
    pub sweep_available: bool,
    pub gc_quarantine_records: usize,
    pub quarantined_gc_objects: usize,
    pub quarantined_gc_logical_bytes: u64,
    pub explicit_gc_quarantine_available: bool,
    pub gc_disposal_records: usize,
    pub pending_gc_disposals: usize,
    pub explicit_gc_disposal_preparation_available: bool,
    pub disposition_executor_available: bool,
    pub pruned_snapshots: usize,
    pub explicit_snapshot_pruning_available: bool,
    pub remote_backup_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) identity: ContentId,
    pub(crate) length: u64,
    pub(crate) modified: SystemTime,
    directory: bool,
    counted: bool,
    pub(crate) object: Option<ContentId>,
    temporary: bool,
}

pub(crate) type Inventory = BTreeMap<PathBuf, Observation>;

#[derive(Clone, Copy)]
pub(crate) enum Region {
    Worktree,
    Cas,
}

impl LocalSpace {
    pub fn storage_report(&self) -> Result<StorageReport> {
        self.verify_root()?;
        self.journal.integrity_check()?;
        self.journal
            .rename_observation(&self.space_id, self.limits.max_storage_entries)?;
        let gc_authorization_records = self.gc_authorizations()?.len();
        let executions = self.gc_executions()?;
        let quarantines = self.gc_quarantines()?;
        let disposals = self.gc_disposals()?;
        let active_gc_execution_fences = executions.iter().filter(|e| e.content_fenced).count();
        let gc_mark_records = self
            .journal
            .gc_marks(&self.space_id, self.limits.max_storage_entries)?
            .len();
        let pruned_snapshots = self
            .snapshot_audit()?
            .iter()
            .filter(|s| !s.content_retained)
            .count();
        self.journal
            .check_storage_metadata_limit(self.limits.max_storage_entries)?;
        self.journal.cleanup_plans(&self.space_id)?;
        let original_disposals = self
            .journal
            .original_disposals(&self.space_id, self.limits.max_storage_entries)?;
        let original_disposal_preparation_records = original_disposals.len();
        let disposed_original_records = original_disposals
            .iter()
            .filter(|a| a.completed_at_ms.is_some())
            .count();
        let trees = self
            .journal
            .tree_restore_preparations(&self.space_id, self.limits.max_storage_entries)?;
        let tree_restore_reserved_metadata_bytes = trees.iter().try_fold(0u64, |total, p| {
            total
                .checked_add(p.reserved_metadata_bytes)
                .ok_or(ReconcileError::ResourceLimit("tree restore metadata bytes"))
        })?;
        let tree_restore_history_reserved_metadata_bytes = trees
            .iter()
            .filter_map(|p| p.history_reservation.as_ref())
            .try_fold(0u64, |total, h| {
                total
                    .checked_add(h.reserved_metadata_bytes)
                    .ok_or(ReconcileError::ResourceLimit("tree restore history bytes"))
            })?;
        let mut tree_inputs = BTreeSet::new();
        let tree_restore_native_reserved_metadata_bytes = trees
            .iter()
            .filter_map(|p| p.native_reservation.as_ref())
            .try_fold(0u64, |total, n| {
                total
                    .checked_add(n.reserved_metadata_bytes)
                    .ok_or(ReconcileError::ResourceLimit("tree restore native bytes"))
            })?;
        let mut tree_restore_reserved_worktree_logical_bytes = 0;
        let tree_restore_execution_description_metadata_bytes =
            trees
                .iter()
                .filter_map(|p| p.execution_description.as_ref())
                .try_fold(0u64, |total, e| {
                    total.checked_add(e.reserved_metadata_bytes).ok_or(
                        ReconcileError::ResourceLimit("tree execution description bytes"),
                    )
                })?;
        let tree_restore_execution_record_description_metadata_bytes = trees
            .iter()
            .filter_map(|p| p.execution_records.as_ref())
            .try_fold(0u64, |total, records| {
                total
                    .checked_add(records.metadata_bytes)
                    .ok_or(ReconcileError::ResourceLimit(
                        "tree execution record description bytes",
                    ))
            })?;
        let mut refs = References {
            lengths: BTreeMap::new(),
            seen: 0,
            limit: self.limits.max_storage_entries,
        };
        let mut current = BTreeSet::new();
        if let Some(manifest) = self.manifest()? {
            for content in manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
            {
                refs.add(content, &mut current)?;
            }
        }
        let mut retained = current.clone();
        let snapshots = self
            .journal
            .retained_snapshots(&self.space_id, self.limits.max_storage_entries)?;
        let locked_snapshots = snapshots.iter().filter(|s| s.locked).count();
        for snapshot in snapshots {
            for content in snapshot
                .manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
            {
                refs.add(content, &mut retained)?;
            }
        }
        for preparation in trees.iter().filter(|p| p.writer_gate_held) {
            tree_restore_reserved_worktree_logical_bytes = preparation.retained_and_staging_bytes;
            for root in [
                &preparation.intent.scope.baseline_snapshot,
                &preparation.intent.scope.target_snapshot,
            ] {
                let snapshot = self.journal.retained_snapshot(&self.space_id, root)?;
                for content in snapshot
                    .manifest
                    .entries
                    .values()
                    .filter_map(|e| e.content.as_ref())
                {
                    refs.add(content, &mut tree_inputs)?;
                }
            }
        }
        let mut expected = retained.clone();
        let mut leased = BTreeSet::new();
        let mut active_read_leases = 0;
        for lease in self
            .journal
            .read_leases(&self.space_id, self.limits.max_storage_entries)?
        {
            if lease.state == ReadLeaseState::Active {
                active_read_leases += 1;
                refs.add(
                    lease
                        .intent
                        .entry
                        .content
                        .as_ref()
                        .ok_or(ReconcileError::Invariant("read lease content missing"))?,
                    &mut leased,
                )?;
            }
        }
        expected.extend(leased.iter().cloned());
        let owners = self.reference_reservations()?;
        let worker_reservation_records = owners.len();
        let worker_snapshot_handoff_records = owners
            .iter()
            .filter(|o| o.snapshot_handoff.is_some())
            .count();
        let active_worker_reservations =
            worker_reservation_records - worker_snapshot_handoff_records;
        let mut reserved = BTreeSet::new();
        for owner in owners {
            if owner.snapshot_handoff.is_none() {
                for file in &owner.intent.scope.files {
                    refs.add(file, &mut reserved)?;
                }
            }
        }
        expected.extend(reserved.iter().cloned());
        for mutation in self.journal.mutations(&self.space_id)? {
            self.journal
                .verify_mutation_references(&mutation.intent.transaction_id)?;
            if mutation.state.active() {
                if let Some(content) = &mutation.intent.baseline_entry.content {
                    refs.add(content, &mut expected)?;
                }
                if let MutationAction::Replace { content } = &mutation.intent.action {
                    refs.add(content, &mut expected)?;
                }
            }
        }
        for publication in self.journal.outstanding_publications(&self.space_id)? {
            if publication.state != PublicationState::Committed {
                refs.add(&publication.intent.content, &mut expected)?;
            }
        }
        let protected: BTreeSet<_> = self.journal.protected_objects()?.into_iter().collect();
        if expected != protected {
            return Err(ReconcileError::Invariant(
                "storage reference protection mismatch",
            ));
        }
        let cas = self.storage_inventory(Region::Cas)?;
        let worktree = self.storage_inventory(Region::Worktree)?;
        let objects: BTreeMap<_, _> = cas
            .values()
            .filter_map(|entry| entry.object.as_ref().map(|id| (id.clone(), entry.length)))
            .collect();
        let mut unreferenced = BTreeSet::new();
        for id in objects.keys() {
            if !protected.contains(id) {
                unreferenced.insert(id.clone());
            }
        }
        let internal = inventory_bytes(&worktree)?;
        let quarantine_files: BTreeSet<_> = quarantines
            .iter()
            .map(|q| {
                self.data_dir
                    .join("cas/tmp")
                    .join(format!("gc-{}.object", q.intent.plan_id))
            })
            .collect();
        let quarantined_gc_objects = cas
            .iter()
            .filter(|(path, e)| quarantine_files.contains(*path) && !e.directory)
            .count();
        let quarantine_identities: BTreeSet<_> = cas
            .iter()
            .filter(|(path, _)| quarantine_files.contains(*path))
            .map(|(_, e)| e.identity.clone())
            .collect();
        let quarantined_gc_logical_bytes =
            selected_inventory_bytes(&cas, |e| quarantine_identities.contains(&e.identity))?;
        Ok(StorageReport {
            tree_restore_preparation_records: trees.len(),
            tree_restore_writer_gate_held: trees.iter().any(|p| p.writer_gate_held),
            tree_restore_reserved_metadata_bytes,
            tree_restore_history_reserved_metadata_bytes,
            tree_restore_native_reserved_metadata_bytes,
            tree_restore_execution_description_metadata_bytes,
            tree_restore_execution_record_description_metadata_bytes,
            tree_restore_reserved_worktree_logical_bytes,
            tree_restore_input_unique_chunk_bytes: refs.bytes(tree_inputs.iter())?,
            tree_restore_execution_available: false,
            tree_atomic: false,
            original_disposal_preparation_records,
            disposed_original_records,
            explicit_original_preparation_available: cfg!(windows),
            original_disposition_executor_available: cfg!(windows),
            accounting: "physical_identity_deduplicated_logical_lengths_not_allocated_blocks",
            content_hashes_verified: false,
            current_unique_chunk_bytes: refs.bytes(current.iter())?,
            historical_additional_chunk_bytes: refs.bytes(retained.difference(&current))?,
            transaction_only_chunk_bytes: refs.bytes(expected.difference(&retained))?,
            protected_chunk_bytes: refs.bytes(expected.iter())?,
            protected_objects: protected.len(),
            durable_worker_reservations_available: true,
            worker_reservation_records,
            active_worker_reservations,
            worker_snapshot_handoff_records,
            explicit_local_snapshot_handoff_available: true,
            worker_reservation_unique_chunk_bytes: refs.bytes(reserved.iter())?,
            worker_reservation_release_available: false,
            active_read_leases,
            read_lease_unique_chunk_bytes: refs.bytes(leased.iter())?,
            durable_read_leases_available: true,
            locked_snapshots,
            durable_snapshot_locks_available: true,
            missing_protected_objects: protected
                .iter()
                .filter(|id| !objects.contains_key(*id))
                .count(),
            mismatched_protected_lengths: protected
                .iter()
                .filter(|id| {
                    objects
                        .get(*id)
                        .is_some_and(|length| Some(length) != refs.lengths.get(*id))
                })
                .count(),
            cas_logical_bytes: inventory_bytes(&cas)?,
            cas_object_paths: objects.len(),
            cas_temporary_paths: cas
                .values()
                .filter(|entry| !entry.directory && entry.temporary)
                .count(),
            unreferenced_cas_objects: unreferenced.len(),
            unreferenced_cas_logical_bytes: selected_inventory_bytes(&cas, |entry| {
                entry
                    .object
                    .as_ref()
                    .is_some_and(|id| unreferenced.contains(id))
            })?,
            internal_worktree_logical_bytes: internal,
            internal_worktree_file_paths: worktree
                .values()
                .filter(|entry| entry.counted && !entry.directory)
                .count(),
            internal_worktree_limit_bytes: self.limits.max_internal_worktree_bytes,
            internal_worktree_limit_exceeded: internal > self.limits.max_internal_worktree_bytes,
            history_pruning_enabled: false,
            cleanup_enabled: false,
            explicit_move_marker_cleanup_available: cfg!(windows),
            gc_enabled: false,
            persistent_gc_marks_available: true,
            gc_mark_records,
            guarded_gc_preflight_available: cfg!(windows),
            durable_gc_authorizations_available: cfg!(windows),
            gc_authorization_records,
            durable_gc_execution_fences_available: cfg!(windows),
            gc_execution_records: executions.len(),
            active_gc_execution_fences,
            sweep_available: false,
            gc_quarantine_records: quarantines.len(),
            quarantined_gc_objects,
            quarantined_gc_logical_bytes,
            explicit_gc_quarantine_available: cfg!(windows),
            gc_disposal_records: disposals.len(),
            pending_gc_disposals: disposals.iter().filter(|d| d.content_fenced).count(),
            explicit_gc_disposal_preparation_available: cfg!(windows),
            disposition_executor_available: cfg!(windows),
            pruned_snapshots,
            explicit_snapshot_pruning_available: true,
            remote_backup_complete: false,
        })
    }

    pub(crate) fn reserve_internal_worktree(&self, additional: u64) -> Result<()> {
        let inventory = self.storage_inventory(Region::Worktree)?;
        if inventory_bytes(&inventory)?
            .checked_add(additional)
            .is_none_or(|bytes| bytes > self.limits.max_internal_worktree_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "aggregate internal worktree bytes",
            ));
        }
        checkpoint("after_internal_storage_admission");
        Ok(())
    }

    pub(crate) fn storage_inventory(&self, region: Region) -> Result<Inventory> {
        let root = match region {
            Region::Worktree => self.worktree.clone(),
            Region::Cas => self.data_dir.join("cas"),
        };
        let pass = || {
            self.verify_root()?;
            let mut inventory = BTreeMap::new();
            visit(
                &root,
                &root,
                region,
                false,
                0,
                self.limits.max_storage_entries,
                &mut inventory,
            )?;
            self.verify_root()?;
            Ok::<_, ReconcileError>(inventory)
        };
        let first = pass()?;
        checkpoint(match region {
            Region::Worktree => "after_internal_storage_inventory",
            Region::Cas => "after_cas_storage_inventory",
        });
        let second = pass()?;
        if first != second {
            return Err(ReconcileError::Unstable);
        }
        Ok(second)
    }
}

struct References {
    lengths: BTreeMap<ContentId, u64>,
    seen: usize,
    limit: usize,
}

impl References {
    fn add(&mut self, content: &FileManifest, set: &mut BTreeSet<ContentId>) -> Result<()> {
        content.validate()?;
        for ChunkRef { content_id, length } in &content.chunks {
            self.seen = self
                .seen
                .checked_add(1)
                .filter(|seen| *seen <= self.limit)
                .ok_or(ReconcileError::ResourceLimit("storage reference count"))?;
            let length = u64::from(*length);
            if self
                .lengths
                .insert(content_id.clone(), length)
                .is_some_and(|old| old != length)
            {
                return Err(ReconcileError::Invariant(
                    "conflicting protected chunk lengths",
                ));
            }
            set.insert(content_id.clone());
        }
        Ok(())
    }

    fn bytes<'a>(&self, ids: impl Iterator<Item = &'a ContentId>) -> Result<u64> {
        sum_lengths(ids, &self.lengths)
    }
}

fn sum_lengths<'a>(
    mut ids: impl Iterator<Item = &'a ContentId>,
    lengths: &BTreeMap<ContentId, u64>,
) -> Result<u64> {
    ids.try_fold(0u64, |sum, id| {
        sum.checked_add(
            *lengths
                .get(id)
                .ok_or(ReconcileError::Invariant("missing storage length"))?,
        )
        .ok_or(ReconcileError::ResourceLimit("storage byte overflow"))
    })
}

fn inventory_bytes(inventory: &Inventory) -> Result<u64> {
    selected_inventory_bytes(inventory, |_| true)
}

fn selected_inventory_bytes(
    inventory: &Inventory,
    select: impl Fn(&Observation) -> bool,
) -> Result<u64> {
    let mut lengths = BTreeMap::new();
    for entry in inventory
        .values()
        .filter(|entry| entry.counted && !entry.directory && select(entry))
    {
        if lengths
            .insert(entry.identity.clone(), entry.length)
            .is_some_and(|old| old != entry.length)
        {
            return Err(ReconcileError::Unstable);
        }
    }
    sum_lengths(lengths.keys(), &lengths)
}

fn visit(
    root: &Path,
    path: &Path,
    region: Region,
    internal: bool,
    depth: usize,
    limit: usize,
    inventory: &mut Inventory,
) -> Result<()> {
    if inventory.len() >= limit || depth > 160 {
        return Err(ReconcileError::ResourceLimit(
            "storage inventory entries/depth",
        ));
    }
    check_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err(ReconcileError::Invariant("unsafe storage inventory path"));
    }
    let identity = PathIdentity::capture(path)?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ReconcileError::Invariant("storage root escaped"))?;
    let parts: Vec<_> = relative.iter().collect();
    let mut object = None;
    let temporary = matches!(region, Region::Cas) && parts.first().is_some_and(|p| *p == "tmp");
    if matches!(region, Region::Cas)
        && (!parts.is_empty()
            && !parts
                .first()
                .is_some_and(|p| *p == "objects" || *p == "tmp")
            || parts.len() == 1 && !metadata.is_dir()
            || temporary && (parts.len() > 2 || parts.len() == 2 && !metadata.is_file()))
    {
        return Err(ReconcileError::Invariant(
            "unknown CAS storage directory layout",
        ));
    }
    if matches!(region, Region::Cas) && parts.first().is_some_and(|p| *p == "objects") {
        if metadata.is_dir() {
            if parts.len() > 2
                || (parts.len() == 2
                    && !parts[1]
                        .to_str()
                        .is_some_and(|name| name.len() == 2 && lower_hex(name)))
            {
                return Err(ReconcileError::Invariant("unsafe CAS storage layout"));
            }
        } else {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ReconcileError::Invariant("invalid CAS object name"))?;
            if parts.len() != 3
                || name.len() != 64
                || !lower_hex(name)
                || parts[1].to_str() != Some(&name[..2])
            {
                return Err(ReconcileError::Invariant("invalid CAS object layout"));
            }
            object = Some(name.parse()?);
        }
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(ReconcileError::Invariant("unsupported storage entry type"));
    }
    inventory.insert(
        path.to_owned(),
        Observation {
            identity: identity.physical.clone(),
            length: if metadata.is_dir() { 0 } else { metadata.len() },
            modified: metadata.modified()?,
            directory: metadata.is_dir(),
            counted: matches!(region, Region::Cas) || internal,
            object,
            temporary,
        },
    );
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            if matches!(region, Region::Worktree)
                && !internal
                && name.to_str().is_some_and(|name| {
                    name.eq_ignore_ascii_case(".git") || name.eq_ignore_ascii_case(".sync-extend")
                })
            {
                continue;
            }
            let internal = internal
                || (matches!(region, Region::Worktree)
                    && name
                        .to_str()
                        .is_some_and(|name| name.eq_ignore_ascii_case(".sync-tmp")));
            visit(
                root,
                &entry.path(),
                region,
                internal,
                depth + 1,
                limit,
                inventory,
            )?;
        }
    } else {
        let observed = ObservedFile::open(path)?;
        if observed.identity.physical != identity.physical
            || observed.metadata.len() != metadata.len()
            || observed.metadata.modified()? != metadata.modified()?
        {
            return Err(ReconcileError::Unstable);
        }
        observed.verify(path)?;
    }
    identity.verify(path)?;
    if metadata.modified()? != fs::symlink_metadata(path)?.modified()? {
        return Err(ReconcileError::Unstable);
    }
    Ok(())
}

fn lower_hex(name: &str) -> bool {
    name.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
