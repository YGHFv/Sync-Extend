use crate::{
    storage_inventory::reader::invalid, CleanupPlan, GcDisposalAudit, GcExecutionAudit,
    GcMarkAudit, GcQuarantineAudit, JournalReadView, JournalStoredTable, Mutation,
    OriginalDisposalAudit, Publication, ReadLease, ReferenceReservation, Result, SnapshotAudit,
    TreeRestorePreparation,
};
use sync_extend_core_model::{DeviceId, SpaceId};

pub(super) struct Owners {
    pub snapshots: Vec<SnapshotAudit>,
    pub leases: Vec<ReadLease>,
    pub mutations: Vec<Mutation>,
    pub publications: Vec<Publication>,
    pub cleanup: Vec<CleanupPlan>,
    pub references: Vec<ReferenceReservation>,
    pub originals: Vec<OriginalDisposalAudit>,
    pub marks: Vec<GcMarkAudit>,
    pub executions: Vec<GcExecutionAudit>,
    pub quarantines: Vec<GcQuarantineAudit>,
    pub disposals: Vec<GcDisposalAudit>,
    pub trees: Vec<TreeRestorePreparation>,
}

pub(super) fn owners(view: &JournalReadView<'_>, space: &SpaceId, max: usize) -> Result<Owners> {
    if view.state("space_id")?.as_deref() != Some(space.as_str()) {
        return Err(invalid("journal capacity space mismatch"));
    }
    let _: DeviceId = view
        .state("device_id")?
        .ok_or(invalid("journal capacity device missing"))?
        .parse()?;
    ordinary_scope(view, space)?;
    typed_owners(view, space, max)
}

pub(super) fn lease_owners(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    max: usize,
    tables: &[JournalStoredTable],
) -> Result<Owners> {
    if view.state("space_id")?.is_some() {
        return owners(view, space, max);
    }
    // Trusted standalone snapshots predate initialize. This compatibility
    // contract admits no identity row or unsupported owner, not an audit bypass.
    const IDENTITYLESS_LEASE_TABLES: &[&str] = &[
        "operations",
        "receive_cursors",
        "snapshots",
        "current_manifests",
        "snapshot_objects",
        "read_lease_clock",
        "read_leases",
        "read_lease_objects",
    ];
    if tables
        .iter()
        .any(|table| table.rows != 0 && !IDENTITYLESS_LEASE_TABLES.contains(&table.table))
    {
        return Err(invalid(
            "identityless lease inventory contains unsupported owner",
        ));
    }
    identityless_snapshots(view, space, max)
}

pub(super) fn history_owners(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    max: usize,
    tables: &[JournalStoredTable],
) -> Result<Owners> {
    if view.state("space_id")?.is_some() {
        return owners(view, space, max);
    }
    const IDENTITYLESS_HISTORY_TABLES: &[&str] = &[
        "operations",
        "receive_cursors",
        "snapshots",
        "current_manifests",
        "snapshot_objects",
        "snapshot_prunings",
        "read_lease_clock",
        "read_leases",
        "read_lease_objects",
    ];
    if tables
        .iter()
        .any(|table| table.rows != 0 && !IDENTITYLESS_HISTORY_TABLES.contains(&table.table))
    {
        return Err(invalid(
            "identityless history inventory contains unsupported owner",
        ));
    }
    identityless_snapshots(view, space, max)
}

pub(super) fn receive_owners(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    max: usize,
    tables: &[JournalStoredTable],
) -> Result<Owners> {
    if view.state("space_id")?.is_some() {
        if view.state("worktree")?.is_none() {
            return Err(invalid("receive initialized worktree identity missing"));
        }
        return owners(view, space, max);
    }
    const IDENTITYLESS_RECEIVE_TABLES: &[&str] = &[
        "operations",
        "receive_cursors",
        "snapshots",
        "current_manifests",
        "snapshot_objects",
        "snapshot_prunings",
        "read_lease_clock",
        "read_leases",
        "read_lease_objects",
    ];
    if tables
        .iter()
        .any(|table| table.rows != 0 && !IDENTITYLESS_RECEIVE_TABLES.contains(&table.table))
    {
        return Err(invalid(
            "identityless receive inventory contains unsupported owner",
        ));
    }
    identityless_snapshots(view, space, max)
}

pub(super) fn local_commit_owners(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    max: usize,
    tables: &[JournalStoredTable],
) -> Result<Owners> {
    if view.state("space_id")?.is_some() && view.state("worktree")?.is_none() {
        return Err(invalid(
            "local commit initialized worktree identity missing",
        ));
    }
    if view.state("space_id")?.is_some() {
        return owners(view, space, max);
    }
    const IDENTITYLESS_LOCAL_COMMIT_TABLES: &[&str] = &[
        "operations",
        "receive_cursors",
        "snapshots",
        "current_manifests",
        "snapshot_objects",
        "snapshot_prunings",
        "read_lease_clock",
        "read_leases",
        "read_lease_objects",
        "mutations",
    ];
    if tables
        .iter()
        .any(|table| table.rows != 0 && !IDENTITYLESS_LOCAL_COMMIT_TABLES.contains(&table.table))
    {
        return Err(invalid(
            "identityless local commit contains unsupported owner",
        ));
    }
    let mut audited = identityless_snapshots(view, space, max)?;
    audited.mutations = view.mutations(space)?;
    for mutation in &audited.mutations {
        if mutation.state != crate::MutationState::Cancelled {
            return Err(invalid(
                "identityless local commit requires cancelled mutations",
            ));
        }
        view.verify_mutation_references(&mutation.intent.transaction_id)?;
    }
    Ok(audited)
}

pub(super) fn storage_receive_owners(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    max: usize,
    tables: &[JournalStoredTable],
) -> Result<Owners> {
    if view.state("space_id")?.as_deref() != Some(space.as_str())
        || view.state("device_id")?.is_none()
        || view.state("worktree")?.is_some()
        || view.state("storage_role")?.as_deref() != Some("storage-v1")
    {
        return Err(invalid(
            "storage receive requires exact worktree-free initialized identity",
        ));
    }
    let keys: Vec<String> = view
        .connection
        .prepare("SELECT key FROM main.local_state ORDER BY key")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    if keys != ["device_id", "space_id", "storage_role"] {
        return Err(invalid("storage receive exact role identity keys"));
    }
    // No client mutation owner may be accepted through the storage-only adapter.
    const STORAGE_TABLES: &[&str] = &[
        "local_state",
        // Migration 008 creates this singleton even without a lease owner.
        // ordinary::liabilities still audits its exact singleton inventory.
        "read_lease_clock",
        "operations",
        "receive_cursors",
        "original_operation_provenance",
        "storage_page_handoffs",
        "reference_reservations",
        "reference_reservation_objects",
        "cas_leases",
    ];
    if tables
        .iter()
        .any(|table| table.rows != 0 && !STORAGE_TABLES.contains(&table.table))
    {
        return Err(invalid("storage receive contains client/native owner"));
    }
    owners(view, space, max)
}

fn identityless_snapshots(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    max: usize,
) -> Result<Owners> {
    ordinary_scope(view, space)?;
    let snapshots = view.snapshot_audit(space)?;
    view.current(space)?;
    view.diagnostic_operation_count(space, max)?;
    let leases = view.read_leases(space)?;
    Ok(Owners {
        snapshots,
        leases,
        mutations: Vec::new(),
        publications: Vec::new(),
        cleanup: Vec::new(),
        references: Vec::new(),
        originals: Vec::new(),
        marks: Vec::new(),
        executions: Vec::new(),
        quarantines: Vec::new(),
        disposals: Vec::new(),
        trees: Vec::new(),
    })
}

fn ordinary_scope(view: &JournalReadView<'_>, space: &SpaceId) -> Result<()> {
    let foreign = [
        "operations",
        "receive_cursors",
        "snapshots",
        "current_manifests",
        "mutations",
        "publications",
        "cleanup_plans",
        "read_leases",
        "snapshot_prunings",
        "gc_marks",
        "reference_reservations",
        "original_disposals",
        "rename_observations",
        "original_operation_provenance",
        "original_page_inbox",
        "forwarded_page_inbox",
        "storage_page_handoffs",
    ]
    .into_iter()
    .map(|table| format!("EXISTS(SELECT 1 FROM main.{table} WHERE space_id!=?1)"))
    .collect::<Vec<_>>()
    .join(" OR ");
    if view
        .connection
        .query_row(&format!("SELECT {foreign}"), [space.as_str()], |r| {
            r.get::<_, bool>(0)
        })?
    {
        return Err(invalid("journal capacity foreign ordinary row"));
    }
    let mut foreign_keys = view.connection.prepare("PRAGMA main.foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(invalid("journal capacity orphan foreign key"));
    }
    Ok(())
}

fn typed_owners(view: &JournalReadView<'_>, space: &SpaceId, max: usize) -> Result<Owners> {
    let snapshots = view.snapshot_audit(space)?;
    view.current(space)?;
    view.diagnostic_operation_count(space, max)?;
    crate::rename_observation::audit_observation(view.connection, space, max)?;
    let leases = view.read_leases(space)?;
    let mutations = view.mutations(space)?;
    for mutation in &mutations {
        view.verify_mutation_references(&mutation.intent.transaction_id)?;
    }
    let publications = view.publications(space)?;
    for publication in &publications {
        let intent = &publication.intent;
        let baseline = view
            .retained_snapshot(space, &intent.baseline_root)?
            .manifest;
        let requested = baseline
            .entries
            .values()
            .find(|e| e.path == intent.requested_path);
        if requested != intent.requested_baseline.as_ref()
            || baseline.entries.contains_key(&intent.entry_id)
        {
            return Err(invalid("journal capacity publication baseline mismatch"));
        }
        if let Some(root) = &intent.source_snapshot {
            let source = view.retained_snapshot(space, root)?;
            if !source
                .manifest
                .entries
                .values()
                .any(|e| e.content.as_ref() == Some(&intent.content))
            {
                return Err(invalid("journal capacity publication source mismatch"));
            }
        }
        if let Some(root) = &publication.committed_snapshot {
            let completed = view.retained_snapshot(space, root)?;
            if completed
                .manifest
                .entries
                .get(&intent.entry_id)
                .is_none_or(|e| {
                    e.path != intent.target_path || e.content.as_ref() != Some(&intent.content)
                })
            {
                return Err(invalid("journal capacity publication completion mismatch"));
            }
        }
    }
    let cleanup = view.cleanup_plans(space)?;
    let references = view.reference_reservations(space, max)?;
    let originals = view.audit_original_disposals(space, max)?;
    let marks = view.gc_marks(space)?;
    let authorizations = view.gc_authorizations(space, &marks)?;
    let executions = view.gc_executions(&authorizations)?;
    let quarantines = view.audit_gc_quarantines(&executions)?;
    let disposals = view.audit_gc_disposals(&quarantines, &executions)?;
    let trees = view.audit_tree_restore_preparations(space, max)?;
    Ok(Owners {
        snapshots,
        leases,
        mutations,
        publications,
        cleanup,
        references,
        originals,
        marks,
        executions,
        quarantines,
        disposals,
        trees,
    })
}
