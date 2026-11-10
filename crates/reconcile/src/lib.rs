mod cleanup;
mod conflict_admission;
#[cfg(windows)]
mod conflict_native;
pub use conflict_admission::{ForeignConflictAdmission, LocalConflictAdmission};
#[cfg(windows)]
pub use conflict_native::ConflictNativeResult;
mod conflict_branches;
pub use conflict_branches::ConflictBranchPreparation;
mod delete;
mod diagnostics;
mod fault;
mod filesystem;
mod gc_authorization;
mod gc_disposal;
mod gc_execution;
mod gc_mark;
mod gc_preflight;
mod gc_quarantine;
#[cfg(windows)]
mod guarded_mutation;
mod identity;
mod join;
mod metadata_cycle;
pub use metadata_cycle::PeerMetadataCycle;
mod peer_operations;
pub use peer_operations::PeerOperationPull;
mod peer_pull;
mod peer_transfer;
mod remote_file;
mod remote_replay;
mod transport_identity;
pub use peer_pull::PeerFilePull;
pub use remote_file::{RemoteFileChunkImport, RemoteFileMaterialization, RemoteFilePreparation};
mod move_file;
mod mutation;
#[cfg(windows)]
mod native_file_view;
#[cfg(windows)]
mod native_publish;
mod original_retention;
mod persisted_rename;
mod publish;
#[cfg(windows)]
mod remote_delete;
#[cfg(windows)]
mod remote_native;
#[cfg(windows)]
mod remote_rename;
#[cfg(windows)]
mod remote_replace;
#[cfg(windows)]
pub use native_publish::NativePublishResult;
#[cfg(windows)]
pub use remote_delete::RemoteDeleteResult;
#[cfg(windows)]
pub use remote_rename::RemoteRenameResult;
#[cfg(windows)]
pub use remote_replace::RemoteReplaceResult;
mod read_lease;
mod reference_reservation;
mod replace_file;
mod scan;
mod snapshot_pruning;
mod snapshot_retention;
mod storage;
mod tree_final_observation;
mod tree_restore_capture;
pub use delete::{DeleteResult, MutationResult};
pub use diagnostics::Diagnostics;
pub use gc_authorization::GcAuthorizationCheck;
pub use gc_mark::GcRevalidation;
pub use gc_preflight::GcPreflight;
pub use mutation::MutationCheck;
pub use publish::PublishResult;
pub use read_lease::LeasedExportResult;
pub use reference_reservation::ReservedChunkImport;
pub use snapshot_retention::{RetentionReport, SnapshotLockResult, SnapshotRetention};
pub use storage::StorageReport;
pub use sync_extend_journal::{ReferenceReservation, ReferenceReservationIntent};
pub use tree_final_observation::{TreeFinalObservation, TreeFinalObservationReport};
pub use tree_restore_capture::TreeRestoreCapture;

use fs2::FileExt;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use sync_extend_cas::{is_reparse, sync_directory, Cas};
use sync_extend_core_model::limits::LocalLimits;
use sync_extend_core_model::*;
use sync_extend_journal::Journal;

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("local filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("model error: {0}")]
    Model(#[from] ModelError),
    #[error("content storage error: {0}")]
    Cas(#[from] sync_extend_cas::CasError),
    #[error("journal error: {0}")]
    Journal(#[from] sync_extend_journal::JournalError),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("safety check failed: {0}")]
    Invariant(&'static str),
    #[error("worktree changed during scanning; retry after writers settle")]
    Unstable,
    #[error("local resource limit exceeded: {0}; existing state is preserved")]
    ResourceLimit(&'static str),
}

pub type Result<T> = std::result::Result<T, ReconcileError>;

fn managed_cas(data_dir: &Path) -> Result<Cas> {
    let access_journal = Journal::open(&data_dir.join("journal.sqlite"))?;
    let session_journal = Journal::open(&data_dir.join("journal.sqlite"))?;
    Ok(Cas::open_session_coordinated(
        &data_dir.join("cas"),
        move |id| {
            access_journal
                .acquire_cas_access(id)
                .map(|guard| -> Box<dyn Send> {
                    fault::checkpoint("after_cas_access_lock");
                    Box::new(guard)
                })
                .map_err(|e| e.to_string())
        },
        move || {
            session_journal
                .acquire_cas_session()
                .map(|guard| -> Box<dyn Send> {
                    fault::checkpoint("after_cas_session_lock");
                    Box::new(SessionGuard { _guard: guard })
                })
                .map_err(|e| e.to_string())
        },
    )?)
}

struct SessionGuard {
    _guard: sync_extend_journal::CasAccessGuard,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        fault::checkpoint("before_cas_session_release");
    }
}

pub struct LocalSpace {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    worktree: PathBuf,
    data_dir: PathBuf,
    cas: Cas,
    journal: Journal,
    limits: LocalLimits,
    root_identity: filesystem::PathIdentity,
    _lock: File,
    _worktree_lock: File,
}

#[derive(Serialize)]
pub struct ScanResult {
    pub space_id: SpaceId,
    pub snapshot_id: SnapshotId,
    pub entries: usize,
    pub operations: usize,
    pub files: usize,
    pub logical_bytes: u64,
    pub network_enabled: bool,
}

#[derive(Serialize)]
pub struct Status {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub snapshot_id: Option<SnapshotId>,
    pub entries: usize,
    pub operations: usize,
    pub snapshots: usize,
    pub network_enabled: bool,
    pub webdav_enabled: bool,
    pub history_pruning_enabled: bool,
    pub outstanding_publications: usize,
    pub publication_stages: Vec<sync_extend_journal::PublicationState>,
    pub protected_objects: usize,
    pub local_limits: LocalLimits,
    pub outstanding_mutations: usize,
    pub destructive_mutation_enabled: bool,
    pub windows_delete_executor_available: bool,
    pub windows_move_executor_available: bool,
    pub windows_replace_executor_available: bool,
    pub mutation_executor_actions: Vec<&'static str>,
    pub tree_restore_preparation_records: usize,
    pub tree_restore_history_reservations: usize,
    pub tree_restore_native_reservations: usize,
    pub tree_restore_execution_descriptions: usize,
    pub tree_restore_execution_description_records: usize,
    pub tree_restore_original_reservations: usize,
    pub tree_restore_original_reference_rows: usize,
    pub tree_restore_owner_descriptions: usize,
    pub tree_restore_owner_description_records: usize,
    pub tree_restore_final_descriptions: usize,
    pub tree_restore_retained_original_descriptions: usize,
    pub tree_restore_disposition_descriptions: usize,
    pub tree_restore_disposition_description_records: usize,
    pub tree_restore_irreversible_admissions: usize,
    pub tree_restore_native_protocol_descriptions: usize,
    pub tree_restore_native_protocol_description_records: usize,
    pub tree_restore_writer_gate_held: bool,
    pub tree_restore_execution_available: bool,
    pub tree_atomic: bool,
    pub gc: sync_extend_journal::GcDiagnostics,
}

impl LocalSpace {
    pub fn initialize(data_dir: &Path, worktree: &Path) -> Result<Self> {
        Self::initialize_with_limits(data_dir, worktree, LocalLimits::default())
    }

    pub fn initialize_with_limits(
        data_dir: &Path,
        worktree: &Path,
        limits: LocalLimits,
    ) -> Result<Self> {
        limits.validate()?;
        check_ancestors(worktree)?;
        check_ancestors(data_dir)?;
        let worktree = fs::canonicalize(worktree)?;
        if !fs::metadata(&worktree)?.is_dir() {
            return Err(ReconcileError::Invariant("worktree must already exist"));
        }
        validate_roots(&canonical_destination(data_dir)?, &worktree)?;
        create_private_directory(data_dir)?;
        let data_dir = fs::canonicalize(data_dir)?;
        validate_roots(&data_dir, &worktree)?;
        let lock = acquire_lock(&data_dir)?;
        let mut journal = Journal::open_with_storage_limit(
            &data_dir.join("journal.sqlite"),
            limits.max_storage_entries,
        )?;
        if journal.state("space_id")?.is_some() {
            return Err(ReconcileError::Invariant(
                "space already initialized; use scan/status",
            ));
        }
        let device_id = identity::load_or_create(&data_dir.join("device.secret"), true)?;
        let marker_directory = worktree.join(".sync-extend");
        let marker = marker_directory.join("space-id");
        let space_id: SpaceId = if marker.try_exists()? {
            read_marker(&marker)?
        } else {
            if marker_directory.try_exists()? {
                return Err(ReconcileError::Invariant(
                    "reserved worktree directory already exists",
                ));
            }
            let space = SpaceId::random()?;
            fs::create_dir(&marker_directory)?;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)?;
            file.write_all(space.as_str().as_bytes())?;
            file.sync_all()?;
            sync_directory(&marker_directory)?;
            sync_directory(&worktree)?;
            space
        };
        journal.initialize(
            &space_id,
            &device_id,
            worktree
                .to_str()
                .ok_or(ReconcileError::Invariant("non-UTF8 root"))?,
        )?;
        let cas = managed_cas(&data_dir)?;
        let worktree_lock = acquire_lock(&marker_directory)?;
        let root_identity = filesystem::PathIdentity::capture(&worktree)?;
        Ok(Self {
            space_id,
            device_id,
            worktree,
            data_dir,
            cas,
            journal,
            limits,
            root_identity,
            _lock: lock,
            _worktree_lock: worktree_lock,
        })
    }

    pub fn open(data_dir: &Path) -> Result<Self> {
        Self::open_with_limits(data_dir, LocalLimits::default())
    }

    pub fn open_with_limits(data_dir: &Path, limits: LocalLimits) -> Result<Self> {
        limits.validate()?;
        check_ancestors(data_dir)?;
        let data_dir = fs::canonicalize(data_dir)?;
        let lock = acquire_lock(&data_dir)?;
        if !data_dir.join("journal.sqlite").is_file() {
            return Err(ReconcileError::Invariant("space is not initialized"));
        }
        let journal = Journal::open_with_storage_limit(
            &data_dir.join("journal.sqlite"),
            limits.max_storage_entries,
        )?;
        let required = |key| {
            journal
                .state(key)?
                .ok_or(ReconcileError::Invariant("incomplete initialization"))
        };
        let space_id = required("space_id")?.parse()?;
        let device_id: DeviceId = required("device_id")?.parse()?;
        let worktree = PathBuf::from(required("worktree")?);
        if identity::load_or_create(&data_dir.join("device.secret"), false)? != device_id {
            return Err(ReconcileError::Invariant("device public key mismatch"));
        }
        validate_roots(&data_dir, &worktree)?;
        let cas = managed_cas(&data_dir)?;
        let worktree_lock = acquire_lock(&worktree.join(".sync-extend"))?;
        let root_identity = filesystem::PathIdentity::capture(&worktree)?;
        let local = Self {
            space_id,
            device_id,
            worktree,
            data_dir,
            cas,
            journal,
            limits,
            root_identity,
            _lock: lock,
            _worktree_lock: worktree_lock,
        };
        local.verify_root()?;
        Ok(local)
    }

    pub fn with_limits(mut self, limits: LocalLimits) -> Result<Self> {
        limits.validate()?;
        self.journal
            .set_max_storage_entries(limits.max_storage_entries)?;
        self.limits = limits;
        Ok(self)
    }

    fn verify_root(&self) -> Result<()> {
        self.root_identity.verify(&self.worktree)?;
        check_ancestors(&self.worktree)?;
        let metadata = fs::symlink_metadata(&self.worktree)?;
        if !metadata.is_dir()
            || is_reparse(&metadata)
            || metadata.file_type().is_symlink()
            || read_marker(&self.worktree.join(".sync-extend/space-id"))? != self.space_id
        {
            return Err(ReconcileError::Invariant(
                "worktree unavailable or identity marker changed",
            ));
        }
        Ok(())
    }

    pub fn scan(&mut self) -> Result<ScanResult> {
        self.recover()?;
        self.scan_without_recovery()
    }

    fn stable_scan(&self) -> Result<scan::Scan> {
        self.verify_root()?;
        let first = scan::scan(&self.worktree, &self.cas, &self.limits)?;
        fault::checkpoint("after_first_scan");
        self.verify_root()?;
        let second = scan::scan(&self.worktree, &self.cas, &self.limits)?;
        if first != second {
            return Err(ReconcileError::Unstable);
        }
        self.verify_root()?;
        Ok(second)
    }

    fn scan_without_recovery(&mut self) -> Result<ScanResult> {
        self.require_no_mutation()?;
        let second = self.stable_scan()?;
        self.commit_scan(&second, None)
    }

    fn commit_scan(
        &mut self,
        second: &scan::Scan,
        publication: Option<&sync_extend_journal::PublicationIntent>,
    ) -> Result<ScanResult> {
        if let Some(intent) = publication.filter(|intent| intent.completion.is_some()) {
            return self.commit_admitted_publication_scan(second, intent);
        }
        let old = self.journal.current(&self.space_id)?;
        let baseline = old.as_ref().map(Manifest::root).transpose()?;
        let previous = old.unwrap_or_else(|| Manifest::empty(self.space_id.clone()));
        let candidates = self.persisted_rename_candidates(&previous, second)?;
        let mut manifest = build_manifest(&previous, second, &candidates)?;
        if let Some(intent) = publication {
            let observed = second
                .get(&intent.target_path)
                .ok_or(ReconcileError::Unstable)?;
            if observed.content.as_ref() != Some(&intent.content) {
                return Err(ReconcileError::Unstable);
            }
            manifest
                .entries
                .retain(|_, entry| entry.path != intent.target_path);
            manifest.entries.insert(
                intent.entry_id.clone(),
                Entry {
                    entry_id: intent.entry_id.clone(),
                    path: intent.target_path.clone(),
                    kind: EntryKind::File,
                    content: Some(intent.content.clone()),
                },
            );
            manifest.tombstones.remove(&intent.entry_id);
        }
        let timestamp = now_ms()?;
        let mut changes = Vec::new();
        for entry in manifest.entries.values() {
            match previous.entries.get(&entry.entry_id) {
                None => changes.push(Change::Put {
                    entry: entry.clone(),
                }),
                Some(old) => {
                    if old.path != entry.path {
                        changes.push(Change::Rename {
                            entry_id: entry.entry_id.clone(),
                            path: entry.path.clone(),
                        });
                    }
                    if old.kind != entry.kind || old.content != entry.content {
                        changes.push(Change::Put {
                            entry: entry.clone(),
                        });
                    }
                }
            }
        }
        for id in previous.entries.keys() {
            if !manifest.entries.contains_key(id) {
                changes.push(Change::Delete {
                    entry_id: id.clone(),
                });
            }
        }
        let mut operations = Vec::new();
        for change in changes {
            let seq = manifest
                .version_vector
                .get(&self.device_id)
                .checked_add(1)
                .ok_or(ReconcileError::Invariant("sequence exhausted"))?;
            let op = Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.space_id.clone(),
                origin_device_id: self.device_id.clone(),
                origin_seq: seq,
                causal: manifest.version_vector.clone(),
                change,
                created_at_ms: timestamp,
            })?;
            if let Change::Delete { entry_id } = &op.payload.change {
                manifest
                    .tombstones
                    .insert(entry_id.clone(), op.op_id.clone());
            }
            manifest.version_vector.observe(self.device_id.clone(), seq);
            operations.push(op);
        }
        for entry in manifest.entries.values() {
            if let Some(content) = &entry.content {
                self.cas.verify(content)?;
            }
        }
        let root = if let Some(intent) = publication {
            self.journal.commit_publication(
                &intent.transaction_id,
                baseline
                    .as_ref()
                    .ok_or(ReconcileError::Invariant("missing publication baseline"))?,
                &manifest,
                &operations,
                timestamp,
            )?
        } else {
            let observations = self.scan_observations(&manifest, second)?;
            fault::checkpoint("before_scan_observation_commit");
            let root = self.journal.commit_local_with_observations(
                baseline.as_ref(),
                &manifest,
                &operations,
                timestamp,
                &observations,
                self.limits.max_storage_entries,
            )?;
            fault::checkpoint("after_scan_observation_commit");
            root
        };
        Ok(ScanResult {
            space_id: self.space_id.clone(),
            snapshot_id: root,
            entries: manifest.entries.len(),
            operations: operations.len(),
            files: manifest
                .entries
                .values()
                .filter(|e| e.kind == EntryKind::File)
                .count(),
            logical_bytes: manifest
                .entries
                .values()
                .filter_map(|e| e.content.as_ref())
                .map(|c| c.length)
                .sum(),
            network_enabled: false,
        })
    }

    fn commit_admitted_publication_scan(
        &mut self,
        scanned: &scan::Scan,
        intent: &sync_extend_journal::PublicationIntent,
    ) -> Result<ScanResult> {
        let mut observed = scanned.clone();
        observed.remove(&intent.target_path);
        self.refresh_publication_observations(intent, &observed)?;
        let intent = self.journal.publication(&intent.transaction_id)?.intent;
        let completion = intent.completion.as_ref().ok_or(ReconcileError::Invariant(
            "publication completion admission missing",
        ))?;
        if scanned.len() != completion.manifest.entries.len()
            || completion.manifest.entries.values().any(|entry| {
                scanned.get(&entry.path).is_none_or(|observed| {
                    observed.kind != entry.kind || observed.content != entry.content
                })
            })
        {
            return Err(ReconcileError::Invariant(
                "native worktree differs from admitted publication; preserve pending owner",
            ));
        }
        for content in completion
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            self.cas.verify(content)?;
        }
        let root = self.journal.commit_publication(
            &intent.transaction_id,
            &intent.baseline_root,
            &completion.manifest,
            &completion.operations,
            completion.timestamp_ms,
        )?;
        Ok(ScanResult {
            space_id: self.space_id.clone(),
            snapshot_id: root,
            entries: completion.manifest.entries.len(),
            operations: completion.operations.len(),
            files: completion
                .manifest
                .entries
                .values()
                .filter(|entry| entry.kind == EntryKind::File)
                .count(),
            logical_bytes: completion
                .manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .map(|content| content.length)
                .sum(),
            network_enabled: false,
        })
    }

    fn refresh_publication_observations(
        &mut self,
        intent: &sync_extend_journal::PublicationIntent,
        observed: &scan::Scan,
    ) -> Result<bool> {
        let prior = intent.completion.as_ref().ok_or(ReconcileError::Invariant(
            "publication completion admission missing",
        ))?;
        let mut reference = prior.manifest.clone();
        reference.entries.remove(&intent.entry_id);
        let native = build_manifest(&reference, observed, &BTreeMap::new())?;
        let mut completion = sync_extend_journal::PublicationCompletion::from_observed(
            &prior.baseline,
            &self.device_id,
            native.entries,
            Entry {
                entry_id: intent.entry_id.clone(),
                path: intent.target_path.clone(),
                kind: EntryKind::File,
                content: Some(intent.content.clone()),
            },
            intent.created_at_ms,
        )?;
        for (id, length) in &prior.protected_objects {
            if completion
                .protected_objects
                .insert(id.clone(), *length)
                .is_some_and(|observed| observed != *length)
            {
                return Err(ReconcileError::Invariant(
                    "publication observed chunk length changed",
                ));
            }
        }
        if completion == *prior {
            self.journal
                .refresh_publication_completion(intent, &completion)?;
            return Ok(false);
        }
        for content in completion
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            self.cas.verify(content)?;
        }
        self.journal
            .refresh_publication_completion(intent, &completion)?;
        Ok(true)
    }

    pub fn manifest(&self) -> Result<Option<Manifest>> {
        Ok(self.journal.current(&self.space_id)?)
    }

    pub fn operations(&self) -> Result<Vec<Operation>> {
        Ok(self.journal.operations(&self.space_id)?)
    }

    pub fn snapshots(&self) -> Result<Vec<(SnapshotId, String)>> {
        self.snapshot_audit()?;
        Ok(self.journal.snapshots(&self.space_id)?)
    }

    pub fn status(&self) -> Result<Status> {
        self.verify_root()?;
        self.journal
            .with_gc_diagnostics(&self.space_id, self.limits.max_storage_entries, |gc| {
                fault::checkpoint("after_status_read_snapshot");
                let status = self.status_in_snapshot(gc)?;
                self.verify_root()?;
                Ok(status)
            })
    }

    fn status_in_snapshot(&self, gc: &sync_extend_journal::GcDiagnostics) -> Result<Status> {
        let manifest = self.manifest()?;
        let publications = self.journal.outstanding_publications(&self.space_id)?;
        let trees = self
            .journal
            .tree_restore_preparations(&self.space_id, self.limits.max_storage_entries)?;
        Ok(Status {
            space_id: self.space_id.clone(),
            device_id: self.device_id.clone(),
            snapshot_id: manifest.as_ref().map(Manifest::root).transpose()?,
            entries: manifest.as_ref().map_or(0, |m| m.entries.len()),
            operations: self
                .journal
                .diagnostic_operation_count(&self.space_id, self.limits.max_storage_entries)?,
            snapshots: self.journal.snapshots(&self.space_id)?.len(),
            network_enabled: false,
            webdav_enabled: false,
            history_pruning_enabled: false,
            outstanding_publications: publications.len(),
            publication_stages: publications.iter().map(|p| p.state).collect(),
            protected_objects: self.journal.protected_objects()?.len(),
            local_limits: self.limits.clone(),
            outstanding_mutations: self.journal.outstanding_mutations(&self.space_id)?.len(),
            destructive_mutation_enabled: cfg!(windows),
            windows_delete_executor_available: cfg!(windows),
            windows_move_executor_available: cfg!(windows),
            windows_replace_executor_available: cfg!(windows),
            mutation_executor_actions: if cfg!(windows) {
                vec!["delete", "move", "replace"]
            } else {
                vec![]
            },
            tree_restore_preparation_records: trees.len(),
            tree_restore_history_reservations: trees
                .iter()
                .filter(|p| p.history_reservation.is_some())
                .count(),
            tree_restore_writer_gate_held: trees.iter().any(|p| p.writer_gate_held),
            tree_restore_native_reservations: trees
                .iter()
                .filter(|p| p.native_reservation.is_some())
                .count(),
            tree_restore_execution_available: false,
            tree_restore_owner_descriptions: trees
                .iter()
                .filter(|p| p.owner_description.is_some())
                .count(),
            tree_restore_final_descriptions: trees
                .iter()
                .filter(|p| p.final_description.is_some())
                .count(),
            tree_restore_retained_original_descriptions: trees
                .iter()
                .filter_map(|p| p.final_description.as_ref())
                .map(|p| p.intent.retained_originals.len())
                .sum(),
            tree_restore_disposition_descriptions: trees
                .iter()
                .filter(|p| p.disposition_description.is_some())
                .count(),
            tree_restore_irreversible_admissions: trees
                .iter()
                .filter(|p| p.coordinator_admission.is_some())
                .count(),
            tree_restore_native_protocol_descriptions: trees
                .iter()
                .filter(|p| p.native_protocol_description.is_some())
                .count(),
            tree_restore_native_protocol_description_records: trees
                .iter()
                .filter_map(|p| p.native_protocol_description.as_ref())
                .map(|a| a.records.len())
                .sum(),
            tree_restore_disposition_description_records: trees
                .iter()
                .filter_map(|p| p.disposition_description.as_ref())
                .flat_map(|p| p.records.values())
                .map(Vec::len)
                .sum(),
            tree_restore_owner_description_records: trees
                .iter()
                .filter_map(|p| p.owner_description.as_ref())
                .map(|p| p.records.len())
                .sum(),
            tree_restore_original_reservations: trees
                .iter()
                .filter(|p| p.original_pins.is_some())
                .count(),
            tree_restore_original_reference_rows: trees
                .iter()
                .filter_map(|p| p.original_pins.as_ref())
                .map(|p| p.active_reference_count)
                .sum(),
            tree_restore_execution_descriptions: trees
                .iter()
                .filter(|p| p.execution_description.is_some())
                .count(),
            tree_restore_execution_description_records: trees
                .iter()
                .filter_map(|p| p.execution_records.as_ref())
                .map(|records| records.record_count)
                .sum(),
            tree_atomic: false,
            gc: gc.clone(),
        })
    }

    pub fn verify(&self) -> Result<usize> {
        self.journal.integrity_check()?;
        self.journal
            .tree_restore_preparations(&self.space_id, self.limits.max_storage_entries)?;
        self.journal
            .rename_observation(&self.space_id, self.limits.max_storage_entries)?;
        self.gc_marks()?;
        self.gc_authorizations()?;
        self.gc_executions()?;
        self.gc_quarantines()?;
        self.snapshot_audit()?;
        self.cleanup_plans()?;
        self.journal
            .original_disposals(&self.space_id, self.limits.max_storage_entries)?;
        for lease in self.read_leases()? {
            if lease.state == sync_extend_journal::ReadLeaseState::Active {
                self.cas.verify(
                    lease
                        .intent
                        .entry
                        .content
                        .as_ref()
                        .ok_or(ReconcileError::Invariant("read lease content missing"))?,
                )?;
            }
        }
        for owner in self.reference_reservations()? {
            if owner.snapshot_handoff.is_none() {
                for file in &owner.intent.scope.files {
                    self.cas.verify(file)?;
                }
            }
        }
        let mut files = 0;
        let mut checked = std::collections::BTreeSet::new();
        for publication in self.journal.outstanding_publications(&self.space_id)? {
            self.cas.verify(&publication.intent.content)?;
        }
        let protected: std::collections::BTreeSet<_> =
            self.journal.protected_objects()?.into_iter().collect();
        for mutation in self.journal.mutations(&self.space_id)? {
            let intent = &mutation.intent;
            self.journal
                .verify_mutation_references(&intent.transaction_id)?;
            let baseline = self
                .journal
                .snapshot(&self.space_id, &intent.baseline_root)?;
            if baseline.entries.get(&intent.baseline_entry.entry_id) != Some(&intent.baseline_entry)
            {
                return Err(ReconcileError::Invariant("mutation baseline mismatch"));
            }
            if mutation.state.active() {
                for content in std::iter::once(intent.baseline_entry.content.as_ref().ok_or(
                    ReconcileError::Invariant("mutation baseline content missing"),
                )?)
                .chain(match &intent.action {
                    sync_extend_journal::MutationAction::Replace { content } => Some(content),
                    _ => None,
                }) {
                    if content
                        .chunks
                        .iter()
                        .any(|chunk| !protected.contains(&chunk.content_id))
                    {
                        return Err(ReconcileError::Invariant(
                            "mutation object lacks a protection reference",
                        ));
                    }
                    self.cas.verify(content)?;
                }
            }
        }
        for snapshot in self
            .journal
            .retained_snapshots(&self.space_id, self.limits.max_storage_entries)?
        {
            for entry in snapshot.manifest.entries.values() {
                if let Some(content) = &entry.content {
                    if content
                        .chunks
                        .iter()
                        .any(|chunk| !protected.contains(&chunk.content_id))
                    {
                        return Err(ReconcileError::Invariant(
                            "retained snapshot object lacks a protection reference",
                        ));
                    }
                    if checked.insert(content.content_id.clone()) {
                        self.cas.verify(content)?;
                        files += 1;
                    }
                }
            }
        }
        Ok(files)
    }

    pub fn export_file(&self, path: &PortablePath, output: &Path) -> Result<()> {
        check_ancestors(output)?;
        let parent = fs::canonicalize(
            output
                .parent()
                .ok_or(ReconcileError::Invariant("output requires a parent"))?,
        )?;
        if parent.starts_with(&self.worktree) || parent.starts_with(&self.data_dir) {
            return Err(ReconcileError::Invariant(
                "export must be outside the worktree and internal data; use restore for retained versions",
            ));
        }
        let manifest = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("no scanned manifest"))?;
        let entry = manifest
            .entries
            .values()
            .find(|entry| &entry.path == path)
            .ok_or(ReconcileError::Invariant("file not found"))?;
        let content = entry
            .content
            .as_ref()
            .ok_or(ReconcileError::Invariant("path is a directory"))?;
        let _session = self.cas.acquire_session()?;
        self.cas.verify(content)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        self.cas.write_file(content, &mut file)?;
        fault::checkpoint("after_export_cas_write");
        file.sync_all()?;
        sync_directory(&parent)?;
        Ok(())
    }
}

fn build_manifest(
    old: &Manifest,
    scanned: &scan::Scan,
    candidates: &BTreeMap<PortablePath, EntryId>,
) -> Result<Manifest> {
    let mut result = old.clone();
    result.entries.clear();
    let by_path: BTreeMap<_, _> = old.entries.values().map(|e| (e.path.clone(), e)).collect();
    let mut unmatched_old = BTreeMap::<(EntryKindKey, String), Vec<EntryId>>::new();
    let mut unmatched_new = BTreeMap::<(EntryKindKey, String), Vec<PortablePath>>::new();
    for entry in old.entries.values() {
        if scanned
            .get(&entry.path)
            .is_none_or(|e| e.kind != entry.kind)
        {
            unmatched_old
                .entry(fingerprint_old(entry, old)?)
                .or_default()
                .push(entry.entry_id.clone());
        }
    }
    for (path, entry) in scanned {
        if by_path.get(path).is_none_or(|e| e.kind != entry.kind) {
            unmatched_new
                .entry(fingerprint_scan(path, entry, scanned)?)
                .or_default()
                .push(path.clone());
        }
    }
    let mut renames = BTreeMap::new();
    for (fingerprint, paths) in &unmatched_new {
        if paths.len() == 1 {
            if let Some(ids) = unmatched_old.get(fingerprint).filter(|ids| ids.len() == 1) {
                renames.insert(paths[0].clone(), ids[0].clone());
            }
        }
    }
    // An unambiguous whole-directory move also identifies duplicate-content children.
    let directory_moves: Vec<_> = renames
        .iter()
        .filter_map(|(new_path, id)| {
            old.entries
                .get(id)
                .filter(|entry| entry.kind == EntryKind::Directory)
                .map(|entry| (format!("{new_path}/"), format!("{}/", entry.path)))
        })
        .collect();
    for (new_path, entry) in scanned {
        if by_path
            .get(new_path)
            .is_some_and(|old| old.kind == entry.kind)
        {
            continue;
        }
        for (new_prefix, old_prefix) in &directory_moves {
            if let Some(relative) = new_path.as_str().strip_prefix(new_prefix) {
                let old_path = PortablePath::new(format!("{old_prefix}{relative}"))?;
                if let Some(old_entry) = by_path
                    .get(&old_path)
                    .filter(|old| old.kind == entry.kind && old.content == entry.content)
                {
                    renames.insert(new_path.clone(), old_entry.entry_id.clone());
                    break;
                }
            }
        }
    }
    let mut used: std::collections::BTreeSet<_> = renames.values().cloned().collect();
    for (path, id) in candidates {
        let old_entry = old
            .entries
            .get(id)
            .ok_or(ReconcileError::Invariant("rename candidate missing"))?;
        let key = fingerprint_old(old_entry, old)?;
        if !renames.contains_key(path)
            && !used.contains(id)
            && unmatched_old
                .get(&key)
                .is_some_and(|ids| ids.len() > 1 && ids.contains(id))
            && unmatched_new
                .get(&key)
                .is_some_and(|paths| paths.len() > 1 && paths.contains(path))
        {
            renames.insert(path.clone(), id.clone());
            used.insert(id.clone());
        }
    }
    for (path, scanned) in scanned {
        let id = if let Some(old) = by_path.get(path).filter(|e| e.kind == scanned.kind) {
            old.entry_id.clone()
        } else if let Some(id) = renames.get(path) {
            id.clone()
        } else {
            EntryId::random()?
        };
        result.tombstones.remove(&id);
        result.entries.insert(
            id.clone(),
            Entry {
                entry_id: id,
                path: path.clone(),
                kind: scanned.kind,
                content: scanned.content.clone(),
            },
        );
    }
    // Deleted IDs receive their tombstones when their new operations are formed.
    result.validate()?;
    Ok(result)
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum EntryKindKey {
    File,
    Directory,
}

fn fingerprint_old(entry: &Entry, manifest: &Manifest) -> Result<(EntryKindKey, String)> {
    if let Some(content) = &entry.content {
        return Ok((EntryKindKey::File, content.content_id.to_string()));
    }
    let prefix = format!("{}/", entry.path);
    let descendants: Vec<_> = manifest
        .entries
        .values()
        .filter_map(|e| {
            e.path.as_str().strip_prefix(&prefix).map(|relative| {
                (
                    relative.to_owned(),
                    e.kind,
                    e.content.as_ref().map(|c| &c.content_id),
                )
            })
        })
        .collect();
    fingerprint_directory(descendants)
}

fn fingerprint_scan(
    path: &PortablePath,
    entry: &scan::ScannedEntry,
    scan: &scan::Scan,
) -> Result<(EntryKindKey, String)> {
    if let Some(content) = &entry.content {
        return Ok((EntryKindKey::File, content.content_id.to_string()));
    }
    let prefix = format!("{path}/");
    let descendants: Vec<_> = scan
        .iter()
        .filter_map(|(p, e)| {
            p.as_str().strip_prefix(&prefix).map(|relative| {
                (
                    relative.to_owned(),
                    e.kind,
                    e.content.as_ref().map(|c| &c.content_id),
                )
            })
        })
        .collect();
    fingerprint_directory(descendants)
}

fn fingerprint_directory(
    mut descendants: Vec<(String, EntryKind, Option<&ContentId>)>,
) -> Result<(EntryKindKey, String)> {
    descendants.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((
        EntryKindKey::Directory,
        ContentId::hash(&serde_json::to_vec(&descendants)?).to_string(),
    ))
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReconcileError::Invariant("system clock predates epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| ReconcileError::Invariant("timestamp overflow"))
}

fn validate_roots(data: &Path, worktree: &Path) -> Result<()> {
    if data.starts_with(worktree) || worktree.starts_with(data) {
        return Err(ReconcileError::Invariant(
            "data and worktree roots must not overlap",
        ));
    }
    Ok(())
}

fn canonical_destination(path: &Path) -> Result<PathBuf> {
    if path.try_exists()? {
        return Ok(fs::canonicalize(path)?);
    }
    let parent = path
        .parent()
        .ok_or(ReconcileError::Invariant("missing root parent"))?;
    let name = path
        .file_name()
        .ok_or(ReconcileError::Invariant("missing directory name"))?;
    Ok(canonical_destination(parent)?.join(name))
}

fn check_ancestors(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ReconcileError::Invariant(
            "root must be absolute without traversal",
        ));
    }
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() || is_reparse(&metadata) => {
                return Err(ReconcileError::Invariant(
                    "root contains a link/reparse point",
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn read_marker(path: &Path) -> Result<SpaceId> {
    check_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(ReconcileError::Invariant(
            "invalid or unavailable worktree marker",
        ));
    }
    let mut value = String::new();
    File::open(path)?.take(33).read_to_string(&mut value)?;
    Ok(value.parse()?)
}

fn acquire_lock(data: &Path) -> Result<File> {
    let path = data.join("writer.lock");
    check_ancestors(&path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    FileExt::try_lock_exclusive(&file)
        .map_err(|_| ReconcileError::Invariant("another local writer is running"))?;
    Ok(file)
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(ReconcileError::Invariant(
                "data directory permissions must be private",
            ));
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    Ok(())
}
