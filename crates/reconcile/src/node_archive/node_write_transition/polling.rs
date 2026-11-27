//! Explicit mutable worktree windows under the same recovered Journal/CAS owner.
//! Only this module ends and reacquires content observation handles. Data roots,
//! coordination locks, the native connection and history evidence never leave.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use sync_extend_core_model::{
    limits::LocalLimits, Change, EntryKind, Operation, OperationPayload, PortablePath,
    persisted_rename::{RenameObservationMap, RenameObservationScope, RenamePathObservation,
        PriorRenameObservation, preserves_logical_metadata},
    PortableMetadataProjectionPlatform, Manifest, EntryId,
    FORMAT_VERSION,
};
use sync_extend_platform_fs::{
    ClosedWindowsOriginalResources, LockedDirectory, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

pub(super) struct RecoveredPollingState {
    limits: LocalLimits,
    detached: bool,
    closed: Option<ClosedWindowsOriginalResources>,
    failed: Option<WindowsOriginalResourceCloseFailure>,
    pending_files: Vec<RecoveredFileProtection>,
    pending_directories: Vec<LockedDirectory>,
    observations: Option<RenameObservationMap>,
}
impl RecoveredPollingState {
    pub(super) fn close_into_attempt(self, attempt: &mut WindowsOriginalCloseAttempt) {
        for file in self.pending_files {
            file.close_into_attempt(attempt);
        }
        for directory in self.pending_directories.into_iter().rev() {
            attempt.close_directory(directory);
        }
        if let Some(closed) = self.closed {
            attempt.append_result(Ok(closed));
        }
        if let Some(failed) = self.failed {
            attempt.append_result(Err(failed));
        }
    }
}
pub(super) fn managed(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).ok().is_some_and(|relative| {
        !relative.as_os_str().is_empty()
            && relative.components().next().is_some_and(|part| {
                part.as_os_str().to_str().is_some_and(|name| {
                    ![".sync-extend", ".sync-tmp", ".git"]
                        .iter()
                        .any(|reserved| name.eq_ignore_ascii_case(reserved))
                })
            })
    })
}

impl FreshRecoveredNodeWalV2Session {
    pub(super) fn recovered_logical_metadata_for_observed_file(
        &self, path: &Path, key: FileKey, content: &sync_extend_core_model::FileManifest,
        actual: sync_extend_core_model::PortableEntryMetadata,
    ) -> Result<sync_extend_core_model::PortableEntryMetadata> {
        let identity = key.to_string();
        let Some(proof) = self.read.metadata_observations.iter().find(|proof| proof.key == identity) else {
            return Ok(actual);
        };
        if proof.local_metadata.as_ref() != Some(&actual)
            || proof.digest.as_ref() != Some(&content.content_id) || proof.bytes != content.length {
            return Ok(actual);
        }
        let Some(entry) = self.read.read.manifest.entries.values()
            .find(|entry| entry.path.as_str() == proof.path && entry.content.as_ref() == Some(content)) else {
            return Ok(actual);
        };
        let Some(logical) = &entry.metadata else { return Ok(actual); };
        // The caller holds this exact physical file and its retained parent;
        // the proof may follow a real rename, never a same-byte replacement.
        if managed(path, &self.read.read.worktree)
            && logical.matches_local_projection(&actual, PortableMetadataProjectionPlatform::Windows)? {
            return Ok(logical.clone());
        }
        Ok(actual)
    }

    pub(crate) fn finish_deployment_polling(&mut self) -> Result<()> {
        if self.polling.is_some() {
            self.scan_deployment_polling(crate::now_ms()?)?;
        }
        Ok(())
    }
    pub(crate) fn enable_deployment_polling(&mut self, limits: LocalLimits) -> Result<()> {
        self.deployment_runtime_binding()?.verify()?;
        limits.validate()?;
        if self.polling.is_some() || self.history_count != 0 || self.metadata_count != 0 {
            return Err(ReconcileError::Invariant(
                "polling requires the original new generation",
            ));
        }
        self.constrain_recovered_entry_limit(
            limits.max_scan_entries.min(self.manifest_entry_limit),
        )?;
        self.polling = Some(RecoveredPollingState {
            limits,
            detached: false,
            closed: None,
            failed: None,
            pending_files: Vec::new(),
            pending_directories: Vec::new(),
            observations: None,
        });
        let raw = self.held_polling_scan()?;
        let mut observations = self.polling_observations(&self.read.read.manifest, &raw)?;
        let proofs: BTreeMap<_, _> = self.read.metadata_observations.iter()
            .filter(|object| object.root == "work" && !object.directory)
            .map(|object| (object.path.as_str(), object)).collect();
        let parents: BTreeMap<_, _> = self.read.read.files.iter()
            .filter(|file| managed(&file.path, &self.read.read.worktree))
            .map(|file| Ok((portable_relative(&file.path, &self.read.read.worktree)?, file.file.parent_key()?.to_string())))
            .collect::<Result<_>>()?;
        for row in &mut observations.entries {
            if row.observed.kind != EntryKind::File { continue; }
            // Only the actual original CREATE completion or the verified closed
            // generation may supply the previous capture. A new FD alone cannot.
            let proof = proofs.get(row.observed.path.as_str());
            row.observed.local_metadata = proof.and_then(|proof| {
                row.observed.content.as_ref().filter(|content| {
                    proof.digest.as_ref() == Some(&content.content_id) && proof.bytes == content.length
                        && parents.get(&row.observed.path) == Some(&proof.parent)
                }).and(proof.local_metadata.clone())
            });
            if let Some(proof) = proof {
                row.observed.physical_identity = ContentId::hash(proof.key.as_bytes());
            }
        }
        observations.validate(&self.read.read.manifest, self.manifest_entry_limit)?;
        self.polling.as_mut().expect("selected polling").observations = Some(observations);
        // Full original scope has been audited before any observation protection ends.
        self.release_polling_observation()
    }

    pub(crate) fn release_polling_observation(&mut self) -> Result<()> {
        self.verify()?;
        let Some(state) = self.polling.as_ref() else {
            return Ok(());
        };
        if state.detached {
            return Ok(());
        }
        let root = self.read.read.worktree.clone();
        self.poisoned = true;
        let mut terminal = WindowsOriginalCloseAttempt::new();
        let state = self.polling.as_mut().expect("checked polling");
        if let Some(closed) = state.closed.take() {
            terminal.append_result(Ok(closed));
        }
        let mut retained = Vec::new();
        for original in self.read.read.files.drain(..) {
            if managed(&original.path, &root) {
                original.file.close_into_attempt(&mut terminal);
            } else {
                retained.push(original);
            }
        }
        self.read.read.files = retained;
        let mut retained = Vec::new();
        for original in self.read.read.directories.drain(..).rev() {
            if managed(&original.path, &root) {
                terminal.close_directory(original.file);
            } else {
                retained.push(original);
            }
        }
        retained.reverse();
        self.read.read.directories = retained;
        for (_, original) in std::mem::take(&mut self.created_work_directories) {
            original.close_into_attempt(&mut terminal);
        }
        self.read
            .read
            .expected_membership
            .retain(|path, _| path != &root && !managed(path, &root));
        // .sync-extend and every retained internal descendant keep their own
        // original directory keys, exact contents and membership checks. The
        // root handle itself remains retained with rename/delete exclusion.
        match terminal.finish() {
            Ok(closed) => state.closed = Some(closed),
            Err(failed) => {
                let message = failed.error.to_string();
                state.failed = Some(failed);
                return Err(ReconcileError::Io(std::io::Error::other(message)));
            }
        }
        state.detached = true;
        self.poisoned = false;
        self.verify()
    }

    pub(crate) fn request_deployment_native_mutations(&mut self) -> Result<()> {
        self.deployment_runtime_binding()?.verify()?;
        self.mutation_requested = true;
        self.verify()
    }

    pub(crate) fn polling_mutation_observation(&mut self) -> Result<()> {
        self.verify()?;
        if self.polling.as_ref().is_some_and(|state| state.detached) {
            return Err(ReconcileError::Invariant(
                "authorized mutation requires a current stable observation",
            ));
        }
        // The existing native mutation API independently checks its explicit
        // same-session mutation grant; observation alone cannot create one.
        if !self.mutation_requested {
            return Ok(());
        }
        let root = self.read.read.worktree.clone();
        let targets = self
            .read
            .read
            .files
            .iter()
            .filter(|file| managed(&file.path, &root))
            .map(|file| file.path.clone())
            .collect::<Vec<_>>();
        for path in targets {
            let index = self
                .read
                .read
                .files
                .iter()
                .position(|file| file.path == path)
                .ok_or(ReconcileError::Unstable)?;
            if !matches!(
                self.read.read.files[index].file,
                RecoveredFileProtection::Read(_)
            ) {
                continue;
            }
            let old_key = self.read.read.files[index].file.key()?;
            let old_metadata = self.read.read.files[index].file.portable_metadata()?;
            let parent = path.parent().ok_or(ReconcileError::Unstable)?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ReconcileError::Unstable)?;
            self.poisoned = true;
            let original = self.read.read.files.remove(index);
            let mut terminal = WindowsOriginalCloseAttempt::new();
            original.file.close_into_attempt(&mut terminal);
            if let Some(closed) = self.mutation_observation_closed.take() {
                terminal.append_result(Ok(closed));
            }
            match terminal.finish() {
                Ok(closed) => self.mutation_observation_closed = Some(closed),
                Err(failed) => {
                    let message = failed.error.to_string();
                    self.mutation_observation_failed = Some(failed);
                    return Err(ReconcileError::Io(std::io::Error::other(message)));
                }
            }
            let held = self
                .read
                .read
                .directories
                .iter()
                .find(|held| held.path == parent)
                .ok_or(ReconcileError::Unstable)?;
            let acquired = held.file.reacquire_existing_node_mutation_file(name)?;
            let parent_key = held.key;
            let file = RecoveredFileProtection::Mutation(acquired);
            self.read.read.files.insert(
                index,
                ReacquiredFile {
                    path,
                    file,
                    digest: original.digest,
                    bytes: original.bytes,
                },
            );
            let retained = &self.read.read.files[index];
            if retained.file.key()? != old_key
                || retained.file.portable_metadata()? != old_metadata
                || retained.file.parent_key()? != parent_key
                || !retained.file.matches_path(&retained.path)?
                || ContentId::hash(&retained.file.exact_bytes(retained.bytes)?) != retained.digest
            {
                return Err(ReconcileError::Unstable);
            }
            self.poisoned = false;
            self.verify()?;
        }
        Ok(())
    }
    pub(crate) fn polling_limits(&self) -> Option<serde_json::Value> {
        self.polling.as_ref().map(|state| serde_json::json!({
            "max_scan_entries": state.limits.max_scan_entries.min(self.bounds.max_entries),
            "max_scan_bytes": state.limits.max_scan_bytes.min(self.bounds.capacity.max_logical_bytes).min(64 * 1024 * 1024),
            "max_file_bytes": state.limits.max_file_bytes.min(8 * 1024 * 1024),
            "max_scan_chunks": state.limits.max_scan_chunks,
            "max_file_chunks": 128,
            "native_history_commits_per_generation": FRESH_OPERATION_MAXIMUM,
            "ordinary_local_space_opened": false,
        }))
    }
    fn acquire_polling_observation(&mut self) -> Result<crate::scan::Scan> {
        self.verify()?;
        let state = self
            .polling
            .as_ref()
            .ok_or(ReconcileError::Invariant("polling not selected"))?;
        if !state.detached {
            return self.held_polling_scan();
        }
        let limits = state.limits.clone();
        let root = self.read.read.worktree.clone();
        let entry_limit = limits.max_scan_entries.min(self.bounds.max_entries);
        let bytes_limit = limits
            .max_scan_bytes
            .min(self.bounds.capacity.max_logical_bytes)
            .min(64 * 1024 * 1024);
        let file_limit = limits.max_file_bytes.min(8 * 1024 * 1024);
        self.poisoned = true;
        let mut pending = vec![root.clone()];
        let mut entries = 0usize;
        let mut bytes = 0u64;
        while let Some(path) = pending.pop() {
            if path.components().count() > 256 || pending.len() > entry_limit {
                return Err(ReconcileError::ResourceLimit(
                    "polling directory depth and count",
                ));
            }
            if !self
                .read
                .read
                .directories
                .iter()
                .any(|held| held.path == path)
            {
                // Ancestors remain held with no DELETE sharing. Verify the exact
                // child slot before accepting its newly opened observation handle.
                let parent = path
                    .parent()
                    .ok_or(ReconcileError::Invariant("polling child parent"))?;
                let held = self
                    .read
                    .read
                    .directories
                    .iter()
                    .find(|held| held.path == parent)
                    .ok_or(ReconcileError::Invariant(
                        "polling retained ancestor absent",
                    ))?;
                if !held.file.matches_path(parent)? {
                    return Err(ReconcileError::Unstable);
                }
                let volume = held.key.volume;
                let file = LockedDirectory::open(&path)?;
                let state = self.polling.as_mut().expect("selected polling");
                state.pending_directories.push(file);
                let file = state
                    .pending_directories
                    .last()
                    .expect("retained acquisition");
                file.require_local_ntfs(&path)?;
                file.require_case_insensitive()?;
                let key = file.key()?;
                if key.volume != volume || !file.matches_path(&path)? {
                    return Err(ReconcileError::Unstable);
                }
                let file = state
                    .pending_directories
                    .pop()
                    .expect("verified acquisition");
                self.read.read.directories.push(ReacquiredDirectory {
                    path: path.clone(),
                    file,
                    key,
                });
            }
            let held = self
                .read
                .read
                .directories
                .iter()
                .find(|held| held.path == path)
                .ok_or(ReconcileError::Invariant(
                    "polling retained directory absent",
                ))?;
            if !held.file.matches_path(&path)? {
                return Err(ReconcileError::Unstable);
            }
            let mut names = BTreeSet::new();
            let mut aliases = BTreeSet::new();
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| ReconcileError::Invariant("polling UTF-8 name"))?;
                entries = entries
                    .checked_add(1)
                    .filter(|n| *n <= entry_limit)
                    .ok_or(ReconcileError::ResourceLimit("polling entry budget"))?;
                if !names.insert(name.clone()) || !aliases.insert(name.to_uppercase()) {
                    return Err(ReconcileError::Invariant("polling duplicate portable name"));
                }
                let target = entry.path();
                let metadata = std::fs::symlink_metadata(&target)?;
                if metadata.file_type().is_symlink() || sync_extend_cas::is_reparse(&metadata) {
                    return Err(ReconcileError::Invariant("polling link or reparse member"));
                }
                if !managed(&target, &root) {
                    continue;
                }
                let relative = target
                    .strip_prefix(&root)
                    .map_err(|_| ReconcileError::Unstable)?;
                PortablePath::new(
                    relative
                        .iter()
                        .map(|part| part.to_str().ok_or(ReconcileError::Unstable))
                        .collect::<Result<Vec<_>>>()?
                        .join("/"),
                )?;
                if metadata.is_dir() {
                    pending.push(target);
                } else if metadata.is_file() {
                    bytes = bytes
                        .checked_add(metadata.len())
                        .filter(|n| *n <= bytes_limit)
                        .ok_or(ReconcileError::ResourceLimit(
                            "polling aggregate content budget",
                        ))?;
                    // Fresh read-only acquisition rejects reparse points/hardlinks
                    // and excludes concurrent WRITE/DELETE for this complete scan.
                    let file = held.file.reacquire_existing_node_read_file(&name)?;
                    let state = self.polling.as_mut().expect("selected polling");
                    state
                        .pending_files
                        .push(RecoveredFileProtection::Read(file));
                    let file = state.pending_files.last().expect("retained acquisition");
                    if file.parent_key()? != held.key || !file.matches_path(&target)? {
                        return Err(ReconcileError::Unstable);
                    }
                    let content = file.exact_bytes(file_limit)?;
                    if content.len() as u64 != metadata.len() {
                        return Err(ReconcileError::Unstable);
                    }
                    let file = state.pending_files.pop().expect("verified acquisition");
                    self.read.read.files.push(ReacquiredFile {
                        path: target,
                        digest: ContentId::hash(&content),
                        bytes: content.len() as u64,
                        file,
                    });
                } else {
                    return Err(ReconcileError::Invariant("polling unsupported member"));
                }
            }
            self.read.read.expected_membership.insert(path, names);
        }
        self.polling.as_mut().expect("selected polling").detached = false;
        self.poisoned = false;
        self.verify()?;
        let first = self.held_polling_scan()?;
        let second = self.held_polling_scan()?;
        if first != second {
            self.poisoned = true;
            return Err(ReconcileError::Unstable);
        }
        Ok(second)
    }

    fn held_polling_scan(&self) -> Result<crate::scan::Scan> {
        self.verify()?;
        let limits = &self
            .polling
            .as_ref()
            .ok_or(ReconcileError::Invariant("polling not selected"))?
            .limits;
        let root = &self.read.read.worktree;
        let mut scan = BTreeMap::new();
        let mut chunks = 0usize;
        for directory in &self.read.read.directories {
            if !managed(&directory.path, root) {
                continue;
            }
            let path = portable_relative(&directory.path, root)?;
            scan.insert(
                path,
                crate::scan::ScannedEntry {
                    kind: EntryKind::Directory,
                    content: None,
                    metadata: None,
                    physical_identity: ContentId::hash(
                        format!("windows:{}:{}", directory.key.volume, directory.key.id).as_bytes(),
                    ),
                    single_link: false,
                },
            );
        }
        for file in &self.read.read.files {
            if !managed(&file.path, root) {
                continue;
            }
            let bytes = file
                .file
                .exact_bytes(limits.max_file_bytes.min(8 * 1024 * 1024))?;
            let plan = sync_extend_cas::plan_bounded_content(
                &bytes,
                limits.max_file_bytes.min(8 * 1024 * 1024),
                limits.max_scan_chunks.saturating_sub(chunks).min(128),
            )?;
            chunks = chunks
                .checked_add(plan.chunks.len())
                .filter(|n| *n <= limits.max_scan_chunks)
                .ok_or(ReconcileError::ResourceLimit(
                    "polling aggregate chunk budget",
                ))?;
            let key = file.file.key()?;
            scan.insert(
                portable_relative(&file.path, root)?,
                crate::scan::ScannedEntry {
                    kind: EntryKind::File,
                    content: Some(plan.manifest),
                    metadata: Some(crate::filesystem::portable_metadata_from_capture(
                        file.file.portable_metadata()?,
                    )?),
                    physical_identity: ContentId::hash(
                        format!("windows:{}:{}", key.volume, key.id).as_bytes(),
                    ),
                    single_link: true,
                },
            );
        }
        if scan.len() > limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit(
                "polling manifest entry budget",
            ));
        }
        self.verify()?;
        Ok(scan)
    }

    fn polling_scope(&self, manifest: &Manifest) -> Result<RenameObservationScope> {
        let root = self.read.read.directories.iter()
            .find(|held| held.path == self.read.read.worktree).ok_or(ReconcileError::Unstable)?;
        Ok(RenameObservationScope {
            format_version: FORMAT_VERSION,
            space_id: self.space.clone(),
            prior_snapshot: manifest.root()?,
            local_root_identity: ContentId::hash(root.key.to_string().as_bytes()),
            platform_epoch: ContentId::hash(format!("recovered-windows-observation-v1:{}", self.fresh).as_bytes()),
        })
    }

    pub(super) fn refresh_polling_after_commit(&mut self, operations: &[Operation]) -> Result<()> {
        let mut observations = super::history_current_objects(&self.read.read)?;
        let put_paths: BTreeSet<_> = operations.iter().filter_map(|op| match &op.payload.change {
            Change::Put { entry } => Some(entry.path.as_str()), _ => None,
        }).collect();
        let old: BTreeMap<_, _> = self.read.metadata_observations.iter()
            .map(|object| (object.key.as_str(), object)).collect();
        for object in &mut observations {
            if !put_paths.contains(object.path.as_str()) {
                object.local_metadata = old.get(object.key.as_str())
                    .and_then(|prior| prior.local_metadata.clone());
            }
        }
        self.read.metadata_observations = observations;
        if self.polling.is_none() { return Ok(()); }
        let raw = self.held_polling_scan()?;
        let mut map = self.polling_observations(&self.read.read.manifest, &raw)?;
        let old: BTreeMap<_, _> = self.polling.as_ref().and_then(|state| state.observations.as_ref())
            .into_iter().flat_map(|map| &map.entries).map(|row| (&row.entry_id, &row.observed)).collect();
        for row in &mut map.entries {
            if !put_paths.contains(row.observed.path.as_str()) {
                if let Some(prior) = old.get(&row.entry_id) {
                    row.observed.local_metadata = prior.local_metadata.clone();
                    row.observed.physical_identity = prior.physical_identity.clone();
                } else {
                    row.observed.local_metadata = None;
                }
            }
        }
        self.polling.as_mut().expect("selected polling").observations = Some(map);
        Ok(())
    }

    fn polling_observations(&self, manifest: &Manifest, scanned: &crate::scan::Scan) -> Result<RenameObservationMap> {
        let map = RenameObservationMap {
            scope: self.polling_scope(manifest)?,
            entries: manifest.entries.values().map(|entry| {
                let actual = scanned.get(&entry.path).ok_or(ReconcileError::Unstable)?;
                if actual.kind != entry.kind || actual.content != entry.content {
                    return Err(ReconcileError::Unstable);
                }
                Ok(PriorRenameObservation { entry_id: entry.entry_id.clone(), observed: polling_observation(&entry.path, actual) })
            }).collect::<Result<Vec<_>>>()?,
        };
        map.validate(manifest, self.manifest_entry_limit)?;
        Ok(map)
    }

    fn polling_logical_scan(&self, prior: &Manifest, raw: &crate::scan::Scan) -> Result<(crate::scan::Scan, BTreeSet<EntryId>)> {
        let map = self.polling.as_ref().and_then(|state| state.observations.as_ref())
            .ok_or(ReconcileError::Invariant("polling original observation absent"))?;
        if map.scope != self.polling_scope(prior)? {
            return Err(ReconcileError::Invariant("polling original observation scope differs"));
        }
        map.validate(prior, self.manifest_entry_limit)?;
        let mut result = raw.clone();
        let mut changed = BTreeSet::new();
        let mut by_identity = BTreeMap::new();
        for (path, observed) in raw {
            if observed.kind == EntryKind::File && observed.single_link
                && by_identity.insert(&observed.physical_identity, path).is_some() {
                return Err(ReconcileError::Invariant("polling ambiguous physical observation"));
            }
        }
        for row in &map.entries {
            let entry = prior.entries.get(&row.entry_id).ok_or(ReconcileError::Unstable)?;
            if entry.kind != EntryKind::File { continue; }
            if raw.get(&entry.path).is_some_and(|actual| actual.kind == entry.kind
                && actual.physical_identity != row.observed.physical_identity) {
                changed.insert(entry.entry_id.clone());
            }
            let Some(path) = by_identity.get(&row.observed.physical_identity) else { continue; };
            let actual = result.get_mut(*path).ok_or(ReconcileError::Unstable)?;
            if preserves_logical_metadata(entry, &row.observed, &polling_observation(path, actual), PortableMetadataProjectionPlatform::Windows)? {
                actual.metadata = entry.metadata.clone();
            } else if entry.metadata.is_some() {
                // A missing old capture or any changed field becomes a genuine
                // Put, even if the logical supported fields happen to compare equal.
                changed.insert(entry.entry_id.clone());
            }
        }
        Ok((result, changed))
    }

    pub(crate) fn scan_deployment_polling(&mut self, timestamp: u64) -> Result<crate::ScanResult> {
        let result = self.scan_deployment_polling_inner(timestamp);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn scan_deployment_polling_inner(&mut self, timestamp: u64) -> Result<crate::ScanResult> {
        let raw = self.acquire_polling_observation()?;
        let previous = self.read.read.manifest.clone();
        let (scanned, changed_physical) = self.polling_logical_scan(&previous, &raw)?;
        let mut manifest = crate::build_manifest(&previous, &scanned, &BTreeMap::new())?;
        let origin = self.recovered_device_id()?;
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
                    if old.kind != entry.kind
                        || old.content != entry.content
                        || old.metadata != entry.metadata
                        || changed_physical.contains(&entry.entry_id)
                    {
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
            let sequence = manifest
                .version_vector
                .get(&origin)
                .checked_add(1)
                .ok_or(ReconcileError::Invariant("polling sequence overflow"))?;
            let operation = Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.space.clone(),
                origin_device_id: origin.clone(),
                origin_seq: sequence,
                causal: manifest.version_vector.clone(),
                change,
                created_at_ms: timestamp,
            })?;
            if let Change::Delete { entry_id } = &operation.payload.change {
                manifest
                    .tombstones
                    .insert(entry_id.clone(), operation.op_id.clone());
            }
            manifest.version_vector.observe(origin.clone(), sequence);
            operations.push(operation);
        }
        let operation_count = operations.len();
        let root = if operations.is_empty() {
            manifest.root()?
        } else {
            let held: BTreeSet<_> = self.read.read.files.iter()
                .filter(|file| file.path.starts_with(self.read.read.data.join("cas/objects")))
                .map(|file| &file.digest).collect();
            let missing: BTreeSet<_> = scanned.values().filter_map(|entry| entry.content.as_ref())
                .flat_map(|content| &content.chunks).map(|chunk| &chunk.content_id)
                .filter(|id| !held.contains(id)).collect();
            self.preflight_history_close_envelope(None, false, missing.len(), 1, 3)?;
            let bytes = self.native.exact_main_bytes()?;
            let image = sync_extend_journal::JournalBackupImage::from_current_node_image(
                bytes.clone(),
                ContentId::hash(&bytes).as_str(),
                bytes.len(),
                &self.space,
                self.bounds,
            )?;
            // Validate the actual history plan/budget before CAS-side CREATE.
            image.plan_recovered_local_history(
                &self.space,
                &previous.root()?,
                &manifest,
                &operations,
                timestamp,
                self.bounds,
            )?;
            self.publish_polling_content(&scanned, timestamp)?;
            self.commit_exact_recovered_history(manifest.clone(), operations, timestamp)?
        };
        let observations = self.polling_observations(&manifest, &raw)?;
        self.polling.as_mut().expect("selected polling").observations = Some(observations);
        self.verify()?;
        Ok(crate::ScanResult {
            space_id: self.space.clone(),
            snapshot_id: root,
            entries: manifest.entries.len(),
            operations: operation_count,
            files: manifest
                .entries
                .values()
                .filter(|entry| entry.kind == EntryKind::File)
                .count(),
            logical_bytes: manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .map(|content| content.length)
                .sum(),
            network_enabled: false,
        })
    }

    fn publish_polling_content(
        &mut self,
        scanned: &crate::scan::Scan,
        timestamp: u64,
    ) -> Result<()> {
        self.verify()?;
        if self.history_count >= FRESH_OPERATION_MAXIMUM
            || self.metadata_count != 0
            || self
                .retained_receipt_bytes
                .checked_add(2 * 256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
        {
            return Err(ReconcileError::ResourceLimit(
                "polling history preeffect budget",
            ));
        }
        let limits = &self
            .polling
            .as_ref()
            .ok_or(ReconcileError::Invariant("polling not selected"))?
            .limits;
        let mut missing = BTreeMap::new();
        let mut new_bytes = 0u64;
        for (path, entry) in scanned {
            let Some(content) = &entry.content else {
                continue;
            };
            let target = self.read.read.worktree.join(path.as_str());
            let file = self
                .read
                .read
                .files
                .iter()
                .find(|file| file.path == target)
                .ok_or(ReconcileError::Invariant("polling content unheld"))?;
            let bytes = file.file.exact_bytes(8 * 1024 * 1024)?;
            let plan = sync_extend_cas::plan_bounded_content(&bytes, 8 * 1024 * 1024, 128)?;
            if &plan.manifest != content {
                return Err(ReconcileError::Unstable);
            }
            for (chunk, bytes) in plan.chunks {
                let id = chunk.content_id.as_str();
                let path = self
                    .read
                    .read
                    .data
                    .join("cas/objects")
                    .join(&id[..2])
                    .join(id);
                if let Some(file) = self.read.read.files.iter().find(|file| file.path == path) {
                    if file.digest != chunk.content_id
                        || file.bytes != u64::from(chunk.length)
                        || file.file.exact_bytes(file.bytes)? != bytes
                    {
                        return Err(ReconcileError::Invariant(
                            "polling existing CAS exact bytes",
                        ));
                    }
                } else if !missing.contains_key(&chunk.content_id) {
                    new_bytes = new_bytes
                        .checked_add(bytes.len() as u64)
                        .ok_or(ReconcileError::ResourceLimit("polling CAS bytes overflow"))?;
                    missing.insert(chunk.content_id, bytes);
                }
            }
        }
        if new_bytes > limits.max_staging_bytes
            || self
                .new_cas_bytes
                .checked_add(new_bytes)
                .is_none_or(|n| n > 64 * 1024 * 1024)
            || self
                .new_cas_objects
                .checked_add(missing.len())
                .is_none_or(|n| n > FRESH_CAS_OBJECT_MAXIMUM)
        {
            return Err(ReconcileError::ResourceLimit(
                "polling CAS preeffect budget",
            ));
        }
        if missing.is_empty() {
            return Ok(());
        }
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("polling external parent"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|held| held.path == external)
            .ok_or(ReconcileError::Invariant("polling external owner absent"))?;
        let intended = serde_json::to_vec(&(
            1u32,
            &self.archive,
            &self.fresh,
            "scan",
            timestamp,
            missing
                .iter()
                .map(|(id, bytes)| (id, bytes.len()))
                .collect::<Vec<_>>(),
        ))?;
        if intended.len() > 65536 {
            return Err(ReconcileError::ResourceLimit("polling CAS intended bytes"));
        }
        self.poisoned = true;
        let mut receipt = held.file.create_new_file(&format!(
            "node-recovered-cas-{}-{}.frames",
            self.fresh, self.history_count
        ))?;
        receipt.writer().write_all(&intended)?;
        receipt.writer().sync_all()?;
        for (id, bytes) in &missing {
            let bucket = self
                .read
                .read
                .data
                .join("cas/objects")
                .join(&id.as_str()[..2]);
            if !self
                .read
                .read
                .directories
                .iter()
                .any(|held| held.path == bucket)
            {
                let root = self.read.read.data.join("cas/objects");
                let held = self
                    .read
                    .read
                    .directories
                    .iter()
                    .find(|held| held.path == root)
                    .ok_or(ReconcileError::Invariant("polling CAS root absent"))?;
                let creator = held.file.create_new_child(&id.as_str()[..2])?;
                let key = creator.key()?;
                let file = creator.duplicate_read_guard()?;
                self.read
                    .read
                    .expected_membership
                    .get_mut(&root)
                    .ok_or(ReconcileError::Unstable)?
                    .insert(id.as_str()[..2].to_owned());
                self.read
                    .read
                    .expected_membership
                    .insert(bucket.clone(), BTreeSet::new());
                self.read.read.directories.push(ReacquiredDirectory {
                    path: bucket.clone(),
                    file,
                    key,
                });
                self.new_cas_buckets
                    .insert(bucket.clone(), RecoveredCasBucket { creator, key });
            }
            let held = self
                .read
                .read
                .directories
                .iter()
                .find(|held| held.path == bucket)
                .ok_or(ReconcileError::Invariant("polling CAS bucket absent"))?;
            let mut creator = held.file.create_new_file(id.as_str())?;
            creator.writer().write_all(bytes)?;
            creator.writer().sync_all()?;
            let sealed = creator.seal_original()?;
            let path = bucket.join(id.as_str());
            if !sealed.matches_path(&path)? || sealed.parent_key()? != held.key {
                return Err(ReconcileError::Unstable);
            }
            self.read.read.files.push(ReacquiredFile {
                path,
                file: RecoveredFileProtection::Created(sealed),
                digest: id.clone(),
                bytes: bytes.len() as u64,
            });
            self.read
                .read
                .expected_membership
                .get_mut(&bucket)
                .ok_or(ReconcileError::Unstable)?
                .insert(id.to_string());
        }
        self.new_cas_bytes += new_bytes;
        self.new_cas_objects += missing.len();
        receipt.writer().write_all(&serde_json::to_vec(&(
            1u32,
            "committed",
            &self.fresh,
            new_bytes,
        ))?)?;
        receipt.writer().sync_all()?;
        self.retain_recovered_receipt(receipt)?;
        self.poisoned = false;
        self.verify()
    }
}

fn polling_observation(path: &PortablePath, entry: &crate::scan::ScannedEntry) -> RenamePathObservation {
    RenamePathObservation {
        path: path.clone(), kind: entry.kind, content: entry.content.clone(),
        physical_identity: entry.physical_identity.clone(), single_link: entry.single_link,
        local_metadata: entry.metadata.clone(),
    }
}
fn portable_relative(path: &Path, root: &Path) -> Result<PortablePath> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ReconcileError::Unstable)?;
    Ok(PortablePath::new(
        relative
            .iter()
            .map(|part| part.to_str().ok_or(ReconcileError::Unstable))
            .collect::<Result<Vec<_>>>()?
            .join("/"),
    )?)
}
