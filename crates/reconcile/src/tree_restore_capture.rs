//! Fresh, retained read-only tree observations; never durable native admission.

use crate::{LocalSpace, Result};
use sync_extend_core_model::tree_restore_identity::{TreeIdentityLimits, TreeIdentityPlan};
use sync_extend_journal::{CasAccessGuard, TreeRestoreHistoryIntent};

/// Holds the existing LocalSpace process locks and native/CAS read guards.
/// Directory membership is not frozen; this cannot authorize a future step.
pub struct TreeRestoreCapture<'a, T> {
    _local: &'a LocalSpace,
    _guards: (CasAccessGuard, Box<dyn Send>),
    plan: TreeIdentityPlan,
    inspection: T,
}

impl<T> TreeRestoreCapture<'_, T> {
    pub fn identity_plan(&self) -> &TreeIdentityPlan {
        &self.plan
    }

    pub fn inspection(&self) -> &T {
        &self.inspection
    }

    pub fn transient_guarded_observation_complete(&self) -> bool {
        true
    }

    pub fn execution_admission_available(&self) -> bool {
        false
    }
}

impl LocalSpace {
    /// Always recapture under shared CAS and SQLite writer exclusion.
    /// Callback errors and native recheck failures preserve all durable state.
    pub fn with_tree_restore_capture<T>(
        &self,
        intent: &TreeRestoreHistoryIntent,
        bounds: TreeIdentityLimits,
        inspect: impl FnOnce(&TreeIdentityPlan) -> Result<T>,
    ) -> Result<TreeRestoreCapture<'_, T>> {
        self.verify_root()?;
        self.capture_tree_platform(intent, bounds, inspect)
    }

    #[cfg(not(windows))]
    fn capture_tree_platform<T>(
        &self,
        _intent: &TreeRestoreHistoryIntent,
        _bounds: TreeIdentityLimits,
        _inspect: impl FnOnce(&TreeIdentityPlan) -> Result<T>,
    ) -> Result<TreeRestoreCapture<'_, T>> {
        Err(crate::ReconcileError::Invariant(
            "guarded tree observation requires Windows fixed local NTFS",
        ))
    }

    /// Bind an immutable native description, not executable admission.
    pub fn reserve_tree_restore_native_identity(
        &self,
        request: &sync_extend_journal::TreeRestoreNativeRequest,
    ) -> Result<sync_extend_journal::TreeRestoreNativeReservation> {
        self.reserve_tree_native_platform(request)
    }

    #[cfg(not(windows))]
    fn reserve_tree_native_platform(
        &self,
        _request: &sync_extend_journal::TreeRestoreNativeRequest,
    ) -> Result<sync_extend_journal::TreeRestoreNativeReservation> {
        Err(crate::ReconcileError::Invariant(
            "native tree identity capture requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{check_ancestors, fault::checkpoint, filesystem, ReconcileError};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        io::{Read, Seek, SeekFrom},
        path::{Path, PathBuf},
    };
    use sync_extend_cas::is_reparse;
    use sync_extend_core_model::{
        limits::LocalLimits,
        tree_restore::TreeRestorePlan,
        tree_restore_identity::{
            plan_tree_restore_identities, TreeNativeEntry, TreeNativeIdentity, TreeNativeInventory,
            TreeSlotBinding,
        },
        ContentId, EntryKind, FileManifest, Manifest, PortablePath,
    };
    use sync_extend_journal::TreeRestorePreparationIntent;
    use sync_extend_platform_fs::{FileKey, GuardedReadFile, LockedDirectory};

    fn native(key: FileKey) -> TreeNativeIdentity {
        TreeNativeIdentity {
            volume_serial: key.volume,
            file_id: format!("{:032x}", key.id),
        }
    }

    struct Directory {
        path: PathBuf,
        guard: LockedDirectory,
        key: FileKey,
    }

    struct CapturedFile {
        path: PathBuf,
        guard: GuardedReadFile,
        key: FileKey,
        content: FileManifest,
    }

    struct Guards {
        directories: Vec<Directory>,
        files: Vec<CapturedFile>,
        marker: GuardedReadFile,
        marker_key: FileKey,
        marker_path: PathBuf,
        inventory: TreeNativeInventory,
    }

    fn add_directory(directories: &mut Vec<Directory>, path: &Path, max: usize) -> Result<FileKey> {
        if directories.len() >= max {
            return Err(ReconcileError::ResourceLimit(
                "tree native directory handles",
            ));
        }
        check_ancestors(path)?;
        let guard = LockedDirectory::open(path)?;
        guard.require_case_insensitive()?;
        guard.require_local_ntfs(path)?;
        let key = guard.key()?;
        if ContentId::hash(key.to_string().as_bytes()) != filesystem::physical_identity(path)? {
            return Err(ReconcileError::Unstable);
        }
        directories.push(Directory {
            path: path.to_owned(),
            guard,
            key,
        });
        Ok(key)
    }

    fn namespace(
        root: &Path,
        limits: &LocalLimits,
        expected: &BTreeMap<PortablePath, EntryKind>,
    ) -> Result<BTreeMap<PortablePath, EntryKind>> {
        let mut pending = vec![root.to_owned()];
        let mut result = BTreeMap::new();
        let mut collisions = BTreeSet::new();
        while let Some(directory) = pending.pop() {
            check_ancestors(&directory)?;
            for child in fs::read_dir(directory)? {
                let child = child?;
                let name = child.file_name();
                let name = name
                    .to_str()
                    .ok_or(ReconcileError::Invariant("non-UTF8 tree component"))?;
                if [".sync-extend", ".sync-tmp", ".git"]
                    .iter()
                    .any(|internal| name.eq_ignore_ascii_case(internal))
                {
                    continue;
                }
                if result.len() >= limits.max_scan_entries {
                    return Err(ReconcileError::ResourceLimit("tree observation entries"));
                }
                let path = child.path();
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| ReconcileError::Invariant("tree observation escaped root"))?;
                let portable = PortablePath::new(
                    relative
                        .iter()
                        .map(|c| {
                            c.to_str()
                                .ok_or(ReconcileError::Invariant("non-UTF8 tree component"))
                        })
                        .collect::<Result<Vec<_>>>()?
                        .join("/"),
                )?;
                if !collisions.insert(portable.collision_key()) {
                    return Err(ReconcileError::Invariant("tree observation case alias"));
                }
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink() || is_reparse(&metadata) {
                    return Err(ReconcileError::Invariant("tree observation link/reparse"));
                }
                let kind = if metadata.is_dir() {
                    EntryKind::Directory
                } else if metadata.is_file() {
                    EntryKind::File
                } else {
                    return Err(ReconcileError::Invariant("tree observation special file"));
                };
                if expected.get(&portable) != Some(&kind) {
                    return Err(ReconcileError::Invariant("tree observation foreign entry"));
                }
                if kind == EntryKind::Directory {
                    pending.push(path);
                }
                result.insert(portable, kind);
            }
        }
        Ok(result)
    }

    fn verify_file(file: &CapturedFile) -> Result<()> {
        file.guard.verify_single_link()?;
        if file.guard.key()? != file.key
            || filesystem::physical_identity(&file.path)?
                != ContentId::hash(file.key.to_string().as_bytes())
            || file.guard.reader().metadata()?.len() != file.content.length
        {
            return Err(ReconcileError::Unstable);
        }
        let before = file.guard.reader().metadata()?;
        let mut reader = file.guard.reader();
        reader.seek(SeekFrom::Start(0))?;
        let mut hasher = blake3::Hasher::new();
        let mut left = file.content.length;
        let mut buffer = [0u8; 65536];
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if n as u64 > left {
                return Err(ReconcileError::Unstable);
            }
            left -= n as u64;
            hasher.update(&buffer[..n]);
        }
        if left != 0
            || ContentId::from_hasher(&hasher) != file.content.content_id
            || !filesystem::same_metadata(&before, &file.guard.reader().metadata()?)
            || !filesystem::same_metadata(&before, &fs::symlink_metadata(&file.path)?)
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }

    fn verify_budget(baseline: &Manifest, target: &Manifest, limits: &LocalLimits) -> Result<()> {
        for manifest in [baseline, target] {
            let mut bytes = 0u64;
            let mut chunks = 0usize;
            if manifest.entries.len() > limits.max_scan_entries {
                return Err(ReconcileError::ResourceLimit("tree observation entries"));
            }
            for file in manifest.entries.values().filter_map(|e| e.content.as_ref()) {
                bytes = bytes
                    .checked_add(file.length)
                    .filter(|n| *n <= limits.max_scan_bytes)
                    .ok_or(ReconcileError::ResourceLimit("tree observation bytes"))?;
                chunks = chunks
                    .checked_add(file.chunks.len())
                    .filter(|n| *n <= limits.max_scan_chunks)
                    .ok_or(ReconcileError::ResourceLimit("tree observation chunks"))?;
                if file.length > limits.max_file_bytes {
                    return Err(ReconcileError::ResourceLimit("tree observation file bytes"));
                }
            }
        }
        Ok(())
    }

    impl Guards {
        fn verify(&self, local: &LocalSpace, plan: &TreeIdentityPlan) -> Result<()> {
            local.verify_root()?;
            for directory in &self.directories {
                directory.guard.require_case_insensitive()?;
                if directory.guard.key()? != directory.key
                    || filesystem::physical_identity(&directory.path)?
                        != ContentId::hash(directory.key.to_string().as_bytes())
                {
                    return Err(ReconcileError::Unstable);
                }
            }
            self.marker.verify_single_link()?;
            let mut marker = Vec::new();
            let mut reader = self.marker.reader();
            reader.seek(SeekFrom::Start(0))?;
            reader.take(33).read_to_end(&mut marker)?;
            if marker != local.space_id.as_str().as_bytes()
                || self.marker.key()? != self.marker_key
                || filesystem::physical_identity(&self.marker_path)?
                    != ContentId::hash(self.marker_key.to_string().as_bytes())
            {
                return Err(ReconcileError::Invariant("tree observation marker changed"));
            }
            let expected = self
                .inventory
                .entries
                .iter()
                .map(|(path, entry)| (path.clone(), entry.kind))
                .collect();
            if namespace(&local.worktree, &local.limits, &expected)? != expected {
                return Err(ReconcileError::Invariant(
                    "tree observation namespace changed",
                ));
            }
            for file in &self.files {
                verify_file(file)?;
            }
            for step in plan.steps() {
                if matches!(step.slot, TreeSlotBinding::InitiallyAbsent) {
                    match fs::symlink_metadata(local.worktree.join(step.path.as_str())) {
                        Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => {}
                        Err(e) => return Err(e.into()),
                        Ok(_) => {
                            return Err(ReconcileError::Invariant(
                                "tree observation initial slot occupied",
                            ))
                        }
                    }
                }
            }
            Ok(())
        }
    }

    fn capture(
        local: &LocalSpace,
        preparation: &TreeRestorePreparationIntent,
        tree: &TreeRestorePlan,
        baseline: &Manifest,
        target: &Manifest,
        bounds: TreeIdentityLimits,
    ) -> Result<(Guards, TreeIdentityPlan)> {
        verify_budget(baseline, target, &local.limits)?;
        if bounds.max_bindings == 0
            || bounds.max_bindings > sync_extend_core_model::limits::MAX_ENTRIES
            || bounds.max_metadata_bytes
                > sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES
        {
            return Err(ReconcileError::ResourceLimit(
                "tree observation identity bounds",
            ));
        }
        let max = bounds.max_bindings.min(local.limits.max_storage_entries);
        let mut directories = Vec::new();
        let mut paths: Vec<_> = local
            .worktree
            .ancestors()
            .filter(|p| p.is_absolute())
            .collect();
        paths.reverse();
        for path in paths {
            add_directory(&mut directories, path, max)?;
        }
        let root = directories
            .last()
            .ok_or(ReconcileError::Invariant(
                "tree observation root unavailable",
            ))?
            .key;
        let marker_directory =
            add_directory(&mut directories, &local.worktree.join(".sync-extend"), max)?;
        if directories.len() >= max {
            return Err(ReconcileError::ResourceLimit(
                "tree observation handle count",
            ));
        }
        let marker_path = local.worktree.join(".sync-extend/space-id");
        let marker = GuardedReadFile::open(&marker_path)?;
        let marker_key = marker.key()?;
        let expected = baseline
            .entries
            .values()
            .map(|e| (e.path.clone(), e.kind))
            .collect();
        let mut entries = BTreeMap::new();
        let mut files = Vec::new();
        let mut ordered: Vec<_> = baseline.entries.values().collect();
        ordered.sort_by_key(|e| (e.kind != EntryKind::Directory, e.path.clone()));
        // Existing parent directories are retained before any descendant file.
        for entry in ordered {
            if directories.len() + files.len() + 1 >= max {
                return Err(ReconcileError::ResourceLimit(
                    "tree observation handle count",
                ));
            }
            let path = local.worktree.join(entry.path.as_str());
            let key = match entry.kind {
                EntryKind::Directory => add_directory(&mut directories, &path, max)?,
                EntryKind::File => {
                    let guard = GuardedReadFile::open(&path)?;
                    let key = guard.key()?;
                    let content = entry.content.clone().ok_or(ReconcileError::Invariant(
                        "tree observation file content absent",
                    ))?;
                    let file = CapturedFile {
                        path,
                        guard,
                        key,
                        content,
                    };
                    verify_file(&file)?;
                    files.push(file);
                    key
                }
            };
            entries.insert(
                entry.path.clone(),
                TreeNativeEntry {
                    entry_id: entry.entry_id.clone(),
                    kind: entry.kind,
                    identity: native(key),
                },
            );
        }
        if namespace(&local.worktree, &local.limits, &expected)? != expected {
            return Err(ReconcileError::Invariant(
                "tree observation baseline mismatch",
            ));
        }
        for manifest in [baseline, target] {
            for file in manifest.entries.values().filter_map(|e| e.content.as_ref()) {
                local.cas.verify(file)?;
            }
        }
        let inventory = TreeNativeInventory {
            transaction_id: preparation.transaction_id.clone(),
            preparation_hash: ContentId::hash(&serde_json::to_vec(preparation)?),
            root: native(root),
            marker_directory: native(marker_directory),
            marker_file: native(marker_key),
            entries,
        };
        let plan = plan_tree_restore_identities(
            tree,
            baseline,
            &preparation.transaction_id,
            &inventory.preparation_hash,
            &inventory,
            bounds,
        )?;
        let guards = Guards {
            directories,
            files,
            marker,
            marker_key,
            marker_path,
            inventory,
        };
        guards.verify(local, &plan)?;
        Ok((guards, plan))
    }

    impl LocalSpace {
        pub(super) fn reserve_tree_native_platform(
            &self,
            request: &sync_extend_journal::TreeRestoreNativeRequest,
        ) -> Result<sync_extend_journal::TreeRestoreNativeReservation> {
            let (held, audit) = self.journal.with_tree_restore_native_identity(
                request,
                self.limits.max_storage_entries,
                |preparation, tree, baseline, target| {
                    self.verify_root()?;
                    let (guards, plan) =
                        capture(self, preparation, tree, baseline, target, request.limits)?;
                    let inventory = plan.inventory().clone();
                    checkpoint("after_tree_native_binding_capture");
                    Ok::<_, ReconcileError>(((guards, baseline.clone(), target.clone()), inventory))
                },
                |(guards, baseline, target), plan| {
                    for snapshot in [baseline, target] {
                        for file in snapshot.entries.values().filter_map(|e| e.content.as_ref()) {
                            self.cas.verify(file)?;
                        }
                    }
                    checkpoint("before_tree_native_binding_recheck");
                    guards.verify(self, plan)?;
                    Ok::<_, ReconcileError>(())
                },
            )?;
            checkpoint("after_tree_native_binding_commit");
            drop(held);
            Ok(audit)
        }

        pub(super) fn capture_tree_platform<T>(
            &self,
            intent: &TreeRestoreHistoryIntent,
            bounds: TreeIdentityLimits,
            inspect: impl FnOnce(&TreeIdentityPlan) -> Result<T>,
        ) -> Result<TreeRestoreCapture<'_, T>> {
            let (cas, (guards, plan, inspection)) =
                self.journal.with_tree_restore_history_observation(
                    intent,
                    self.limits.max_storage_entries,
                    |preparation, tree, baseline, target| {
                        let (guards, plan) =
                            capture(self, preparation, tree, baseline, target, bounds)?;
                        checkpoint("after_tree_native_capture");
                        let inspection = inspect(&plan)?;
                        checkpoint("before_tree_native_capture_recheck");
                        for manifest in [baseline, target] {
                            for file in manifest.entries.values().filter_map(|e| e.content.as_ref())
                            {
                                self.cas.verify(file)?;
                            }
                        }
                        guards.verify(self, &plan)?;
                        Ok::<_, ReconcileError>((
                            Box::new(guards) as Box<dyn Send>,
                            plan,
                            inspection,
                        ))
                    },
                )?;
            Ok(TreeRestoreCapture {
                _local: self,
                _guards: (cas, guards),
                plan,
                inspection,
            })
        }
    }
}
