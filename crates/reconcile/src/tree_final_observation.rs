//! Fresh exact final native observation, not historical action or commit proof.
use crate::{LocalSpace, Result};
use serde::Serialize;
use sync_extend_core_model::{tree_final_transaction::TreeFinalTransactionPlan, ContentId};
use sync_extend_journal::{CasAccessGuard, TreeFinalObservationRequest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeFinalObservationReport {
    pub transaction_hash: ContentId,
    pub native_observation_hash: ContentId,
    pub tree_entries: usize,
    pub retained_originals: usize,
    pub retained_native_handles: usize,
    pub logical_content_bytes: u64,
    pub cas_logical_bytes: u64,
    pub cas_chunk_visits: usize,
    pub transient_guarded_layout_verified: bool,
    pub durable_native_action_evidence: bool,
    pub history_commit_available: bool,
    pub input_reference_release_available: bool,
    pub original_reference_release_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

pub struct TreeFinalObservation<'a> {
    _local: &'a LocalSpace,
    _guards: (CasAccessGuard, Box<dyn Send>),
    transaction: TreeFinalTransactionPlan,
    report: TreeFinalObservationReport,
}
impl TreeFinalObservation<'_> {
    pub fn transaction(&self) -> &TreeFinalTransactionPlan {
        &self.transaction
    }
    /// Describes the last guarded checks, not a frozen directory namespace.
    pub fn report(&self) -> &TreeFinalObservationReport {
        &self.report
    }
}
impl LocalSpace {
    pub fn observe_tree_restore_final(
        &self,
        request: &TreeFinalObservationRequest,
    ) -> Result<TreeFinalObservation<'_>> {
        self.observe_tree_final_platform(request)
    }
    #[cfg(not(windows))]
    fn observe_tree_final_platform(
        &self,
        _request: &TreeFinalObservationRequest,
    ) -> Result<TreeFinalObservation<'_>> {
        Err(crate::ReconcileError::Invariant(
            "final native observation requires guarded Windows",
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
        tree_restore_history::encode_history_record, tree_restore_identity::TreeNativeIdentity,
        EntryKind, FileManifest, PortablePath,
    };
    use sync_extend_journal::TreeFinalObservationInspection;
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
    struct File {
        path: PathBuf,
        guard: GuardedReadFile,
        key: FileKey,
        content: Option<FileManifest>,
        marker: Option<Vec<u8>>,
    }
    struct Guards {
        directories: Vec<Directory>,
        files: Vec<File>,
        user_namespace: BTreeMap<PortablePath, EntryKind>,
        internal_names: BTreeSet<String>,
        owner_directory: PathBuf,
        marker_parent: PathBuf,
        published_component: String,
        stage_component: String,
        max_namespace_entries: usize,
    }
    impl Guards {
        fn count(&self) -> usize {
            self.directories.len() + self.files.len()
        }
        fn directory(
            &mut self,
            path: &Path,
            expected: Option<&TreeNativeIdentity>,
            max: usize,
        ) -> Result<()> {
            if self.count() >= max {
                return Err(ReconcileError::ResourceLimit(
                    "final native handle inventory",
                ));
            }
            check_ancestors(path)?;
            let guard = LockedDirectory::open(path)?;
            guard.require_case_insensitive()?;
            guard.require_local_ntfs(path)?;
            let key = guard.key()?;
            if expected.is_some_and(|e| e != &native(key))
                || filesystem::physical_identity(path)?
                    != ContentId::hash(key.to_string().as_bytes())
            {
                return Err(ReconcileError::Unstable);
            }
            self.directories.push(Directory {
                path: path.to_owned(),
                guard,
                key,
            });
            Ok(())
        }
        fn file(
            &mut self,
            path: &Path,
            expected: &TreeNativeIdentity,
            content: Option<&FileManifest>,
            marker: Option<&[u8]>,
            max: usize,
        ) -> Result<()> {
            if self.count() >= max {
                return Err(ReconcileError::ResourceLimit(
                    "final native handle inventory",
                ));
            }
            check_ancestors(path)?;
            let guard = GuardedReadFile::open(path)?;
            let key = guard.key()?;
            if &native(key) != expected {
                return Err(ReconcileError::Unstable);
            }
            let held = File {
                path: path.to_owned(),
                guard,
                key,
                content: content.cloned(),
                marker: marker.map(|m| m.to_vec()),
            };
            verify_file(&held)?;
            self.files.push(held);
            Ok(())
        }
        fn verify(&self, local: &LocalSpace) -> Result<()> {
            local.verify_root()?;
            for d in &self.directories {
                d.guard.require_case_insensitive()?;
                if d.guard.key()? != d.key
                    || filesystem::physical_identity(&d.path)?
                        != ContentId::hash(d.key.to_string().as_bytes())
                {
                    return Err(ReconcileError::Unstable);
                }
            }
            if namespace(local, &self.user_namespace)? != self.user_namespace {
                return Err(ReconcileError::Invariant("final native namespace changed"));
            }
            verify_internal(self)?;
            for file in &self.files {
                verify_file(file)?;
            }
            Ok(())
        }
    }
    fn absent(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Err(e) if matches!(e.raw_os_error(), Some(2 | 3)) => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) => Err(ReconcileError::Invariant(
                "final creator stage still occupied",
            )),
        }
    }
    fn verify_internal(g: &Guards) -> Result<()> {
        absent(&g.marker_parent.join(&g.stage_component))?;
        let mut names = BTreeSet::new();
        for (index, child) in fs::read_dir(&g.owner_directory)?.enumerate() {
            if index >= g.max_namespace_entries {
                return Err(ReconcileError::ResourceLimit("final owner child inventory"));
            }
            let child = child?;
            let name = child
                .file_name()
                .to_str()
                .ok_or(ReconcileError::Invariant("non-UTF8 final owner component"))?
                .to_owned();
            if !g.internal_names.contains(&name) || !names.insert(name) {
                return Err(ReconcileError::Invariant("unexpected final owner child"));
            }
            let m = fs::symlink_metadata(child.path())?;
            if !m.is_file() || m.file_type().is_symlink() || is_reparse(&m) {
                return Err(ReconcileError::Invariant(
                    "final owner child is not regular file",
                ));
            }
        }
        if names != g.internal_names {
            return Err(ReconcileError::Invariant("final owner child missing"));
        }
        for (index, child) in fs::read_dir(&g.marker_parent)?.enumerate() {
            if index >= g.max_namespace_entries {
                return Err(ReconcileError::ResourceLimit(
                    "final marker child inventory",
                ));
            }
            let child = child?;
            let name = child
                .file_name()
                .to_str()
                .ok_or(ReconcileError::Invariant("non-UTF8 final marker component"))?
                .to_owned();
            if name.eq_ignore_ascii_case(&g.published_component) && name != g.published_component {
                return Err(ReconcileError::Invariant(
                    "final owner directory case alias",
                ));
            }
        }
        Ok(())
    }
    fn namespace(
        local: &LocalSpace,
        expected: &BTreeMap<PortablePath, EntryKind>,
    ) -> Result<BTreeMap<PortablePath, EntryKind>> {
        let mut pending = vec![local.worktree.clone()];
        let mut result = BTreeMap::new();
        let mut collisions = BTreeSet::new();
        while let Some(dir) = pending.pop() {
            check_ancestors(&dir)?;
            for child in fs::read_dir(dir)? {
                let child = child?;
                let component = child.file_name();
                let component = component
                    .to_str()
                    .ok_or(ReconcileError::Invariant("non-UTF8 final component"))?;
                if [".sync-extend", ".sync-tmp", ".git"]
                    .iter()
                    .any(|name| component.eq_ignore_ascii_case(name))
                {
                    continue;
                }
                if result.len() >= local.limits.max_scan_entries {
                    return Err(ReconcileError::ResourceLimit("final namespace inventory"));
                }
                let path = child.path();
                let relative = path
                    .strip_prefix(&local.worktree)
                    .map_err(|_| ReconcileError::Invariant("final path escaped root"))?;
                let portable = PortablePath::new(
                    relative
                        .iter()
                        .map(|c| {
                            c.to_str()
                                .ok_or(ReconcileError::Invariant("non-UTF8 final component"))
                        })
                        .collect::<Result<Vec<_>>>()?
                        .join("/"),
                )?;
                if !collisions.insert(portable.collision_key()) {
                    return Err(ReconcileError::Invariant("final namespace case alias"));
                }
                let m = fs::symlink_metadata(&path)?;
                if m.file_type().is_symlink() || is_reparse(&m) {
                    return Err(ReconcileError::Invariant("final namespace reparse"));
                }
                let kind = if m.is_dir() {
                    EntryKind::Directory
                } else if m.is_file() {
                    EntryKind::File
                } else {
                    return Err(ReconcileError::Invariant("final namespace special file"));
                };
                if expected.get(&portable) != Some(&kind) {
                    return Err(ReconcileError::Invariant("final namespace foreign entry"));
                }
                if kind == EntryKind::Directory {
                    pending.push(path);
                }
                result.insert(portable, kind);
            }
        }
        Ok(result)
    }
    fn verify_file(file: &File) -> Result<()> {
        file.guard.verify_single_link()?;
        let before = file.guard.reader().metadata()?;
        if file.guard.key()? != file.key
            || filesystem::physical_identity(&file.path)?
                != ContentId::hash(file.key.to_string().as_bytes())
        {
            return Err(ReconcileError::Unstable);
        }
        let mut reader = file.guard.reader();
        reader.seek(SeekFrom::Start(0))?;
        if let Some(marker) = &file.marker {
            let mut data = Vec::new();
            reader
                .take(marker.len() as u64 + 1)
                .read_to_end(&mut data)?;
            if &data != marker {
                return Err(ReconcileError::Invariant("final marker payload changed"));
            }
        } else if let Some(content) = &file.content {
            if before.len() != content.length {
                return Err(ReconcileError::Unstable);
            }
            let mut hash = blake3::Hasher::new();
            let mut remaining = content.length;
            let mut buffer = [0u8; 65536];
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                if n as u64 > remaining {
                    return Err(ReconcileError::Unstable);
                }
                remaining -= n as u64;
                hash.update(&buffer[..n]);
            }
            if remaining != 0 || ContentId::from_hasher(&hash) != content.content_id {
                return Err(ReconcileError::Unstable);
            }
        } else {
            return Err(ReconcileError::Invariant(
                "final observation file has no expected payload",
            ));
        }
        if !filesystem::same_metadata(&before, &file.guard.reader().metadata()?)
            || !filesystem::same_metadata(&before, &fs::symlink_metadata(&file.path)?)
        {
            return Err(ReconcileError::Unstable);
        }
        file.guard.verify_single_link()?;
        Ok(())
    }
    fn verify_cas(local: &LocalSpace, p: &TreeFinalObservationInspection) -> Result<()> {
        for manifest in [p.baseline(), p.target(), p.final_manifest()] {
            for content in manifest.entries.values().filter_map(|e| e.content.as_ref()) {
                local.cas.verify(content)?;
            }
        }
        for original in p.transaction().intent().retained_originals.values() {
            local.cas.verify(&original.original.original_content)?;
        }
        Ok(())
    }
    fn content_inventory<'a>(
        local: &LocalSpace,
        contents: impl Iterator<Item = &'a FileManifest>,
    ) -> Result<(u64, usize)> {
        let mut bytes = 0u64;
        let mut chunks = 0usize;
        for content in contents {
            if content.length > local.limits.max_file_bytes {
                return Err(ReconcileError::ResourceLimit("final file bytes"));
            }
            bytes = bytes
                .checked_add(content.length)
                .filter(|n| *n <= local.limits.max_scan_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "final combined content bytes",
                ))?;
            chunks = chunks
                .checked_add(content.chunks.len())
                .filter(|n| *n <= local.limits.max_scan_chunks)
                .ok_or(ReconcileError::ResourceLimit("final combined chunk visits"))?;
        }
        Ok((bytes, chunks))
    }
    fn capture(
        local: &LocalSpace,
        p: &TreeFinalObservationInspection,
        request: &TreeFinalObservationRequest,
    ) -> Result<(Guards, TreeFinalObservationReport)> {
        local.verify_root()?;
        let originals = &p.transaction().intent().retained_originals;
        let contents = p
            .final_manifest()
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .chain(originals.values().map(|o| &o.original.original_content));
        let (bytes, _) = content_inventory(local, contents)?;
        // CAS traversal includes input-only files, not just NEW and originals.
        // Repeated logical visits count even when their chunks are deduplicated.
        let (cas_bytes, cas_chunks) = content_inventory(
            local,
            [p.baseline(), p.target(), p.final_manifest()]
                .into_iter()
                .flat_map(|m| m.entries.values().filter_map(|e| e.content.as_ref()))
                .chain(originals.values().map(|o| &o.original.original_content)),
        )?;
        if p.final_entries().len() > local.limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit("final tree entries"));
        }
        let owner = p.owner().intent();
        let marker_parent = local.worktree.join(".sync-extend");
        let owner_directory = marker_parent.join(&owner.published_component);
        let mut g = Guards {
            directories: vec![],
            files: vec![],
            user_namespace: p
                .final_entries()
                .iter()
                .map(|(path, e)| (path.clone(), e.kind))
                .collect(),
            internal_names: BTreeSet::from([owner.marker_component.clone()]),
            owner_directory: owner_directory.clone(),
            marker_parent: marker_parent.clone(),
            published_component: owner.published_component.clone(),
            stage_component: owner.stage_component.clone(),
            max_namespace_entries: local.limits.max_storage_entries,
        };
        let max = local
            .limits
            .max_storage_entries
            .min(request.max_native_handles);
        let mut ancestors: Vec<_> = local
            .worktree
            .ancestors()
            .filter(|p| p.is_absolute())
            .collect();
        ancestors.reverse();
        for path in ancestors {
            g.directory(
                path,
                if path == local.worktree {
                    Some(&p.identity().inventory().root)
                } else {
                    None
                },
                max,
            )?;
        }
        g.directory(
            &marker_parent,
            Some(&p.identity().inventory().marker_directory),
            max,
        )?;
        g.file(
            &marker_parent.join("space-id"),
            &p.identity().inventory().marker_file,
            None,
            Some(local.space_id.as_str().as_bytes()),
            max,
        )?;
        let final_intent = p.transaction().intent();
        // Zero-original plans obtain directory/marker IDs from their exact final
        // protocol; they must never invent an original merely to carry ownership.
        let (directory, marker) = p.owner_native_identities();
        g.directory(&owner_directory, Some(directory), max)?;
        g.file(
            &owner_directory.join(&owner.marker_component),
            marker,
            None,
            Some(p.owner().marker_bytes()),
            max,
        )?;
        let mut ordered: Vec<_> = p.final_entries().iter().collect();
        ordered.sort_by_key(|(path, e)| (e.kind != EntryKind::Directory, (*path).clone()));
        for (path, e) in ordered {
            let native_path = local.worktree.join(path.as_str());
            match e.kind {
                EntryKind::Directory => g.directory(&native_path, Some(&e.identity), max)?,
                EntryKind::File => {
                    let entry = p.final_manifest().entries.get(&e.entry_id).ok_or(
                        ReconcileError::Invariant("final native logical entry missing"),
                    )?;
                    g.file(&native_path, &e.identity, entry.content.as_ref(), None, max)?;
                }
            }
        }
        for original in originals.values() {
            if &original.owner_directory != directory || &original.owner_marker != marker {
                return Err(ReconcileError::Invariant(
                    "final original owner binding changed",
                ));
            }
            g.internal_names.insert(original.retained_component.clone());
            g.file(
                &owner_directory.join(&original.retained_component),
                &original.original.original_identity,
                Some(&original.original.original_content),
                None,
                max,
            )?;
        }
        let mut identities = BTreeSet::new();
        for key in g
            .directories
            .iter()
            .map(|d| d.key)
            .chain(g.files.iter().map(|f| f.key))
        {
            if !identities.insert((key.volume, key.id)) {
                return Err(ReconcileError::Invariant(
                    "final retained native handle alias",
                ));
            }
        }
        let retained_bytes = originals.values().try_fold(0u64, |n, o| {
            n.checked_add(o.original.original_content.length)
                .ok_or(ReconcileError::ResourceLimit(
                    "final original byte inventory",
                ))
        })?;
        if retained_bytes
            .checked_add(p.owner().marker_bytes().len() as u64)
            .is_none_or(|n| n > local.limits.max_internal_worktree_bytes)
        {
            return Err(ReconcileError::ResourceLimit("final owner logical bytes"));
        }
        verify_cas(local, p)?;
        g.verify(local)?;
        let native_json = encode_history_record(
            &(
                final_intent,
                p.final_entries(),
                directory,
                marker,
                bytes,
                cas_bytes,
                cas_chunks,
                g.count(),
            ),
            request.limits.max_encoded_bytes,
        )?;
        let report = TreeFinalObservationReport {
            transaction_hash: p.transaction().intent_hash().clone(),
            native_observation_hash: ContentId::hash(&native_json),
            tree_entries: p.final_entries().len(),
            retained_originals: originals.len(),
            retained_native_handles: g.count(),
            logical_content_bytes: bytes,
            cas_logical_bytes: cas_bytes,
            cas_chunk_visits: cas_chunks,
            transient_guarded_layout_verified: true,
            durable_native_action_evidence: false,
            history_commit_available: false,
            input_reference_release_available: false,
            original_reference_release_available: false,
            final_handoff_capacity_verified: false,
            tree_atomic: false,
        };
        Ok((g, report))
    }
    impl LocalSpace {
        pub(super) fn observe_tree_final_platform(
            &self,
            request: &TreeFinalObservationRequest,
        ) -> Result<TreeFinalObservation<'_>> {
            let (cas, (g, transaction, report)) = self.journal.with_tree_final_observation(
                request,
                self.limits.max_storage_entries,
                |p| {
                    let (g, report) = capture(self, p, request)?;
                    checkpoint("after_tree_final_native_capture");
                    Ok::<_, ReconcileError>((g, p.transaction().clone(), report))
                },
                |(g, _, _), p| {
                    checkpoint("before_tree_final_native_recheck");
                    verify_cas(self, p)?;
                    g.verify(self)
                },
            )?;
            checkpoint("after_tree_final_native_observation");
            Ok(TreeFinalObservation {
                _local: self,
                _guards: (cas, Box::new(g)),
                transaction,
                report,
            })
        }
    }
}
