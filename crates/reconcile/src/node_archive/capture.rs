//! Bounded consistent stopped-writer node archive capture; Windows original handles.
use super::{
    captured_file::CapturedFile,
    layout::{ArchiveBounds, ArchiveRole, FramedNodeArchive, SourceSection},
};
use crate::{check_ancestors, identity, LocalSpace, ReconcileError, Result};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
use sync_extend_core_model::{config::Config, ContentId, DeviceId};
use sync_extend_platform_fs::{FileKey, LockedDirectory};
use sync_extend_transport::PeerIdentity;

/// No source paths or protected payloads are serialized into a receipt.
pub struct CapturedNodeArchive {
    archive: FramedNodeArchive,
}

impl CapturedNodeArchive {
    pub fn bytes(&self) -> &[u8] {
        self.archive.bytes()
    }

    pub fn digest(&self) -> &ContentId {
        self.archive.digest()
    }
}

struct CaptureSet {
    files: Vec<(ArchiveRole, CapturedFile)>,
    directories: Vec<(PathBuf, LockedDirectory, FileKey, Vec<String>)>,
    bytes: u64,
    worktree_files: Vec<CapturedFile>,
    bounds: ArchiveBounds,
}

impl CaptureSet {
    fn directory(&mut self, path: &Path) -> Result<Vec<String>> {
        check_ancestors(path)?;
        let held = LockedDirectory::open(path)?;
        held.require_local_ntfs(path)?;
        held.require_case_insensitive()?;
        if !held.matches_path(path)? {
            return Err(ReconcileError::Unstable);
        }
        let key = held.key()?;
        let names = enumerate(path, self.bounds.sections)?;
        self.directories
            .push((path.to_owned(), held, key, names.clone()));
        Ok(names)
    }

    fn file(&mut self, role: ArchiveRole, path: &Path, max_bytes: usize) -> Result<()> {
        if self.files.len().saturating_add(1) >= self.bounds.sections {
            return Err(ReconcileError::ResourceLimit("node source section count"));
        }
        let remaining = self.bounds.archive_bytes.checked_sub(self.bytes).ok_or(
            ReconcileError::ResourceLimit("node capture remaining bytes"),
        )?;
        let maximum = max_bytes.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let captured = CapturedFile::open(path, maximum)?;
        self.bytes = self
            .bytes
            .checked_add(captured.bytes().len() as u64)
            .filter(|total| *total <= self.bounds.archive_bytes)
            .ok_or(ReconcileError::ResourceLimit("node capture total bytes"))?;
        if let ArchiveRole::CasObject { content_id } = &role {
            if captured.digest() != content_id {
                return Err(ReconcileError::Invariant("node captured CAS hash differs"));
            }
        }
        self.files.push((role, captured));
        Ok(())
    }

    fn verify(&self) -> Result<()> {
        for (path, held, key, names) in &self.directories {
            if held.key()? != *key
                || !held.matches_path(path)?
                || enumerate(path, self.bounds.sections)? != *names
            {
                return Err(ReconcileError::Unstable);
            }
        }
        for original in &self.worktree_files {
            original.verify()?;
        }
        for (_, original) in &self.files {
            original.verify()?;
        }
        Ok(())
    }
}

fn enumerate(path: &Path, limit: usize) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for item in fs::read_dir(path)? {
        let item = item?;
        let name = item
            .file_name()
            .to_str()
            .ok_or(ReconcileError::Invariant("node source filename encoding"))?
            .to_owned();
        if name.is_empty() || names.len() >= limit {
            return Err(ReconcileError::ResourceLimit("node directory entry bound"));
        }
        let metadata = item.file_type()?;
        if metadata.is_symlink() || sync_extend_cas::is_reparse(&item.metadata()?) {
            return Err(ReconcileError::Invariant(
                "node source link or reparse entry",
            ));
        }
        names.push(name);
    }
    names.sort();
    Ok(names)
}

impl LocalSpace {
    /// Capture explicit stopped-writer state while all original handles remain live.
    /// This method never recovers, scans or alters portable operation history.
    pub fn capture_node_archive(
        &self,
        configs: &[(String, PathBuf)],
        bounds: ArchiveBounds,
    ) -> Result<CapturedNodeArchive> {
        bounds.validate()?;
        self.verify_root()?;
        self.journal.integrity_check()?;
        let _session = self.journal.acquire_cas_session()?;
        let status = self.status()?;
        let report = self.storage_report()?;
        if status.outstanding_publications != 0
            || status.outstanding_mutations != 0
            || status.tree_restore_writer_gate_held
            || report.active_gc_execution_fences != 0
            || report.pending_gc_disposals != 0
            || report.quarantined_gc_objects != 0
            || report.cas_temporary_paths != 0
            || report.internal_worktree_file_paths != 0
            || report.missing_protected_objects != 0
            || report.mismatched_protected_lengths != 0
        {
            return Err(ReconcileError::Invariant(
                "node archive refuses unresolved native or missing content state",
            ));
        }
        let journal_limit = usize::try_from(bounds.archive_bytes.min(256 * 1024 * 1024))
            .map_err(|_| ReconcileError::ResourceLimit("node Journal archive bound"))?;
        let before = self.journal.backup_image(journal_limit)?;
        let snapshot = self
            .manifest()?
            .map(|manifest| manifest.root())
            .transpose()?;
        let protected = self.journal.protected_objects()?;
        let mut set = CaptureSet {
            files: Vec::new(),
            worktree_files: Vec::new(),
            directories: Vec::new(),
            bytes: before.bytes().len() as u64,
            bounds,
        };
        let manifest = self.manifest()?.ok_or(ReconcileError::Invariant(
            "node capture requires actual current manifest",
        ))?;
        capture_worktree(&mut set, &self.worktree, &manifest, &self.space_id)?;
        let data_names = set.directory(&self.data_dir)?;
        let allowed: BTreeSet<_> = [
            "journal.sqlite",
            "journal.sqlite-wal",
            "journal.sqlite-shm",
            "device.secret",
            "writer.lock",
            "cas-access.lock",
            "cas",
            "peers",
        ]
        .into_iter()
        .collect();
        if data_names
            .iter()
            .any(|name| !allowed.contains(name.as_str()))
        {
            return Err(ReconcileError::Invariant(
                "node data contains an unclassified state file",
            ));
        }
        set.file(
            ArchiveRole::DeviceSecret,
            &self.data_dir.join("device.secret"),
            4096,
        )?;
        if identity::load_or_create(&self.data_dir.join("device.secret"), false)? != self.device_id
        {
            return Err(ReconcileError::Invariant(
                "node original device identity differs",
            ));
        }
        let cas = self.data_dir.join("cas");
        if set.directory(&cas)? != ["objects", "tmp"] {
            return Err(ReconcileError::Invariant(
                "node CAS directory layout differs",
            ));
        }
        if !set.directory(&cas.join("tmp"))?.is_empty() {
            return Err(ReconcileError::Invariant("node CAS staging is unresolved"));
        }
        let mut object_ids = BTreeSet::new();
        for prefix in set.directory(&cas.join("objects"))? {
            if prefix.len() != 2
                || !prefix
                    .bytes()
                    .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
            {
                return Err(ReconcileError::Invariant("node CAS prefix differs"));
            }
            let parent = cas.join("objects").join(&prefix);
            for name in set.directory(&parent)? {
                let content_id: ContentId = name.parse()?;
                if !name.starts_with(&prefix) || !object_ids.insert(content_id.clone()) {
                    return Err(ReconcileError::Invariant("node CAS object slot differs"));
                }
                set.file(
                    ArchiveRole::CasObject { content_id },
                    &parent.join(name),
                    4 * 1024 * 1024,
                )?;
            }
        }
        if protected.iter().any(|id| !object_ids.contains(id)) {
            return Err(ReconcileError::Invariant(
                "node protected CAS object absent",
            ));
        }
        let peers = self.data_dir.join("peers");
        if peers.try_exists()? {
            for name in set.directory(&peers)? {
                let device: DeviceId = name
                    .strip_suffix(".json")
                    .ok_or(ReconcileError::Invariant("node peer residue differs"))?
                    .parse()?;
                set.file(
                    ArchiveRole::PeerApproval {
                        device_id: device.clone(),
                    },
                    &peers.join(&name),
                    64 * 1024,
                )?;
                let bytes = set.files.last().ok_or(ReconcileError::Unstable)?.1.bytes();
                let peer: PeerIdentity = serde_json::from_slice(bytes)?;
                peer.validate().map_err(|_| {
                    ReconcileError::Invariant("node original peer approval invalid")
                })?;
                if peer.device_id != device
                    || peer.device_id == self.device_id
                    || peer.space_id != self.space_id
                {
                    return Err(ReconcileError::Invariant(
                        "node peer identity scope differs",
                    ));
                }
            }
        }
        for (name, path) in configs {
            set.file(
                ArchiveRole::ExplicitConfig { name: name.clone() },
                path,
                1024 * 1024,
            )?;
            let config: Config = serde_json::from_slice(
                set.files.last().ok_or(ReconcileError::Unstable)?.1.bytes(),
            )?;
            config.validate()?;
            if config.webdav.credential_ref.is_some()
                || config.webdav.tls_certificate.is_some()
                || config.webdav.tls_key.is_some()
            {
                return Err(ReconcileError::Invariant(
                    "node config references require separately captured protected artifacts",
                ));
            }
            if config.data_dir != self.data_dir || config.worktree.as_ref() != Some(&self.worktree)
            {
                return Err(ReconcileError::Invariant(
                    "node explicit config scope differs",
                ));
            }
        }
        set.verify()?;
        self.verify_root()?;
        let after = self.journal.backup_image(journal_limit)?;
        if before.bytes() != after.bytes()
            || self.journal.protected_objects()? != protected
            || self
                .manifest()?
                .map(|manifest| manifest.root())
                .transpose()?
                != snapshot
        {
            return Err(ReconcileError::Unstable);
        }
        drop(after);
        let source_schema = before.schema_version();
        let mut sections = vec![SourceSection {
            role: ArchiveRole::Journal,
            bytes: before.into_bytes(),
        }];
        for (role, captured) in &mut set.files {
            sections.push(SourceSection {
                role: role.clone(),
                bytes: captured.take_bytes()?,
            });
        }
        let archive = FramedNodeArchive::assemble(
            self.space_id.clone(),
            self.device_id.clone(),
            snapshot,
            source_schema,
            sections,
            bounds,
        )?;
        set.verify()?;
        self.verify_root()?;
        Ok(CapturedNodeArchive { archive })
    }
}

/// Hold each committed current file and directory until the archive has closed.
/// Native files outside current history refuse: backup never silently drops them.
fn capture_worktree(
    set: &mut CaptureSet,
    worktree: &Path,
    manifest: &sync_extend_core_model::Manifest,
    space: &sync_extend_core_model::SpaceId,
) -> Result<()> {
    use std::collections::BTreeMap;
    use sync_extend_core_model::EntryKind;
    let mut expected = BTreeMap::new();
    for entry in manifest.entries.values() {
        expected.insert(worktree.join(entry.path.as_str()), entry);
    }
    let mut pending = vec![worktree.to_owned()];
    let mut observed = 0usize;
    let mut bytes = 0u64;
    while let Some(directory) = pending.pop() {
        for name in set.directory(&directory)? {
            let path = directory.join(&name);
            if directory == worktree && name == ".sync-extend" {
                if set.directory(&path)? != ["space-id", "writer.lock"] {
                    return Err(ReconcileError::Invariant(
                        "node worktree marker directory differs",
                    ));
                }
                let marker = CapturedFile::open(&path.join("space-id"), 32)?;
                if marker.bytes() != space.as_str().as_bytes() {
                    return Err(ReconcileError::Invariant(
                        "node worktree original space marker differs",
                    ));
                }
                set.worktree_files.push(marker);
                continue;
            }
            observed = observed
                .checked_add(1)
                .filter(|count| *count <= set.bounds.sections)
                .ok_or(ReconcileError::ResourceLimit(
                    "node current native worktree entries",
                ))?;
            let entry = expected.remove(&path).ok_or(ReconcileError::Invariant(
                "node worktree has uncommitted native entry",
            ))?;
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || sync_extend_cas::is_reparse(&metadata) {
                return Err(ReconcileError::Invariant(
                    "node worktree original link or reparse",
                ));
            }
            match entry.kind {
                EntryKind::Directory if metadata.is_dir() => pending.push(path),
                EntryKind::File if metadata.is_file() => {
                    let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
                        "node worktree original file manifest absent",
                    ))?;
                    bytes = bytes
                        .checked_add(content.length)
                        .filter(|bytes| *bytes <= set.bounds.archive_bytes)
                        .ok_or(ReconcileError::ResourceLimit(
                            "node current worktree hash byte work",
                        ))?;
                    let held =
                        CapturedFile::hold_matching(&path, content.length, &content.content_id)?;
                    set.worktree_files.push(held);
                }
                _ => {
                    return Err(ReconcileError::Invariant(
                        "node worktree original native entry type differs",
                    ))
                }
            }
        }
    }
    if !expected.is_empty() {
        return Err(ReconcileError::Invariant(
            "node worktree committed original entry absent",
        ));
    }
    Ok(())
}
