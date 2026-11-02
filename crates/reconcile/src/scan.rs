use crate::{
    fault::checkpoint,
    filesystem::{same_metadata, ObservedFile, PathIdentity},
    ReconcileError, Result,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use sync_extend_cas::{is_reparse, Cas};
use sync_extend_core_model::{
    limits::LocalLimits, ContentId, EntryKind, FileManifest, PortablePath,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedEntry {
    pub kind: EntryKind,
    pub content: Option<FileManifest>,
    // Local observation only: identity is not part of the portable manifest.
    pub physical_identity: ContentId,
}

pub type Scan = BTreeMap<PortablePath, ScannedEntry>;

pub fn scan(root: &Path, cas: &Cas, limits: &LocalLimits) -> Result<Scan> {
    let mut result = BTreeMap::new();
    let mut collisions = BTreeSet::new();
    let mut budget = Budget {
        limits,
        entries: 0,
        bytes: 0,
        chunks: 0,
    };
    visit(root, root, cas, &mut result, &mut collisions, &mut budget)?;
    Ok(result)
}

fn visit(
    root: &Path,
    directory: &Path,
    cas: &Cas,
    result: &mut Scan,
    collisions: &mut BTreeSet<String>,
    budget: &mut Budget<'_>,
) -> Result<()> {
    let before = fs::symlink_metadata(directory)?;
    if !before.is_dir() || before.file_type().is_symlink() || is_reparse(&before) {
        return Err(ReconcileError::Invariant(
            "directory is unavailable or a link/reparse point",
        ));
    }
    let directory_identity = PathIdentity::capture(directory)?;
    let mut children = Vec::new();
    for child in fs::read_dir(directory)? {
        let child = child?;
        if child.file_name().to_str().is_some_and(is_internal) {
            continue;
        }
        budget.reserve_entry()?;
        children.push(child);
    }
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let full_path = child.path();
        let relative = full_path
            .strip_prefix(root)
            .map_err(|_| ReconcileError::Invariant("path escaped root"))?;
        let path = PortablePath::new(
            relative
                .iter()
                .map(|c| {
                    c.to_str()
                        .ok_or(ReconcileError::Invariant("non-UTF8 component"))
                })
                .collect::<Result<Vec<_>>>()?
                .join("/"),
        )?;
        if !collisions.insert(path.collision_key()) {
            return Err(ReconcileError::Invariant(
                "portable case collision; no files overwritten",
            ));
        }
        let metadata = fs::symlink_metadata(&full_path)?;
        if metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(ReconcileError::Invariant(
                "links/reparse points are not supported",
            ));
        }
        let entry = if metadata.is_dir() {
            let identity = PathIdentity::capture(&full_path)?;
            visit(root, &full_path, cas, result, collisions, budget)?;
            identity.verify(&full_path)?;
            ScannedEntry {
                kind: EntryKind::Directory,
                content: None,
                physical_identity: identity.physical,
            }
        } else if metadata.is_file() {
            let observed = ObservedFile::open(&full_path)?;
            if !same_metadata(&metadata, &observed.metadata) {
                return Err(ReconcileError::Unstable);
            }
            budget.reserve_bytes(metadata.len())?;
            checkpoint("after_scan_file_open");
            let content = cas.import_bounded(
                &observed.file,
                metadata.len(),
                budget.limits.max_scan_chunks - budget.chunks,
            )?;
            checkpoint("after_scan_file_import");
            observed.verify(&full_path)?;
            if content.length != metadata.len() {
                return Err(ReconcileError::Unstable);
            }
            budget.chunks += content.chunks.len();
            ScannedEntry {
                kind: EntryKind::File,
                content: Some(content),
                physical_identity: observed.identity.physical,
            }
        } else {
            return Err(ReconcileError::Invariant("unsupported special file"));
        };
        result.insert(path, entry);
    }
    checkpoint("before_scan_directory_verify");
    if !same_metadata(&before, &fs::symlink_metadata(directory)?) {
        return Err(ReconcileError::Unstable);
    }
    directory_identity.verify(directory)?;
    Ok(())
}

fn is_internal(name: &str) -> bool {
    [".sync-extend", ".sync-tmp", ".git"]
        .iter()
        .any(|internal| name.eq_ignore_ascii_case(internal))
}

struct Budget<'a> {
    limits: &'a LocalLimits,
    entries: usize,
    bytes: u64,
    chunks: usize,
}

impl Budget<'_> {
    fn reserve_entry(&mut self) -> Result<()> {
        if self.entries >= self.limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit("scan entries"));
        }
        self.entries += 1;
        Ok(())
    }

    fn reserve_bytes(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.limits.max_file_bytes {
            return Err(ReconcileError::ResourceLimit("file bytes"));
        }
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limits.max_scan_bytes)
            .ok_or(ReconcileError::ResourceLimit("scan bytes"))?;
        Ok(())
    }
}
