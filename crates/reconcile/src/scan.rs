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
    pub single_link: bool,
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
    visit(
        root,
        root,
        cas,
        &mut result,
        &mut collisions,
        &mut budget,
        #[cfg(windows)]
        None,
    )?;
    Ok(result)
}

#[cfg(windows)]
pub(crate) fn scan_native(
    root: &Path,
    cas: &Cas,
    limits: &LocalLimits,
    view: &dyn crate::native_file_view::NativeFileView,
) -> Result<Scan> {
    view.verify()?;
    let mut result = BTreeMap::new();
    let mut collisions = BTreeSet::new();
    let mut budget = Budget {
        limits,
        entries: 0,
        bytes: 0,
        chunks: 0,
    };
    visit(
        root,
        root,
        cas,
        &mut result,
        &mut collisions,
        &mut budget,
        Some(view),
    )?;
    view.verify()?;
    Ok(result)
}

fn visit(
    root: &Path,
    directory: &Path,
    cas: &Cas,
    result: &mut Scan,
    collisions: &mut BTreeSet<String>,
    budget: &mut Budget<'_>,
    #[cfg(windows)] view: Option<&dyn crate::native_file_view::NativeFileView>,
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
            visit(
                root,
                &full_path,
                cas,
                result,
                collisions,
                budget,
                #[cfg(windows)]
                view,
            )?;
            identity.verify(&full_path)?;
            ScannedEntry {
                kind: EntryKind::Directory,
                content: None,
                physical_identity: identity.physical,
                single_link: false,
            }
        } else if metadata.is_file() {
            #[cfg(windows)]
            if let Some(native) = view
                .map(|view| view.observe_file(&full_path))
                .transpose()?
                .flatten()
            {
                let content = native.content.ok_or(ReconcileError::Invariant(
                    "native scan view requires exact observed target",
                ))?;
                if !same_metadata(&metadata, &native.metadata) || content.length != metadata.len() {
                    return Err(ReconcileError::Unstable);
                }
                budget.reserve_bytes(content.length)?;
                if content.chunks.len() > budget.limits.max_scan_chunks - budget.chunks {
                    return Err(ReconcileError::ResourceLimit("scan chunks"));
                }
                budget.chunks += content.chunks.len();
                result.insert(
                    path,
                    ScannedEntry {
                        kind: EntryKind::File,
                        content: Some(content),
                        physical_identity: native.physical_identity,
                        single_link: true,
                    },
                );
                continue;
            }
            let observed = ObservedFile::open(&full_path)?;
            let single_link = single_link(&observed.file)?;
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
            if single_link != self::single_link(&observed.file)? {
                return Err(ReconcileError::Unstable);
            }
            if content.length != metadata.len() {
                return Err(ReconcileError::Unstable);
            }
            budget.chunks += content.chunks.len();
            ScannedEntry {
                kind: EntryKind::File,
                content: Some(content),
                physical_identity: observed.identity.physical,
                single_link,
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

fn single_link(file: &fs::File) -> Result<bool> {
    #[cfg(windows)]
    {
        Ok(sync_extend_platform_fs::regular_file_link_count(file)? == 1)
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(file.metadata()?.nlink() == 1)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = file;
        Ok(false)
    }
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
