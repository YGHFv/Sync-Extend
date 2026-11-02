use crate::{ReconcileError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    path::Path,
};
use sync_extend_cas::{is_reparse, Cas};
use sync_extend_core_model::{EntryKind, FileManifest, PortablePath};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScannedEntry {
    pub kind: EntryKind,
    pub content: Option<FileManifest>,
}

pub type Scan = BTreeMap<PortablePath, ScannedEntry>;

pub fn scan(root: &Path, cas: &Cas) -> Result<Scan> {
    let mut result = BTreeMap::new();
    let mut collisions = BTreeSet::new();
    visit(root, root, cas, &mut result, &mut collisions)?;
    Ok(result)
}

fn visit(
    root: &Path,
    directory: &Path,
    cas: &Cas,
    result: &mut Scan,
    collisions: &mut BTreeSet<String>,
) -> Result<()> {
    let before = fs::symlink_metadata(directory)?;
    if !before.is_dir() || before.file_type().is_symlink() || is_reparse(&before) {
        return Err(ReconcileError::Invariant(
            "directory is unavailable or a link/reparse point",
        ));
    }
    let mut children = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let name = child.file_name();
        let name = name
            .to_str()
            .ok_or(ReconcileError::Invariant("non-UTF8 filename"))?;
        if [".sync-extend", ".sync-tmp", ".git"]
            .iter()
            .any(|internal| name.eq_ignore_ascii_case(internal))
        {
            continue;
        }
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
            visit(root, &full_path, cas, result, collisions)?;
            ScannedEntry {
                kind: EntryKind::Directory,
                content: None,
            }
        } else if metadata.is_file() {
            let file = File::open(&full_path)?;
            if !same_metadata(&metadata, &file.metadata()?) {
                return Err(ReconcileError::Unstable);
            }
            let content = cas.import(&file)?;
            if content.length != metadata.len()
                || !same_metadata(&metadata, &file.metadata()?)
                || !same_metadata(&metadata, &fs::symlink_metadata(&full_path)?)
            {
                return Err(ReconcileError::Unstable);
            }
            ScannedEntry {
                kind: EntryKind::File,
                content: Some(content),
            }
        } else {
            return Err(ReconcileError::Invariant("unsupported special file"));
        };
        result.insert(path, entry);
        if result.len() > 1_000_000 {
            return Err(ReconcileError::Invariant("scan entry limit exceeded"));
        }
    }
    if !same_metadata(&before, &fs::symlink_metadata(directory)?) {
        return Err(ReconcileError::Unstable);
    }
    Ok(())
}

fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    a.len() == b.len()
        && a.modified().ok() == b.modified().ok()
        && a.file_type() == b.file_type()
        && !b.file_type().is_symlink()
        && !is_reparse(b)
}
