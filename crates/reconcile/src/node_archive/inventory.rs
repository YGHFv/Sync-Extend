//! Original immutable layout membership after actual Journal/CAS read assembly.
use super::{CreatedNodeDirectorySet, NodeTargetRoot};
use crate::{ReconcileError, Result};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn verify_after_journal(directories: &CreatedNodeDirectorySet<'_>) -> Result<()> {
    directories.verify()?;
    let mut expected: BTreeMap<(NodeTargetRoot, Vec<String>), BTreeSet<String>> = BTreeMap::new();
    expected.insert((NodeTargetRoot::Worktree, Vec::new()), BTreeSet::new());
    expected.insert((NodeTargetRoot::Data, Vec::new()), BTreeSet::new());
    for slot in directories
        .mapped
        .directories()
        .iter()
        .chain(directories.mapped.files())
    {
        let parts = slot.components();
        let name = parts.last().ok_or(ReconcileError::Invariant(
            "original inventory component absent",
        ))?;
        expected
            .entry((slot.root(), parts[..parts.len() - 1].to_vec()))
            .or_default()
            .insert(name.clone());
    }
    for slot in directories.mapped.directories() {
        expected
            .entry((slot.root(), slot.components().to_vec()))
            .or_default();
    }
    expected
        .entry((NodeTargetRoot::Worktree, vec![".sync-extend".into()]))
        .or_default()
        .insert("writer.lock".into());
    let data = expected
        .entry((NodeTargetRoot::Data, Vec::new()))
        .or_default();
    data.insert("writer.lock".into());
    data.insert("cas-access.lock".into());
    // These names are optional SQLite-managed runtime state, never original
    // CREATE/cleanup/adoption evidence. Foreign preexisting sidecars need separate
    // pre-reopen gate; name acceptance alone does not prove their ownership.
    for suffix in ["journal.sqlite-wal", "journal.sqlite-shm"] {
        let path = directories.roots.data_path.join(suffix);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !sync_extend_cas::is_reparse(&metadata) => {
                data.insert(suffix.into());
            }
            Ok(_) => {
                return Err(ReconcileError::Invariant(
                    "runtime Journal sidecar link/type differs",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    for ((root, parts), names) in expected {
        let mut actual = BTreeSet::new();
        for item in std::fs::read_dir(directories.path(root, &parts))? {
            let item = item?;
            if item.file_type()?.is_symlink() || sync_extend_cas::is_reparse(&item.metadata()?) {
                return Err(ReconcileError::Invariant(
                    "runtime original inventory reparse",
                ));
            }
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| ReconcileError::Invariant("runtime original inventory encoding"))?;
            if actual.len() >= names.len() || !actual.insert(name) {
                return Err(ReconcileError::Invariant(
                    "runtime original inventory unknown entry",
                ));
            }
        }
        if actual != names {
            return Err(ReconcileError::Invariant(
                "runtime original inventory names differ",
            ));
        }
    }
    directories.verify()
}
