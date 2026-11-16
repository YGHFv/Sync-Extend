//! Original archive-derived relative slots. This plan grants no native CREATE.
use super::{NodeRestoreDirectory, NodeRestoreFile, NodeRestoreLayout};
use crate::{ReconcileError, Result};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{ContentId, PortablePath};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum NodeTargetRoot {
    Worktree,
    Data,
}

/// Relative slot carries private source index, never a caller manifest/hash.
pub struct NodeRestoreSlot {
    root: NodeTargetRoot,
    components: Vec<String>,
    source: Source,
}

#[derive(Clone, Copy)]
enum Source {
    Directory(usize),
    File(usize),
}

impl NodeRestoreSlot {
    pub fn root(&self) -> NodeTargetRoot {
        self.root
    }
    pub fn components(&self) -> &[String] {
        &self.components
    }
}

/// Complete original count and uniqueness audit precedes target root creation.
pub struct NodeRestoreMappedLayout {
    archive_digest: ContentId,
    directories: Vec<NodeRestoreSlot>,
    files: Vec<NodeRestoreSlot>,
    total_file_bytes: u64,
}

impl NodeRestoreMappedLayout {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn directories(&self) -> &[NodeRestoreSlot] {
        &self.directories
    }
    pub fn files(&self) -> &[NodeRestoreSlot] {
        &self.files
    }
    pub fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }
    pub(super) fn directory<'a>(
        &self,
        slot: &NodeRestoreSlot,
        original: &'a NodeRestoreLayout,
    ) -> Result<&'a NodeRestoreDirectory> {
        if self.archive_digest != *original.archive_digest() {
            return Err(ReconcileError::Invariant(
                "original mapped directory archive scope",
            ));
        }
        if !self
            .directories
            .iter()
            .any(|expected| std::ptr::eq(expected, slot))
        {
            return Err(ReconcileError::Invariant(
                "mapped directory belongs to another plan",
            ));
        }
        match slot.source {
            Source::Directory(index) => {
                original
                    .directories()
                    .get(index)
                    .ok_or(ReconcileError::Invariant(
                        "original mapped directory index differs",
                    ))
            }
            Source::File(_) => Err(ReconcileError::Invariant(
                "mapped original is not directory",
            )),
        }
    }
    pub(super) fn file<'a>(
        &self,
        slot: &NodeRestoreSlot,
        original: &'a NodeRestoreLayout,
    ) -> Result<&'a NodeRestoreFile> {
        if self.archive_digest != *original.archive_digest() {
            return Err(ReconcileError::Invariant(
                "original mapped file archive scope",
            ));
        }
        if !self
            .files
            .iter()
            .any(|expected| std::ptr::eq(expected, slot))
        {
            return Err(ReconcileError::Invariant(
                "mapped file belongs to another plan",
            ));
        }
        match slot.source {
            Source::File(index) => original.files().get(index).ok_or(ReconcileError::Invariant(
                "original mapped file index differs",
            )),
            Source::Directory(_) => Err(ReconcileError::Invariant("mapped original is not file")),
        }
    }
}

fn ordinary(path: &PortablePath) -> Vec<String> {
    path.as_str().split('/').map(str::to_owned).collect()
}
fn fixed(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}
fn directory_slot(value: &NodeRestoreDirectory) -> (NodeTargetRoot, Vec<String>) {
    use NodeRestoreDirectory as D;
    match value {
        D::DataCas => (NodeTargetRoot::Data, fixed(&["cas"])),
        D::DataCasObjects => (NodeTargetRoot::Data, fixed(&["cas", "objects"])),
        D::DataCasTemporary => (NodeTargetRoot::Data, fixed(&["cas", "tmp"])),
        D::DataPeers => (NodeTargetRoot::Data, fixed(&["peers"])),
        D::DataCasPrefix(prefix) => (NodeTargetRoot::Data, fixed(&["cas", "objects", prefix])),
        D::WorktreeMarker => (NodeTargetRoot::Worktree, fixed(&[".sync-extend"])),
        D::WorktreeEntry { path, .. } => (NodeTargetRoot::Worktree, ordinary(path)),
    }
}
fn file_slot(value: &NodeRestoreFile) -> (NodeTargetRoot, Vec<String>) {
    use NodeRestoreFile as F;
    match value {
        F::Journal => (NodeTargetRoot::Data, fixed(&["journal.sqlite"])),
        F::ProtectedDeviceIdentity => (NodeTargetRoot::Data, fixed(&["device.secret"])),
        F::CasObject { content_id } => (
            NodeTargetRoot::Data,
            fixed(&[
                "cas",
                "objects",
                &content_id.as_str()[..2],
                content_id.as_str(),
            ]),
        ),
        F::PeerApproval { device_id } => (
            NodeTargetRoot::Data,
            vec!["peers".to_owned(), format!("{device_id}.json")],
        ),
        F::WorktreeSpaceMarker => (
            NodeTargetRoot::Worktree,
            fixed(&[".sync-extend", "space-id"]),
        ),
        F::WorktreeCurrent { path, .. } => (NodeTargetRoot::Worktree, ordinary(path)),
    }
}

impl NodeRestoreLayout {
    /// Exact deterministic storage paths originate solely in verified layout.
    /// Every descendant parent must already exist in the derived directory set.
    pub fn map_original_slots(&self, max_creations: usize) -> Result<NodeRestoreMappedLayout> {
        if max_creations == 0
            || max_creations > 1_000_000
            || self
                .directories()
                .len()
                .checked_add(self.files().len())
                .is_none_or(|count| count > max_creations)
        {
            return Err(ReconcileError::ResourceLimit(
                "bounded mapped original slot count",
            ));
        }
        let mut directories = Vec::with_capacity(self.directories().len());
        let mut files = Vec::with_capacity(self.files().len());
        let mut names = BTreeSet::new();
        let mut directory_names = BTreeMap::new();
        for (index, directory) in self.directories().iter().enumerate() {
            let (root, components) = directory_slot(directory);
            let folded: Vec<_> = components
                .iter()
                .map(|component| component.to_uppercase())
                .collect();
            if !names.insert((root, folded.clone()))
                || directory_names.insert((root, folded), index).is_some()
            {
                return Err(ReconcileError::Invariant(
                    "original directory slot collision",
                ));
            }
            directories.push(NodeRestoreSlot {
                root,
                components,
                source: Source::Directory(index),
            });
        }
        for (index, file) in self.files().iter().enumerate() {
            let (root, components) = file_slot(file);
            let folded: Vec<_> = components
                .iter()
                .map(|component| component.to_uppercase())
                .collect();
            if !names.insert((root, folded)) {
                return Err(ReconcileError::Invariant(
                    "original file/directory slot collision",
                ));
            }
            files.push(NodeRestoreSlot {
                root,
                components,
                source: Source::File(index),
            });
        }
        for slot in directories.iter().chain(&files) {
            if slot.components.is_empty()
                || slot.components.len() > 128
                || slot
                    .components
                    .iter()
                    .any(|component| component.is_empty() || component.len() > 255)
            {
                return Err(ReconcileError::Invariant(
                    "original mapped component count/size",
                ));
            }
            if slot.components.len() > 1 {
                let parent: Vec<_> = slot.components[..slot.components.len() - 1]
                    .iter()
                    .map(|component| component.to_uppercase())
                    .collect();
                if !directory_names.contains_key(&(slot.root, parent)) {
                    return Err(ReconcileError::Invariant(
                        "original mapped parent directory absent",
                    ));
                }
            }
        }
        directories.sort_by(|left, right| {
            (left.root, left.components.len(), &left.components).cmp(&(
                right.root,
                right.components.len(),
                &right.components,
            ))
        });
        files.sort_by(|left, right| {
            (left.root, &left.components).cmp(&(right.root, &right.components))
        });
        Ok(NodeRestoreMappedLayout {
            archive_digest: self.archive_digest().clone(),
            directories,
            files,
            total_file_bytes: self.required_file_bytes(),
        })
    }
}
