//! Derived relative CREATE plan only. It grants no target path or native authority.
use super::{ArchiveRole, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::collections::BTreeSet;
use sync_extend_core_model::{ContentId, EntryId, EntryKind, PortablePath};
use sync_extend_journal::NodeInspectionBounds;

pub enum NodeRestoreDirectory {
    DataCas,
    DataCasObjects,
    DataCasTemporary,
    DataPeers,
    DataCasPrefix(String),
    WorktreeMarker,
    WorktreeEntry {
        entry_id: EntryId,
        path: PortablePath,
    },
}
pub enum NodeRestoreFile {
    Journal,
    ProtectedDeviceIdentity,
    CasObject {
        content_id: ContentId,
    },
    PeerApproval {
        device_id: sync_extend_core_model::DeviceId,
    },
    WorktreeSpaceMarker,
    WorktreeCurrent {
        entry_id: EntryId,
        path: PortablePath,
        content_id: ContentId,
        bytes: u64,
    },
}

/// Opaque plan records only original relative scope; no path mapping constructor.
/// Directory order retains parent-before-child creation for all original entries.
pub struct NodeRestoreLayout {
    archive_digest: ContentId,
    directories: Vec<NodeRestoreDirectory>,
    files: Vec<NodeRestoreFile>,
    required_file_bytes: u64,
}
impl NodeRestoreLayout {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn directories(&self) -> &[NodeRestoreDirectory] {
        &self.directories
    }
    pub fn files(&self) -> &[NodeRestoreFile] {
        &self.files
    }
    pub fn required_file_bytes(&self) -> u64 {
        self.required_file_bytes
    }
}

impl VerifiedNodeStateArchive {
    /// Explicit config mapping and credentials need separate original contracts.
    /// This initial layout refuses such roles, retaining them in the archive.
    /// Current native history can describe current files without declaring that
    /// the original Journal can be installed at a fresh root.
    pub fn current_node_restore_layout(
        &self,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
    ) -> Result<NodeRestoreLayout> {
        if max_creations == 0
            || max_creations > 1_000_000
            || max_file_bytes == 0
            || max_file_bytes > 1024 * 1024 * 1024
        {
            return Err(ReconcileError::ResourceLimit(
                "explicit node layout creation/byte bound",
            ));
        }
        let manifest = self.current_node_manifest(inspection)?;
        let mut directories = vec![
            NodeRestoreDirectory::DataCas,
            NodeRestoreDirectory::DataCasObjects,
            NodeRestoreDirectory::DataCasTemporary,
        ];
        let mut prefixes = BTreeSet::new();
        let mut peers = false;
        let mut files = Vec::new();
        let mut required_file_bytes = 0u64;
        for role in self.archive.roles() {
            let section = self.archive.section(role).ok_or(ReconcileError::Invariant(
                "node layout original role bytes absent",
            ))?;
            required_file_bytes = required_file_bytes
                .checked_add(section.len() as u64)
                .filter(|count| *count <= max_file_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "node layout original section byte bound",
                ))?;
            let file = match role {
                ArchiveRole::Journal => NodeRestoreFile::Journal,
                ArchiveRole::DeviceSecret => NodeRestoreFile::ProtectedDeviceIdentity,
                ArchiveRole::CasObject { content_id } => {
                    prefixes.insert(content_id.as_str()[..2].to_owned());
                    NodeRestoreFile::CasObject {
                        content_id: content_id.clone(),
                    }
                }
                ArchiveRole::PeerApproval { device_id } => {
                    peers = true;
                    NodeRestoreFile::PeerApproval {
                        device_id: device_id.clone(),
                    }
                }
                ArchiveRole::ExplicitConfig { .. } => {
                    return Err(ReconcileError::Invariant(
                        "node layout requires separate explicit original config mapping",
                    ));
                }
            };
            files.push(file);
            if files.len() + directories.len() > max_creations {
                return Err(ReconcileError::ResourceLimit(
                    "node layout original creation count",
                ));
            }
        }
        for prefix in prefixes {
            directories.push(NodeRestoreDirectory::DataCasPrefix(prefix));
        }
        if peers {
            directories.push(NodeRestoreDirectory::DataPeers);
        }
        directories.push(NodeRestoreDirectory::WorktreeMarker);
        required_file_bytes = required_file_bytes
            .checked_add(self.space().as_str().len() as u64)
            .filter(|count| *count <= max_file_bytes)
            .ok_or(ReconcileError::ResourceLimit(
                "node layout marker byte bound",
            ))?;
        files.push(NodeRestoreFile::WorktreeSpaceMarker);
        let mut original_directories: Vec<_> = manifest
            .entries
            .values()
            .filter(|entry| entry.kind == EntryKind::Directory)
            .collect();
        original_directories.sort_by(|left, right| {
            (left.path.as_str().split('/').count(), left.path.as_str())
                .cmp(&(right.path.as_str().split('/').count(), right.path.as_str()))
        });
        for entry in original_directories {
            directories.push(NodeRestoreDirectory::WorktreeEntry {
                entry_id: entry.entry_id.clone(),
                path: entry.path.clone(),
            });
        }
        let mut original_files: Vec<_> = manifest
            .entries
            .values()
            .filter(|entry| entry.kind == EntryKind::File)
            .collect();
        original_files.sort_by(|left, right| left.path.cmp(&right.path));
        for entry in original_files {
            let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
                "node layout original file content absent",
            ))?;
            required_file_bytes = required_file_bytes
                .checked_add(content.length)
                .filter(|count| *count <= max_file_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "node layout current file byte bound",
                ))?;
            files.push(NodeRestoreFile::WorktreeCurrent {
                entry_id: entry.entry_id.clone(),
                path: entry.path.clone(),
                content_id: content.content_id.clone(),
                bytes: content.length,
            });
        }
        if files
            .len()
            .checked_add(directories.len())
            .filter(|count| *count <= max_creations)
            .is_none()
        {
            return Err(ReconcileError::ResourceLimit(
                "node layout total original creation count",
            ));
        }
        Ok(NodeRestoreLayout {
            archive_digest: self.digest().clone(),
            directories,
            files,
            required_file_bytes,
        })
    }
}
