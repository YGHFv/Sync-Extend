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
    config_scope: NodeConfigRestoreScope,
}

pub(super) enum NodeConfigRestoreScope {
    Ordinary,
    InspectionOnly,
    #[cfg(windows)]
    SeparatedDeployment {
        configs: crate::SeparatedDeploymentNodeConfigs,
        worktree: std::path::PathBuf,
        data: std::path::PathBuf,
    },
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

    pub(super) fn verify_original_source_scope(
        &self,
        archive: &VerifiedNodeStateArchive,
        worktree: &std::path::Path,
        data: &std::path::Path,
    ) -> Result<()> {
        if self.archive_digest != *archive.digest() {
            return Err(ReconcileError::Invariant(
                "node layout original full archive differs",
            ));
        }
        match &self.config_scope {
            NodeConfigRestoreScope::Ordinary => Ok(()),
            NodeConfigRestoreScope::InspectionOnly => Err(ReconcileError::Invariant(
                "source inspection layout cannot create original node roots",
            )),
            #[cfg(windows)]
            NodeConfigRestoreScope::SeparatedDeployment {
                configs,
                worktree: expected_worktree,
                data: expected_data,
            } => {
                if worktree != expected_worktree || data != expected_data {
                    return Err(ReconcileError::Invariant(
                        "separated node layout original target roots differ",
                    ));
                }
                configs.verify_for_archive(archive, worktree, data)
            }
        }
    }

    #[cfg(windows)]
    pub(crate) fn separated_deployment_configs(
        &self,
    ) -> Option<&crate::SeparatedDeploymentNodeConfigs> {
        match &self.config_scope {
            NodeConfigRestoreScope::Ordinary | NodeConfigRestoreScope::InspectionOnly => None,
            NodeConfigRestoreScope::SeparatedDeployment { configs, .. } => Some(configs),
        }
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
        self.current_node_restore_layout_inner(
            inspection,
            max_creations,
            max_file_bytes,
            NodeConfigRestoreScope::Ordinary,
        )
    }

    #[cfg(windows)]
    pub(crate) fn current_node_restore_layout_for_deployment(
        &self,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        worktree: &std::path::Path,
        data: &std::path::Path,
        configs: crate::SeparatedDeploymentNodeConfigs,
    ) -> Result<NodeRestoreLayout> {
        self.current_node_restore_layout_inner(
            inspection,
            max_creations,
            max_file_bytes,
            NodeConfigRestoreScope::SeparatedDeployment {
                configs,
                worktree: worktree.to_owned(),
                data: data.to_owned(),
            },
        )
    }

    pub(super) fn current_node_restore_layout_inner(
        &self,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        config_scope: NodeConfigRestoreScope,
    ) -> Result<NodeRestoreLayout> {
        let (configs, worktree, data) = match &config_scope {
            NodeConfigRestoreScope::Ordinary => (
                None,
                self.original_worktree(),
                self.original_config_data().unwrap_or(self.original_worktree()),
            ),
            NodeConfigRestoreScope::InspectionOnly => {
                return Err(ReconcileError::Invariant(
                    "source inspection layout requires its actual deployment proof",
                ));
            }
            NodeConfigRestoreScope::SeparatedDeployment {
                configs,
                worktree,
                data,
            } => (Some(configs), worktree.as_path(), data.as_path()),
        };
        let mut layout = self.derive_current_node_restore_layout(
            inspection,
            max_creations,
            max_file_bytes,
            worktree,
            data,
            configs,
        )?;
        layout.config_scope = config_scope;
        Ok(layout)
    }

    /// Source-only restart comparison borrows a newly verified full deployment
    /// proof. This projection is explicitly unable to create any original root.
    pub(super) fn current_node_restore_layout_for_deployment_inspection(
        &self,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        worktree: &std::path::Path,
        data: &std::path::Path,
        configs: &crate::SeparatedDeploymentNodeConfigs,
    ) -> Result<NodeRestoreLayout> {
        self.derive_current_node_restore_layout(
            inspection,
            max_creations,
            max_file_bytes,
            worktree,
            data,
            Some(configs),
        )
    }

    fn derive_current_node_restore_layout(
        &self,
        inspection: NodeInspectionBounds,
        max_creations: usize,
        max_file_bytes: u64,
        worktree: &std::path::Path,
        data: &std::path::Path,
        configs: Option<&crate::SeparatedDeploymentNodeConfigs>,
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
        if let Some(configs) = configs {
            configs.verify_for_archive(self, worktree, data)?;
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
        let mut separated_names = BTreeSet::new();
        for role in self.archive.roles() {
            let section = self.archive.section(role).ok_or(ReconcileError::Invariant(
                "node layout original role bytes absent",
            ))?;
            if let ArchiveRole::ExplicitConfig { name } = role {
                let Some(configs) = configs else {
                    return Err(ReconcileError::Invariant(
                        "node layout requires separate explicit original config mapping",
                    ));
                };
                configs.verify_excluded_original_config(self, name, section)?;
                if !separated_names.insert(name.as_str()) {
                    return Err(ReconcileError::Invariant(
                        "separated node layout duplicate original config",
                    ));
                }
                // The deployment CREATE plan owns this verified mapped config
                // file. It is never a node-restore file slot.
                continue;
            }
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
                ArchiveRole::ExplicitConfig { .. } => continue,
            };
            files.push(file);
            if files.len() + directories.len() > max_creations {
                return Err(ReconcileError::ResourceLimit(
                    "node layout original creation count",
                ));
            }
        }
        if let Some(configs) = configs {
            if configs.config_names().collect::<BTreeSet<_>>() != separated_names {
                return Err(ReconcileError::Invariant(
                    "separated node layout complete original config membership differs",
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
            // Pure source preflight runs before any destination root/file
            // CREATE. Deterministically unrepresentable mandatory metadata must
            // fail here; native apply failures later retain their real prefix.
            if let Some(metadata) = &entry.metadata {
                crate::filesystem::projected_metadata(metadata)?;
            }
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
            config_scope: NodeConfigRestoreScope::InspectionOnly,
        })
    }
}
