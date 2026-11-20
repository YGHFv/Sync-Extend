//! Actual restored LocalSpace reads while original creator scope remains live.
use super::{CreatedNodeDirectorySet, OriginalNodeReadAssembly, VerifiedNodeStateArchive};
use crate::{filesystem, identity, LocalSpace, ReconcileError, Result};
use sync_extend_core_model::{limits::LocalLimits, ContentId};

/// Exposes owned status and manifest values only. LocalSpace has effectful
/// methods accepting &self, so even its shared reference must remain private.
pub struct OriginalRestoredLocalSpace<'a> {
    local: LocalSpace,
    pub(super) directories: &'a CreatedNodeDirectorySet<'a>,
    readers: super::assembly::ReadContents,
    data_locks: super::CreatedNodeDataLocks<'a>,
    archive_digest: ContentId,
}

impl OriginalRestoredLocalSpace<'_> {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn verify(&self) -> Result<()> {
        self.directories.verify()?;
        self.data_locks.verify()?;
        self.local.journal.verify_original_created_image()?;
        self.local.verify_root()?;
        for ((root, parts), file) in &self.readers {
            super::read_content::verify(&file.original, file.bytes, &file.digest)?;
            if !file
                .original
                .matches_path(&self.directories.path(*root, parts))?
            {
                return Err(ReconcileError::Invariant(
                    "restoredLocalSpace original content slot differs",
                ));
            }
        }
        if self.archive_digest != *self.directories.archive_digest() {
            return Err(ReconcileError::Invariant(
                "restoredLocalSpace original archive scope",
            ));
        }
        let current = self.local.manifest()?.ok_or(ReconcileError::Invariant(
            "restoredLocalSpace current manifest absent",
        ))?;
        for content in current
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            self.local.cas.verify(content)?;
        }
        self.local.journal.integrity_check()?;
        super::inventory::verify_after_journal(self.directories)?;
        Ok(())
    }
    /// Return the original current manifest without exposing LocalSpace methods.
    pub fn manifest(&self) -> Result<Option<sync_extend_core_model::Manifest>> {
        self.verify()?;
        let result = self.local.manifest()?;
        self.verify()?;
        Ok(result)
    }
    /// Return an owned status while original native scope remains retained.
    pub fn status(&self) -> Result<crate::Status> {
        self.verify()?;
        let result = self.local.status()?;
        self.verify()?;
        Ok(result)
    }
}

impl<'a> OriginalNodeReadAssembly<'a> {
    /// Actual original archive device and roots are checked before constructing
    /// LocalSpace directly with real original Journal/CAS and retained writerlocks.
    /// It never invokes normal open/create/recovery/scanning on target paths.
    pub fn into_original_local_space(
        self,
        archive: &VerifiedNodeStateArchive,
        limits: LocalLimits,
    ) -> Result<OriginalRestoredLocalSpace<'a>> {
        self.verify()?;
        limits.validate()?;
        let mut journal = self.journal;
        journal.set_max_storage_entries(limits.max_storage_entries)?;
        let current = journal
            .current(archive.space())?
            .ok_or(ReconcileError::Invariant(
                "actual original current manifest absent beforeLocalSpace",
            ))?;
        if current.entries.len() > limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit(
                "actual restored LocalSpace entry bound",
            ));
        }

        if self.archive_digest != *archive.digest() || self.space != *archive.space() {
            return Err(ReconcileError::Invariant(
                "originalLocalSpace actual archive scope",
            ));
        }
        let inspection = sync_extend_journal::NodeInspectionBounds {
            max_entries: limits.max_storage_entries,
            capacity: sync_extend_journal::JournalCapacityLimits {
                inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                    max_rows: limits.max_storage_entries,
                    max_logical_bytes: limits.max_storage_entries as u64 * 1024,
                },
                max_rows: limits.max_storage_entries as u64,
                max_logical_bytes: limits.max_storage_entries as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        let mapped = archive.map_original_restore_journal(
            &self.directories.roots.worktree_path,
            inspection,
            256 * 1024 * 1024,
            self.read_lease_hold.as_ref(),
        )?;
        journal.verify_original_image_rows(&mapped, archive.space(), inspection)?;
        self.directories.marker.enable_original_readers()?;
        let data = self.directories.roots.data_path.clone();
        let worktree = self.directories.roots.worktree_path.clone();
        let device = identity::load_or_create(&data.join("device.secret"), false)?;
        if device != *archive.device()
            || journal.state("space_id")?.as_deref() != Some(archive.space().as_str())
            || journal.state("device_id")?.as_deref() != Some(archive.device().as_str())
            || journal.state("worktree")?.as_deref() != worktree.to_str()
        {
            return Err(ReconcileError::Invariant(
                "originalLocalSpace device/worktree states differ",
            ));
        }
        let root_identity = filesystem::PathIdentity::capture(&worktree)?;
        let data_chain = self.directories.roots.original_writer_chain(false)?;
        let writer = sync_extend_platform_fs::WriterOwner::from_original_creation(
            &data,
            self.data_locks.writer.original_creation()?,
            data_chain,
        )?;
        let marker_path = worktree.join(".sync-extend");
        let mut worktree_chain = self.directories.roots.original_writer_chain(true)?;
        worktree_chain.push(
            self.directories
                .marker
                .directory
                .original_creation()?
                .retain_writer_directory(&marker_path)?,
        );
        let worktree_writer = sync_extend_platform_fs::WriterOwner::from_original_creation(
            &marker_path,
            self.directories.marker.writer_lock.original_creation()?,
            worktree_chain,
        )?;
        let local = LocalSpace {
            space_id: archive.space().clone(),
            device_id: device,
            worktree,
            data_dir: data,
            cas: self.cas,
            journal,
            limits,
            root_identity,
            _lock: writer,
            _worktree_lock: worktree_writer,
        };
        let result = OriginalRestoredLocalSpace {
            local,
            directories: self.directories,
            readers: self.readers,
            data_locks: self.data_locks,
            archive_digest: self.archive_digest,
        };
        result.verify()?;
        crate::fault::checkpoint("node_actual_local_space_verified");
        Ok(result)
    }
}

// Appended inside local_space.rs; observe private originals, never export handles.
impl OriginalRestoredLocalSpace<'_> {
    pub(super) fn original_file_completion_evidence(
        &self,
        slot: &super::NodeRestoreSlot,
    ) -> Result<super::completion::ObjectEvidence> {
        use super::completion::ObjectEvidence;
        let root = slot.root();
        let parts = slot.components();
        let root_name = match root {
            super::NodeTargetRoot::Worktree => "worktree",
            super::NodeTargetRoot::Data => "data",
        };
        if root == super::NodeTargetRoot::Data && parts == ["journal.sqlite"] {
            let (key, parent) = self.local.journal.original_completion_main_identity()?;
            let bytes = self.local.journal.original_completion_image_bytes()?;
            return Ok(ObjectEvidence {
                root: root_name.into(),
                components: parts.to_vec(),
                kind: "file".into(),
                created_component: "journal.sqlite".into(),
                object_key: key.to_string(),
                parent_key: parent.to_string(),
                content_bytes: Some(bytes.len() as u64),
                content_digest: Some(ContentId::hash(&bytes)),
            });
        }
        if root == super::NodeTargetRoot::Worktree && parts == [".sync-extend", "space-id"] {
            return self
                .directories
                .marker
                .original_completion_marker_evidence();
        }
        let content =
            self.readers
                .get(&(root, parts.to_vec()))
                .ok_or(ReconcileError::Invariant(
                    "completion original protected file slot absent",
                ))?;
        super::read_content::verify(&content.original, content.bytes, &content.digest)?;
        Ok(ObjectEvidence {
            root: root_name.into(),
            components: parts.to_vec(),
            kind: "file".into(),
            created_component: parts
                .last()
                .ok_or(ReconcileError::Invariant(
                    "completion original file component absent",
                ))?
                .clone(),
            parent_key: content.original.original_parent_key()?.to_string(),
            object_key: content.original.original_key()?.to_string(),
            content_bytes: Some(content.bytes),
            content_digest: Some(content.digest.clone()),
        })
    }

    pub(super) fn original_sentinel_completion_evidence(
        &self,
    ) -> Result<Vec<super::completion::ObjectEvidence>> {
        let mut result = Vec::new();
        for (root, components, held) in [
            (
                "worktree",
                vec![".sync-extend".into(), "writer.lock".into()],
                &self.directories.marker.writer_lock,
            ),
            ("data", vec!["writer.lock".into()], &self.data_locks.writer),
        ] {
            held.verify_single_link()?;
            if held.reader().metadata()?.len() != 0 {
                return Err(ReconcileError::Invariant(
                    "completion original writer sentinel bytes differ",
                ));
            }
            let original = held.original_creation()?;
            result.push(super::completion::ObjectEvidence {
                root: root.into(),
                components,
                kind: "file".into(),
                created_component: original.created_component().to_owned(),
                parent_key: original.parent_key()?.to_string(),
                object_key: original.key()?.to_string(),
                content_bytes: Some(0),
                content_digest: Some(ContentId::hash(&[])),
            });
        }
        let (key, parent) = self.local.journal.original_completion_cas_identity()?;
        result.push(super::completion::ObjectEvidence {
            root: "data".into(),
            components: vec!["cas-access.lock".into()],
            kind: "file".into(),
            created_component: "cas-access.lock".into(),
            parent_key: parent.to_string(),
            object_key: key.to_string(),
            content_bytes: Some(0),
            content_digest: Some(ContentId::hash(&[])),
        });
        Ok(result)
    }

    pub(super) fn original_complete_rows_digest(&self) -> Result<ContentId> {
        self.local
            .journal
            .original_completion_rows_digest(
                &self.local.space_id,
                self.local.limits.max_storage_entries,
            )
            .map_err(Into::into)
    }
}

impl OriginalRestoredLocalSpace<'_> {
    pub(super) fn verify_original_prepared_completion(
        &self,
        plan: &super::PreparedOriginalNodeRestore,
    ) -> Result<()> {
        if self.directories.roots.worktree_path != plan.worktree
            || self.directories.roots.data_path != plan.data
        {
            return Err(ReconcileError::Invariant(
                "completion original precomputed target paths differ",
            ));
        }
        self.local.journal.verify_original_image_rows(
            &plan.journal,
            &self.local.space_id,
            sync_extend_journal::NodeInspectionBounds {
                max_entries: self.local.limits.max_storage_entries,
                capacity: sync_extend_journal::JournalCapacityLimits {
                    inventory: sync_extend_journal::TreeRestoreInventoryLimits {
                        max_rows: self.local.limits.max_storage_entries,
                        max_logical_bytes: self.local.limits.max_storage_entries as u64 * 1024,
                    },
                    max_rows: self.local.limits.max_storage_entries as u64,
                    max_logical_bytes: self.local.limits.max_storage_entries as u64 * 1024,
                },
                max_vm_instructions: 100_000_000,
                max_query_time: std::time::Duration::from_secs(60),
            },
        )?;
        let actual = self.local.journal.original_completion_image_bytes()?;
        if actual != plan.journal.bytes() {
            return Err(ReconcileError::Invariant(
                "completion original actual Journal bytes differ from plan",
            ));
        }
        self.verify()
    }
}

impl OriginalRestoredLocalSpace<'_> {
    pub(super) fn verify_original_completion_membership(
        &self,
        manifest: &super::completion::OriginalNodeCompletionManifest,
    ) -> Result<()> {
        use std::collections::{BTreeMap, BTreeSet};
        manifest.validate()?;
        self.verify()?;
        let mut expected: BTreeMap<(String, Vec<String>), BTreeSet<String>> = BTreeMap::new();
        for object in &manifest.objects {
            if object.kind == "directory" {
                expected
                    .entry((object.root.clone(), object.components.clone()))
                    .or_default();
            }
            if !object.components.is_empty() {
                expected
                    .entry((
                        object.root.clone(),
                        object.components[..object.components.len() - 1].to_vec(),
                    ))
                    .or_default()
                    .insert(object.created_component.clone());
            }
        }
        for ((root, parts), names) in expected {
            let root = match root.as_str() {
                "worktree" => super::NodeTargetRoot::Worktree,
                "data" => super::NodeTargetRoot::Data,
                _ => {
                    return Err(ReconcileError::Invariant(
                        "completion original membership root",
                    ))
                }
            };
            let held = self.directories.parent(root, &parts)?;
            let path = self.directories.path(root, &parts);
            if !held.matches_path(&path)? {
                return Err(ReconcileError::Invariant(
                    "completion original membership directory slot",
                ));
            }
            let mut actual = BTreeSet::new();
            for item in std::fs::read_dir(&path)? {
                let item = item?;
                let metadata = std::fs::symlink_metadata(item.path())?;
                if metadata.file_type().is_symlink() || sync_extend_cas::is_reparse(&metadata) {
                    return Err(ReconcileError::Invariant(
                        "completion membership foreign reparse",
                    ));
                }
                let name = item.file_name().into_string().map_err(|_| {
                    ReconcileError::Invariant("completion membership unknown encoding")
                })?;
                if actual.len() >= names.len() || !names.contains(&name) || !actual.insert(name) {
                    return Err(ReconcileError::Invariant(
                        "completion membership foreign or excess entry",
                    ));
                }
            }
            if actual != names || !held.matches_path(&path)? {
                return Err(ReconcileError::Invariant(
                    "completion exact original full membership differs",
                ));
            }
        }
        self.verify()
    }
}

include!("local_write_transition.rs");
