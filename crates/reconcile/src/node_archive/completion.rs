//! Exact original snapshot evidence; never restored native mutation authority.
use super::{
    CreatedNodeDirectorySet, NodeRestoreSlot, NodeTargetRoot, OriginalRestoredLocalSpace,
    PreparedOriginalNodeRestore, VerifiedNodeStateArchive,
};
use crate::{ReconcileError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, SpaceId};

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectEvidence {
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) root: String,
    #[serde(deserialize_with = "super::completion_codec::components")]
    pub(super) components: Vec<String>,
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) kind: String,
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) created_component: String,
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) parent_key: String,
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) object_key: String,
    pub(super) content_bytes: Option<u64>,
    pub(super) content_digest: Option<ContentId>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalNodeCompletionManifest {
    pub(super) version: u32,
    pub(super) archive_digest: ContentId,
    pub(super) ledger_id: SpaceId,
    pub(super) original_chain_terminal: ContentId,
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) worktree_root_key: String,
    #[serde(deserialize_with = "super::completion_codec::text")]
    pub(super) data_root_key: String,
    #[serde(deserialize_with = "super::completion_codec::path_text")]
    pub(super) original_worktree_target: String,
    #[serde(deserialize_with = "super::completion_codec::path_text")]
    pub(super) original_data_target: String,
    pub(super) mapped_journal_digest: ContentId,
    pub(super) journal_rows_digest: ContentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) read_lease_hold: Option<ContentId>,
    pub(super) membership_digest: ContentId,
    pub(super) file_bytes: u64,
    pub(super) object_count: usize,
    #[serde(deserialize_with = "super::completion_codec::objects")]
    pub(super) objects: Vec<ObjectEvidence>,
}

/// A living verified completion snapshot. No public constructor, clone,
/// serde or reference-only restart interface can mint this receipt.
pub struct OriginalNodeCompletionObservation<'a, 'scope> {
    pub(super) local: &'a OriginalRestoredLocalSpace<'scope>,
    pub(super) manifest: OriginalNodeCompletionManifest,
}

impl OriginalNodeCompletionManifest {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn object_count(&self) -> usize {
        self.object_count
    }
    pub fn file_bytes(&self) -> u64 {
        self.file_bytes
    }
    pub(super) fn validate(&self) -> Result<()> {
        use std::collections::BTreeSet;
        if self.version != 1
            || self.object_count == 0
            || self.object_count > super::completion_codec::MAX_OBJECTS
            || self.object_count != self.objects.len()
        {
            return Err(ReconcileError::Invariant(
                "completion original manifest count/version",
            ));
        }
        let worktree = std::path::Path::new(&self.original_worktree_target);
        let data = std::path::Path::new(&self.original_data_target);
        if self.original_worktree_target.len() > 4096
            || self.original_data_target.len() > 4096
            || worktree == data
            || worktree.starts_with(data)
            || data.starts_with(worktree)
        {
            return Err(ReconcileError::Invariant(
                "completion original target path scope differs",
            ));
        }
        super::roots::split_target(worktree)?;
        super::roots::split_target(data)?;
        let mut slots = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut total = 0u64;
        let mut roots = BTreeSet::new();
        let mut directories = std::collections::BTreeMap::new();
        let mut aliases = BTreeSet::new();
        for object in &self.objects {
            if !matches!(object.root.as_str(), "worktree" | "data")
                || !matches!(object.kind.as_str(), "file" | "directory")
                || object.components.len() > 128
                || object.created_component.is_empty()
                || object.created_component.len() > 255
                || !keys.insert(object.object_key.clone())
                || !slots.insert((object.root.clone(), object.components.clone()))
            {
                return Err(ReconcileError::Invariant(
                    "completion original object typed scope",
                ));
            }
            for key in [&object.parent_key, &object.object_key] {
                let parts: Vec<_> = key.split(':').collect();
                if !matches!(parts.as_slice(), ["windows", volume, id]
                    if volume.parse::<u64>().is_ok_and(|n| n.to_string() == *volume)
                    && id.parse::<u128>().is_ok_and(|n| n.to_string() == *id))
                {
                    return Err(ReconcileError::Invariant(
                        "completion original canonical native key",
                    ));
                }
            }
            if object.parent_key == object.object_key {
                return Err(ReconcileError::Invariant(
                    "completion original parent/self identity",
                ));
            }
            validate_component(
                &object.created_component,
                object.root == "worktree" && object.components == [".sync-extend"],
            )?;
            let alias = object
                .components
                .iter()
                .map(|part| part.to_uppercase())
                .collect::<Vec<_>>();
            if !aliases.insert((object.root.clone(), alias)) {
                return Err(ReconcileError::Invariant(
                    "completion original portable slot alias",
                ));
            }
            for (index, part) in object.components.iter().enumerate() {
                validate_component(
                    part,
                    object.root == "worktree" && index == 0 && part == ".sync-extend",
                )?;
                if part.is_empty() || part.len() > 255 || part.contains(['/', '\\']) {
                    return Err(ReconcileError::Invariant(
                        "completion original relative component",
                    ));
                }
            }
            if object.components.is_empty() {
                if object.kind != "directory" || !roots.insert(object.root.clone()) {
                    return Err(ReconcileError::Invariant(
                        "completion original root evidence",
                    ));
                }
                let expected = if object.root == "worktree" {
                    &self.worktree_root_key
                } else {
                    &self.data_root_key
                };
                if &object.object_key != expected {
                    return Err(ReconcileError::Invariant(
                        "completion original root key differs",
                    ));
                }
            } else if object.components.last() != Some(&object.created_component) {
                return Err(ReconcileError::Invariant(
                    "completion original created component differs",
                ));
            }
            if !object.components.is_empty() {
                let parent_parts = object.components[..object.components.len() - 1].to_vec();
                let parent = directories
                    .get(&(object.root.clone(), parent_parts))
                    .ok_or(ReconcileError::Invariant(
                        "completion original parent closure absent",
                    ))?;
                if *parent != object.parent_key {
                    return Err(ReconcileError::Invariant(
                        "completion original parent closure key differs",
                    ));
                }
            }
            if object.kind == "directory" {
                directories.insert(
                    (object.root.clone(), object.components.clone()),
                    object.object_key.clone(),
                );
            }
            if object.kind == "file" {
                let bytes = object
                    .content_bytes
                    .ok_or(ReconcileError::Invariant("completion file length absent"))?;
                if object.content_digest.is_none() {
                    return Err(ReconcileError::Invariant("completion file hash absent"));
                }
                total = total
                    .checked_add(bytes)
                    .ok_or(ReconcileError::ResourceLimit("completion bytes overflow"))?;
            } else if object.content_bytes.is_some() || object.content_digest.is_some() {
                return Err(ReconcileError::Invariant(
                    "completion directory has file content",
                ));
            }
        }
        if roots.len() != 2
            || total != self.file_bytes
            || self.objects.windows(2).any(|pair| {
                (&pair[0].root, &pair[0].components) >= (&pair[1].root, &pair[1].components)
            })
            || super::completion_codec::digest(&self.objects)? != self.membership_digest
        {
            return Err(ReconcileError::Invariant(
                "completion full canonical membership/byte mismatch",
            ));
        }
        Ok(())
    }
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        super::completion_codec::bytes(self, super::completion_codec::MAX_BYTES)
    }
}

impl<'scope> OriginalRestoredLocalSpace<'scope> {
    /// Snapshot observes only the exact living original scope. All original
    /// bytes, native keys, protected readers and full memberships are verified
    /// before and after collection. It does not unlock restored mutation APIs.
    pub fn observe_original_completion<'a>(
        &'a self,
        archive: &VerifiedNodeStateArchive,
        plan: &PreparedOriginalNodeRestore,
        ledger: &super::NodeRestoreLedger,
    ) -> Result<OriginalNodeCompletionObservation<'a, 'scope>> {
        self.verify()?;
        ledger.verify_external()?;
        if self.archive_digest() != archive.digest()
            || self.archive_digest() != plan.archive_digest()
            || !std::ptr::eq(self.directories.original, plan.original_layout())
            || !std::ptr::eq(self.directories.mapped, plan.mapped_layout())
        {
            return Err(ReconcileError::Invariant(
                "completion requires exact original plan and live archive scope",
            ));
        }
        self.verify_original_prepared_completion(plan)?;
        let (ledger_id, terminal) = ledger.original_completion_scope()?;
        let mut objects = Vec::new();
        for root in [NodeTargetRoot::Worktree, NodeTargetRoot::Data] {
            let (held, path) = match root {
                NodeTargetRoot::Worktree => (
                    &self.directories.roots.worktree,
                    &self.directories.roots.worktree_path,
                ),
                NodeTargetRoot::Data => (
                    &self.directories.roots.data,
                    &self.directories.roots.data_path,
                ),
            };
            let original = held.original_creation()?;
            original.verify()?;
            if !held.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "completion original root named slot differs",
                ));
            }
            objects.push(ObjectEvidence {
                root: root_name(root).into(),
                components: Vec::new(),
                kind: "directory".into(),
                created_component: original.created_component().to_owned(),
                parent_key: original.parent_key()?.to_string(),
                object_key: original.key()?.to_string(),
                content_bytes: None,
                content_digest: None,
            });
        }
        for slot in plan.mapped_layout().directories() {
            objects.push(directory_evidence(self.directories, slot)?);
        }
        for slot in plan.mapped_layout().files() {
            objects.push(self.original_file_completion_evidence(slot)?);
        }
        objects.extend(self.original_sentinel_completion_evidence()?);
        if objects.len() != plan.required_intents() {
            return Err(ReconcileError::Invariant(
                "completion exact full object count differs",
            ));
        }
        objects.sort_by(|left, right| {
            (&left.root, &left.components).cmp(&(&right.root, &right.components))
        });
        if objects
            .windows(2)
            .any(|pair| pair[0].root == pair[1].root && pair[0].components == pair[1].components)
        {
            return Err(ReconcileError::Invariant(
                "completion original object slot duplicate",
            ));
        }
        let file_bytes = objects.iter().try_fold(0u64, |bytes, object| {
            bytes.checked_add(object.content_bytes.unwrap_or(0)).ok_or(
                ReconcileError::ResourceLimit("completion original file byte overflow"),
            )
        })?;
        if file_bytes != plan.required_file_bytes() {
            return Err(ReconcileError::Invariant(
                "completion exact original file bytes differ",
            ));
        }
        let manifest = OriginalNodeCompletionManifest {
            version: 1,
            archive_digest: archive.digest().clone(),
            ledger_id,
            original_chain_terminal: terminal,
            worktree_root_key: self.directories.roots.worktree.key()?.to_string(),
            data_root_key: self.directories.roots.data.key()?.to_string(),
            original_worktree_target: plan
                .worktree
                .to_str()
                .ok_or(ReconcileError::Invariant(
                    "completion original worktree UTF8 path",
                ))?
                .to_owned(),
            original_data_target: plan
                .data
                .to_str()
                .ok_or(ReconcileError::Invariant(
                    "completion original data UTF8 path",
                ))?
                .to_owned(),
            mapped_journal_digest: plan.journal.digest().parse()?,
            journal_rows_digest: self.original_complete_rows_digest()?,
            read_lease_hold: plan.read_lease_hold.clone(),
            membership_digest: super::completion_codec::digest(&objects)?,
            file_bytes,
            object_count: objects.len(),
            objects,
        };
        manifest.bytes()?;
        self.verify_original_completion_membership(&manifest)?;
        ledger.verify_original_completion_objects(&manifest)?;
        self.verify()?;
        ledger.verify_external()?;
        Ok(OriginalNodeCompletionObservation {
            local: self,
            manifest,
        })
    }
}

fn root_name(root: NodeTargetRoot) -> &'static str {
    match root {
        NodeTargetRoot::Worktree => "worktree",
        NodeTargetRoot::Data => "data",
    }
}

fn directory_evidence(
    directories: &CreatedNodeDirectorySet<'_>,
    slot: &NodeRestoreSlot,
) -> Result<ObjectEvidence> {
    let held = directories.parent(slot.root(), slot.components())?;
    let original = held.original_creation()?;
    original.verify()?;
    if !held.matches_path(&directories.path(slot.root(), slot.components()))? {
        return Err(ReconcileError::Invariant(
            "completion original derived directory slot differs",
        ));
    }
    Ok(ObjectEvidence {
        root: root_name(slot.root()).into(),
        components: slot.components().to_vec(),
        kind: "directory".into(),
        created_component: original.created_component().to_owned(),
        parent_key: original.parent_key()?.to_string(),
        object_key: original.key()?.to_string(),
        content_bytes: None,
        content_digest: None,
    })
}

fn validate_component(part: &str, internal_marker: bool) -> Result<()> {
    if internal_marker && part == ".sync-extend" {
        return Ok(());
    }
    if part.len() > 255 {
        return Err(ReconcileError::Invariant(
            "completion original component bytes",
        ));
    }
    let path = sync_extend_core_model::PortablePath::new(part)?;
    if path.parent().is_some() || path.as_str() != part {
        return Err(ReconcileError::Invariant(
            "completion original exact portable component",
        ));
    }
    Ok(())
}

// Source-derived values only: restart classification never opens target roots.
impl OriginalNodeCompletionManifest {
    pub(super) fn verify_archive_source(
        &self,
        archive: &VerifiedNodeStateArchive,
        inspection: sync_extend_journal::NodeInspectionBounds,
    ) -> Result<()> {
        use super::{ArchiveRole, NodeRestoreFile, NodeRestoreLayout, NodeTargetRoot};
        use std::collections::BTreeMap;
        self.validate()?;
        if self.archive_digest != *archive.digest() {
            return Err(ReconcileError::Invariant(
                "completion restart exact source archive differs",
            ));
        }
        let worktree = std::path::Path::new(&self.original_worktree_target);
        if self.read_lease_hold.is_some() {
            archive.validate_read_lease_migration_roots(
                worktree,
                std::path::Path::new(&self.original_data_target),
            )?;
        }
        let mapped_image = archive.map_original_restore_journal(
            worktree,
            inspection,
            256 * 1024 * 1024,
            self.read_lease_hold.as_ref(),
        )?;
        if mapped_image.digest() != self.mapped_journal_digest.as_str()
            || mapped_image.original_completion_rows_digest(archive.space(), inspection)?
                != self.journal_rows_digest
        {
            return Err(ReconcileError::Invariant(
                "completion restart original mapped Journal/typedrows differs",
            ));
        }
        let layout: NodeRestoreLayout = archive.current_node_restore_layout(
            inspection,
            super::completion_codec::MAX_OBJECTS,
            1024 * 1024 * 1024,
        )?;
        let mapped = layout.map_original_slots(super::completion_codec::MAX_OBJECTS)?;
        if self.object_count != mapped.directories().len() + mapped.files().len() + 5 {
            return Err(ReconcileError::Invariant(
                "completion restart original source inventory count differs",
            ));
        }
        type CompletedSlot<'a> = (&'a str, Option<(u64, ContentId)>);
        let mut expected: BTreeMap<(String, Vec<String>), CompletedSlot<'_>> = BTreeMap::new();
        for root in ["worktree", "data"] {
            expected.insert((root.into(), Vec::new()), ("directory", None));
        }
        for slot in mapped.directories() {
            expected.insert(
                (root_name(slot.root()).into(), slot.components().to_vec()),
                ("directory", None),
            );
        }
        for slot in mapped.files() {
            let source = mapped.file(slot, &layout)?;
            let content = match source {
                NodeRestoreFile::Journal => Some((
                    mapped_image.bytes().len() as u64,
                    self.mapped_journal_digest.clone(),
                )),
                NodeRestoreFile::WorktreeSpaceMarker => Some((
                    archive.space().as_str().len() as u64,
                    ContentId::hash(archive.space().as_str().as_bytes()),
                )),
                NodeRestoreFile::WorktreeCurrent {
                    content_id, bytes, ..
                } => Some((*bytes, content_id.clone())),
                other => {
                    let role = match other {
                        NodeRestoreFile::ProtectedDeviceIdentity => ArchiveRole::DeviceSecret,
                        NodeRestoreFile::CasObject { content_id } => ArchiveRole::CasObject {
                            content_id: content_id.clone(),
                        },
                        NodeRestoreFile::PeerApproval { device_id } => ArchiveRole::PeerApproval {
                            device_id: device_id.clone(),
                        },
                        _ => {
                            return Err(ReconcileError::Invariant(
                                "completion restart unsupported source role",
                            ))
                        }
                    };
                    let bytes = archive
                        .archive
                        .section(&role)
                        .ok_or(ReconcileError::Invariant(
                            "completion restart original section absent",
                        ))?;
                    Some((bytes.len() as u64, ContentId::hash(bytes)))
                }
            };
            expected.insert(
                (root_name(slot.root()).into(), slot.components().to_vec()),
                ("file", content),
            );
        }
        for (root, parts) in [
            (
                NodeTargetRoot::Worktree,
                vec![".sync-extend".into(), "writer.lock".into()],
            ),
            (NodeTargetRoot::Data, vec!["writer.lock".into()]),
            (NodeTargetRoot::Data, vec!["cas-access.lock".into()]),
        ] {
            expected.insert(
                (root_name(root).into(), parts),
                ("file", Some((0, ContentId::hash(&[])))),
            );
        }
        if expected.len() != self.objects.len() {
            return Err(ReconcileError::Invariant(
                "completion restart complete source slots differ",
            ));
        }
        for object in &self.objects {
            let (kind, content) = expected
                .get(&(object.root.clone(), object.components.clone()))
                .ok_or(ReconcileError::Invariant(
                    "completion restart unexpected source slot",
                ))?;
            if object.kind != *kind
                || object.content_bytes != content.as_ref().map(|value| value.0)
                || object.content_digest.as_ref() != content.as_ref().map(|value| &value.1)
            {
                return Err(ReconcileError::Invariant(
                    "completion restart original source bytes/hash differ",
                ));
            }
        }
        Ok(())
    }
}

impl OriginalNodeCompletionObservation<'_, '_> {
    /// A value-only manifest view. It never exposes native originals or LocalSpace.
    pub fn manifest(&self) -> &OriginalNodeCompletionManifest {
        &self.manifest
    }

    pub(super) fn into_manifest(self) -> OriginalNodeCompletionManifest {
        self.manifest
    }
}

impl OriginalNodeCompletionObservation<'_, '_> {
    pub(super) fn verify(&self) -> Result<()> {
        self.local
            .verify_original_completion_membership(&self.manifest)
    }
}

/// A sealed borrow of the living completion. It exposes owned identity values
/// and exact roots, never LocalSpace or recovered native mutation authority.
pub(crate) struct DeploymentCompletionBinding<'proof, 'local, 'scope> {
    original: &'proof OriginalNodeCompletionObservation<'local, 'scope>,
}

impl<'local, 'scope> OriginalNodeCompletionObservation<'local, 'scope> {
    pub(crate) fn deployment_binding(
        &self,
    ) -> Result<DeploymentCompletionBinding<'_, 'local, 'scope>> {
        self.verify()?;
        Ok(DeploymentCompletionBinding { original: self })
    }
}

impl DeploymentCompletionBinding<'_, '_, '_> {
    pub(crate) fn verify(&self) -> Result<()> {
        self.original.verify()
    }
    pub(crate) fn archive_digest(&self) -> &ContentId {
        &self.original.manifest.archive_digest
    }
    pub(crate) fn data_dir(&self) -> &std::path::Path {
        std::path::Path::new(&self.original.manifest.original_data_target)
    }
    pub(crate) fn worktree(&self) -> &std::path::Path {
        std::path::Path::new(&self.original.manifest.original_worktree_target)
    }
    pub(crate) fn data_key(&self) -> &str {
        &self.original.manifest.data_root_key
    }
    pub(crate) fn worktree_key(&self) -> &str {
        &self.original.manifest.worktree_root_key
    }
    pub(crate) fn manifest_digest(&self) -> Result<ContentId> {
        self.verify()?;
        let digest = ContentId::hash(&self.original.manifest.bytes()?);
        self.verify()?;
        Ok(digest)
    }
    pub(crate) fn space_id(&self) -> Result<SpaceId> {
        self.verify()?;
        let space = self.original.local.status()?.space_id;
        self.verify()?;
        Ok(space)
    }
    pub(crate) fn device_id(&self) -> Result<sync_extend_core_model::DeviceId> {
        self.verify()?;
        let device = self.original.local.status()?.device_id;
        self.verify()?;
        Ok(device)
    }
}
