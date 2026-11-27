//! Full immutable restore planning before any original destination CREATE.
use super::{ArchiveRole, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};
use sync_extend_core_model::{ContentId, EntryId, EntryKind, Manifest, PortableEntryMetadata};
use sync_extend_journal::{JournalBackupImage, NativeHistoryPreparedProjectionEvidence, NodeInspectionBounds};

#[derive(Clone, Copy)]
pub struct UnixNodeRestoreBounds {
    pub maximum_creations: usize,
    pub maximum_file_bytes: u64,
    pub maximum_total_bytes: u64,
    pub maximum_journal_bytes: usize,
    pub journal_sidecar_bytes: u64,
}
impl UnixNodeRestoreBounds {
    pub(super) fn validate(self) -> Result<()> {
        if self.maximum_creations == 0
            || self.maximum_creations > 100_000
            || self.maximum_file_bytes == 0
            || self.maximum_file_bytes > 1024 * 1024 * 1024
            || self.maximum_total_bytes == 0
            || self.maximum_total_bytes > 4 * 1024 * 1024 * 1024
            || !(512..=256 * 1024 * 1024).contains(&self.maximum_journal_bytes)
            || self.journal_sidecar_bytes < 32 * 1024
            || self.journal_sidecar_bytes > 256 * 1024 * 1024
            || self.journal_sidecar_bytes % (32 * 1024) != 0
        {
            return Err(ReconcileError::ResourceLimit(
                "bounded original Unix restore allocations",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct Slot {
    pub(super) data: bool,
    pub(super) parts: Vec<String>,
}
impl Slot {
    pub(super) fn new(data: bool, parts: &[&str]) -> Self {
        Self {
            data,
            parts: parts.iter().map(|p| (*p).to_owned()).collect(),
        }
    }
    pub(super) fn parent(&self) -> Self {
        Self {
            data: self.data,
            parts: self.parts[..self.parts.len() - 1].to_vec(),
        }
    }
    pub(super) fn name(&self) -> &str {
        self.parts.last().expect("planned leaf")
    }
}

pub(super) enum Content {
    Section(ArchiveRole),
    Current(EntryId),
    SpaceMarker,
}
pub(super) struct PlannedFile {
    pub(super) source: Content,
    pub(super) bytes: u64,
    pub(super) digest: ContentId,
    pub(super) projected: Option<PortableEntryMetadata>,
}

pub struct PreparedUnixNodeRestore<'archive> {
    pub(super) archive: &'archive VerifiedNodeStateArchive,
    pub(super) data: PathBuf,
    pub(super) worktree: PathBuf,
    pub(super) directories: Vec<Slot>,
    pub(super) files: BTreeMap<Slot, PlannedFile>,
    pub(super) mapped: JournalBackupImage,
    pub(super) native_projection: Option<NativeHistoryPreparedProjectionEvidence>,
    pub(super) manifest: Manifest,
    pub(super) bounds: UnixNodeRestoreBounds,
    pub(super) inspection: NodeInspectionBounds,
    pub(super) total_bytes: u64,
}

fn root(path: &Path) -> Result<()> {
    let spelling = path
        .to_str()
        .ok_or(ReconcileError::Invariant("UTF8 Unix restore root"))?;
    if !path.is_absolute()
        || path.parent().is_none()
        || path.to_str().is_none()
        || path.as_os_str().len() > 32_768
        || spelling.split('/').skip(1).any(|part| {
            part.is_empty() || matches!(part, "." | "..") || part.contains(['\\', '\0'])
        })
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(ReconcileError::Invariant(
            "explicit normalized Unix restore root",
        ));
    }
    Ok(())
}

impl VerifiedNodeStateArchive {
    pub fn prepare_unix_restore<'archive>(
        &'archive self,
        data: &Path,
        worktree: &Path,
        inspection: NodeInspectionBounds,
        bounds: UnixNodeRestoreBounds,
    ) -> Result<PreparedUnixNodeRestore<'archive>> {
        self.prepare_unix_restore_inner(data, worktree, inspection, bounds, false)
    }

    /// Preserve every original native row and hold as inert history while
    /// preparing the existing safe active projection. Logical preparation
    /// records are not actual target creator or restart certificates.
    pub fn prepare_unix_restore_with_native_history<'archive>(
        &'archive self,
        data: &Path,
        worktree: &Path,
        inspection: NodeInspectionBounds,
        bounds: UnixNodeRestoreBounds,
    ) -> Result<PreparedUnixNodeRestore<'archive>> {
        self.prepare_unix_restore_inner(data, worktree, inspection, bounds, true)
    }

    fn prepare_unix_restore_inner<'archive>(
        &'archive self,
        data: &Path,
        worktree: &Path,
        inspection: NodeInspectionBounds,
        bounds: UnixNodeRestoreBounds,
        native_history: bool,
    ) -> Result<PreparedUnixNodeRestore<'archive>> {
        bounds.validate()?;
        inspection.validate()?;
        root(data)?;
        root(worktree)?;
        if data.starts_with(worktree)
            || worktree.starts_with(data)
            || data.starts_with(self.original_worktree())
            || self.original_worktree().starts_with(data)
            || worktree.starts_with(self.original_worktree())
            || self.original_worktree().starts_with(worktree)
        {
            return Err(ReconcileError::Invariant(
                "independent original Unix restore roots",
            ));
        }
        // Configuration/provider remapping is a separate deployment stage.
        if self
            .archive
            .roles()
            .any(|role| matches!(role, ArchiveRole::ExplicitConfig { .. }))
        {
            return Err(ReconcileError::Invariant(
                "Unix node configuration requires separate verified deployment mapping",
            ));
        }
        let image = JournalBackupImage::from_current_node_image(
            self.journal_bytes()?.to_vec(),
            self.journal_digest.as_str(),
            bounds.maximum_journal_bytes,
            self.space(),
            inspection,
        )?;
        let (mapped, native_projection) = if native_history {
            let (image, evidence) = image.prepare_native_history_projection(
                self.space(), self.device(), self.original_worktree(), worktree,
                inspection, bounds.maximum_journal_bytes,
            )?.into_parts();
            (image, Some(evidence))
        } else {
            (image.mapped_portable_worktree_image(
                self.space(), self.original_worktree(), worktree, inspection,
                bounds.maximum_journal_bytes,
            )?, None)
        };
        let manifest = self.current_node_manifest(inspection)?;
        let mut directories = BTreeSet::from([
            Slot::new(true, &["cas"]),
            Slot::new(true, &["cas", "objects"]),
            Slot::new(true, &["cas", "tmp"]),
            Slot::new(false, &[".sync-extend"]),
        ]);
        let mut files = BTreeMap::new();
        // The live original database may grow after entering WAL mode. Reserve
        // its entire admitted creator capacity alongside all sidecar bounds.
        let mut total = bounds.maximum_journal_bytes as u64;
        for role in self.archive.roles() {
            let slot = match role {
                ArchiveRole::Journal => continue,
                ArchiveRole::DeviceSecret => Slot::new(true, &["device.secret"]),
                ArchiveRole::CasObject { content_id } => {
                    let prefix = &content_id.as_str()[..2];
                    directories.insert(Slot::new(true, &["cas", "objects", prefix]));
                    Slot::new(true, &["cas", "objects", prefix, content_id.as_str()])
                }
                ArchiveRole::PeerApproval { device_id } => {
                    directories.insert(Slot::new(true, &["peers"]));
                    Slot::new(true, &["peers", &format!("{device_id}.json")])
                }
                ArchiveRole::ExplicitConfig { .. } => unreachable!("configuration preflight"),
            };
            let bytes = self.archive.section(role).ok_or(ReconcileError::Invariant(
                "original Unix source section missing",
            ))?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or(ReconcileError::ResourceLimit("Unix restore sum overflow"))?;
            files.insert(
                slot,
                PlannedFile {
                    source: Content::Section(role.clone()),
                    bytes: bytes.len() as u64,
                    digest: ContentId::hash(bytes),
                    projected: None,
                },
            );
        }
        for entry in manifest.entries.values() {
            let parts: Vec<_> = entry.path.as_str().split('/').map(str::to_owned).collect();
            if parts.first().is_some_and(|name| name == ".sync-extend") {
                return Err(ReconcileError::Invariant(
                    "original current path overlaps Unix control directory",
                ));
            }
            let slot = Slot { data: false, parts };
            if entry.kind == EntryKind::Directory {
                directories.insert(slot);
                continue;
            }
            if entry.kind != EntryKind::File {
                return Err(ReconcileError::Invariant(
                    "supported original Unix current entry kind",
                ));
            }
            let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
                "original current file content missing",
            ))?;
            content.validate()?;
            let projected = entry
                .metadata
                .as_ref()
                .map(crate::filesystem::projected_metadata)
                .transpose()?;
            if let Some(projected) = &projected {
                crate::filesystem::platform_metadata_for_apply(projected)?;
            }
            total = total
                .checked_add(content.length)
                .ok_or(ReconcileError::ResourceLimit("Unix restore sum overflow"))?;
            if files
                .insert(
                    slot,
                    PlannedFile {
                        source: Content::Current(entry.entry_id.clone()),
                        bytes: content.length,
                        digest: content.content_id.clone(),
                        projected,
                    },
                )
                .is_some()
            {
                return Err(ReconcileError::Invariant(
                    "duplicate original Unix file slot",
                ));
            }
        }
        let marker = self.space().as_str().as_bytes();
        total = total
            .checked_add(marker.len() as u64)
            .ok_or(ReconcileError::ResourceLimit("Unix marker bytes overflow"))?;
        files.insert(
            Slot::new(false, &[".sync-extend", "space-id"]),
            PlannedFile {
                source: Content::SpaceMarker,
                bytes: marker.len() as u64,
                digest: ContentId::hash(marker),
                projected: None,
            },
        );
        // Account all actual fixed creators and the intent bytes before effects.
        total = total
            .checked_add(
                bounds
                    .journal_sidecar_bytes
                    .checked_mul(3)
                    .ok_or(ReconcileError::ResourceLimit("Unix sidecar sum"))?,
            )
            .and_then(|bytes| bytes.checked_add(65_536))
            .ok_or(ReconcileError::ResourceLimit("Unix restore allocated sum"))?;
        if total > bounds.maximum_total_bytes
            || files
                .values()
                .any(|file| file.bytes > bounds.maximum_file_bytes)
            || files.len() + directories.len() + 8 > bounds.maximum_creations
        {
            return Err(ReconcileError::ResourceLimit(
                "complete original Unix restore budget",
            ));
        }
        for slot in files.keys().chain(directories.iter()) {
            if slot.parts.is_empty()
                || slot.parts.len() > 128
                || slot.parts.iter().any(|part| {
                    part.is_empty()
                        || part.len() > 255
                        || matches!(part.as_str(), "." | "..")
                        || part.contains(['\\', '/', '\0'])
                })
                || (!slot.parent().parts.is_empty() && !directories.contains(&slot.parent()))
                || files.contains_key(&slot.parent())
                || files.contains_key(slot) && directories.contains(slot)
            {
                return Err(ReconcileError::Invariant(
                    "complete Unix normalized parent-before-child slots",
                ));
            }
        }
        let mut directories: Vec<_> = directories.into_iter().collect();
        directories.sort_by(|a, b| (a.parts.len(), a).cmp(&(b.parts.len(), b)));
        Ok(PreparedUnixNodeRestore {
            archive: self,
            data: data.into(),
            worktree: worktree.into(),
            directories,
            files,
            mapped,
            native_projection,
            manifest,
            bounds,
            inspection,
            total_bytes: total,
        })
    }
}

impl PreparedUnixNodeRestore<'_> {
    pub fn native_projection_evidence(&self) -> Option<&NativeHistoryPreparedProjectionEvidence> {
        self.native_projection.as_ref()
    }
    pub fn required_bytes(&self) -> u64 {
        self.total_bytes
    }
    pub fn archive_digest(&self) -> &ContentId {
        self.archive.digest()
    }
    pub(super) fn chunks<'a>(&'a self, file: &PlannedFile) -> Result<Vec<&'a [u8]>> {
        match &file.source {
            Content::Section(role) => Ok(vec![self.archive.archive.section(role).ok_or(
                ReconcileError::Invariant("verified Unix section disappeared"),
            )?]),
            Content::SpaceMarker => Ok(vec![self.archive.space().as_str().as_bytes()]),
            Content::Current(id) => {
                let content = self
                    .manifest
                    .entries
                    .get(id)
                    .and_then(|entry| entry.content.as_ref())
                    .ok_or(ReconcileError::Invariant(
                        "verified Unix current contents disappeared",
                    ))?;
                content
                    .chunks
                    .iter()
                    .map(|chunk| {
                        self.archive
                            .archive
                            .section(&ArchiveRole::CasObject {
                                content_id: chunk.content_id.clone(),
                            })
                            .ok_or(ReconcileError::Invariant(
                                "verified Unix ordered chunk disappeared",
                            ))
                    })
                    .collect()
            }
        }
    }
}
