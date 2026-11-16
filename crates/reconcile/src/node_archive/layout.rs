//! Bounded node archive framing; captured identity and restore authority are separate.
use crate::{ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{ContentId, DeviceId, SnapshotId, SpaceId};

const MAGIC: &[u8; 16] = b"SyncNodeImageV1\0";
const MAX_SECTIONS: usize = 100_000;
const MAX_METADATA: usize = 16 * 1024 * 1024;
const MAX_ARCHIVE: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveBounds {
    pub sections: usize,
    pub metadata_bytes: usize,
    pub archive_bytes: u64,
}

impl ArchiveBounds {
    pub fn validate(self) -> Result<()> {
        if self.sections < 2
            || self.sections > MAX_SECTIONS
            || self.metadata_bytes == 0
            || self.metadata_bytes > MAX_METADATA
            || self.archive_bytes == 0
            || self.archive_bytes > MAX_ARCHIVE
        {
            return Err(ReconcileError::ResourceLimit(
                "explicit bounded node archive limits",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ArchiveRole {
    Journal,
    DeviceSecret,
    CasObject { content_id: ContentId },
    PeerApproval { device_id: DeviceId },
    ExplicitConfig { name: String },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    role: ArchiveRole,
    bytes: u64,
    digest: ContentId,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format_version: u32,
    space: SpaceId,
    device: DeviceId,
    snapshot: Option<SnapshotId>,
    source_schema: u32,
    sections: Vec<Section>,
}

/// Opaque bytes intentionally have no Debug/Serialize implementation.
/// Framing validity does not prove that all node state was captured consistently.
pub struct FramedNodeArchive {
    bytes: Vec<u8>,
    header: Header,
    section_offsets: BTreeMap<Vec<u8>, (usize, usize)>,
    digest: ContentId,
}

/// The source capturer supplies exact bytes; this type has no path reader.
pub(crate) struct SourceSection {
    pub role: ArchiveRole,
    pub bytes: Vec<u8>,
}

fn component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !matches!(name, "." | "..")
        && name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'))
}

fn validate_roles(sections: &[Section], device: &DeviceId) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut journal = 0;
    let mut secret = 0;
    for section in sections {
        let key = serde_json::to_vec(&section.role)?;
        if !seen.insert(key) {
            return Err(ReconcileError::Invariant("duplicate node archive role"));
        }
        match &section.role {
            ArchiveRole::Journal => {
                journal += 1;
                if section.bytes < 512 || section.bytes > 256 * 1024 * 1024 {
                    return Err(ReconcileError::Invariant("node Journal image size"));
                }
            }
            ArchiveRole::DeviceSecret => {
                secret += 1;
                if section.bytes == 0 || section.bytes > 4096 {
                    return Err(ReconcileError::Invariant("node protected identity size"));
                }
            }
            ArchiveRole::CasObject { content_id } => {
                if section.bytes == 0
                    || section.bytes > 4 * 1024 * 1024
                    || *content_id != section.digest
                {
                    return Err(ReconcileError::Invariant("node CAS object identity"));
                }
            }
            ArchiveRole::PeerApproval { device_id } => {
                if device_id == device || section.bytes == 0 || section.bytes > 64 * 1024 {
                    return Err(ReconcileError::Invariant("node peer approval section"));
                }
            }
            ArchiveRole::ExplicitConfig { name } => {
                if !component(name) || section.bytes == 0 || section.bytes > 1024 * 1024 {
                    return Err(ReconcileError::Invariant(
                        "node explicit configuration section",
                    ));
                }
            }
        }
    }
    if journal != 1 || secret != 1 {
        return Err(ReconcileError::Invariant(
            "one original Journal and protected identity required",
        ));
    }
    Ok(())
}

impl FramedNodeArchive {
    pub(crate) fn assemble(
        space: SpaceId,
        device: DeviceId,
        snapshot: Option<SnapshotId>,
        source_schema: u32,
        mut sources: Vec<SourceSection>,
        bounds: ArchiveBounds,
    ) -> Result<Self> {
        bounds.validate()?;
        if sources.len() > bounds.sections || sources.len() < 2 || source_schema == 0 {
            return Err(ReconcileError::ResourceLimit("node archive section count"));
        }
        // Order by canonical metadata bytes, never by caller filesystem enumeration.
        let mut keyed = sources
            .drain(..)
            .map(|section| Ok((serde_json::to_vec(&section.role)?, section)))
            .collect::<Result<Vec<_>>>()?;
        keyed.sort_by(|left, right| left.0.cmp(&right.0));
        let sections: Vec<_> = keyed
            .iter()
            .map(|(_, section)| Section {
                role: section.role.clone(),
                bytes: section.bytes.len() as u64,
                digest: ContentId::hash(&section.bytes),
            })
            .collect();
        validate_roles(&sections, &device)?;
        let header = Header {
            format_version: 1,
            space,
            device,
            snapshot,
            source_schema,
            sections,
        };
        let metadata = serde_json::to_vec(&header)?;
        if metadata.len() > bounds.metadata_bytes {
            return Err(ReconcileError::ResourceLimit("node archive metadata bytes"));
        }
        let metadata_size = u32::try_from(metadata.len())
            .map_err(|_| ReconcileError::ResourceLimit("node metadata size encoding"))?;
        let mut total = 20u64
            .checked_add(metadata.len() as u64)
            .ok_or(ReconcileError::ResourceLimit("node archive size overflow"))?;
        for section in &header.sections {
            total = total
                .checked_add(section.bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "node archive payload overflow",
                ))?;
        }
        if total > bounds.archive_bytes {
            return Err(ReconcileError::ResourceLimit("node archive total bytes"));
        }
        let capacity = usize::try_from(total)
            .map_err(|_| ReconcileError::ResourceLimit("node archive memory bound"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ReconcileError::ResourceLimit("node archive allocation"))?;
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&metadata_size.to_le_bytes());
        bytes.extend_from_slice(&metadata);
        for (_, section) in keyed {
            bytes.extend_from_slice(&section.bytes);
        }
        let expected = ContentId::hash(&bytes);
        Self::verify_framing(bytes, &expected, bounds)
    }

    /// Validate untrusted framing, canonical roles and complete hashes before any CREATE.
    /// Semantic Journal/identity/peer consistency is required by the node verifier.
    pub fn verify_framing(
        bytes: Vec<u8>,
        expected: &ContentId,
        bounds: ArchiveBounds,
    ) -> Result<Self> {
        bounds.validate()?;
        if bytes.len() < 20
            || bytes.len() as u64 > bounds.archive_bytes
            || bytes.get(..16) != Some(MAGIC.as_slice())
            || ContentId::hash(&bytes) != *expected
        {
            return Err(ReconcileError::Invariant("node archive framing digest"));
        }
        let encoded_size: [u8; 4] = bytes[16..20]
            .try_into()
            .map_err(|_| ReconcileError::Invariant("node metadata length encoding"))?;
        let size = usize::try_from(u32::from_le_bytes(encoded_size))
            .map_err(|_| ReconcileError::ResourceLimit("node metadata length bound"))?;
        let payload_start = 20usize
            .checked_add(size)
            .ok_or(ReconcileError::ResourceLimit(
                "node metadata offset overflow",
            ))?;
        if size > bounds.metadata_bytes || payload_start > bytes.len() {
            return Err(ReconcileError::Invariant("node bounded metadata absent"));
        }
        let header: Header = serde_json::from_slice(&bytes[20..payload_start])?;
        if header.format_version != 1
            || header.source_schema == 0
            || header.sections.len() > bounds.sections
            || serde_json::to_vec(&header)? != bytes[20..payload_start]
        {
            return Err(ReconcileError::Invariant(
                "node canonical versioned metadata",
            ));
        }
        validate_roles(&header.sections, &header.device)?;
        let mut previous = None;
        let mut offset = payload_start;
        let mut section_offsets = BTreeMap::new();
        for section in &header.sections {
            let key = serde_json::to_vec(&section.role)?;
            if previous.as_ref().is_some_and(|last| last >= &key) {
                return Err(ReconcileError::Invariant("node archive role order"));
            }
            previous = Some(key.clone());
            let length = usize::try_from(section.bytes)
                .map_err(|_| ReconcileError::ResourceLimit("node section length"))?;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= bytes.len())
                .ok_or(ReconcileError::Invariant("node section truncated"))?;
            if ContentId::hash(&bytes[offset..end]) != section.digest {
                return Err(ReconcileError::Invariant("node section digest"));
            }
            section_offsets.insert(key, (offset, end));
            offset = end;
        }
        if offset != bytes.len() {
            return Err(ReconcileError::Invariant("node archive trailing payload"));
        }
        Ok(Self {
            bytes,
            header,
            section_offsets,
            digest: expected.clone(),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn digest(&self) -> &ContentId {
        &self.digest
    }

    pub(crate) fn section(&self, role: &ArchiveRole) -> Option<&[u8]> {
        let key = serde_json::to_vec(role).ok()?;
        let &(start, end) = self.section_offsets.get(&key)?;
        self.bytes.get(start..end)
    }
}

impl FramedNodeArchive {
    pub(super) fn space_id(&self) -> &SpaceId {
        &self.header.space
    }
    pub(super) fn device_id(&self) -> &DeviceId {
        &self.header.device
    }
    pub(super) fn source_schema(&self) -> u32 {
        self.header.source_schema
    }
    pub(super) fn snapshot_id(&self) -> Option<&SnapshotId> {
        self.header.snapshot.as_ref()
    }
    pub(super) fn roles(&self) -> impl Iterator<Item = &ArchiveRole> {
        self.header.sections.iter().map(|section| &section.role)
    }
}
