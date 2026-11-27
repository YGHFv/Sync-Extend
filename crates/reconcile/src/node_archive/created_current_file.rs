//! Ordered original CAS reconstruction into caller's actual empty CREATE.
use super::{ArchiveRole, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::io::{Seek, SeekFrom, Write};
use sync_extend_core_model::{ContentId, EntryId, EntryKind, PortableEntryMetadata, PortablePath};
use sync_extend_journal::NodeInspectionBounds;
use sync_extend_platform_fs::{FileKey, OriginalFileCreation, OwnedFileCreation};

/// A complete current-file content receipt, with no pathname adoption or writer accessor.
pub struct CreatedNodeCurrentFile<'a> {
    creator: &'a OwnedFileCreation,
    key: FileKey,
    parent_key: FileKey,
    entry_id: EntryId,
    original_path: PortablePath,
    digest: ContentId,
    bytes: u64,
    metadata: Option<PortableEntryMetadata>,
}
impl CreatedNodeCurrentFile<'_> {
    pub fn key(&self) -> FileKey {
        self.key
    }
    pub fn parent_key(&self) -> FileKey {
        self.parent_key
    }
    pub fn entry_id(&self) -> &EntryId {
        &self.entry_id
    }
    pub fn original_path(&self) -> &PortablePath {
        &self.original_path
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(super) fn metadata(&self) -> Option<&PortableEntryMetadata> {
        self.metadata.as_ref()
    }
    pub fn verify(&self) -> Result<()> {
        super::created_bytes::verify(
            self.creator,
            self.key,
            self.parent_key,
            self.bytes,
            &self.digest,
        )?;
        verify_metadata(self.creator.reader(), self.metadata.as_ref())
    }
    pub fn original(&self) -> Result<OriginalFileCreation<'_>> {
        self.verify()?;
        self.creator.original_creation().map_err(Into::into)
    }
}

pub(super) fn verify_metadata(
    file: &std::fs::File,
    expected: Option<&PortableEntryMetadata>,
) -> Result<()> {
    if let Some(expected) = expected {
        let observed = crate::filesystem::portable_metadata(file)?.ok_or(
            ReconcileError::Invariant("restored current metadata capture absent"),
        )?;
        if !crate::filesystem::metadata_matches_observed(expected, &observed) {
            return Err(ReconcileError::Unstable);
        }
    }
    Ok(())
}

impl VerifiedNodeStateArchive {
    /// No caller-supplied content manifest is accepted. The exact entry and ordered
    /// chunks come from this original archive's current audited Journal snapshot.
    /// Caller activates durable intent before CREATE and retains all target ancestors.
    /// Errors preserve the possible partial file and its actual original creator.
    pub fn materialize_created_current_file<'a>(
        &self,
        entry_id: &EntryId,
        creator: &'a mut OwnedFileCreation,
        inspection: NodeInspectionBounds,
        max_file_bytes: u64,
    ) -> Result<CreatedNodeCurrentFile<'a>> {
        if max_file_bytes == 0 || max_file_bytes > 1024 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "explicit current node file byte bound",
            ));
        }
        let manifest = self.current_node_manifest(inspection)?;
        let entry = manifest
            .entries
            .get(entry_id)
            .ok_or(ReconcileError::Invariant(
                "original current node entry absent",
            ))?;
        if entry.kind != EntryKind::File {
            return Err(ReconcileError::Invariant(
                "original current node entry is not a file",
            ));
        }
        let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
            "original current node file manifest absent",
        ))?;
        content.validate()?;
        // Resolve the supported local values before the first payload write.
        // The signed historical Entry is retained unchanged in the Journal.
        let metadata = entry
            .metadata
            .as_ref()
            .map(crate::filesystem::projected_metadata)
            .transpose()?;
        if content.length > max_file_bytes
            || content.chunks.len() > inspection.capacity.inventory.max_rows
        {
            return Err(ReconcileError::ResourceLimit(
                "current node original file reconstruction bound",
            ));
        }
        // Close every required source chunk and full concatenated content before
        // any target write. Repeated chunks retain their original sequence.
        let mut hasher = blake3::Hasher::new();
        let mut length = 0u64;
        for chunk in &content.chunks {
            let bytes = self
                .archive
                .section(&ArchiveRole::CasObject {
                    content_id: chunk.content_id.clone(),
                })
                .ok_or(ReconcileError::Invariant(
                    "current node original CAS chunk absent",
                ))?;
            if bytes.len() as u64 != u64::from(chunk.length)
                || ContentId::hash(bytes) != chunk.content_id
            {
                return Err(ReconcileError::Invariant(
                    "current node original CAS chunk differs",
                ));
            }
            length = length
                .checked_add(bytes.len() as u64)
                .filter(|length| *length <= max_file_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "current node original chunk byte sum",
                ))?;
            hasher.update(bytes);
        }
        if length != content.length
            || hasher.finalize().to_hex().as_str() != content.content_id.as_str()
        {
            return Err(ReconcileError::Invariant(
                "current node original ordered file hash differs",
            ));
        }
        let original = creator.original_creation()?;
        let key = original.key()?;
        let parent_key = original.parent_key()?;
        creator.verify_single_link()?;
        if creator.reader().metadata()?.len() != 0 {
            return Err(ReconcileError::Invariant(
                "current node requires actual empty fresh CREATE",
            ));
        }
        creator.writer().seek(SeekFrom::Start(0))?;
        crate::fault::checkpoint("node_current_file_created_empty");
        let mut written = 0u64;
        for chunk in &content.chunks {
            let bytes = self
                .archive
                .section(&ArchiveRole::CasObject {
                    content_id: chunk.content_id.clone(),
                })
                .ok_or(ReconcileError::Invariant(
                    "current node original chunk disappeared",
                ))?;
            for part in bytes.chunks(64 * 1024) {
                creator.verify_single_link()?;
                creator.writer().write_all(part)?;
                if written == 0 {
                    crate::fault::checkpoint("node_current_file_created_first_chunk");
                }
                written =
                    written
                        .checked_add(part.len() as u64)
                        .ok_or(ReconcileError::ResourceLimit(
                            "current node written byte count",
                        ))?;
            }
        }
        if written != content.length {
            return Err(ReconcileError::Invariant(
                "current node complete written length differs",
            ));
        }
        creator.writer().flush()?;
        if let Some(metadata) = &metadata {
            // Apply to the original CREATE handle. The platform implementation
            // applies timestamps/executable before readonly and reads them back.
            crate::filesystem::apply_portable_metadata(creator.reader(), metadata)?;
        }
        creator.writer().sync_all()?;
        crate::fault::checkpoint("node_current_file_created_synced");
        let receipt = CreatedNodeCurrentFile {
            creator,
            key,
            parent_key,
            entry_id: entry.entry_id.clone(),
            original_path: entry.path.clone(),
            digest: content.content_id.clone(),
            bytes: written,
            metadata,
        };
        receipt.verify()?;
        crate::fault::checkpoint("node_current_file_created_verified");
        Ok(receipt)
    }
}
