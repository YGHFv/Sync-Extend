//! Materialize one verified original archive section into caller's fresh CREATE.
//! This does not publish a pathname, restore a node, recover ownership or clean partials.
use super::{layout::ArchiveRole, verifier::VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::io::{Seek, SeekFrom, Write};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{FileKey, OriginalFileCreation, OwnedFileCreation};

/// Borrows the caller's actual creator and preserves lineage after sync.
/// No Debug/Serialize/Clone, secret contents, filesystem path or writable accessor.
pub struct CreatedNodeSection<'a> {
    creator: &'a OwnedFileCreation,
    key: FileKey,
    parent_key: FileKey,
    role: ArchiveRole,
    digest: ContentId,
    bytes: u64,
}

impl CreatedNodeSection<'_> {
    pub fn role(&self) -> &ArchiveRole {
        &self.role
    }
    pub fn key(&self) -> FileKey {
        self.key
    }
    pub fn parent_key(&self) -> FileKey {
        self.parent_key
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn original(&self) -> Result<OriginalFileCreation<'_>> {
        self.verify()?;
        self.creator.original_creation().map_err(Into::into)
    }

    pub fn verify(&self) -> Result<()> {
        super::created_bytes::verify(
            self.creator,
            self.key,
            self.parent_key,
            self.bytes,
            &self.digest,
        )
    }
}

impl VerifiedNodeStateArchive {
    /// Caller activates durable intent before CREATE and retains destination ancestors.
    /// On any error this leaves the possible partial file and its original live creator.
    /// It never deletes, reopens, adopts or overwrites any existing occupant.
    pub fn materialize_created_section<'a>(
        &self,
        role: &ArchiveRole,
        creator: &'a mut OwnedFileCreation,
    ) -> Result<CreatedNodeSection<'a>> {
        let bytes = self.archive.section(role).ok_or(ReconcileError::Invariant(
            "node original archive section absent",
        ))?;
        let digest = ContentId::hash(bytes);
        let original = creator.original_creation()?;
        let key = original.key()?;
        let parent_key = original.parent_key()?;
        creator.verify_single_link()?;
        if creator.reader().metadata()?.len() != 0 {
            return Err(ReconcileError::Invariant(
                "node restore requires empty fresh CREATE",
            ));
        }
        creator.writer().seek(SeekFrom::Start(0))?;
        crate::fault::checkpoint("node_restore_created_empty");
        for (index, chunk) in bytes.chunks(64 * 1024).enumerate() {
            creator.verify_single_link()?;
            creator.writer().write_all(chunk)?;
            if index == 0 {
                crate::fault::checkpoint("node_restore_created_first_chunk");
            }
        }
        creator.writer().flush()?;
        creator.writer().sync_all()?;
        crate::fault::checkpoint("node_restore_created_synced");
        let result = CreatedNodeSection {
            creator,
            key,
            parent_key,
            role: role.clone(),
            digest,
            bytes: bytes.len() as u64,
        };
        result.verify()?;
        crate::fault::checkpoint("node_restore_created_verified");
        Ok(result)
    }
}
