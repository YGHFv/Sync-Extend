//! Fixed worktree marker creation, bound to actual original roots and archive.
use super::{CreatedNodeRestoreRoots, NodeRestoreLedger, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::io::{Seek, SeekFrom, Write};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{FileKey, LockedDirectoryMutation, OwnedFileCreation};

/// Holds actual original directory, space marker and exclusive process writerlock.
/// Root ancestors stay held by the separately retained original root receipt.
pub struct CreatedNodeWorktreeMarker<'a> {
    roots: &'a CreatedNodeRestoreRoots,
    pub(super) directory: LockedDirectoryMutation,
    marker: std::cell::RefCell<MarkerContent>,
    pub(super) writer_lock: OwnedFileCreation,
    archive_digest: ContentId,
    marker_digest: ContentId,
    marker_bytes: u64,
    key: FileKey,
    parent_key: FileKey,
}

impl CreatedNodeWorktreeMarker<'_> {
    pub fn verify(&self) -> Result<()> {
        self.roots.verify()?;
        self.directory.original_creation()?.verify()?;
        let parent = self.directory.key()?;
        if parent != self.parent_key
            || self.writer_lock.original_creation()?.parent_key()? != parent
        {
            return Err(ReconcileError::Invariant(
                "original marker/lock parent differs",
            ));
        }
        self.writer_lock.original_creation()?.verify()?;
        self.writer_lock.verify_single_link()?;
        match &*self.marker.borrow() {
            MarkerContent::Created(creator) => super::created_bytes::verify(
                creator,
                self.key,
                parent,
                self.marker_bytes,
                &self.marker_digest,
            ),
            MarkerContent::Read(reader) => {
                if reader.original_key()? != self.key || reader.original_parent_key()? != parent {
                    return Err(ReconcileError::Invariant(
                        "original marker readonly lineage differs",
                    ));
                }
                super::read_content::verify(reader, self.marker_bytes, &self.marker_digest)
            }
            MarkerContent::Failed => Err(ReconcileError::Invariant(
                "original marker content handoff failed",
            )),
        }
    }
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
}

impl VerifiedNodeStateArchive {
    /// Root ancestors and original root slot remain held for the marker lifetime.
    /// Internal reserved name has its own private ledger/native CREATE protocol.
    /// Errors retain any partial original marker/locks, never replace occupants.
    pub fn create_worktree_marker<'a>(
        &self,
        roots: &'a CreatedNodeRestoreRoots,
        ledger: &mut NodeRestoreLedger,
    ) -> Result<CreatedNodeWorktreeMarker<'a>> {
        roots.verify()?;
        ledger.verify_external()?;
        if roots.archive_digest() != self.digest() || ledger.archive_digest() != self.digest() {
            return Err(ReconcileError::Invariant(
                "original marker archive/root/ledger scope",
            ));
        }
        let root_original = roots.worktree.original_creation()?;
        let mut directory_intent = ledger.intend_worktree_marker(&root_original)?;
        crate::fault::checkpoint("node_marker_directory_intended");
        let directory = roots.worktree.create_new_worktree_marker_directory()?;
        ledger.created_directory(&mut directory_intent, &directory.original_creation()?)?;
        crate::fault::checkpoint("node_marker_directory_created");
        let directory_original = directory.original_creation()?;
        let mut marker_intent = ledger.intend_file(&directory_original, "space-id")?;
        crate::fault::checkpoint("node_marker_space_intended");
        let mut marker = directory.create_new_file("space-id")?;
        ledger.created_file(&mut marker_intent, &marker.original_creation()?)?;
        let key = marker.key()?;
        let parent_key = directory.key()?;
        let bytes = self.space().as_str().as_bytes();
        if marker.reader().metadata()?.len() != 0 {
            return Err(ReconcileError::Invariant(
                "original space marker requires empty CREATE",
            ));
        }
        marker.writer().seek(SeekFrom::Start(0))?;
        marker.writer().write_all(bytes)?;
        marker.writer().flush()?;
        marker.writer().sync_all()?;
        let digest = ContentId::hash(bytes);
        super::created_bytes::verify(&marker, key, parent_key, bytes.len() as u64, &digest)?;
        crate::fault::checkpoint("node_marker_space_synced");
        ledger.close_original_space_marker(&mut marker_intent, &marker, self)?;
        let mut lock_intent = ledger.intend_file(&directory.original_creation()?, "writer.lock")?;
        crate::fault::checkpoint("node_marker_lock_intended");
        let writer_lock = directory.create_new_file("writer.lock")?;
        writer_lock.reader().sync_all()?;
        ledger.created_file(&mut lock_intent, &writer_lock.original_creation()?)?;
        crate::fault::checkpoint("node_marker_lock_created");
        let receipt = CreatedNodeWorktreeMarker {
            roots,
            directory,
            marker: std::cell::RefCell::new(MarkerContent::Created(marker)),
            writer_lock,
            archive_digest: self.digest().clone(),
            marker_digest: digest,
            marker_bytes: bytes.len() as u64,
            key,
            parent_key,
        };
        roots.verify()?;
        receipt.verify()?;
        Ok(receipt)
    }
}

// Private same-original marker handle state; failures retain disk evidence.
enum MarkerContent {
    Created(OwnedFileCreation),
    Read(sync_extend_platform_fs::ReleasedOriginalReadFile),
    Failed,
}

impl CreatedNodeWorktreeMarker<'_> {
    pub(super) fn enable_original_readers(&self) -> Result<()> {
        self.verify()?;
        let mut current = self.marker.borrow_mut();
        let prior = std::mem::replace(&mut *current, MarkerContent::Failed);
        let original = match prior {
            MarkerContent::Read(reader) => {
                *current = MarkerContent::Read(reader);
                return Ok(());
            }
            MarkerContent::Created(creator) => {
                match creator.release_for_identity_checked_reopen() {
                    Ok(original) => original,
                    Err((creator, error)) => {
                        *current = MarkerContent::Created(*creator);
                        return Err(error.into());
                    }
                }
            }
            MarkerContent::Failed => {
                return Err(ReconcileError::Invariant("original marker handoff failed"))
            }
        };
        crate::fault::checkpoint("node_marker_original_identity_released");
        let reader = match original.retain_read_after_creation() {
            Ok(reader) => reader,
            Err((_original, error)) => return Err(error.into()),
        };
        super::read_content::verify(&reader, self.marker_bytes, &self.marker_digest)?;
        *current = MarkerContent::Read(reader);
        drop(current);
        self.verify()?;
        crate::fault::checkpoint("node_marker_original_read_verified");
        Ok(())
    }
}

// Private marker implementation exposes only original immutable evidence values.
impl CreatedNodeWorktreeMarker<'_> {
    pub(super) fn original_completion_marker_evidence(
        &self,
    ) -> Result<super::completion::ObjectEvidence> {
        self.verify()?;
        Ok(super::completion::ObjectEvidence {
            root: "worktree".into(),
            components: vec![".sync-extend".into(), "space-id".into()],
            kind: "file".into(),
            created_component: "space-id".into(),
            parent_key: self.parent_key.to_string(),
            object_key: self.key.to_string(),
            content_bytes: Some(self.marker_bytes),
            content_digest: Some(self.marker_digest.clone()),
        })
    }
}
