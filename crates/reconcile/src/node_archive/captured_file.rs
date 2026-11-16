//! Exact retained source file for bounded node backup; no restore owner authority.
use crate::{check_ancestors, ReconcileError, Result};
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{FileKey, GuardedReadFile, LockedDirectory};

/// Retains all source ancestors and the original single-link readonly file.
/// The caller owns the node session and rejects mutable transaction residue.
pub(super) struct CapturedFile {
    path: PathBuf,
    original: GuardedReadFile,
    ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
    key: FileKey,
    bytes: Vec<u8>,
    captured_length: u64,
    digest: ContentId,
}

impl CapturedFile {
    pub(super) fn open(path: &Path, max_bytes: usize) -> Result<Self> {
        if max_bytes == 0 {
            return Err(ReconcileError::ResourceLimit("explicit backup file bound"));
        }
        check_ancestors(path)?;
        let mut ancestors = Vec::new();
        let parent = path.parent().ok_or(ReconcileError::Invariant(
            "backup original parent is absent",
        ))?;
        for ancestor in parent.ancestors() {
            let held = LockedDirectory::open(ancestor)?;
            held.require_local_ntfs(ancestor)?;
            held.require_case_insensitive()?;
            if !held.matches_path(ancestor)? {
                return Err(ReconcileError::Unstable);
            }
            let key = held.key()?;
            ancestors.push((ancestor.to_owned(), held, key));
            if ancestors.len() > 128 {
                return Err(ReconcileError::ResourceLimit("backup ancestor depth"));
            }
        }
        let original = GuardedReadFile::open(path)?;
        let key = original.key()?;
        original.verify_single_link()?;
        let expected = original.reader().metadata()?.len();
        if expected > max_bytes as u64 {
            return Err(ReconcileError::ResourceLimit("backup source file bytes"));
        }
        let mut reader = original.reader().try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader
            .take((max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes || bytes.len() as u64 != expected {
            return Err(ReconcileError::Unstable);
        }
        let digest = ContentId::hash(&bytes);
        let captured = Self {
            path: path.to_owned(),
            original,
            ancestors,
            key,
            captured_length: expected,
            bytes,
            digest,
        };
        captured.verify()?;
        Ok(captured)
    }

    /// Hold a committed worktree source and hash it with a fixed buffer.
    /// No complete source payload is allocated or later exposed as a section.
    pub(super) fn hold_matching(
        path: &Path,
        expected_length: u64,
        expected_digest: &ContentId,
    ) -> Result<Self> {
        check_ancestors(path)?;
        let parent = path
            .parent()
            .ok_or(ReconcileError::Invariant("node original parent absent"))?;
        let mut ancestors = Vec::new();
        for ancestor in parent.ancestors() {
            if ancestors.len() >= 128 {
                return Err(ReconcileError::ResourceLimit(
                    "node original ancestor depth",
                ));
            }
            let held = LockedDirectory::open(ancestor)?;
            held.require_local_ntfs(ancestor)?;
            held.require_case_insensitive()?;
            if !held.matches_path(ancestor)? {
                return Err(ReconcileError::Unstable);
            }
            let key = held.key()?;
            ancestors.push((ancestor.to_owned(), held, key));
        }
        let original = GuardedReadFile::open(path)?;
        let key = original.key()?;
        let held = Self {
            path: path.to_owned(),
            original,
            ancestors,
            key,
            bytes: Vec::new(),
            captured_length: expected_length,
            digest: expected_digest.clone(),
        };
        // verify rereads only the original retained single-link handle in 64KiB.
        held.verify()?;
        Ok(held)
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfer the payload while retaining the original file and ancestor handles.
    /// A subsequent verify still rereads the held original against length and digest.
    pub(super) fn take_bytes(&mut self) -> Result<Vec<u8>> {
        if self.bytes.len() as u64 != self.captured_length {
            return Err(ReconcileError::Invariant(
                "node original payload already transferred",
            ));
        }
        self.verify()?;
        Ok(std::mem::take(&mut self.bytes))
    }

    pub(super) fn digest(&self) -> &ContentId {
        &self.digest
    }

    pub(super) fn verify(&self) -> Result<()> {
        check_ancestors(&self.path)?;
        for (path, held, key) in &self.ancestors {
            if held.key()? != *key || !held.matches_path(path)? {
                return Err(ReconcileError::Unstable);
            }
        }
        self.original.verify_single_link()?;
        if self.original.key()? != self.key
            || !sync_extend_platform_fs::regular_file_matches_path(
                self.original.reader(),
                &self.path,
            )?
            || self.original.reader().metadata()?.len() != self.captured_length
        {
            return Err(ReconcileError::Unstable);
        }
        let mut reader = self.original.reader().try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut limited = reader.take((self.captured_length).saturating_add(1));
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = limited.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(ReconcileError::ResourceLimit("backup verify byte count"))?;
            if total > self.captured_length {
                return Err(ReconcileError::Unstable);
            }
            hasher.update(&buffer[..count]);
        }
        self.original.verify_single_link()?;
        if total != self.captured_length
            || hasher.finalize().to_hex().as_str() != self.digest.as_str()
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }
}
