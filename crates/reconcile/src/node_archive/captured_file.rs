//! Exact retained source file for bounded node backup; no restore owner authority.
use crate::{check_ancestors, ReconcileError, Result};
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{
    FileKey, GuardedReadFile, LockedDirectory, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};

pub(super) struct CapturedFileOpenFailure {
    pub(super) error: ReconcileError,
    pub(super) original_resources: Option<WindowsOriginalResourceCloseFailure>,
}

#[derive(Default)]
struct OriginalFilePrefix {
    original: Option<GuardedReadFile>,
    ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
    unverified_ancestors: Vec<LockedDirectory>,
}

impl OriginalFilePrefix {
    fn acquire(&mut self, path: &Path) -> Result<()> {
        check_ancestors(path)?;
        let parent = path
            .parent()
            .ok_or(ReconcileError::Invariant("backup original parent is absent"))?;
        for ancestor in parent.ancestors() {
            if self.ancestors.len() >= 128 {
                return Err(ReconcileError::ResourceLimit("backup ancestor depth"));
            }
            self.unverified_ancestors.push(LockedDirectory::open(ancestor)?);
            let held = self
                .unverified_ancestors
                .last()
                .ok_or(ReconcileError::Unstable)?;
            held.require_local_ntfs(ancestor)?;
            held.require_case_insensitive()?;
            if !held.matches_path(ancestor)? {
                return Err(ReconcileError::Unstable);
            }
            let key = held.key()?;
            let held = self
                .unverified_ancestors
                .pop()
                .ok_or(ReconcileError::Unstable)?;
            self.ancestors.push((ancestor.to_owned(), held, key));
        }
        self.original = Some(GuardedReadFile::open(path)?);
        self.original()?.verify_single_link()?;
        Ok(())
    }

    fn original(&self) -> Result<&GuardedReadFile> {
        self.original.as_ref().ok_or(ReconcileError::Unstable)
    }

    fn fail(mut self, error: ReconcileError) -> CapturedFileOpenFailure {
        let mut close = WindowsOriginalCloseAttempt::new();
        if let Some(original) = self.original.take() {
            original.close_into_attempt(&mut close);
        }
        for (_, original, _) in self.ancestors.drain(..) {
            close.close_directory(original);
        }
        for original in self.unverified_ancestors.drain(..) {
            close.close_directory(original);
        }
        CapturedFileOpenFailure {
            error,
            original_resources: close.finish().err(),
        }
    }
}

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
    pub(super) fn open(
        path: &Path,
        max_bytes: usize,
    ) -> std::result::Result<Self, CapturedFileOpenFailure> {
        let mut prefix = OriginalFilePrefix::default();
        let prepared = (|| {
            if max_bytes == 0 {
                return Err(ReconcileError::ResourceLimit("explicit backup file bound"));
            }
            prefix.acquire(path)?;
            let original = prefix.original()?;
            let key = original.key()?;
            let expected = original.reader().metadata()?.len();
            if expected > max_bytes as u64 {
                return Err(ReconcileError::ResourceLimit("backup source file bytes"));
            }
            let mut reader = original.reader();
            reader.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            reader
                .take((max_bytes as u64).saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() > max_bytes || bytes.len() as u64 != expected {
                return Err(ReconcileError::Unstable);
            }
            Ok((key, expected, bytes))
        })();
        let (key, captured_length, bytes) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err(prefix.fail(error)),
        };
        let captured = Self {
            path: path.to_owned(),
            original: prefix.original.take().expect("acquired original was checked"),
            ancestors: std::mem::take(&mut prefix.ancestors),
            key,
            captured_length,
            digest: ContentId::hash(&bytes),
            bytes,
        };
        if let Err(error) = captured.verify() {
            return Err(captured.fail(error));
        }
        Ok(captured)
    }

    /// Hold a committed worktree source and hash it with a fixed buffer.
    /// No complete source payload is allocated or later exposed as a section.
    pub(super) fn hold_matching(
        path: &Path,
        expected_length: u64,
        expected_digest: &ContentId,
    ) -> std::result::Result<Self, CapturedFileOpenFailure> {
        let mut prefix = OriginalFilePrefix::default();
        let prepared = (|| {
            prefix.acquire(path)?;
            prefix.original()?.key().map_err(ReconcileError::from)
        })();
        let key = match prepared {
            Ok(key) => key,
            Err(error) => return Err(prefix.fail(error)),
        };
        let held = Self {
            path: path.to_owned(),
            original: prefix.original.take().expect("acquired original was checked"),
            ancestors: std::mem::take(&mut prefix.ancestors),
            key,
            bytes: Vec::new(),
            captured_length: expected_length,
            digest: expected_digest.clone(),
        };
        // verify rereads only the original retained single-link handle in 64KiB.
        if let Err(error) = held.verify() {
            return Err(held.fail(error));
        }
        Ok(held)
    }

    fn fail(self, error: ReconcileError) -> CapturedFileOpenFailure {
        let mut close = WindowsOriginalCloseAttempt::new();
        self.close_into_attempt(&mut close);
        CapturedFileOpenFailure {
            error,
            original_resources: close.finish().err(),
        }
    }

    pub(super) fn close_into_attempt(self, close: &mut WindowsOriginalCloseAttempt) {
        self.original.close_into_attempt(close);
        for (_, ancestor, _) in self.ancestors {
            close.close_directory(ancestor);
        }
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
        let mut reader = self.original.reader();
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
