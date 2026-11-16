use crate::{Journal, JournalError, Result};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use sync_extend_core_model::ContentId;

/// Cooperative process-lifetime CAS coordination, not a content pin or delete right.
pub struct CasAccessGuard {
    file: File,
    path: PathBuf,
    #[cfg(windows)]
    _directories: Vec<sync_extend_platform_fs::LockedDirectory>,
}

impl CasAccessGuard {
    fn shared(database: &Path) -> Result<Self> {
        let parent = database
            .parent()
            .ok_or(JournalError::Invariant("CAS lock parent missing"))?;
        let path = parent.join("cas-access.lock");
        #[cfg(windows)]
        let mut directories = Vec::new();
        for ancestor in parent.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            if !metadata.is_dir() || unsafe_metadata(&metadata) {
                return Err(JournalError::Invariant("unsafe CAS coordination directory"));
            }
            #[cfg(windows)]
            {
                let directory = sync_extend_platform_fs::LockedDirectory::open(ancestor)?;
                directory.require_case_insensitive()?;
                directories.push(directory);
            }
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || unsafe_metadata(&metadata) || metadata.len() != 0 {
                    return Err(JournalError::Invariant("unsafe CAS coordination file"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // Deny ordinary replacement of the sentinel while a lock handle lives.
            options.share_mode(0x1 | 0x2).custom_flags(0x00200000);
        }
        let file = options.open(&path)?;
        file.try_lock_shared()
            .map_err(|_| JournalError::Invariant("CAS exclusive access is running"))?;
        let guard = Self {
            file,
            path,
            #[cfg(windows)]
            _directories: directories,
        };
        guard.verify()?;
        Ok(guard)
    }

    pub(crate) fn try_exclusive(&mut self) -> Result<()> {
        // A failed upgrade grants nothing; callers roll back their DB transaction.
        self.file.unlock()?;
        self.file
            .try_lock()
            .map_err(|_| JournalError::Invariant("CAS readers are running"))?;
        self.verify()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        let held = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !held.is_file()
            || !named.is_file()
            || held.len() != 0
            || named.len() != 0
            || unsafe_metadata(&held)
            || unsafe_metadata(&named)
        {
            return Err(JournalError::Invariant("CAS coordination file changed"));
        }
        #[cfg(windows)]
        {
            use sync_extend_platform_fs::verify_regular_file;
            verify_regular_file(&self.file)?;
            // Observe only the named slot. File::open's default READ sharing
            // conflicts with the retained original RW coordination handles.
            // This metadata-only nonfollowing check grants no writer authority.
            if !sync_extend_platform_fs::regular_file_matches_path(&self.file, &self.path)? {
                return Err(JournalError::Invariant("CAS coordination identity changed"));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if held.dev() != named.dev() || held.ino() != named.ino() || held.nlink() != 1 {
                return Err(JournalError::Invariant("CAS coordination identity changed"));
            }
        }
        Ok(())
    }
}

fn unsafe_metadata(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.file_type().is_symlink()
}

impl Journal {
    /// Acquire cooperative session exclusion before any per-content fence checks.
    /// This is not a persistent owner and cannot override an existing fence.
    pub fn acquire_cas_session(&self) -> Result<CasAccessGuard> {
        self.acquire_cas_coordination()
    }

    pub fn acquire_cas_access(&self, content: &ContentId) -> Result<CasAccessGuard> {
        let guard = self.acquire_cas_coordination()?;
        self.require_cas_access(content)?;
        Ok(guard)
    }

    pub(crate) fn acquire_cas_coordination(&self) -> Result<CasAccessGuard> {
        #[cfg(windows)]
        if self.original_restored_image.is_some() {
            let original =
                self.original_cas_coordination
                    .as_ref()
                    .ok_or(JournalError::Invariant(
                        "restored Journal original CAS sentinel unbound",
                    ))?;
            self.verify_original_created_image()?;
            return CasAccessGuard::shared_original(&self.database_path, original);
        }
        CasAccessGuard::shared(&self.database_path)
    }
}

// Included inside original cas_access.rs to reuse exact guard/verify/upgrade.
impl CasAccessGuard {
    #[cfg(windows)]
    fn shared_original(
        database: &Path,
        original: &sync_extend_platform_fs::ReleasedOriginalCoordinationFile,
    ) -> Result<Self> {
        let parent = database
            .parent()
            .ok_or(JournalError::Invariant("original CAS parent absent"))?;
        let path = parent.join("cas-access.lock");
        original.verify(&path)?;
        // The retained original CREATE parent has DELETE access and excludes
        // a fresh read open that omits DELETE sharing. Duplicate its actual
        // read-only witness without releasing the creator or reopening its path.
        let mut directories = vec![original.retain_original_parent_directory(parent)?];
        for ancestor in parent.ancestors().skip(1) {
            let directory = sync_extend_platform_fs::LockedDirectory::open(ancestor)?;
            directory.require_local_ntfs(ancestor)?;
            directory.require_case_insensitive()?;
            directories.push(directory);
        }
        let file = original.open_for_shared_coordination(&path)?;
        file.try_lock_shared()
            .map_err(|_| JournalError::Invariant("original CAS exclusive access running"))?;
        let guard = Self {
            file,
            path,
            _directories: directories,
        };
        guard.verify()?;
        original.verify(&guard.path)?;
        Ok(guard)
    }
}

#[cfg(windows)]
impl crate::OriginalJournalWriteTransition {
    pub fn acquire_original_cas_session(&self) -> crate::Result<crate::CasAccessGuard> {
        self.verify()?;
        crate::CasAccessGuard::shared_original(&self.path, &self.cas)
    }
}
