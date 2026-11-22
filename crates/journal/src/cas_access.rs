use crate::{Journal, JournalError, Result};
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
};
use sync_extend_core_model::ContentId;

fn try_lock(file: &File, shared: bool, busy: &'static str) -> Result<()> {
    // Rust 1.92's File locks return Unsupported on Android. Use the same
    // kernel flock API as the local writer locks for every operation there.
    #[cfg(target_os = "android")]
    let acquired = (if shared {
        fs2::FileExt::try_lock_shared(file)
    } else {
        fs2::FileExt::try_lock_exclusive(file)
    })
    .map_err(|error| {
        if error.kind() == std::io::ErrorKind::WouldBlock {
            TryLockError::WouldBlock
        } else {
            TryLockError::Error(error)
        }
    });
    #[cfg(not(target_os = "android"))]
    let acquired = if shared {
        file.try_lock_shared()
    } else {
        file.try_lock()
    };
    acquired.map_err(|error| match error {
        TryLockError::WouldBlock => JournalError::Invariant(busy),
        TryLockError::Error(error) => error.into(),
    })
}

/// Cooperative process-lifetime CAS coordination, not a content pin or delete right.
pub struct CasAccessGuard {
    file: Option<File>,
    path: PathBuf,
    #[cfg(target_os = "linux")]
    original_linux: Option<sync_extend_platform_fs::LinuxStorageCasCoordinationGuard>,
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
        try_lock(&file, true, "CAS exclusive access is running")?;
        let guard = Self {
            file: Some(file),
            path,
            #[cfg(target_os = "linux")]
            original_linux: None,
            #[cfg(windows)]
            _directories: directories,
        };
        guard.verify()?;
        Ok(guard)
    }

    pub(crate) fn try_exclusive(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &mut self.original_linux {
            original.try_exclusive().map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    JournalError::Invariant("original Linux CAS readers are running")
                } else {
                    error.into()
                }
            })?;
            return self.verify();
        }
        // A failed upgrade grants nothing; callers roll back their DB transaction.
        let file = self.file.as_ref().ok_or(JournalError::Invariant(
            "ordinary CAS coordination descriptor absent",
        ))?;
        #[cfg(target_os = "android")]
        fs2::FileExt::unlock(file)?;
        #[cfg(not(target_os = "android"))]
        file.unlock()?;
        try_lock(file, false, "CAS readers are running")?;
        self.verify()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.original_linux {
            if self.file.is_some() {
                return Err(JournalError::Invariant(
                    "original Linux CAS guard cannot contain an escaping ordinary descriptor",
                ));
            }
            original.verify()?;
            return Ok(());
        }
        let file = self.file.as_ref().ok_or(JournalError::Invariant(
            "ordinary CAS coordination descriptor absent",
        ))?;
        let held = file.metadata()?;
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
            verify_regular_file(file)?;
            // Observe only the named slot. File::open's default READ sharing
            // conflicts with the retained original RW coordination handles.
            // This metadata-only nonfollowing check grants no writer authority.
            if !sync_extend_platform_fs::regular_file_matches_path(file, &self.path)? {
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

    #[cfg(target_os = "linux")]
    fn shared_original_linux(
        database: &Path,
        original: &sync_extend_platform_fs::LinuxStorageCasCoordinationLoan,
    ) -> Result<Self> {
        let parent = database.parent().ok_or(JournalError::Invariant(
            "original Linux CAS Journal parent absent",
        ))?;
        let guard = original.acquire_shared()?;
        let result = Self {
            file: None,
            // Audit label only; actual opens/checks/upgrade use the typed loan.
            path: parent.join("cas-access.lock"),
            original_linux: Some(guard),
        };
        result.verify()?;
        original.verify()?;
        Ok(result)
    }

    /// Verify actual typed original possession. Ordinary and v1 guards cannot
    /// acquire an original storage capability from matching paths or keys.
    #[cfg(target_os = "linux")]
    pub fn verify_linux_storage_original(&self) -> Result<()> {
        if self.original_linux.is_none() {
            return Err(JournalError::Invariant(
                "actual original Linux CAS guard required for verification",
            ));
        }
        self.verify()
    }

    #[cfg(target_os = "linux")]
    pub fn linux_storage_exclusive(
        &self,
    ) -> Result<sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>> {
        if self.file.is_some() {
            return Err(JournalError::Invariant(
                "ordinary CAS descriptor cannot issue an original exclusive borrow",
            ));
        }
        Ok(self
            .original_linux
            .as_ref()
            .ok_or(JournalError::Invariant(
                "actual original Linux CAS guard required for exclusive borrowing",
            ))?
            .exclusive_borrow()?)
    }

    /// Actual typed guard release; a failed verification grants no close receipt.
    #[cfg(target_os = "linux")]
    pub fn close_linux_storage_original(self) -> Result<()> {
        let Self {
            file,
            original_linux,
            ..
        } = self;
        let original = original_linux.ok_or(JournalError::Invariant(
            "actual original Linux CAS guard required for explicit close",
        ))?;
        if file.is_some() {
            return Err(JournalError::Invariant(
                "original Linux CAS guard cannot close a mixed ordinary descriptor",
            ));
        }
        original.close()?;
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
    /// Inspection-only acquisition from the original v2 coordination loan.
    /// Ordinary/v1 guards are rejected before any fallback open or CREATE.
    #[cfg(target_os = "linux")]
    pub fn acquire_linux_storage_retirement_exclusive(
        &self,
        content: &ContentId,
    ) -> Result<CasAccessGuard> {
        if self.original_linux_cas_coordination.is_none() {
            return Err(JournalError::Invariant(
                "Unix retirement requires an acquired original v2 CAS coordination loan",
            ));
        }
        let mut guard = self.acquire_cas_coordination()?;
        self.require_cas_access(content)?;
        guard.try_exclusive()?;
        guard.linux_storage_exclusive()?.verify()?;
        Ok(guard)
    }

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
        #[cfg(target_os = "linux")]
        if let Some(original) = &self.original_linux_cas_coordination {
            self.linux_storage_cas_coordination_key()?
                .ok_or(JournalError::Invariant(
                    "original Linux CAS coordination binding lost",
                ))?;
            return CasAccessGuard::shared_original_linux(&self.database_path, original);
        }
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
        try_lock(&file, true, "original CAS exclusive access running")?;
        let guard = Self {
            file: Some(file),
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
