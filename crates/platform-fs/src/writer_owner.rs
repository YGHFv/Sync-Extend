//! Process-lifetime writer lock; no constructor from a boolean or serialized proof.
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

pub struct WriterOwner {
    file: File,
    path: PathBuf,
    #[cfg(windows)]
    key: crate::FileKey,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(windows)]
    directories: Vec<crate::LockedDirectory>,
    #[cfg(windows)]
    ordinary_capture_close: bool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

impl WriterOwner {
    /// End the actual owning sentinel/lock and each original retained ancestor.
    /// This consuming terminal works for both constructor families and grants
    /// no capture, CREATE, restart, or completed native restore permission.
    #[cfg(windows)]
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.close_file(self.file);
        for directory in self.directories.into_iter().rev() {
            attempt.close_directory(directory);
        }
    }

    /// Acquire an actual exclusive OS file lock and retain its original named slot.
    #[cfg(not(windows))]
    pub fn acquire(directory: &Path) -> io::Result<Self> {
        if !directory.is_absolute() {
            return Err(invalid("absolute writer owner directory required"));
        }
        #[cfg(windows)]
        let mut directories = Vec::new();
        for ancestor in directory.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let metadata = fs::symlink_metadata(ancestor)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(invalid(
                    "writer owner directory must be original non-symlink",
                ));
            }
            #[cfg(windows)]
            {
                let held = crate::LockedDirectory::open(ancestor)?;
                held.require_case_insensitive()?;
                directories.push(held);
            }
        }
        let path = directory.join("writer.lock");
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() != 0 =>
            {
                return Err(invalid("invalid writer owner sentinel"))
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0x1 | 0x2).custom_flags(0x00200000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        file.try_lock()
            .map_err(|_| invalid("another local writer is running"))?;
        #[cfg(windows)]
        let key = crate::FileKey::from_file(&file)?;
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            let metadata = file.metadata()?;
            (metadata.dev(), metadata.ino())
        };
        let owner = Self {
            file,
            path,
            #[cfg(windows)]
            key,
            #[cfg(unix)]
            identity,
            #[cfg(windows)]
            directories,
            #[cfg(windows)]
            ordinary_capture_close: true,
        };
        owner.verify(directory)?;
        Ok(owner)
    }

    #[cfg(windows)]
    pub fn retained_handle_count(&self) -> usize {
        1 + self.directories.len()
    }
    pub fn verify(&self, directory: &Path) -> io::Result<()> {
        if self.path != directory.join("writer.lock") || !directory.is_absolute() {
            return Err(invalid("writer owner directory differs"));
        }
        let metadata = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        if !metadata.is_file()
            || metadata.len() != 0
            || !named.is_file()
            || named.len() != 0
            || named.file_type().is_symlink()
        {
            return Err(invalid("writer owner original sentinel differs"));
        }
        #[cfg(windows)]
        {
            crate::verify_regular_file(&self.file)?;
            if crate::FileKey::from_file(&self.file)? != self.key
                || !crate::regular_file_matches_path(&self.file, &self.path)?
            {
                return Err(invalid("writer owner full identity or named slot differs"));
            }
            for directory in &self.directories {
                directory.require_case_insensitive()?;
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1
                || named.nlink() != 1
                || (metadata.dev(), metadata.ino()) != self.identity
                || (named.dev(), named.ino()) != self.identity
            {
                return Err(invalid("writer owner inode or alias differs"));
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct WriterCaptureOpenFailure {
    pub error: io::Error,
    pub original_resources: Option<crate::WindowsOriginalResourceCloseFailure>,
}

/// The original CREATE remains borrowed from its caller. Every new observer
/// HANDLE from a failed constructor has reached an actual terminal attempt or
/// remains in this exact typed native failure, with its successful prefix.
#[cfg(windows)]
pub struct WriterOriginalCreationFailure {
    pub error: io::Error,
    pub actual_closed_handles: usize,
    original_resources: crate::WindowsOriginalResourceCloseFailure,
}

#[cfg(windows)]
impl std::fmt::Debug for WriterOriginalCreationFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("WriterOriginalCreationFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field("originals_retained", &self.has_retained_originals())
            .finish()
    }
}

#[cfg(windows)]
impl WriterOriginalCreationFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original_resources.retained_resource_groups() != 0
    }

    pub fn close_remaining(mut self) -> Self {
        self.original_resources = self.original_resources.close_remaining();
        self.actual_closed_handles = self.original_resources.actual_closed_handles;
        self
    }

    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.append_failure(self.original_resources);
    }

    pub fn retain_and_report(self) -> io::Error {
        let error = match self.error.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(self.error.kind(), self.error.to_string()),
        };
        let original = self.close_remaining();
        if original.has_retained_originals() {
            let _ = Box::leak(Box::new(original));
        }
        error
    }
}

#[cfg(windows)]
impl std::fmt::Debug for WriterCaptureOpenFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("WriterCaptureOpenFailure")
            .field("error", &self.error)
            .field("original_resources", &self.original_resources)
            .finish()
    }
}

#[cfg(windows)]
enum SentinelOpenPurpose {
    OrdinaryWriter,
    ExistingStoppedCapture,
}

#[cfg(windows)]
impl WriterOwner {
    pub fn acquire(directory: &Path) -> io::Result<Self> {
        Self::acquire_original_sentinel(directory, SentinelOpenPurpose::OrdinaryWriter).map_err(
            |failure| {
                if let Some(original) = failure.original_resources {
                    original.retain_until_process_exit();
                }
                failure.error
            },
        )
    }

    /// Hold an existing stopped source sentinel without CREATE or truncation.
    /// This cannot construct a full-native original-created writer owner.
    pub fn acquire_existing_stopped_capture(
        directory: &Path,
    ) -> Result<Self, WriterCaptureOpenFailure> {
        Self::acquire_original_sentinel(directory, SentinelOpenPurpose::ExistingStoppedCapture)
    }

    fn acquire_original_sentinel(
        directory: &Path,
        purpose: SentinelOpenPurpose,
    ) -> Result<Self, WriterCaptureOpenFailure> {
        use std::os::windows::fs::OpenOptionsExt;
        let mut directories = Vec::new();
        let mut file = None;
        let prepared = (|| -> io::Result<(PathBuf, crate::FileKey)> {
            if !directory.is_absolute() {
                return Err(invalid("absolute writer owner directory required"));
            }
            for ancestor in directory.ancestors().collect::<Vec<_>>().into_iter().rev() {
                let metadata = fs::symlink_metadata(ancestor)?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(invalid(
                        "writer owner directory must be original non-symlink",
                    ));
                }
                directories.push(crate::LockedDirectory::open(ancestor)?);
                directories
                    .last()
                    .expect("inserted original directory")
                    .require_case_insensitive()?;
            }
            let path = directory.join("writer.lock");
            let create = matches!(purpose, SentinelOpenPurpose::OrdinaryWriter);
            match fs::symlink_metadata(&path) {
                Ok(metadata)
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.len() != 0 =>
                {
                    return Err(invalid("invalid writer owner sentinel"));
                }
                Ok(_) => {}
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            file = Some(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(create)
                    .truncate(false)
                    .share_mode(0x1 | 0x2)
                    .custom_flags(0x00200000)
                    .open(&path)?,
            );
            let original = file.as_ref().expect("opened original sentinel");
            original
                .try_lock()
                .map_err(|_| invalid("another local writer is running"))?;
            Ok((path, crate::FileKey::from_file(original)?))
        })();
        let (path, key) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let mut close = crate::WindowsOriginalCloseAttempt::new();
                if let Some(original) = file.take() {
                    close.close_file(original);
                }
                for original in directories {
                    close.close_directory(original);
                }
                return Err(WriterCaptureOpenFailure {
                    error,
                    original_resources: close.finish().err(),
                });
            }
        };
        let owner = Self {
            file: file.take().expect("prepared original sentinel"),
            path,
            key,
            directories,
            ordinary_capture_close: true,
        };
        if let Err(error) = owner.verify(directory) {
            let Self {
                file, directories, ..
            } = owner;
            let mut close = crate::WindowsOriginalCloseAttempt::new();
            close.close_file(file);
            for original in directories {
                close.close_directory(original);
            }
            return Err(WriterCaptureOpenFailure {
                error,
                original_resources: close.finish().err(),
            });
        }
        Ok(owner)
    }
}

impl WriterOwner {
    /// Construct only from the actual live file CREATE and the complete retained
    /// absolute directory chain. This does not acquire ownership from a path,
    /// completed manifest, historical FileKey or serialized recovery receipt.
    #[cfg(windows)]
    pub fn from_original_creation(
        directory: &Path,
        original: crate::OriginalFileCreation<'_>,
        chain: Vec<crate::RetainedWriterDirectory>,
    ) -> io::Result<Self> {
        Self::from_original_creation_retaining(directory, original, chain)
            .map_err(WriterOriginalCreationFailure::retain_and_report)
    }

    /// Failed chain checks, sentinel preparation, lock acquisition and final
    /// owner verification all end their exact owned prefix through the native
    /// terminal. The caller keeps the original borrowed CREATE and parent scope.
    #[cfg(windows)]
    pub fn from_original_creation_retaining(
        directory: &Path,
        original: crate::OriginalFileCreation<'_>,
        chain: Vec<crate::RetainedWriterDirectory>,
    ) -> Result<Self, WriterOriginalCreationFailure> {
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        let mut file = None;
        let prepared = (|| -> io::Result<(PathBuf, crate::FileKey)> {
            if !directory.is_absolute() {
                return Err(invalid("absolute original writer directory required"));
            }
            original.verify()?;
            let ancestors: Vec<_> = directory
                .ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            if chain.len() != ancestors.len() {
                return Err(invalid("complete original writer directory chain required"));
            }
            let parent_key = original.parent_key()?;
            // Keep the whole original chain intact through every fallible
            // validation. No consumed suffix can default-Drop on a later ?.
            for (held, expected) in chain.iter().zip(ancestors) {
                if held.path != expected
                    || held.directory.key()? != held.key
                    || !held.directory.matches_path(expected)?
                {
                    return Err(invalid("original writer ancestor identity or slot differs"));
                }
                held.directory.require_case_insensitive()?;
                held.directory.require_local_ntfs(expected)?;
            }
            if chain
                .last()
                .ok_or_else(|| invalid("writer parent absent"))?
                .directory
                .key()?
                != parent_key
            {
                return Err(invalid("original writer CREATE parent differs"));
            }
            let path = directory.join("writer.lock");
            file = Some(original.retain_writer_sentinel_into_attempt(&mut terminal)?);
            let key = original.key()?;
            let original_file = file.as_ref().expect("same original sentinel retained");
            if !crate::regular_file_matches_path(original_file, &path)? {
                return Err(invalid("original writer sentinel named slot differs"));
            }
            original_file
                .try_lock()
                .map_err(|_| invalid("original writer lock is already held"))?;
            Ok((path, key))
        })();
        let (path, key) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                terminal.note_error(match error.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(error.kind(), error.to_string()),
                });
                if let Some(original) = file.take() {
                    terminal.close_file(original);
                }
                for original in chain.into_iter().rev() {
                    original.close_into_attempt(&mut terminal);
                }
                let original_resources = terminal
                    .finish()
                    .err()
                    .expect("the first original writer preparation error remains");
                return Err(WriterOriginalCreationFailure {
                    error,
                    actual_closed_handles: original_resources.actual_closed_handles,
                    original_resources,
                });
            }
        };
        let owner = Self {
            file: file.take().expect("prepared same original sentinel"),
            path,
            key,
            directories: chain
                .into_iter()
                .map(|original| original.directory)
                .collect(),
            ordinary_capture_close: false,
        };
        if let Err(error) = owner.verify(directory) {
            terminal.note_error(match error.raw_os_error() {
                Some(code) => io::Error::from_raw_os_error(code),
                None => io::Error::new(error.kind(), error.to_string()),
            });
            owner.close_into_attempt(&mut terminal);
            let original_resources = terminal
                .finish()
                .err()
                .expect("the first original writer verification error remains");
            return Err(WriterOriginalCreationFailure {
                error,
                actual_closed_handles: original_resources.actual_closed_handles,
                original_resources,
            });
        }
        Ok(owner)
    }
}

#[cfg(windows)]
pub struct WriterCaptureCloseFailure {
    pub error: io::Error,
    pub original_native_owner: Option<WriterOwner>,
    pub original_resources: Option<crate::WindowsOriginalResourceCloseFailure>,
}
#[cfg(windows)]
impl std::fmt::Debug for WriterCaptureCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("WriterCaptureCloseFailure")
            .field("error", &self.error)
            .field(
                "original_native_owner_retained",
                &self.original_native_owner.is_some(),
            )
            .field(
                "original_resources_retained",
                &self.original_resources.is_some(),
            )
            .finish()
    }
}

#[cfg(windows)]
impl WriterOwner {
    /// End only the ordinary acquisition used for source capture. A full native
    /// original-created owner must use its existing native close protocol.
    pub fn close_ordinary_capture(
        self,
    ) -> Result<crate::ClosedWindowsOriginalResources, WriterCaptureCloseFailure> {
        if !self.ordinary_capture_close {
            return Err(WriterCaptureCloseFailure {
                error: invalid("original-created writer owner cannot use capture close"),
                original_native_owner: Some(self),
                original_resources: None,
            });
        }
        let mut attempt = crate::WindowsOriginalCloseAttempt::new();
        match self.path.parent() {
            Some(directory) => {
                if let Err(error) = self.verify(directory) {
                    attempt.note_error(error);
                }
            }
            None => attempt.note_error(invalid("ordinary original writer parent missing")),
        }
        attempt.close_file(self.file);
        for directory in self.directories {
            attempt.close_directory(directory);
        }
        match attempt.finish() {
            Ok(closed) => Ok(closed),
            Err(original_resources) => Err(WriterCaptureCloseFailure {
                error: match original_resources.error.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(
                        original_resources.error.kind(),
                        original_resources.error.to_string(),
                    ),
                },
                original_native_owner: None,
                original_resources: Some(original_resources),
            }),
        }
    }
}
