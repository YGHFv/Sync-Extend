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
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

impl WriterOwner {
    /// Acquire an actual exclusive OS file lock and retain its original named slot.
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
        let mut directories = Vec::with_capacity(chain.len());
        for (held, expected) in chain.into_iter().zip(ancestors) {
            if held.path != expected
                || held.directory.key()? != held.key
                || !held.directory.matches_path(expected)?
            {
                return Err(invalid("original writer ancestor identity or slot differs"));
            }
            held.directory.require_case_insensitive()?;
            held.directory.require_local_ntfs(expected)?;
            directories.push(held.directory);
        }
        if directories
            .last()
            .ok_or_else(|| invalid("writer parent absent"))?
            .key()?
            != parent_key
        {
            return Err(invalid("original writer CREATE parent differs"));
        }
        let path = directory.join("writer.lock");
        let file = original.retain_writer_sentinel()?;
        let key = original.key()?;
        if !crate::regular_file_matches_path(&file, &path)? {
            return Err(invalid("original writer sentinel named slot differs"));
        }
        file.try_lock()
            .map_err(|_| invalid("original writer lock is already held"))?;
        let owner = Self {
            file,
            path,
            key,
            directories,
        };
        owner.verify(directory)?;
        Ok(owner)
    }
}
