//! Private deployment files retain their real original CREATE HANDLE, including
//! post-CREATE failures. These types grant no node or namespace authority.
use super::{current_user_file, directory_create, invalid, key, regular, LockedDirectory};
use crate::FileKey;
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

const MAX_BYTES: usize = 1024 * 1024 * 1024;

fn component(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
    {
        return Err(invalid("bounded exact deployment file component required"));
    }
    Ok(())
}

struct Parent {
    path: PathBuf,
    ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
}
impl Parent {
    fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute()
            || path.parent().is_none()
            || path.as_os_str().len() > 32_768
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(invalid("bounded exact private deployment parent required"));
        }
        let mut ancestors = Vec::new();
        for path in path.ancestors().filter(|path| path.is_absolute()) {
            let original = LockedDirectory::open(path)?;
            original.require_local_ntfs(path)?;
            original.require_case_insensitive()?;
            if !original.matches_path(path)? {
                return Err(invalid("original deployment parent changed during open"));
            }
            let native_key = original.key()?;
            ancestors.push((path.to_path_buf(), original, native_key));
        }
        let result = Self {
            path: path.to_path_buf(),
            ancestors,
        };
        result.verify()?;
        Ok(result)
    }
    fn directory(&self) -> io::Result<&LockedDirectory> {
        self.ancestors
            .first()
            .map(|(_, directory, _)| directory)
            .ok_or_else(|| invalid("original deployment parent absent"))
    }
    fn verify(&self) -> io::Result<()> {
        for (path, directory, original_key) in &self.ancestors {
            if directory.key()? != *original_key || !directory.matches_path(path)? {
                return Err(invalid("retained deployment ancestor changed"));
            }
        }
        self.directory()?.require_current_user_private()
    }
}

pub struct WindowsProtectedArtifactParent {
    original: Arc<Parent>,
}
impl WindowsProtectedArtifactParent {
    pub fn open_private(path: &Path) -> io::Result<Self> {
        Ok(Self {
            original: Arc::new(Parent::open(path)?),
        })
    }
    pub fn path(&self) -> &Path {
        &self.original.path
    }
    pub fn key(&self) -> io::Result<FileKey> {
        self.original.verify()?;
        self.original.directory()?.key()
    }
    pub fn verify_original(&self) -> io::Result<()> {
        self.original.verify()
    }
    pub fn available_space(&self) -> io::Result<(u64, u64)> {
        self.original.verify()?;
        let space = crate::held_disk_space(self.original.directory()?, &self.original.path)?;
        self.original.verify()?;
        Ok((space.available_to_caller, space.allocation_unit))
    }
    pub fn require_absent(&self, name: &str) -> io::Result<()> {
        component(name)?;
        self.original.verify()?;
        match fs::symlink_metadata(self.original.path.join(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.original.verify(),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "deployment target slot is occupied",
            )),
        }
    }
    pub fn require_empty(&self) -> io::Result<()> {
        self.original.verify()?;
        if fs::read_dir(&self.original.path)?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "deployment runtime directory is occupied",
            ));
        }
        self.original.verify()
    }
    pub fn create_new(
        &self,
        name: &str,
    ) -> std::result::Result<WindowsProtectedArtifactCreator, WindowsProtectedArtifactCreateFailure>
    {
        let before = |error| WindowsProtectedArtifactCreateFailure {
            error,
            original_created: None,
        };
        component(name).map_err(before)?;
        self.original.verify().map_err(before)?;
        let parent = Arc::clone(&self.original);
        let component = name.to_owned();
        let file = match directory_create::create_new_current_user_file_attempt(
            &parent.directory().map_err(before)?.file,
            name,
        ) {
            Ok(file) => file,
            Err(failure) => {
                return Err(WindowsProtectedArtifactCreateFailure {
                    error: failure.error,
                    original_created: failure.original_created.map(|file| {
                        WindowsFailedArtifactCreation {
                            parent,
                            component,
                            file,
                        }
                    }),
                })
            }
        };
        let pending = WindowsFailedArtifactCreation {
            parent,
            component,
            file,
        };
        let observed = (|| -> io::Result<FileKey> {
            pending.verify_original_slot()?;
            if pending.file.metadata()?.len() != 0 {
                return Err(invalid("new original deployment creator is nonempty"));
            }
            key(&pending.file)
        })();
        let original_key = match observed {
            Ok(value) => value,
            Err(error) => {
                return Err(WindowsProtectedArtifactCreateFailure {
                    error,
                    original_created: Some(pending),
                })
            }
        };
        Ok(WindowsProtectedArtifactCreator {
            parent: pending.parent,
            component: pending.component,
            file: pending.file,
            original_key,
            write_attempted: false,
            exclusive_creation_held: true,
        })
    }
    pub fn close(self) -> io::Result<()> {
        Arc::try_unwrap(self.original)
            .map_err(|_| invalid("deployment parent still has original creator loans"))?;
        Ok(())
    }
}

pub struct WindowsFailedArtifactCreation {
    parent: Arc<Parent>,
    component: String,
    file: File,
}
impl WindowsFailedArtifactCreation {
    pub fn observed_key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }
    pub fn observed_bytes(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
    pub fn verify_original_slot(&self) -> io::Result<()> {
        self.parent.verify()?;
        regular(&self.file, false)?;
        current_user_file::verify_current_user_private_file(&self.file)?;
        if !super::regular_file_matches_path(&self.file, &self.parent.path.join(&self.component))? {
            return Err(invalid("failed original deployment creator slot changed"));
        }
        self.parent.verify()
    }
    pub fn close(self) -> io::Result<()> {
        drop(self);
        Ok(())
    }
}

pub struct WindowsProtectedArtifactCreateFailure {
    pub error: io::Error,
    pub original_created: Option<WindowsFailedArtifactCreation>,
}
impl std::fmt::Debug for WindowsProtectedArtifactCreateFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("WindowsProtectedArtifactCreateFailure")
            .field("error", &self.error)
            .field("original_create_happened", &self.original_created.is_some())
            .finish()
    }
}

pub struct WindowsProtectedArtifactCreator {
    parent: Arc<Parent>,
    component: String,
    file: File,
    original_key: FileKey,
    write_attempted: bool,
    exclusive_creation_held: bool,
}
impl WindowsProtectedArtifactCreator {
    pub fn key(&self) -> FileKey {
        self.original_key
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.parent.verify()?;
        self.parent.directory()?.key()
    }
    pub fn verify_original(&self) -> io::Result<()> {
        self.parent.verify()?;
        regular(&self.file, false)?;
        current_user_file::verify_current_user_private_file(&self.file)?;
        if key(&self.file)? != self.original_key
            || !super::regular_file_matches_path(
                &self.file,
                &self.parent.path.join(&self.component),
            )?
            || self.file.metadata()?.len() > MAX_BYTES as u64
        {
            return Err(invalid(
                "original deployment creator identity/slot/bytes changed",
            ));
        }
        Ok(())
    }
    pub fn write_and_sync(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.verify_original()?;
        if !self.exclusive_creation_held
            || self.write_attempted
            || bytes.is_empty()
            || bytes.len() > MAX_BYTES
            || self.file.metadata()?.len() != 0
        {
            return Err(invalid(
                "one bounded original deployment creator write required",
            ));
        }
        self.write_attempted = true;
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        self.verify_bytes(bytes)
    }
    fn verify_bytes(&self, expected: &[u8]) -> io::Result<()> {
        self.verify_original()?;
        let before = self.file.metadata()?;
        if before.len() != expected.len() as u64 {
            return Err(invalid(
                "original deployment creator readback length changed",
            ));
        }
        let mut reader = &self.file;
        reader.seek(SeekFrom::Start(0))?;
        let mut readback = Vec::with_capacity(expected.len());
        reader
            .take(expected.len() as u64 + 1)
            .read_to_end(&mut readback)?;
        if readback != expected
            || self.file.metadata()?.len() != before.len()
            || self.file.metadata()?.modified()? != before.modified()?
        {
            return Err(invalid(
                "original deployment creator stable readback changed",
            ));
        }
        readback.fill(0);
        self.verify_original()
    }
    pub fn seal(
        self,
        expected: &[u8],
    ) -> std::result::Result<SealedWindowsProtectedArtifact, WindowsProtectedArtifactSealFailure>
    {
        let checked = if self.exclusive_creation_held && self.write_attempted {
            self.verify_bytes(expected)
        } else {
            Err(invalid(
                "original deployment creator content was not attempted",
            ))
        };
        if let Err(error) = checked {
            return Err(WindowsProtectedArtifactSealFailure {
                error,
                original_creator: self,
            });
        }
        let identity = match super::reopen_same_file_object(&self.file, self.original_key, false) {
            Ok(file) => file,
            Err(error) => {
                return Err(WindowsProtectedArtifactSealFailure {
                    error,
                    original_creator: self,
                })
            }
        };
        let WindowsProtectedArtifactCreator {
            parent,
            component,
            file,
            original_key,
            ..
        } = self;
        // The actual same-object metadata witness is already live before the
        // incompatible exclusive CREATE HANDLE is relinquished.
        drop(file);
        let file = match super::reopen_same_file_object(&identity, original_key, true) {
            Ok(file) => file,
            Err(error) => {
                return Err(WindowsProtectedArtifactSealFailure {
                    error,
                    original_creator: WindowsProtectedArtifactCreator {
                        parent,
                        component,
                        file: identity,
                        original_key,
                        write_attempted: true,
                        exclusive_creation_held: false,
                    },
                })
            }
        };
        let result = SealedWindowsProtectedArtifact {
            parent,
            component,
            file,
            original_key,
            bytes: expected.len() as u64,
        };
        // The new READ HANDLE shares READ and excludes WRITE/DELETE. Services
        // can read the selected path while the actual original object is held.
        if let Err(error) = result.verify_original(expected) {
            return Err(WindowsProtectedArtifactSealFailure {
                error,
                original_creator: WindowsProtectedArtifactCreator {
                    parent: result.parent,
                    component: result.component,
                    file: result.file,
                    original_key: result.original_key,
                    write_attempted: true,
                    exclusive_creation_held: false,
                },
            });
        }
        Ok(result)
    }
    pub fn close(self) -> io::Result<()> {
        drop(self);
        Ok(())
    }
}

pub struct WindowsProtectedArtifactSealFailure {
    pub error: io::Error,
    pub original_creator: WindowsProtectedArtifactCreator,
}
impl std::fmt::Debug for WindowsProtectedArtifactSealFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("WindowsProtectedArtifactSealFailure")
            .field("error", &self.error)
            .field("original_creator_retained", &true)
            .finish()
    }
}

pub struct SealedWindowsProtectedArtifact {
    parent: Arc<Parent>,
    component: String,
    file: File,
    original_key: FileKey,
    bytes: u64,
}
impl SealedWindowsProtectedArtifact {
    pub fn key(&self) -> FileKey {
        self.original_key
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.parent.verify()?;
        self.parent.directory()?.key()
    }
    pub fn verify_original(&self, expected: &[u8]) -> io::Result<()> {
        self.parent.verify()?;
        regular(&self.file, false)?;
        current_user_file::verify_current_user_private_file(&self.file)?;
        if key(&self.file)? != self.original_key
            || expected.len() as u64 != self.bytes
            || self.file.metadata()?.len() != self.bytes
            || !super::regular_file_matches_path(
                &self.file,
                &self.parent.path.join(&self.component),
            )?
        {
            return Err(invalid(
                "sealed original deployment key/slot/length changed",
            ));
        }
        let mut reader = &self.file;
        reader.seek(SeekFrom::Start(0))?;
        let mut readback = Vec::with_capacity(expected.len());
        reader
            .take(expected.len() as u64 + 1)
            .read_to_end(&mut readback)?;
        let same = readback == expected;
        readback.fill(0);
        if !same {
            return Err(invalid("sealed original deployment readback changed"));
        }
        self.parent.verify()
    }
    pub fn close(self) -> io::Result<()> {
        drop(self);
        Ok(())
    }
}
