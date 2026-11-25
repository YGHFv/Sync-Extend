//! Retain the original object after relinquishing its exclusive CREATE handle.
//! This is identity continuity only: it grants no recovered creator or write authority.
use super::super::{invalid, key, regular, regular_file_matches_path};
use super::OwnedFileCreation;
use crate::FileKey;
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, FromRawHandle},
    path::Path,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        ReOpenFile, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};

/// Retains the original file object so an unlinked/replaced slot cannot reuse its
/// identity unnoticed. No pathname can construct, clone or deserialize this type.
/// The metadata-only witness permits writes and namespace changes by others.
pub struct ReleasedOriginalFileIdentity {
    original: File,
    original_parent: File,
    key: FileKey,
    parent_key: FileKey,
    original_creator_terminal: Option<crate::ClosedWindowsOriginalResources>,
}

pub(super) enum OriginalSqliteIdentityReleaseFailure {
    Creator {
        creator: Box<OwnedFileCreation>,
        original_resources: Option<crate::WindowsOriginalResourceCloseFailure>,
        error: io::Error,
    },
    Released {
        identity: ReleasedOriginalFileIdentity,
        original_resources: crate::WindowsOriginalResourceCloseFailure,
        error: io::Error,
    },
}

pub(super) struct OriginalSqliteIdentityReadFailure {
    pub(super) identity: ReleasedOriginalFileIdentity,
    pub(super) original_resources: Option<crate::WindowsOriginalResourceCloseFailure>,
    pub(super) error: io::Error,
}

impl OwnedFileCreation {
    /// The SQLite handoff ends both actual exclusive CREATE HANDLEs and carries
    /// the resulting original terminal witness forward with its identity.
    /// Every failed native prefix remains typed, without a replacement creator.
    pub(super) fn release_original_sqlite_identity(
        self,
    ) -> Result<ReleasedOriginalFileIdentity, OriginalSqliteIdentityReleaseFailure> {
        let prepared = (|| -> io::Result<(FileKey, FileKey)> {
            let original = self.original_creation()?;
            original.verify()?;
            self.verify_single_link()?;
            Ok((original.key()?, original.parent_key()?))
        })();
        let (file_key, parent_key) = match prepared {
            Ok(keys) => keys,
            Err(error) => {
                return Err(OriginalSqliteIdentityReleaseFailure::Creator {
                    creator: Box::new(self),
                    original_resources: None,
                    error,
                })
            }
        };
        let original =
            match super::super::reopen_same_file_object_retaining(self.reader(), file_key, false) {
                Ok(original) => original,
                Err(failure) => {
                    return Err(OriginalSqliteIdentityReleaseFailure::Creator {
                        creator: Box::new(self),
                        original_resources: failure.original_resources,
                        error: failure.error,
                    })
                }
            };
        let original_parent = match self.parent.try_clone() {
            Ok(parent) => parent,
            Err(error) => {
                let mut terminal = crate::WindowsOriginalCloseAttempt::new();
                terminal.close_file(original);
                return Err(OriginalSqliteIdentityReleaseFailure::Creator {
                    creator: Box::new(self),
                    original_resources: terminal.finish().err(),
                    error,
                });
            }
        };
        let checked = (|| -> io::Result<()> {
            if key(&original)? != file_key || key(&original_parent)? != parent_key {
                return Err(invalid("original SQLite identity handoff lineage differs"));
            }
            regular(&original, false)?;
            regular(&original_parent, true)
        })();
        if let Err(error) = checked {
            let mut terminal = crate::WindowsOriginalCloseAttempt::new();
            terminal.close_file(original);
            terminal.close_file(original_parent);
            return Err(OriginalSqliteIdentityReleaseFailure::Creator {
                creator: Box::new(self),
                original_resources: terminal.finish().err(),
                error,
            });
        }
        let mut identity = ReleasedOriginalFileIdentity {
            original,
            original_parent,
            key: file_key,
            parent_key,
            original_creator_terminal: None,
        };
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        self.close_into_attempt(&mut terminal);
        match terminal.finish() {
            Ok(closed) => {
                identity.original_creator_terminal = Some(closed);
                Ok(identity)
            }
            Err(original_resources) => {
                let error = match original_resources.error.raw_os_error() {
                    Some(code) => io::Error::from_raw_os_error(code),
                    None => io::Error::new(
                        original_resources.error.kind(),
                        original_resources.error.to_string(),
                    ),
                };
                Err(OriginalSqliteIdentityReleaseFailure::Released {
                    identity,
                    original_resources,
                    error,
                })
            }
        }
    }

    /// Caller records the handoff before consuming the exclusive creator.
    /// The new object handle comes from ReOpenFile on the actual original handle.
    /// All errors before handoff retain the caller's creator via the Err tuple.
    /// Successful handoff grants no original CREATE, immutable bytes or cleanup.
    pub fn release_for_identity_checked_reopen(
        self,
    ) -> Result<ReleasedOriginalFileIdentity, (Box<Self>, io::Error)> {
        let prepare = || -> io::Result<(File, File, FileKey, FileKey)> {
            let proof = self.original_creation()?;
            let expected_key = proof.key()?;
            let expected_parent = proof.parent_key()?;
            self.verify_single_link()?;
            let witness =
                super::super::reopen_same_file_object(self.reader(), expected_key, false)?;
            // Access to original parent is implemented within owned_file.rs;
            // this fragment is included there, where private fields are visible.
            let parent = self.parent.try_clone()?;
            if key(&parent)? != expected_parent {
                return Err(invalid("released original parent differs"));
            }
            Ok((witness, parent, expected_key, expected_parent))
        };
        let (original, original_parent, key, parent_key) = match prepare() {
            Ok(value) => value,
            Err(error) => return Err((Box::new(self), error)),
        };
        // The metadata witness already retains the original object before the
        // incompatible exclusive file handle is relinquished.
        drop(self);
        Ok(ReleasedOriginalFileIdentity {
            original,
            original_parent,
            key,
            parent_key,
            original_creator_terminal: None,
        })
    }
}

impl ReleasedOriginalFileIdentity {
    pub(super) fn retain_original_sqlite_read(
        self,
    ) -> Result<ReleasedOriginalReadFile, OriginalSqliteIdentityReadFailure> {
        if let Err(error) = self.verify() {
            return Err(OriginalSqliteIdentityReadFailure {
                identity: self,
                original_resources: None,
                error,
            });
        }
        match super::super::reopen_same_file_object_retaining(&self.original, self.key, true) {
            Ok(reader) => Ok(ReleasedOriginalReadFile {
                reader,
                original: self,
            }),
            Err(failure) => Err(OriginalSqliteIdentityReadFailure {
                identity: self,
                original_resources: failure.original_resources,
                error: failure.error,
            }),
        }
    }

    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        if let Some(closed) = self.original_creator_terminal {
            attempt.append_result(Ok(closed));
        }
        attempt.close_file(self.original);
        attempt.close_file(self.original_parent);
    }

    pub fn key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.key)
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.parent_key)
    }
    pub fn verify(&self) -> io::Result<()> {
        regular(&self.original, false)?;
        regular(&self.original_parent, true)?;
        if key(&self.original)? != self.key || key(&self.original_parent)? != self.parent_key {
            return Err(invalid("released original retained identity changed"));
        }
        Ok(())
    }
    /// A slot check never mints ownership of the opened object.
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        self.verify()?;
        regular_file_matches_path(&self.original, path)
    }
}

// Duplicate actual object/parent identity handles only, never original CREATE permission.
impl ReleasedOriginalFileIdentity {
    /// Independent observation of the same retained object, not recovered owner authority.
    /// Every duplicate retains the original object against unlinked FileKey reuse.
    pub fn retain_identity_observer(&self) -> std::io::Result<Self> {
        self.verify()?;
        let observed = Self {
            original: self.original.try_clone()?,
            original_parent: self.original_parent.try_clone()?,
            key: self.key,
            parent_key: self.parent_key,
            original_creator_terminal: None,
        };
        observed.verify()?;
        Ok(observed)
    }
}

// Same-object read handoff after releasing exclusive CREATE; no recovered authority.

pub struct ReleasedOriginalReadFile {
    reader: File,
    original: ReleasedOriginalFileIdentity,
}

impl ReleasedOriginalReadFile {
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.close_file(self.reader);
        self.original.close_into_attempt(attempt);
    }

    pub fn original_key(&self) -> io::Result<FileKey> {
        self.original.key()
    }
    pub fn original_parent_key(&self) -> io::Result<FileKey> {
        self.original.parent_key()
    }
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        self.original.verify()?;
        regular_file_matches_path(&self.reader, path)
    }
    pub fn reader(&self) -> &File {
        &self.reader
    }
    pub fn verify_identity(&self) -> io::Result<()> {
        self.original.verify()?;
        regular(&self.reader, false)?;
        if key(&self.reader)? != self.original.key()? {
            return Err(invalid("released original readonly object differs"));
        }
        Ok(())
    }
}

impl ReleasedOriginalFileIdentity {
    /// ReOpenFile acts on the retained same-object witness, never a pathname.
    /// The metadata witness prevents identity reuse during the sharing gap.
    /// New readers exclude writes/deletes; callers verify full bytes afterward.
    /// Failure preserves the original witness, with no recovered CREATE grant.
    pub fn retain_read_after_creation(self) -> Result<ReleasedOriginalReadFile, (Self, io::Error)> {
        let open = || -> io::Result<File> {
            self.verify()?;
            super::super::reopen_same_file_object(&self.original, self.key, true)
        };
        match open() {
            Ok(reader) => Ok(ReleasedOriginalReadFile {
                reader,
                original: self,
            }),
            Err(error) => Err((self, error)),
        }
    }
}

// Same-original coordination sentinel, never recovered native ownership.
pub struct ReleasedOriginalCoordinationFile {
    file: File,
    original: ReleasedOriginalFileIdentity,
}
impl ReleasedOriginalCoordinationFile {
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.close_file(self.file);
        self.original.close_into_attempt(attempt);
    }

    pub fn verify(&self, path: &Path) -> io::Result<()> {
        self.original.verify()?;
        regular(&self.file, false)?;
        if self.file.metadata()?.len() != 0
            || key(&self.file)? != self.original.key()?
            || !self.original.matches_path(path)?
        {
            return Err(invalid("same original empty coordination file differs"));
        }
        Ok(())
    }
    /// A metadata observer can be copied, but cannot mint a CREATE grant.
    pub fn retain_observer(&self) -> io::Result<Self> {
        self.original.verify()?;
        Ok(Self {
            file: self.file.try_clone()?,
            original: self.original.retain_identity_observer()?,
        })
    }
    /// Each cooperative acquisition uses a distinct same-object open description.
    /// DuplicateHandle/try_clone alone would share locking identity.
    pub fn open_for_shared_coordination(&self, path: &Path) -> io::Result<File> {
        self.verify(path)?;
        // SAFETY: original is retained same-object witness; distinct RW open
        // description permits original cooperative shared/exclusive lock calls.
        let handle = unsafe {
            ReOpenFile(
                self.original.original.as_raw_handle() as HANDLE,
                windows_sys::Win32::Foundation::GENERIC_READ
                    | windows_sys::Win32::Foundation::GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful ReOpenFile returned one distinct owned native handle.
        let file = unsafe { File::from_raw_handle(handle) };
        regular(&file, false)?;
        if key(&file)? != self.original.key()? || file.metadata()?.len() != 0 {
            return Err(invalid("same original coordination open differs"));
        }
        Ok(file)
    }
}

impl ReleasedOriginalFileIdentity {
    pub fn retain_coordination_after_creation(
        self,
    ) -> Result<ReleasedOriginalCoordinationFile, (Self, io::Error)> {
        let open = || -> io::Result<File> {
            self.verify()?;
            // SAFETY: original is an actual retained object, no path resolution.
            let handle = unsafe {
                ReOpenFile(
                    self.original.as_raw_handle() as HANDLE,
                    windows_sys::Win32::Foundation::GENERIC_READ
                        | windows_sys::Win32::Foundation::GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                )
            };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: one successful new handle has exactly one File owner.
            let file = unsafe { File::from_raw_handle(handle) };
            regular(&file, false)?;
            if key(&file)? != self.key || file.metadata()?.len() != 0 {
                return Err(invalid(
                    "coordination handoff requires original empty sentinel",
                ));
            }
            Ok(file)
        };
        match open() {
            Ok(file) => Ok(ReleasedOriginalCoordinationFile {
                file,
                original: self,
            }),
            Err(error) => Err((self, error)),
        }
    }
}

// Original sentinel keys remain observations; no raw handle or CREATE is exposed.
impl ReleasedOriginalCoordinationFile {
    pub fn original_key(&self) -> io::Result<FileKey> {
        self.original.verify()?;
        if key(&self.file)? != self.original.key()? || self.file.metadata()?.len() != 0 {
            return Err(invalid("completion original coordination sentinel differs"));
        }
        self.original.key()
    }
    pub fn original_parent_key(&self) -> io::Result<FileKey> {
        self.original.verify()?;
        self.original.parent_key()
    }
}

// Included inside original owned_file/created_identity.rs where fields remain private.
impl ReleasedOriginalReadFile {
    /// Relinquish only the same-object readonly sharing protection. Keep the
    /// original object and parent witnesses continuously alive across the handoff.
    /// This returns identity evidence only; it never grants CREATE or write access.
    pub fn release_read_protection(
        self,
    ) -> Result<ReleasedOriginalFileIdentity, (Self, io::Error)> {
        if let Err(error) = self.verify_identity() {
            return Err((self, error));
        }
        let Self {
            reader,
            mut original,
        } = self;
        match crate::original_resource_close::close_owned_original_file(reader) {
            Ok(()) => {
                let mut terminal = crate::WindowsOriginalCloseAttempt::new();
                terminal.note_actual_handle_closed();
                if let Some(closed) = original.original_creator_terminal.take() {
                    terminal.append_result(Ok(closed));
                }
                original.original_creator_terminal = Some(
                    terminal
                        .finish()
                        .expect("only actual successful original closes were appended"),
                );
                Ok(original)
            }
            Err((reader, error)) => Err((Self { reader, original }, error)),
        }
    }
}

impl ReleasedOriginalReadFile {
    pub fn retain_read_identity_observer(&self) -> io::Result<ReleasedOriginalFileIdentity> {
        self.verify_identity()?;
        self.original.retain_identity_observer()
    }
}

// Retain the actual original CREATE parent; pathname checks grant no authority.
impl ReleasedOriginalCoordinationFile {
    pub fn retain_original_parent_directory(
        &self,
        parent: &Path,
    ) -> io::Result<super::super::LockedDirectory> {
        self.verify(&parent.join("cas-access.lock"))?;
        let held = super::super::retain_writer_directory(&self.original.original_parent, parent)?;
        if held.key != self.original.parent_key()? {
            return Err(invalid("original coordination CREATE parent differs"));
        }
        Ok(held.directory)
    }
}
