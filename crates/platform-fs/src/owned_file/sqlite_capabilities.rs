//! Linear SQLite handoff issued only by an actual still-owned original CREATE.
//! Metadata identities and completed manifests cannot construct this capability.
use super::created_identity::OriginalSqliteIdentityReleaseFailure;
use super::{OwnedFileCreation, ReleasedOriginalFileIdentity, ReleasedOriginalReadFile};
use crate::FileKey;
use std::{
    io,
    path::{Path, PathBuf},
};

/// No Clone/serde/public constructor and no metadata-to-writer conversion.
/// Initial issuer must record this transition before relinquishing its creator.
pub struct OriginalSqliteMainHandoff {
    protected: Option<ReleasedOriginalReadFile>,
    released: Option<ReleasedOriginalFileIdentity>,
    original_path: PathBuf,
    key: FileKey,
    parent: FileKey,
    attempted: bool,
}

/// Before release keeps the original creator; after release keeps exact identity.
/// No failure silently becomes a successful protected handoff.
pub enum OriginalSqliteMainHandoffFailure {
    Creator {
        creator: OwnedFileCreation,
        error: io::Error,
    },
    Released {
        identity: ReleasedOriginalFileIdentity,
        error: io::Error,
    },
    Terminating {
        creator: Option<OwnedFileCreation>,
        identity: Option<ReleasedOriginalFileIdentity>,
        original_resources: crate::WindowsOriginalResourceCloseFailure,
        error: io::Error,
    },
}
impl OwnedFileCreation {
    pub fn handoff_original_sqlite_main(
        self,
        path: &Path,
    ) -> Result<OriginalSqliteMainHandoff, OriginalSqliteMainHandoffFailure> {
        let validate = || -> io::Result<(FileKey, FileKey)> {
            self.original_creation()?.verify()?;
            self.verify_single_link()?;
            if !path.is_absolute()
                || path.file_name().and_then(|name| name.to_str()) != Some("journal.sqlite")
                || !super::super::regular_file_matches_path(self.reader(), path)?
            {
                return Err(io::Error::other(
                    "exact original SQLite main creator slot required",
                ));
            }
            Ok((self.key()?, self.original_creation()?.parent_key()?))
        };
        let (key, parent) = match validate() {
            Ok(value) => value,
            Err(error) => {
                return Err(OriginalSqliteMainHandoffFailure::Creator {
                    creator: self,
                    error,
                })
            }
        };
        let path = path.to_owned();
        // The exclusive actual CREATE is the only issuing edge. The current
        // metadata API has no constructor for this linear capability.
        let identity = match self.release_original_sqlite_identity() {
            Ok(value) => value,
            Err(OriginalSqliteIdentityReleaseFailure::Creator {
                creator,
                original_resources: None,
                error,
            }) => {
                return Err(OriginalSqliteMainHandoffFailure::Creator {
                    creator: *creator,
                    error,
                })
            }
            Err(OriginalSqliteIdentityReleaseFailure::Creator {
                creator,
                original_resources: Some(original_resources),
                error,
            }) => {
                return Err(OriginalSqliteMainHandoffFailure::Terminating {
                    creator: Some(*creator),
                    identity: None,
                    original_resources,
                    error,
                })
            }
            Err(OriginalSqliteIdentityReleaseFailure::Released {
                identity,
                original_resources,
                error,
            }) => {
                return Err(OriginalSqliteMainHandoffFailure::Terminating {
                    creator: None,
                    identity: Some(identity),
                    original_resources,
                    error,
                })
            }
        };
        let protected = match identity.retain_original_sqlite_read() {
            Ok(value) => value,
            Err(failure) => {
                return Err(match failure.original_resources {
                    Some(original_resources) => OriginalSqliteMainHandoffFailure::Terminating {
                        creator: None,
                        identity: Some(failure.identity),
                        original_resources,
                        error: failure.error,
                    },
                    None => OriginalSqliteMainHandoffFailure::Released {
                        identity: failure.identity,
                        error: failure.error,
                    },
                });
            }
        };
        Ok(OriginalSqliteMainHandoff {
            protected: Some(protected),
            released: None,
            original_path: path,
            key,
            parent,
            attempted: false,
        })
    }
}
impl OriginalSqliteMainHandoff {
    pub fn close_into_attempt(mut self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        if let Some(original) = self.protected.take() {
            original.close_into_attempt(attempt);
        }
        if let Some(original) = self.released.take() {
            original.close_into_attempt(attempt);
        }
    }

    pub fn key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.key)
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.parent)
    }
    pub fn path(&self) -> &Path {
        &self.original_path
    }
    pub fn read_protection_established(&self) -> bool {
        self.protected.is_some() && !self.attempted
    }
    pub fn verify(&self) -> io::Result<()> {
        match (&self.protected, &self.released) {
            (Some(protected), None) => {
                protected.verify_identity()?;
                if protected.original_key()? != self.key
                    || protected.original_parent_key()? != self.parent
                    || !protected.matches_path(&self.original_path)?
                {
                    return Err(io::Error::other(
                        "linear original SQLite protected object differs",
                    ));
                }
            }
            (None, Some(released)) => {
                released.verify()?;
                if released.key()? != self.key
                    || released.parent_key()? != self.parent
                    || !released.matches_path(&self.original_path)?
                {
                    return Err(io::Error::other(
                        "linear original SQLite released object differs",
                    ));
                }
            }
            _ => {
                return Err(io::Error::other(
                    "linear original SQLite transition state unavailable",
                ))
            }
        }
        Ok(())
    }
    /// Borrow only the currently protected original image bytes. No File/raw
    /// handle/metadata witness escapes through this linear issuer.
    pub fn exact_protected_bytes(&self, max_bytes: u64) -> io::Result<Vec<u8>> {
        use std::os::windows::fs::FileExt;
        self.verify()?;
        let protected = self
            .protected
            .as_ref()
            .ok_or_else(|| io::Error::other("original SQLite has no read protection"))?;
        let file = protected.reader();
        let length = file.metadata()?.len();
        if !(512..=256 * 1024 * 1024).contains(&max_bytes) || !(512..=max_bytes).contains(&length) {
            return Err(io::Error::other("original SQLite handoff byte bound"));
        }
        let mut bytes = vec![0; length as usize];
        let mut offset = 0;
        while offset < bytes.len() {
            let count = file.seek_read(&mut bytes[offset..], offset as u64)?;
            if count == 0 {
                return Err(io::Error::other("original SQLite protected short read"));
            }
            offset = offset
                .checked_add(count)
                .ok_or_else(|| io::Error::other("original SQLite read overflow"))?;
        }
        self.verify()?;
        if file.metadata()?.len() != length {
            return Err(io::Error::other("original SQLite image length changed"));
        }
        Ok(bytes)
    }
    /// Only the sibling SQLite VFS consumes this linear issuance edge.
    /// It returns identity after protection release, never recovered authority.
    pub(in super::super) fn consume_for_vfs(
        mut self,
    ) -> Result<ReleasedOriginalFileIdentity, (Box<Self>, io::Error)> {
        if let Err(error) = self.verify() {
            return Err((Box::new(self), error));
        }
        if self.attempted || self.protected.is_none() {
            return Err((
                Box::new(self),
                io::Error::other("linear original SQLite issuance unavailable"),
            ));
        }
        self.attempted = true;
        let Some(protected) = self.protected.take() else {
            return Err((
                Box::new(self),
                io::Error::other("linear SQLite protected transition missing"),
            ));
        };
        match protected.release_read_protection() {
            Ok(identity) => Ok(identity),
            Err((protected, error)) => {
                self.protected = Some(protected);
                Err((Box::new(self), error))
            }
        }
    }
}

/// Each sidecar permit also starts at its own exact native CREATE. Names and
/// FileKeys supplied by a caller never construct these objects.
pub enum OriginalSqliteSidecarKind {
    Wal,
    Rollback,
}
pub struct OriginalSqliteSidecarHandoff {
    original: ReleasedOriginalFileIdentity,
    path: PathBuf,
    kind: OriginalSqliteSidecarKind,
}
pub enum OriginalSqliteSidecarHandoffFailure {
    Creator {
        creator: OwnedFileCreation,
        error: io::Error,
    },
    Released {
        identity: ReleasedOriginalFileIdentity,
        error: io::Error,
    },
    Terminating {
        creator: Option<OwnedFileCreation>,
        identity: Option<ReleasedOriginalFileIdentity>,
        original_resources: crate::WindowsOriginalResourceCloseFailure,
        error: io::Error,
    },
}
impl OwnedFileCreation {
    pub fn handoff_original_sqlite_sidecar(
        self,
        path: &Path,
        kind: OriginalSqliteSidecarKind,
    ) -> Result<OriginalSqliteSidecarHandoff, OriginalSqliteSidecarHandoffFailure> {
        let name = match kind {
            OriginalSqliteSidecarKind::Wal => "journal.sqlite-wal",
            OriginalSqliteSidecarKind::Rollback => "journal.sqlite-journal",
        };
        let validate = || -> io::Result<()> {
            self.original_creation()?.verify()?;
            self.verify_single_link()?;
            if !path.is_absolute()
                || path.file_name().and_then(|value| value.to_str()) != Some(name)
                || self.reader().metadata()?.len() != 0
                || !super::super::regular_file_matches_path(self.reader(), path)?
            {
                return Err(io::Error::other(
                    "exact empty original SQLite sidecar creator required",
                ));
            }
            self.reader().sync_all()
        };
        if let Err(error) = validate() {
            return Err(OriginalSqliteSidecarHandoffFailure::Creator {
                creator: self,
                error,
            });
        }
        let original = match self.release_original_sqlite_identity() {
            Ok(value) => value,
            Err(OriginalSqliteIdentityReleaseFailure::Creator {
                creator,
                original_resources: None,
                error,
            }) => {
                return Err(OriginalSqliteSidecarHandoffFailure::Creator {
                    creator: *creator,
                    error,
                })
            }
            Err(OriginalSqliteIdentityReleaseFailure::Creator {
                creator,
                original_resources: Some(original_resources),
                error,
            }) => {
                return Err(OriginalSqliteSidecarHandoffFailure::Terminating {
                    creator: Some(*creator),
                    identity: None,
                    original_resources,
                    error,
                })
            }
            Err(OriginalSqliteIdentityReleaseFailure::Released {
                identity,
                original_resources,
                error,
            }) => {
                return Err(OriginalSqliteSidecarHandoffFailure::Terminating {
                    creator: None,
                    identity: Some(identity),
                    original_resources,
                    error,
                })
            }
        };
        let result = OriginalSqliteSidecarHandoff {
            original,
            path: path.to_owned(),
            kind,
        };
        if let Err(error) = result.verify() {
            return Err(OriginalSqliteSidecarHandoffFailure::Released {
                identity: result.original,
                error,
            });
        }
        Ok(result)
    }
}
impl OriginalSqliteSidecarHandoff {
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        self.original.close_into_attempt(attempt);
    }

    pub fn verify(&self) -> io::Result<()> {
        self.original.verify()?;
        if !self.original.matches_path(&self.path)? {
            return Err(io::Error::other(
                "original SQLite sidecar named slot changed",
            ));
        }
        Ok(())
    }
    pub fn key(&self) -> io::Result<FileKey> {
        self.verify()?;
        self.original.key()
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify()?;
        self.original.parent_key()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub(in super::super) fn consume_for_vfs(
        self,
        main: &Path,
        kind: OriginalSqliteSidecarKind,
        parent: FileKey,
    ) -> Result<ReleasedOriginalFileIdentity, (Box<Self>, io::Error)> {
        let check = || -> io::Result<()> {
            self.verify()?;
            let suffix = match kind {
                OriginalSqliteSidecarKind::Wal => "-wal",
                OriginalSqliteSidecarKind::Rollback => "-journal",
            };
            let expected_kind = matches!(
                (&self.kind, &kind),
                (
                    OriginalSqliteSidecarKind::Wal,
                    OriginalSqliteSidecarKind::Wal
                ) | (
                    OriginalSqliteSidecarKind::Rollback,
                    OriginalSqliteSidecarKind::Rollback
                )
            );
            let mut expected = main.as_os_str().to_owned();
            expected.push(suffix);
            if !expected_kind || self.path != Path::new(&expected) || self.parent_key()? != parent {
                return Err(io::Error::other(
                    "original SQLite sidecar main/parent/type binding differs",
                ));
            }
            Ok(())
        };
        if let Err(error) = check() {
            return Err((Box::new(self), error));
        }
        Ok(self.original)
    }
}

impl OriginalSqliteMainHandoffFailure {
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        match self {
            Self::Creator { creator, error } => {
                attempt.note_error(error);
                creator.close_into_attempt(attempt);
            }
            Self::Released { identity, error } => {
                attempt.note_error(error);
                identity.close_into_attempt(attempt);
            }
            Self::Terminating {
                creator,
                identity,
                original_resources,
                error,
            } => {
                attempt.note_error(error);
                attempt.append_failure(original_resources.close_remaining());
                if let Some(creator) = creator {
                    creator.close_into_attempt(attempt);
                }
                if let Some(identity) = identity {
                    identity.close_into_attempt(attempt);
                }
            }
        }
    }
}

impl OriginalSqliteSidecarHandoffFailure {
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        match self {
            Self::Creator { creator, error } => {
                attempt.note_error(error);
                creator.close_into_attempt(attempt);
            }
            Self::Released { identity, error } => {
                attempt.note_error(error);
                identity.close_into_attempt(attempt);
            }
            Self::Terminating {
                creator,
                identity,
                original_resources,
                error,
            } => {
                attempt.note_error(error);
                attempt.append_failure(original_resources.close_remaining());
                if let Some(creator) = creator {
                    creator.close_into_attempt(attempt);
                }
                if let Some(identity) = identity {
                    identity.close_into_attempt(attempt);
                }
            }
        }
    }
}

// Read-only observer edge does not construct another original main capability.
impl OriginalSqliteMainHandoff {
    pub fn retain_read_identity_observer(&self) -> io::Result<ReleasedOriginalFileIdentity> {
        self.verify()?;
        let protected = self
            .protected
            .as_ref()
            .ok_or_else(|| io::Error::other("original sealed main no read protection"))?;
        // The returned metadata observer cannot convert back into a sealed main.
        protected.retain_read_identity_observer()
    }
}
