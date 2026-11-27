//! One VFS protocol over distinct actual creator/acquisition owners.
use super::super::{
    AnchoredParent, ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure,
    UnixProtectedArtifactKey,
};
use super::namespace::NamespaceLoan;
use super::{
    FreshUnixNativeFile, OriginalUnixCasSentinel, ReacquiredUnixSqliteFile,
    ReacquiredUnixSqliteLock,
};
use std::{ffi::CStr, fs::File, io};

pub(super) enum SqliteOriginalFile<'namespace> {
    Created(FreshUnixNativeFile<'namespace>),
    Acquired(ReacquiredUnixSqliteFile<'namespace>),
}
impl<'namespace> SqliteOriginalFile<'namespace> {
    pub(super) fn verify(&self) -> io::Result<()> {
        match self {
            Self::Created(v) => v.verify(),
            Self::Acquired(v) => v.verify(),
        }
    }
    pub(super) fn namespace(&self) -> &NamespaceLoan<'namespace> {
        match self {
            Self::Created(v) => &v.namespace,
            Self::Acquired(v) => &v.namespace,
        }
    }
    pub(super) fn parent(&self) -> &AnchoredParent {
        match self {
            Self::Created(v) => &v.original.parent,
            Self::Acquired(v) => v.parent.as_ref().expect("live acquired parent"),
        }
    }
    pub(super) fn component(&self) -> &CStr {
        match self {
            Self::Created(v) => &v.original.component,
            Self::Acquired(v) => &v.component,
        }
    }
    pub(super) fn file(&self) -> &File {
        match self {
            Self::Created(v) => &v.original.file,
            Self::Acquired(v) => v.file.as_ref().expect("live acquired file"),
        }
    }
    pub(super) fn maximum(&self) -> u64 {
        match self {
            Self::Created(v) => v.maximum,
            Self::Acquired(v) => v.maximum,
        }
    }
    pub(super) fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        match self {
            Self::Created(v) => v.key(),
            Self::Acquired(v) => v.key(),
        }
    }
    pub(super) fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        match self {
            Self::Created(v) => v.close_retaining(),
            Self::Acquired(v) => v.close_retaining(),
        }
    }
}

pub(super) enum SqliteCoordination<'namespace> {
    Created(OriginalUnixCasSentinel<'namespace>),
    Acquired(ReacquiredUnixSqliteLock<'namespace>),
}
impl<'namespace> SqliteCoordination<'namespace> {
    pub(super) fn verify(&self) -> io::Result<()> {
        match self {
            Self::Created(v) => v.verify(),
            Self::Acquired(v) => v.verify(),
        }
    }
    pub(super) fn namespace(&self) -> &NamespaceLoan<'namespace> {
        match self {
            Self::Created(v) => &v.original.namespace,
            Self::Acquired(v) => &v.original.namespace,
        }
    }
    pub(super) fn parent(&self) -> &AnchoredParent {
        match self {
            Self::Created(v) => &v.original.original.parent,
            Self::Acquired(v) => v
                .original
                .parent
                .as_ref()
                .expect("live acquired coordination parent"),
        }
    }
    pub(super) fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        match self {
            Self::Created(v) => v.original.key(),
            Self::Acquired(v) => v.original.key(),
        }
    }
    pub(super) fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        match self {
            Self::Created(v) => v.close_retaining(),
            Self::Acquired(v) => v.close_retaining(),
        }
    }
}
