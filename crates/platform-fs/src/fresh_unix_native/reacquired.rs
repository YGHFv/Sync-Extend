//! Existing writable SQLite resources retain a distinct acquisition type.
//! No existing inode is ever represented as an exclusive creator.
use super::super::{
    component, mount_identity, observe_fd, observe_slot, open_child, refuse, verify_file,
    AnchoredParent, ClosedUnixOriginalResources, UnixOriginalCloseAttempt,
    UnixOriginalResourceCloseFailure, UnixProtectedArtifactKey,
};
use super::{namespace::NamespaceLoan, AcquiredUnixChildDirectory, OriginalUnixNativeRoot};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::Arc,
};

pub struct ReacquiredUnixSqliteFile<'namespace> {
    pub(super) namespace: NamespaceLoan<'namespace>,
    pub(super) parent: Option<Arc<AnchoredParent>>,
    pub(super) component: CString,
    pub(super) file: Option<File>,
    pub(super) key: UnixProtectedArtifactKey,
    pub(super) maximum: u64,
}

pub struct ReacquiredUnixSqliteFileFailure<'namespace> {
    pub error: io::Error,
    pub original: Option<ReacquiredUnixSqliteFile<'namespace>>,
}
impl std::fmt::Debug for ReacquiredUnixSqliteFileFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReacquiredUnixSqliteFileFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .finish()
    }
}
impl Drop for ReacquiredUnixSqliteFileFailure<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
    }
}

fn acquire<'namespace>(
    namespace: &NamespaceLoan<'namespace>,
    parent: &Arc<AnchoredParent>,
    name: &str,
    expected: UnixProtectedArtifactKey,
    maximum: u64,
) -> Result<ReacquiredUnixSqliteFile<'namespace>, ReacquiredUnixSqliteFileFailure<'namespace>> {
    let fail = |error| ReacquiredUnixSqliteFileFailure {
        error,
        original: None,
    };
    namespace.verify_current().map_err(fail)?;
    parent.verify().map_err(fail)?;
    if !matches!(
        name,
        "journal.sqlite"
            | "journal.sqlite-wal"
            | "journal.sqlite-journal"
            | "journal.sqlite-shm"
            | "cas.lock"
            | "writer.lock"
    ) || maximum == 0
        || maximum > 256 * 1024 * 1024
    {
        return Err(fail(refuse("bounded existing Unix SQLite member")));
    }
    let component = component(OsStr::new(name)).map_err(fail)?;
    let before = observe_slot(parent.fd().map_err(fail)?, &component).map_err(fail)?;
    verify_file(before, true, maximum as usize).map_err(fail)?;
    if before.key != expected {
        return Err(fail(refuse(
            "existing Unix SQLite slot differs before writable open",
        )));
    }
    let before_mount =
        mount_identity::slot_mount_id(parent.fd().map_err(fail)?, &component).map_err(fail)?;
    let file = open_child(
        parent.fd().map_err(fail)?,
        &component,
        libc::O_RDWR | libc::O_NONBLOCK,
    )
    .map_err(fail)?;
    let original = ReacquiredUnixSqliteFile {
        namespace: namespace.clone(),
        parent: Some(Arc::clone(parent)),
        component,
        file: Some(file),
        key: expected,
        maximum,
    };
    let checked = (|| {
        original.verify()?;
        let descriptor = original
            .file
            .as_ref()
            .expect("actual acquired original")
            .as_raw_fd();
        if observe_fd(descriptor)? != before
            || mount_identity::mount_id(descriptor)? != before_mount
        {
            return Err(refuse(
                "existing Unix SQLite slot changed during writable acquisition",
            ));
        }
        Ok(())
    })();
    match checked {
        Ok(()) => Ok(original),
        Err(error) => Err(ReacquiredUnixSqliteFileFailure {
            error,
            original: Some(original),
        }),
    }
}
impl<'namespace> OriginalUnixNativeRoot<'namespace> {
    /// Keys are comparisons; acquisition always retains an actual parent-relative descriptor.
    pub fn reacquire_sqlite_file(
        &self,
        name: &str,
        expected: UnixProtectedArtifactKey,
        maximum: u64,
    ) -> Result<ReacquiredUnixSqliteFile<'namespace>, ReacquiredUnixSqliteFileFailure<'namespace>>
    {
        acquire(
            &self.namespace,
            &self.original.original,
            name,
            expected,
            maximum,
        )
    }
}
impl<'namespace> AcquiredUnixChildDirectory<'namespace> {
    pub fn reacquire_sqlite_file(
        &self,
        name: &str,
        expected: UnixProtectedArtifactKey,
        maximum: u64,
    ) -> Result<ReacquiredUnixSqliteFile<'namespace>, ReacquiredUnixSqliteFileFailure<'namespace>>
    {
        acquire(
            &self.namespace,
            &self.original.original,
            name,
            expected,
            maximum,
        )
    }
}
impl ReacquiredUnixSqliteFile<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| refuse("reacquired Unix parent closed"))?;
        parent.verify()?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| refuse("reacquired Unix file closed"))?;
        let observed = observe_fd(file.as_raw_fd())?;
        verify_file(
            observed,
            true,
            usize::try_from(self.maximum).map_err(|_| refuse("existing Unix file capacity"))?,
        )?;
        if observed.key != self.key
            || observe_slot(parent.fd()?, &self.component)? != observed
            || mount_identity::mount_id(file.as_raw_fd())?
                != mount_identity::slot_mount_id(parent.fd()?, &self.component)?
        {
            return Err(refuse("reacquired Unix SQLite original slot differs"));
        }
        Ok(())
    }
    pub fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.verify()?;
        Ok(self.key)
    }
    pub fn close_retaining(
        mut self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify() {
            close.note_error(error);
        }
        if let Some(file) = self.file.take() {
            close.close_file(file);
        }
        if let Some(parent) = self.parent.take() {
            if let Ok(parent) = Arc::try_unwrap(parent) {
                parent.close_into_attempt(&mut close);
            }
        }
        close.finish()
    }
}
impl Drop for ReacquiredUnixSqliteFile<'_> {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = Box::leak(Box::new((file, self.parent.take(), self.namespace.clone())));
        }
    }
}

pub struct ReacquiredUnixSqliteLock<'namespace> {
    pub(super) original: ReacquiredUnixSqliteFile<'namespace>,
}
impl<'namespace> ReacquiredUnixSqliteFile<'namespace> {
    pub fn lock_exclusive(
        self,
    ) -> Result<ReacquiredUnixSqliteLock<'namespace>, ReacquiredUnixSqliteFileFailure<'namespace>>
    {
        let checked = (|| {
            self.verify()?;
            if !matches!(self.component.to_bytes(), b"cas.lock" | b"writer.lock")
                || self.file.as_ref().expect("verified file").metadata()?.len() != 0
            {
                return Err(refuse("reacquired empty coordination original required"));
            }
            // SAFETY: this retained descriptor was acquired above; no integer is reconstructed.
            if unsafe {
                libc::flock(
                    self.file.as_ref().expect("verified file").as_raw_fd(),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.verify()
        })();
        match checked {
            Ok(()) => Ok(ReacquiredUnixSqliteLock { original: self }),
            Err(error) => Err(ReacquiredUnixSqliteFileFailure {
                error,
                original: Some(self),
            }),
        }
    }
}
impl ReacquiredUnixSqliteLock<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.original.verify()?;
        // SAFETY: reasserts exclusive flock on the same owned open description.
        if unsafe {
            libc::flock(
                self.original
                    .file
                    .as_ref()
                    .expect("verified file")
                    .as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        self.original.close_retaining()
    }
}
