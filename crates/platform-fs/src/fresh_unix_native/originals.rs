//! Actual originals with namespace loans, never reconstructed from reported keys.
use super::super::{
    component, mount_identity, observe_fd, observe_slot, open_child, refuse, verify_directory,
    AnchoredParent, ClosedUnixOriginalResources, DirectoryAnchor, UnixOriginalCloseAttempt,
    UnixOriginalResourceCloseFailure, UnixProtectedArtifactCreator, UnixProtectedArtifactKey,
    UnixProtectedArtifactParent,
};
use super::{namespace::NamespaceLoan, OriginalUnixNamespace};
use std::{ffi::OsStr, io, os::fd::AsRawFd, path::Path, sync::Arc};

pub struct OriginalUnixNativeRoot<'namespace> {
    namespace: NamespaceLoan<'namespace>,
    original: UnixProtectedArtifactParent,
}

/// mkdirat does not return an original descriptor. This type proves only the
/// directory actually acquired and checked after mkdirat, not atomic creation.
pub struct AcquiredUnixChildDirectory<'namespace> {
    namespace: NamespaceLoan<'namespace>,
    original: UnixProtectedArtifactParent,
}

pub struct AcquiredUnixChildDirectoryFailure<'namespace> {
    pub error: io::Error,
    pub mkdir_succeeded: bool,
    pub acquired: Option<AcquiredUnixChildDirectory<'namespace>>,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for AcquiredUnixChildDirectoryFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("AcquiredUnixChildDirectoryFailure")
            .field("error", &self.error)
            .field("mkdir_succeeded", &self.mkdir_succeeded)
            .field("original_acquired", &self.acquired.is_some())
            .field("original_close_uncertain", &self.original_close.is_some())
            .finish()
    }
}

impl Drop for AcquiredUnixChildDirectoryFailure<'_> {
    fn drop(&mut self) {
        if let Some(acquired) = self.acquired.take() {
            let _ = Box::leak(Box::new(acquired));
        }
        if let Some(original_close) = self.original_close.take() {
            original_close.retain_until_process_exit();
        }
    }
}

pub struct FreshUnixNativeFile<'namespace> {
    pub(super) namespace: NamespaceLoan<'namespace>,
    pub(super) original: UnixProtectedArtifactCreator,
    pub(super) maximum: u64,
}

pub struct FreshUnixNativeFileFailure<'namespace> {
    pub error: io::Error,
    pub original: Option<FreshUnixNativeFile<'namespace>>,
    pub failed_create: Option<FailedUnixNativeFileCreation<'namespace>>,
}

pub struct FailedUnixNativeFileCreation<'namespace> {
    namespace: NamespaceLoan<'namespace>,
    original: super::super::UnixFailedArtifactCreation,
}

impl FailedUnixNativeFileCreation<'_> {
    pub fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.namespace.verify_current() {
            close.note_error(error);
        }
        close.append_result(self.original.close_retaining());
        close.finish()
    }
}

impl std::fmt::Debug for FreshUnixNativeFileFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("FreshUnixNativeFileFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .field("failed_create_retained", &self.failed_create.is_some())
            .finish()
    }
}

impl Drop for FreshUnixNativeFileFailure<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
        if let Some(original) = self.failed_create.take() {
            let _ = Box::leak(Box::new(original));
        }
    }
}

/// Holds flock on the actual freshly created CAS coordination file.
pub struct OriginalUnixCasSentinel<'namespace> {
    pub(super) original: FreshUnixNativeFile<'namespace>,
}

fn close_parent(
    namespace: &NamespaceLoan<'_>,
    original: UnixProtectedArtifactParent,
) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
    let mut close = UnixOriginalCloseAttempt::new();
    if let Err(error) = namespace.verify_current() {
        close.note_error(error);
    }
    close.close_artifact_parent(original);
    close.finish()
}

fn create_file<'namespace>(
    namespace: &NamespaceLoan<'namespace>,
    parent: &UnixProtectedArtifactParent,
    name: &str,
    maximum: u64,
) -> Result<FreshUnixNativeFile<'namespace>, FreshUnixNativeFileFailure<'namespace>> {
    let preflight = namespace.verify_current().and_then(|()| {
        if maximum == 0 || maximum > 1024 * 1024 * 1024 {
            Err(refuse("bounded Unix original file capacity required"))
        } else {
            parent.verify_original()
        }
    });
    if let Err(error) = preflight {
        return Err(FreshUnixNativeFileFailure {
            error,
            original: None,
            failed_create: None,
        });
    }
    let original = parent
        .create_new(name)
        .map_err(|failure| FreshUnixNativeFileFailure {
            error: failure.error,
            original: None,
            failed_create: failure
                .original_created
                .map(|original| FailedUnixNativeFileCreation {
                    namespace: namespace.clone(),
                    original,
                }),
        })?;
    let result = FreshUnixNativeFile {
        namespace: namespace.clone(),
        original,
        maximum,
    };
    if let Err(error) = result.verify() {
        return Err(FreshUnixNativeFileFailure {
            error,
            original: Some(result),
            failed_create: None,
        });
    }
    Ok(result)
}

fn acquire_child<'namespace>(
    namespace: &NamespaceLoan<'namespace>,
    parent: &UnixProtectedArtifactParent,
    child: &str,
) -> Result<AcquiredUnixChildDirectory<'namespace>, AcquiredUnixChildDirectoryFailure<'namespace>> {
    let mut mkdir_succeeded = false;
    let mut directories = Vec::new();
    let mut pending = None;
    let opened = (|| -> io::Result<()> {
        namespace.verify_current()?;
        parent.verify_original()?;
        let name = component(OsStr::new(child))?;
        let fd = parent.original.fd()?;
        // SAFETY: the actual parent FD and normalized NUL-terminated component
        // remain live. Success proves mkdir occurred, not atomic FD creation.
        if unsafe { libc::mkdirat(fd, name.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        mkdir_succeeded = true;
        pending = Some(open_child(fd, &name, libc::O_RDONLY | libc::O_DIRECTORY)?);
        let file = pending.as_ref().expect("acquired directory descriptor");
        let observed = observe_fd(file.as_raw_fd())?;
        verify_directory(observed, true)?;
        if !observed.same_object(observe_slot(fd, &name)?) {
            return Err(refuse("acquired Unix child directory slot changed"));
        }
        let mount_id = mount_identity::mount_id(file.as_raw_fd())?;
        if mount_id != mount_identity::slot_mount_id(fd, &name)? {
            return Err(refuse("acquired Unix child directory mount changed"));
        }
        // Duplicate only actual retained ancestor descriptors, never pathname
        // reopen. Each successful duplicate is immediately owned by this prefix.
        for original in &parent.original.directories {
            directories.push(DirectoryAnchor {
                file: original.file.try_clone()?,
                key: original.key,
                mount_id: original.mount_id,
                component: original.component.clone(),
            });
        }
        directories.push(DirectoryAnchor {
            file: pending.take().expect("checked directory descriptor"),
            key: observed.key,
            mount_id,
            component: Some(name),
        });
        parent
            .original
            .directories
            .last()
            .expect("retained parent")
            .file
            .sync_all()?;
        namespace.verify_current()?;
        parent.verify_original()
    })();
    if let Err(error) = opened {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Some(file) = pending {
            close.close_file(file);
        }
        for directory in directories.into_iter().rev() {
            close.close_file(directory.file);
        }
        return Err(AcquiredUnixChildDirectoryFailure {
            error,
            mkdir_succeeded,
            acquired: None,
            original_close: close.finish().err(),
        });
    }
    let original = UnixProtectedArtifactParent {
        original: Arc::new(AnchoredParent {
            path: parent.path().join(child),
            directories,
        }),
    };
    let result = AcquiredUnixChildDirectory {
        namespace: namespace.clone(),
        original,
    };
    if let Err(error) = result
        .verify()
        .and_then(|()| result.original.require_empty())
    {
        return Err(AcquiredUnixChildDirectoryFailure {
            error,
            mkdir_succeeded,
            acquired: Some(result),
            original_close: None,
        });
    }
    Ok(result)
}

impl<'namespace> OriginalUnixNativeRoot<'namespace> {
    pub fn acquire_private(
        namespace: &'namespace OriginalUnixNamespace,
        path: &Path,
    ) -> io::Result<Self> {
        namespace.verify_current()?;
        let original = UnixProtectedArtifactParent::open_private(path)?;
        if let Err(error) = namespace.verify_current() {
            let mut close = UnixOriginalCloseAttempt::new();
            close.note_error(error);
            close.close_artifact_parent(original);
            return Err(close
                .finish()
                .err()
                .expect("root acquisition first error")
                .retain_and_report());
        }
        Ok(Self {
            namespace: namespace.loan(),
            original,
        })
    }
    pub fn verify(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        self.original.verify_original()
    }
    pub fn require_empty(&self) -> io::Result<()> {
        self.verify()?;
        self.original.require_empty()?;
        self.verify()
    }
    pub fn create_file(
        &self,
        name: &str,
        maximum: u64,
    ) -> Result<FreshUnixNativeFile<'namespace>, FreshUnixNativeFileFailure<'namespace>> {
        create_file(&self.namespace, &self.original, name, maximum)
    }
    pub fn acquire_new_child(
        &self,
        name: &str,
    ) -> Result<AcquiredUnixChildDirectory<'namespace>, AcquiredUnixChildDirectoryFailure<'namespace>>
    {
        acquire_child(&self.namespace, &self.original, name)
    }
    pub fn create_cas_sentinel(
        &self,
    ) -> Result<OriginalUnixCasSentinel<'namespace>, FreshUnixNativeFileFailure<'namespace>> {
        let original = self.create_file("cas.lock", 4096)?;
        OriginalUnixCasSentinel::acquire(original)
    }
    pub fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        close_parent(&self.namespace, self.original)
    }
}

impl<'namespace> AcquiredUnixChildDirectory<'namespace> {
    pub fn verify(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        self.original.verify_original()
    }
    pub fn create_file(
        &self,
        name: &str,
        maximum: u64,
    ) -> Result<FreshUnixNativeFile<'namespace>, FreshUnixNativeFileFailure<'namespace>> {
        create_file(&self.namespace, &self.original, name, maximum)
    }
    pub fn acquire_new_child(
        &self,
        name: &str,
    ) -> Result<AcquiredUnixChildDirectory<'namespace>, AcquiredUnixChildDirectoryFailure<'namespace>>
    {
        acquire_child(&self.namespace, &self.original, name)
    }
    pub fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        close_parent(&self.namespace, self.original)
    }
}

impl FreshUnixNativeFile<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        self.original.verify_original()?;
        if self.original.file.metadata()?.len() > self.maximum {
            return Err(refuse("actual original file exceeds its capacity"));
        }
        Ok(())
    }
    pub fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.verify()?;
        Ok(self.original.key())
    }
    pub fn write_and_sync(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.verify()?;
        if bytes.len() as u64 > self.maximum {
            return Err(refuse("original file bounded write"));
        }
        self.original.write_and_sync(bytes)?;
        self.verify()
    }
    pub fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify() {
            close.note_error(error);
        }
        close.append_result(self.original.close_retaining());
        close.finish()
    }
}

impl<'namespace> OriginalUnixCasSentinel<'namespace> {
    fn acquire(
        original: FreshUnixNativeFile<'namespace>,
    ) -> Result<Self, FreshUnixNativeFileFailure<'namespace>> {
        // SAFETY: flock is acquired on this actual freshly created retained FD.
        if unsafe {
            libc::flock(
                original.original.file.as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            return Err(FreshUnixNativeFileFailure {
                error: io::Error::last_os_error(),
                original: Some(original),
                failed_create: None,
            });
        }
        Ok(Self { original })
    }
    pub fn verify(&self) -> io::Result<()> {
        self.original.verify()?;
        // SAFETY: reasserting LOCK_EX on the same open file description preserves
        // its existing lock; no pathname or new file description is used.
        if unsafe {
            libc::flock(
                self.original.original.file.as_raw_fd(),
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
        // The single actual descriptor close ends flock. An explicit unlock
        // would introduce an unowned interval before the original is closed.
        self.original.close_retaining()
    }
}
