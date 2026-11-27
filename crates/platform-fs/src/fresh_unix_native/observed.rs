//! Bounded read-only observations acquired relative to retained originals.
//! A previously existing file is never represented as an O_EXCL creator.
use super::super::{
    component, mount_identity, observe_fd, observe_slot, open_child, refuse, verify_file,
    AnchoredParent, ClosedUnixOriginalResources, FileObservation, UnixOriginalCloseAttempt,
    UnixOriginalResourceCloseFailure,
};
use super::{namespace::NamespaceLoan, AcquiredUnixChildDirectory, OriginalUnixNativeRoot};
use crate::PortableMetadataCapture;
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{fd::AsRawFd, unix::fs::FileExt},
    sync::Arc,
};

pub struct ObservedUnixNativeFile<'namespace> {
    namespace: NamespaceLoan<'namespace>,
    parent: Option<Arc<AnchoredParent>>,
    component: CString,
    original: Option<File>,
    captured: FileObservation,
    metadata: PortableMetadataCapture,
    maximum: usize,
    private: bool,
}

fn acquire<'n>(
    namespace: &NamespaceLoan<'n>,
    parent: &Arc<AnchoredParent>,
    name: &str,
    maximum: usize,
    private: bool,
) -> io::Result<ObservedUnixNativeFile<'n>> {
    namespace.verify_current()?;
    parent.verify()?;
    let name = component(OsStr::new(name))?;
    let original = open_child(parent.fd()?, &name, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let checked = (|| {
        let captured = observe_fd(original.as_raw_fd())?;
        verify_file(captured, private, maximum)?;
        if observe_slot(parent.fd()?, &name)? != captured
            || mount_identity::mount_id(original.as_raw_fd())?
                != mount_identity::slot_mount_id(parent.fd()?, &name)?
        {
            return Err(refuse(
                "original Unix observed file changed during acquisition",
            ));
        }
        let metadata = crate::capture_portable_file_metadata(&original)?;
        if observe_fd(original.as_raw_fd())? != captured {
            return Err(refuse(
                "original Unix observed metadata changed during acquisition",
            ));
        }
        namespace.verify_current()?;
        parent.verify()?;
        Ok((captured, metadata))
    })();
    let (captured, metadata) = match checked {
        Ok(values) => values,
        Err(error) => {
            let mut close = UnixOriginalCloseAttempt::new();
            close.note_error(error);
            close.close_file(original);
            return Err(close
                .finish()
                .err()
                .expect("original observation first error")
                .retain_and_report());
        }
    };
    Ok(ObservedUnixNativeFile {
        namespace: namespace.clone(),
        parent: Some(Arc::clone(parent)),
        component: name,
        original: Some(original),
        captured,
        metadata,
        maximum,
        private,
    })
}

impl<'n> OriginalUnixNativeRoot<'n> {
    pub fn observe_file(
        &self,
        name: &str,
        maximum: usize,
        private: bool,
    ) -> io::Result<ObservedUnixNativeFile<'n>> {
        self.verify()?;
        acquire(
            &self.namespace,
            &self.original.original,
            name,
            maximum,
            private,
        )
    }
}
impl<'n> AcquiredUnixChildDirectory<'n> {
    pub fn observe_file(
        &self,
        name: &str,
        maximum: usize,
        private: bool,
    ) -> io::Result<ObservedUnixNativeFile<'n>> {
        self.verify()?;
        acquire(
            &self.namespace,
            &self.original.original,
            name,
            maximum,
            private,
        )
    }
}
impl ObservedUnixNativeFile<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.namespace.verify_current()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| refuse("original Unix observation parent closed"))?;
        parent.verify()?;
        let original = self
            .original
            .as_ref()
            .ok_or_else(|| refuse("original Unix observation closed"))?;
        let actual = observe_fd(original.as_raw_fd())?;
        verify_file(actual, self.private, self.maximum)?;
        if actual != self.captured
            || observe_slot(parent.fd()?, &self.component)? != actual
            || mount_identity::mount_id(original.as_raw_fd())?
                != mount_identity::slot_mount_id(parent.fd()?, &self.component)?
            || crate::capture_portable_file_metadata(original)? != self.metadata
        {
            return Err(refuse(
                "actual Unix observed file content/metadata capture changed",
            ));
        }
        Ok(())
    }
    pub fn read_bounded(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        let length = usize::try_from(self.captured.bytes)
            .map_err(|_| refuse("observed Unix file length"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| refuse("observed Unix file allocation"))?;
        bytes.resize(length, 0);
        self.original
            .as_ref()
            .expect("verified actual observation")
            .read_exact_at(&mut bytes, 0)?;
        self.verify()?;
        Ok(bytes)
    }
    pub fn metadata(&self) -> io::Result<PortableMetadataCapture> {
        self.verify()?;
        Ok(self.metadata)
    }
    pub fn key(&self) -> io::Result<super::super::UnixProtectedArtifactKey> {
        self.verify()?;
        Ok(self.captured.key)
    }
    pub fn parent_key(&self) -> io::Result<super::super::UnixProtectedArtifactKey> {
        self.verify()?;
        self.parent
            .as_ref()
            .expect("verified original observation parent")
            .key()
    }
    pub fn bytes(&self) -> io::Result<u64> {
        self.verify()?;
        Ok(self.captured.bytes)
    }
    pub fn close_retaining(
        mut self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify() {
            close.note_error(error);
        }
        if let Some(original) = self.original.take() {
            close.close_file(original);
        }
        if let Some(parent) = self.parent.take() {
            if let Ok(parent) = Arc::try_unwrap(parent) {
                parent.close_into_attempt(&mut close);
            }
        }
        close.finish()
    }
}

impl Drop for ObservedUnixNativeFile<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            // Cancellation preserves the complete actual prefix; it never
            // turns an implicit close into a positive terminal witness.
            let _ = Box::leak(Box::new((
                original,
                self.parent.take(),
                self.namespace.clone(),
            )));
        }
    }
}
