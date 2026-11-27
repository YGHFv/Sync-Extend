//! Ordered content and projected metadata on the same actual original creator.
use super::super::{
    observe_fd, refuse, ClosedUnixOriginalResources, FileObservation, UnixOriginalCloseAttempt,
    UnixOriginalResourceCloseFailure, UnixProtectedArtifactKey,
};
use super::FreshUnixNativeFile;
use crate::{CapturedFileMetadata, PortableMetadataCapture};
use std::{io, os::fd::AsRawFd};

pub struct SealedUnixNativeFile<'namespace> {
    pub(super) original: FreshUnixNativeFile<'namespace>,
    captured: FileObservation,
    metadata: PortableMetadataCapture,
}

pub struct UnixNativeFileSealFailure<'namespace> {
    pub error: io::Error,
    pub original: Option<FreshUnixNativeFile<'namespace>>,
}

impl std::fmt::Debug for UnixNativeFileSealFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("UnixNativeFileSealFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .finish()
    }
}

impl Drop for UnixNativeFileSealFailure<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
    }
}

impl<'namespace> FreshUnixNativeFile<'namespace> {
    /// Preflight all ordered input lengths before the first write; zero-length
    /// files are valid. Any failed prefix remains attempted on this creator.
    pub fn write_ordered_and_sync(&mut self, chunks: &[&[u8]]) -> io::Result<()> {
        self.verify()?;
        let mut total = 0u64;
        for chunk in chunks {
            total = total
                .checked_add(chunk.len() as u64)
                .filter(|total| *total <= self.maximum)
                .ok_or_else(|| refuse("bounded ordered original Unix file bytes"))?;
        }
        if self.original.write_attempted || self.original.file.metadata()?.len() != 0 {
            return Err(refuse("fresh empty unattempted Unix creator required"));
        }
        self.original.write_attempted = true;
        let mut offset = 0;
        for chunk in chunks {
            crate::unix_descriptor_io::write_all(&self.original.file, chunk, offset)?;
            offset += chunk.len() as u64;
        }
        self.original.file.sync_all()?;
        self.original
            .parent
            .directories
            .last()
            .expect("actual original parent")
            .file
            .sync_all()?;
        self.verify_ordered_bytes(chunks)
    }

    pub fn verify_ordered_bytes(&self, chunks: &[&[u8]]) -> io::Result<()> {
        self.verify()?;
        let before = observe_fd(self.original.file.as_raw_fd())?;
        let mut offset = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        for chunk in chunks {
            for part in chunk.chunks(buffer.len()) {
                if offset
                    .checked_add(part.len() as u64)
                    .is_none_or(|end| end > self.maximum)
                {
                    return Err(refuse("bounded original content verification"));
                }
                let read = crate::unix_descriptor_io::read_until_eof(
                    &self.original.file,
                    &mut buffer[..part.len()],
                    offset,
                )?;
                if read != part.len() || buffer[..read] != *part {
                    return Err(refuse("actual original Unix ordered contents differ"));
                }
                offset += read as u64;
            }
        }
        if before.bytes != offset || observe_fd(self.original.file.as_raw_fd())? != before {
            return Err(refuse(
                "actual original Unix content length/capture changed",
            ));
        }
        self.verify()
    }

    pub fn seal_projected_metadata(
        self,
        chunks: &[&[u8]],
        metadata: Option<&CapturedFileMetadata>,
    ) -> Result<SealedUnixNativeFile<'namespace>, UnixNativeFileSealFailure<'namespace>> {
        let checked = (|| -> io::Result<_> {
            if !self.original.write_attempted {
                return Err(refuse("original Unix content write was not attempted"));
            }
            self.verify_ordered_bytes(chunks)?;
            if let Some(metadata) = metadata {
                crate::apply_portable_file_metadata(&self.original.file, metadata)?;
                self.original.file.sync_all()?;
            }
            let captured = observe_fd(self.original.file.as_raw_fd())?;
            let metadata = crate::capture_portable_file_metadata(&self.original.file)?;
            self.verify_ordered_bytes(chunks)?;
            if observe_fd(self.original.file.as_raw_fd())? != captured {
                return Err(refuse("original Unix metadata changed while sealing"));
            }
            Ok((captured, metadata))
        })();
        match checked {
            Ok((captured, metadata)) => Ok(SealedUnixNativeFile {
                original: self,
                captured,
                metadata,
            }),
            Err(error) => Err(UnixNativeFileSealFailure {
                error,
                original: Some(self),
            }),
        }
    }
}

impl SealedUnixNativeFile<'_> {
    /// Explicitly end a superseded worktree observation for polling. This is
    /// only an actual descriptor terminal, not proof that content is unchanged.
    pub fn end_observation(
        self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = self.original.namespace.verify_current() {
            close.note_error(error);
        }
        close.close_file(self.original.original.file);
        if let Ok(parent) = std::sync::Arc::try_unwrap(self.original.original.parent) {
            parent.close_into_attempt(&mut close);
        }
        close.finish()
    }
    pub fn verify(&self) -> io::Result<()> {
        self.original.verify()?;
        if observe_fd(self.original.original.file.as_raw_fd())? != self.captured
            || crate::capture_portable_file_metadata(&self.original.original.file)? != self.metadata
        {
            return Err(refuse("sealed original Unix file complete capture differs"));
        }
        Ok(())
    }
    pub fn verify_ordered_bytes(&self, chunks: &[&[u8]]) -> io::Result<()> {
        self.verify()?;
        self.original.verify_ordered_bytes(chunks)?;
        self.verify()
    }
    pub fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.verify()?;
        Ok(self.captured.key)
    }
    pub fn parent_key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.verify()?;
        self.original.original.parent_key()
    }
    pub fn metadata(&self) -> io::Result<PortableMetadataCapture> {
        self.verify()?;
        Ok(self.metadata)
    }
    pub fn bytes(&self) -> io::Result<u64> {
        self.verify()?;
        Ok(self.captured.bytes)
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
