//! Bounded append-only close evidence on one retained actual creator.
use super::super::{refuse, ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure};
use super::{FreshUnixNativeFile, SealedUnixNativeFile, UnixNativeFileSealFailure};
use std::io;

const MAX_FRAME_BYTES: usize = 1024 * 1024;

pub struct OriginalUnixCloseFrames<'namespace> {
    original: Option<FreshUnixNativeFile<'namespace>>,
    intended: Vec<u8>,
    terminal: Vec<u8>,
    attempted: bool,
    completed: bool,
    maximum_terminal: usize,
}

pub struct OriginalUnixCloseFramesFailure<'namespace> {
    pub error: io::Error,
    pub original: Option<FreshUnixNativeFile<'namespace>>,
}
impl std::fmt::Debug for OriginalUnixCloseFramesFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalUnixCloseFramesFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .finish()
    }
}
impl Drop for OriginalUnixCloseFramesFailure<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
    }
}

impl<'n> OriginalUnixCloseFrames<'n> {
    /// The complete maximum terminal size is reserved before the intent write.
    /// Bytes are descriptive; this object grants no runtime/Journal authority.
    pub fn begin(
        mut original: FreshUnixNativeFile<'n>,
        intended: &[u8],
        maximum_terminal: usize,
    ) -> Result<Self, OriginalUnixCloseFramesFailure<'n>> {
        let total = intended.len().checked_add(maximum_terminal);
        if intended.is_empty()
            || maximum_terminal == 0
            || total.is_none_or(|total| total > MAX_FRAME_BYTES || total as u64 > original.maximum)
        {
            return Err(OriginalUnixCloseFramesFailure {
                error: refuse("complete Unix close frame budget before intent"),
                original: Some(original),
            });
        }
        let mut intended_bytes = Vec::new();
        let mut terminal = Vec::new();
        if intended_bytes.try_reserve_exact(intended.len()).is_err()
            || terminal.try_reserve_exact(maximum_terminal).is_err()
        {
            return Err(OriginalUnixCloseFramesFailure {
                error: refuse("Unix close frame preeffect allocation"),
                original: Some(original),
            });
        }
        intended_bytes.extend_from_slice(intended);
        if let Err(error) = original.write_ordered_and_sync(&[intended]) {
            return Err(OriginalUnixCloseFramesFailure {
                error,
                original: Some(original),
            });
        }
        Ok(Self {
            original: Some(original),
            intended: intended_bytes,
            terminal,
            attempted: false,
            completed: false,
            maximum_terminal,
        })
    }

    pub fn verify(&self) -> io::Result<()> {
        if self.attempted && !self.completed {
            return Err(refuse(
                "original Unix close frame has an incomplete terminal attempt",
            ));
        }
        self.original
            .as_ref()
            .ok_or_else(|| refuse("original Unix close frames ended"))?
            .verify_ordered_bytes(&[&self.intended, &self.terminal])
    }

    /// This append is permitted once, after the caller's typed runtime terminal.
    /// The writer itself never claims that runtime resources have closed.
    pub fn append_terminal_and_sync(&mut self, terminal: &[u8]) -> io::Result<()> {
        self.verify()?;
        if self.attempted || terminal.is_empty() || terminal.len() > self.maximum_terminal {
            return Err(refuse("one prebudgeted original Unix terminal append"));
        }
        self.attempted = true;
        self.terminal.extend_from_slice(terminal);
        let original = self
            .original
            .as_ref()
            .expect("verified original frame creator");
        crate::unix_descriptor_io::write_all(
            &original.original.file,
            &self.terminal,
            self.intended.len() as u64,
        )?;
        original.original.file.sync_all()?;
        original
            .original
            .parent
            .directories
            .last()
            .expect("original frame parent")
            .file
            .sync_all()?;
        original.verify_ordered_bytes(&[&self.intended, &self.terminal])?;
        self.completed = true;
        self.verify()
    }

    pub fn seal(mut self) -> Result<SealedUnixNativeFile<'n>, UnixNativeFileSealFailure<'n>> {
        let original = self.original.take().expect("same original frame creator");
        if !self.completed || self.terminal.is_empty() {
            return Err(UnixNativeFileSealFailure {
                error: refuse("Unix terminal was not appended"),
                original: Some(original),
            });
        }
        original.seal_projected_metadata(&[&self.intended, &self.terminal], None)
    }

    pub fn close_retaining(
        mut self,
    ) -> Result<ClosedUnixOriginalResources, UnixOriginalResourceCloseFailure> {
        let mut close = super::super::UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify() {
            close.note_error(error);
        }
        close.append_result(
            self.original
                .take()
                .expect("same original close frame creator")
                .close_retaining(),
        );
        close.finish()
    }
}
impl Drop for OriginalUnixCloseFrames<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
    }
}
