use super::{
    directory_create::{create_new_child, NewChildKind},
    key, regular, rename_no_replace, request_delete_on_close, LockedDirectory,
    LockedDirectoryMutation,
};
use crate::FileKey;
use std::{fs::File, io, path::Path};

/// Original newly created READ|WRITE|DELETE file handle with no shared opens.
/// Native success is not durable restart-safe ownership; callers journal intent
/// before creation and the full identity before publication. Errors preserve
/// possible orphans, never clean up or adopt another pathname occupant.
/// Sharing does not prevent hard-link creation; independently recheck link count
/// before and after action boundaries. No external alias-free proof is implied.
pub struct OwnedFileCreation {
    file: File,
}

impl LockedDirectory {
    /// Create one new file through this exact retained real NTFS parent.
    pub fn create_new_file(&self, name: &str) -> io::Result<OwnedFileCreation> {
        Ok(OwnedFileCreation {
            file: create_new_child(&self.file, name, NewChildKind::File)?,
        })
    }
}

impl LockedDirectoryMutation {
    /// Create one new file through the original live owned parent handle.
    pub fn create_new_file(&self, name: &str) -> io::Result<OwnedFileCreation> {
        Ok(OwnedFileCreation {
            file: create_new_child(&self.file, name, NewChildKind::File)?,
        })
    }
}

impl OwnedFileCreation {
    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    /// Materialize only this exact created file, without releasing its handle.
    /// This is a writable owner, not an immutable read guard.
    pub fn writer(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn reader(&self) -> &File {
        &self.file
    }

    pub fn verify_single_link(&self) -> io::Result<()> {
        regular(&self.file, false)
    }

    /// Caller retains destination ancestors and owns durable publication intent.
    pub fn rename_no_replace(&self, destination: &Path) -> io::Result<()> {
        self.verify_single_link()?;
        rename_no_replace(&self.file, destination)
    }

    /// Mark only this exact created file; compatible cloned handles may defer
    /// actual absence. This does not certify a durable disposition terminal.
    pub fn delete_on_close(&self) -> io::Result<()> {
        self.verify_single_link()?;
        request_delete_on_close(&self.file)
    }
}
