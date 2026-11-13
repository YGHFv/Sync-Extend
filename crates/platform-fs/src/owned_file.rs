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
    parent: File,
    original_key: FileKey,
    original_parent_key: FileKey,
    created_component: String,
}

/// Borrowed provenance from an actual exclusive native CREATE, not a reopened
/// pathname, immutable-content receipt, current-slot witness or Journal grant.
/// No public constructor, cloning or deserialization can mint this proof.
pub struct OriginalFileCreation<'a> {
    creator: &'a OwnedFileCreation,
}

impl OriginalFileCreation<'_> {
    pub fn key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.creator.original_key)
    }

    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.creator.original_parent_key)
    }

    /// Historical name used by CREATE; a later rename does not make this a
    /// claim that the original pathname still identifies the created file.
    pub fn created_component(&self) -> &str {
        &self.creator.created_component
    }

    pub fn verify(&self) -> io::Result<()> {
        regular(&self.creator.file, false)?;
        regular(&self.creator.parent, true)?;
        if key(&self.creator.file)? != self.creator.original_key
            || key(&self.creator.parent)? != self.creator.original_parent_key
        {
            return Err(super::invalid("original creator lineage changed"));
        }
        Ok(())
    }
}

fn create(parent: &File, name: &str) -> io::Result<OwnedFileCreation> {
    let original_parent_key = key(parent)?;
    let file = create_new_child(parent, name, NewChildKind::File)?;
    let original_key = key(&file)?;
    let created = OwnedFileCreation {
        file,
        parent: parent.try_clone()?,
        original_key,
        original_parent_key,
        created_component: name.into(),
    };
    created.original_creation()?.verify()?;
    Ok(created)
}

impl LockedDirectory {
    /// Create one new file through this exact retained real NTFS parent.
    pub fn create_new_file(&self, name: &str) -> io::Result<OwnedFileCreation> {
        create(&self.file, name)
    }

    /// Kernel lifetime begins at exclusive CREATE, before any application code.
    pub fn create_request_file(&self, name: &str) -> io::Result<OwnedFileCreation> {
        let original_parent_key = key(&self.file)?;
        let file = super::directory_create::create_request_file(&self.file, name)?;
        let original_key = key(&file)?;
        let created = OwnedFileCreation {
            file,
            parent: self.file.try_clone()?,
            original_key,
            original_parent_key,
            created_component: name.into(),
        };
        created.original_creation()?.verify()?;
        Ok(created)
    }
}

impl LockedDirectoryMutation {
    /// Create one new file through the original live owned parent handle.
    pub fn create_new_file(&self, name: &str) -> io::Result<OwnedFileCreation> {
        create(&self.file, name)
    }
}

impl OwnedFileCreation {
    /// Retains both original handles for the entire lifetime of the proof.
    /// The creator remains writable; callers must separately close content and
    /// durably bind the proof to their exact transaction before native effects.
    pub fn original_creation(&self) -> io::Result<OriginalFileCreation<'_>> {
        let proof = OriginalFileCreation { creator: self };
        proof.verify()?;
        Ok(proof)
    }

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
