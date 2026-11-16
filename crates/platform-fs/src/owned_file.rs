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

/// No writer method; only a reduced-right duplicate of the actual original CREATE.
/// Consuming the writable creator cannot close external cloned aliases; callers
/// must not clone writer(). This type alone is not a durable Journal receipt.
pub struct SealedOriginalFile {
    file: File,
    parent: File,
    original_key: FileKey,
    original_parent_key: FileKey,
    created_component: String,
}

impl OwnedFileCreation {
    /// Keep the same original file object continuously held while closing our
    /// writable handle. No path lookup or reopen is used to obtain read rights.
    pub fn seal_original(self) -> io::Result<SealedOriginalFile> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{DuplicateHandle, GENERIC_READ, HANDLE},
            System::Threading::GetCurrentProcess,
        };
        self.verify_single_link()?;
        self.file.sync_all()?;
        let mut duplicate: HANDLE = std::ptr::null_mut();
        // SAFETY: the pseudo-process handle is valid in this process; source
        // owns a live File; duplicate is writable HANDLE output. Desired access
        // is READ|DELETE only, inherit=false, options=0 cannot preserve WRITE.
        let success = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                self.file.as_raw_handle() as HANDLE,
                process,
                &mut duplicate,
                GENERIC_READ | windows_sys::Win32::Storage::FileSystem::DELETE,
                0,
                0,
            )
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        if duplicate.is_null() {
            return Err(super::invalid("no sealed original handle"));
        }
        // SAFETY: successful DuplicateHandle transferred one new owned handle.
        let file = unsafe { File::from_raw_handle(duplicate) };
        let Self {
            file: writable,
            parent,
            original_key,
            original_parent_key,
            created_component,
        } = self;
        let sealed = SealedOriginalFile {
            file,
            parent,
            original_key,
            original_parent_key,
            created_component,
        };
        sealed.verify_original()?;
        drop(writable);
        sealed.verify_original()?;
        Ok(sealed)
    }
}

impl SealedOriginalFile {
    pub fn reader(&self) -> &File {
        &self.file
    }
    pub fn key(&self) -> io::Result<FileKey> {
        self.verify_original()?;
        Ok(self.original_key)
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify_original()?;
        Ok(self.original_parent_key)
    }
    pub fn created_component(&self) -> &str {
        &self.created_component
    }
    pub fn verify_original(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        regular(&self.parent, true)?;
        if key(&self.file)? != self.original_key || key(&self.parent)? != self.original_parent_key {
            return Err(super::invalid("sealed original CREATE lineage changed"));
        }
        Ok(())
    }
    pub fn rename_no_replace(&self, destination: &Path) -> io::Result<()> {
        self.verify_original()?;
        rename_no_replace(&self.file, destination)
    }
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        super::regular_file_matches_path(&self.file, path)
    }
    pub fn delete_on_close(&self) -> io::Result<()> {
        self.verify_original()?;
        request_delete_on_close(&self.file)
    }
}

/// The same original sealed CREATE file, after releasing its historical owner parent.
/// This retains read/delete exclusion and never reopens a pathname or regains write.
pub struct PublishedOriginalFile {
    file: File,
    original_key: FileKey,
    original_parent_key: FileKey,
    created_component: String,
}
impl SealedOriginalFile {
    pub fn release_creation_parent(self) -> io::Result<PublishedOriginalFile> {
        self.verify_original()?;
        let Self {
            file,
            parent,
            original_key,
            original_parent_key,
            created_component,
        } = self;
        let result = PublishedOriginalFile {
            file,
            original_key,
            original_parent_key,
            created_component,
        };
        drop(parent);
        result.verify_original()?;
        Ok(result)
    }
}
impl PublishedOriginalFile {
    pub fn reader(&self) -> &File {
        &self.file
    }
    pub fn key(&self) -> io::Result<FileKey> {
        self.verify_original()?;
        Ok(self.original_key)
    }
    pub fn original_parent_key(&self) -> FileKey {
        self.original_parent_key
    }
    pub fn created_component(&self) -> &str {
        &self.created_component
    }
    pub fn verify_original(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        if key(&self.file)? != self.original_key {
            return Err(super::invalid("original published CREATE file key changed"));
        }
        Ok(())
    }
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        super::regular_file_matches_path(&self.file, path)
    }
}
