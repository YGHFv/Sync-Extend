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
    current_parent: Option<File>,
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
            current_parent: None,
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
        if let Some(parent) = &self.current_parent {
            regular(parent, true)?;
            key(parent)
        } else {
            Ok(self.original_parent_key)
        }
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
            current_parent,
        } = self;
        if current_parent.is_some() {
            return Err(super::invalid(
                "moved namespace file cannot release original creation lineage",
            ));
        }
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

#[path = "owned_file/created_identity.rs"]
mod created_identity;
pub use created_identity::{
    ReleasedOriginalCoordinationFile, ReleasedOriginalFileIdentity, ReleasedOriginalReadFile,
};

impl OriginalFileCreation<'_> {
    /// Observe the original empty writer sentinel through a reduced-right
    /// duplicate. The CREATE remains held by its original restore coordinator.
    pub(crate) fn retain_writer_sentinel(&self) -> io::Result<File> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{DuplicateHandle, GENERIC_READ, HANDLE},
            System::Threading::GetCurrentProcess,
        };
        self.verify()?;
        self.creator.verify_single_link()?;
        if self.created_component() != "writer.lock" || self.creator.file.metadata()?.len() != 0 {
            return Err(super::invalid("original empty writer sentinel required"));
        }
        let mut handle: HANDLE = std::ptr::null_mut();
        // SAFETY: the CREATE is live; this produces one READ-only duplicate
        // without inheritance, writable rights or pathname resolution.
        let success = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                self.creator.file.as_raw_handle() as HANDLE,
                process,
                &mut handle,
                GENERIC_READ,
                0,
                0,
            )
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful duplication transferred exactly one owned handle.
        let file = unsafe { File::from_raw_handle(handle) };
        regular(&file, false)?;
        if key(&file)? != self.key()? || file.metadata()?.len() != 0 {
            return Err(super::invalid("original writer sentinel duplicate differs"));
        }
        Ok(file)
    }
}

#[path = "owned_file/sqlite_capabilities.rs"]
mod sqlite_capabilities;
pub use sqlite_capabilities::{
    OriginalSqliteMainHandoff, OriginalSqliteMainHandoffFailure, OriginalSqliteSidecarHandoff,
    OriginalSqliteSidecarHandoffFailure, OriginalSqliteSidecarKind,
};

impl LockedDirectory {
    /// Original exclusive CREATE receives a current-process-user protected DACL
    /// in its OBJECT_ATTRIBUTES. No plaintext precedes actual handle ACL audit.
    pub fn create_new_current_user_file(&self, name: &str) -> io::Result<OwnedFileCreation> {
        let original_parent_key = key(&self.file)?;
        let file = super::directory_create::create_new_current_user_file(&self.file, name)?;
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

// Rename only the original sealed file into the exact retained native parent.
impl SealedOriginalFile {
    pub fn rename_no_replace_in(
        &self,
        parent: &LockedDirectoryMutation,
        name: &str,
    ) -> io::Result<()> {
        use std::mem::{offset_of, size_of};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{RtlNtStatusToDosError, HANDLE, STATUS_SUCCESS},
            Storage::FileSystem::FILE_RENAME_INFO,
            System::IO::IO_STATUS_BLOCK,
        };
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtSetInformationFile(
                handle: HANDLE,
                status: *mut IO_STATUS_BLOCK,
                information: *const std::ffi::c_void,
                length: u32,
                class: u32,
            ) -> i32;
        }
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
        {
            return Err(super::invalid(
                "relative rename single safe component required",
            ));
        }
        self.verify_original()?;
        parent.original_creation()?.verify()?;
        if self.key()?.volume != parent.key()?.volume {
            return Err(super::invalid("relative rename same volume required"));
        }
        let encoded: Vec<u16> = name.encode_utf16().collect();
        let bytes = encoded
            .len()
            .checked_mul(2)
            .ok_or_else(|| super::invalid("relative rename name overflow"))?;
        let length = offset_of!(FILE_RENAME_INFO, FileName)
            .checked_add(bytes)
            .ok_or_else(|| super::invalid("relative rename structure overflow"))?
            .max(size_of::<FILE_RENAME_INFO>());
        let size = u32::try_from(length)
            .map_err(|_| super::invalid("relative rename structure too large"))?;
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        let header = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        let mut status = IO_STATUS_BLOCK::default();
        // SAFETY: both native handles stay owned; aligned storage has a sized
        // zeroed ABI header and counted single-component UTF16 tail. RootDirectory
        // is the exact retained destination, ReplaceIfExists remains false.
        let result = unsafe {
            std::ptr::write(header, FILE_RENAME_INFO::default());
            (*header).RootDirectory = parent.file.as_raw_handle() as HANDLE;
            (*header).FileNameLength = bytes as u32;
            std::ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                std::ptr::addr_of_mut!((*header).FileName).cast(),
                encoded.len(),
            );
            NtSetInformationFile(
                self.file.as_raw_handle() as HANDLE,
                &mut status,
                header.cast(),
                size,
                10,
            )
        };
        if result != STATUS_SUCCESS {
            // SAFETY: conversion accepts the returned NTSTATUS without pointers.
            let error = unsafe { RtlNtStatusToDosError(result) };
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        self.verify_original()?;
        parent.original_creation()?.verify()?;
        Ok(())
    }
}

// Fresh explicitly acquired objects; no CREATE provenance or old authority is claimed.
pub struct ReacquiredNodeFile {
    file: File,
    parent: File,
    key: FileKey,
    parent_key: FileKey,
}
impl LockedDirectory {
    /// Acquire one existing file through this retained native directory. Only
    /// new READ protection is granted; no historical CREATE/write/delete right.
    pub fn reacquire_existing_node_read_file(&self, name: &str) -> io::Result<ReacquiredNodeFile> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::{
            Wdk::{
                Foundation::OBJECT_ATTRIBUTES,
                Storage::FileSystem::{
                    NtCreateFile, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
                    FILE_SYNCHRONOUS_IO_NONALERT,
                },
            },
            Win32::{
                Foundation::{
                    RtlNtStatusToDosError, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
                    OBJ_CASE_INSENSITIVE, STATUS_SUCCESS, UNICODE_STRING,
                },
                Storage::FileSystem::{FILE_SHARE_READ, SYNCHRONIZE},
                System::{WindowsProgramming::FILE_OPENED, IO::IO_STATUS_BLOCK},
            },
        };
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
        {
            return Err(super::invalid(
                "recovery single safe file component required",
            ));
        }
        regular(&self.file, true)?;
        let parent_key = key(&self.file)?;
        let mut encoded: Vec<u16> = name.encode_utf16().collect();
        let bytes = u16::try_from(encoded.len() * 2)
            .map_err(|_| super::invalid("recovery file name too long"))?;
        let unicode = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: encoded.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.file.as_raw_handle() as HANDLE,
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle = std::ptr::null_mut();
        // SAFETY: exact retained parent and counted single-component name remain
        // live; output pointers are sized. FILE_OPEN forbids CREATE or truncation,
        // READ-only access and no WRITE/DELETE sharing acquire fresh exclusion.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                GENERIC_READ | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                0,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            // SAFETY: NTSTATUS conversion is pointer-free.
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            ));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(super::invalid("recovery existing file handle absent"));
        }
        // SAFETY: successful NtCreateFile transferred one new owned handle.
        let file = unsafe { File::from_raw_handle(handle) };
        if status_block.Information != FILE_OPENED as usize {
            return Err(super::invalid(
                "recovery file must be existing opened object",
            ));
        }
        regular(&file, false)?;
        let file_key = key(&file)?;
        let value = ReacquiredNodeFile {
            file,
            parent: self.file.try_clone()?,
            key: file_key,
            parent_key,
        };
        value.verify()?;
        Ok(value)
    }
}
impl ReacquiredNodeFile {
    pub fn key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.key)
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.parent_key)
    }
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        self.verify()?;
        super::regular_file_matches_path(&self.file, path)
    }
    pub fn exact_bytes(&self, maximum: u64) -> io::Result<Vec<u8>> {
        use std::os::windows::fs::FileExt;
        self.verify()?;
        let bytes = self.file.metadata()?.len();
        if maximum > 256 * 1024 * 1024 || bytes > maximum {
            return Err(super::invalid("recovery file bytes exceed explicit bound"));
        }
        let length = usize::try_from(bytes)
            .map_err(|_| super::invalid("recovery file byte conversion overflow"))?;
        let mut result = vec![0; length];
        let mut offset = 0;
        while offset < result.len() {
            let count = self.file.seek_read(&mut result[offset..], offset as u64)?;
            if count == 0 {
                return Err(super::invalid("recovery existing file short read"));
            }
            offset += count;
        }
        self.verify()?;
        if self.file.metadata()?.len() != bytes {
            return Err(super::invalid("recovery existing file changed length"));
        }
        Ok(result)
    }
    pub fn verify(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        regular(&self.parent, true)?;
        if key(&self.file)? != self.key
            || key(&self.parent)? != self.parent_key
            || self.key.volume != self.parent_key.volume
        {
            return Err(super::invalid(
                "recovery newly acquired file identity changed",
            ));
        }
        Ok(())
    }
}

// Each fresh FILE_OPEN has its own description; its lock shares that read description.
pub struct ReacquiredNodeLock {
    file: File,
    parent: File,
    key: FileKey,
    parent_key: FileKey,
}
impl ReacquiredNodeFile {
    /// Lock this session's newly opened description, so its own exact-byte
    /// audit remains possible under Windows mandatory byte locks. Competing
    /// sessions and probes use their independent native FILE_OPEN descriptions.
    pub fn acquire_fresh_coordination_lock(&self, shared: bool) -> io::Result<ReacquiredNodeLock> {
        self.verify()?;
        let file = self.file.try_clone()?;
        if shared {
            file.try_lock_shared()
        } else {
            file.try_lock()
        }
        .map_err(|_| super::invalid("fresh coordination lock busy"))?;
        let result = ReacquiredNodeLock {
            file,
            parent: self.parent.try_clone()?,
            key: self.key,
            parent_key: self.parent_key,
        };
        result.verify()?;
        Ok(result)
    }
}
impl ReacquiredNodeLock {
    pub fn verify(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        regular(&self.parent, true)?;
        if key(&self.file)? != self.key || key(&self.parent)? != self.parent_key {
            return Err(super::invalid(
                "fresh coordination retained identity differs",
            ));
        }
        Ok(())
    }
}

// Fresh writable acquisition is explicit and separate from the old CREATE issuer.
pub struct FreshExclusiveSqliteFile {
    pub(in super::super) acquired: ReacquiredNodeFile,
}
impl FreshExclusiveSqliteFile {
    pub fn verify(&self) -> io::Result<()> {
        self.acquired.verify()
    }
    pub fn key(&self) -> io::Result<FileKey> {
        self.acquired.key()
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.acquired.parent_key()
    }
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        self.acquired.matches_path(path)
    }
    pub fn exact_bytes(&self, maximum: u64) -> io::Result<Vec<u8>> {
        self.acquired.exact_bytes(maximum)
    }
    pub(in super::super) fn native_file(&self) -> &File {
        &self.acquired.file
    }
}
impl LockedDirectory {
    /// Acquire current SQLite bytes through the retained parent with exclusive
    /// native sharing. No old CREATE or historical cleanup rights are claimed.
    pub fn reacquire_existing_sqlite_exclusive_file(
        &self,
        name: &str,
    ) -> io::Result<FreshExclusiveSqliteFile> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::{
            Wdk::{
                Foundation::OBJECT_ATTRIBUTES,
                Storage::FileSystem::{
                    NtCreateFile, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
                    FILE_SYNCHRONOUS_IO_NONALERT,
                },
            },
            Win32::{
                Foundation::{
                    RtlNtStatusToDosError, GENERIC_READ, GENERIC_WRITE, HANDLE,
                    INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, STATUS_SUCCESS, UNICODE_STRING,
                },
                Storage::FileSystem::SYNCHRONIZE,
                System::{WindowsProgramming::FILE_OPENED, IO::IO_STATUS_BLOCK},
            },
        };
        if !matches!(
            name,
            "journal.sqlite"
                | "journal.sqlite-wal"
                | "journal.sqlite-journal"
                | "journal.sqlite-shm"
        ) {
            return Err(super::invalid(
                "fresh SQLite acquisition exact component required",
            ));
        }
        regular(&self.file, true)?;
        let parent_key = key(&self.file)?;
        let mut encoded: Vec<u16> = name.encode_utf16().collect();
        let bytes = u16::try_from(encoded.len() * 2)
            .map_err(|_| super::invalid("fresh SQLite name bound"))?;
        let unicode = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: encoded.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.file.as_raw_handle() as HANDLE,
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut block = IO_STATUS_BLOCK::default();
        let mut handle = std::ptr::null_mut();
        // SAFETY: retained directory and counted component remain live; outputs
        // are sized. FILE_OPEN excludes CREATE/truncate and share0 excludes every
        // independently opened reader/writer/deleter before any byte is admitted.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                &attributes,
                &mut block,
                std::ptr::null(),
                0,
                0,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            // SAFETY: pointer-free conversion of returned NTSTATUS.
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            ));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(super::invalid("fresh SQLite handle absent"));
        }
        // SAFETY: successful NtCreateFile transferred exactly one new handle.
        let file = unsafe { File::from_raw_handle(handle) };
        if block.Information != FILE_OPENED as usize {
            return Err(super::invalid("fresh SQLite must open an existing file"));
        }
        regular(&file, false)?;
        let result = ReacquiredNodeFile {
            key: key(&file)?,
            file,
            parent: self.file.try_clone()?,
            parent_key,
        };
        result.verify()?;
        Ok(FreshExclusiveSqliteFile { acquired: result })
    }
}

impl OwnedFileCreation {
    /// Transfer the actual new exclusive SHM CREATE; retain its parent and key.
    pub fn into_fresh_sqlite_shm(self) -> io::Result<FreshExclusiveSqliteFile> {
        self.original_creation()?.verify()?;
        if self.created_component != "journal.sqlite-shm" || self.file.metadata()?.len() != 0 {
            return Err(super::invalid(
                "fresh SHM exact empty actual CREATE required",
            ));
        }
        let result = FreshExclusiveSqliteFile {
            acquired: ReacquiredNodeFile {
                file: self.file,
                parent: self.parent,
                key: self.original_key,
                parent_key: self.original_parent_key,
            },
        };
        result.verify()?;
        Ok(result)
    }
}

/// Fresh explicit READ|DELETE native acquisition. No historical CREATE rights.
pub struct FreshRecoveredMutationFile {
    acquired: ReacquiredNodeFile,
}
impl LockedDirectory {
    pub fn reacquire_existing_node_mutation_file(
        &self,
        name: &str,
    ) -> io::Result<FreshRecoveredMutationFile> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::{
            Wdk::{
                Foundation::OBJECT_ATTRIBUTES,
                Storage::FileSystem::{
                    NtCreateFile, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
                    FILE_SYNCHRONOUS_IO_NONALERT,
                },
            },
            Win32::{
                Foundation::{
                    RtlNtStatusToDosError, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
                    OBJ_CASE_INSENSITIVE, STATUS_SUCCESS, UNICODE_STRING,
                },
                Storage::FileSystem::{DELETE, FILE_SHARE_READ, SYNCHRONIZE},
                System::{WindowsProgramming::FILE_OPENED, IO::IO_STATUS_BLOCK},
            },
        };
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
        {
            return Err(super::invalid(
                "recovery single safe file component required",
            ));
        }
        regular(&self.file, true)?;
        let parent_key = key(&self.file)?;
        let mut encoded: Vec<u16> = name.encode_utf16().collect();
        let bytes = u16::try_from(encoded.len() * 2)
            .map_err(|_| super::invalid("recovery file name too long"))?;
        let unicode = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: encoded.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: self.file.as_raw_handle() as HANDLE,
            ObjectName: &unicode,
            Attributes: OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle = std::ptr::null_mut();
        // SAFETY: exact retained parent and counted single-component name remain
        // live; output pointers are sized. FILE_OPEN forbids CREATE or truncation,
        // Explicit new READ|DELETE access and no WRITE/DELETE sharing acquire fresh exclusion.
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                GENERIC_READ | DELETE | SYNCHRONIZE,
                &attributes,
                &mut status_block,
                std::ptr::null(),
                0,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            // SAFETY: NTSTATUS conversion is pointer-free.
            return Err(io::Error::from_raw_os_error(
                unsafe { RtlNtStatusToDosError(status) } as i32,
            ));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(super::invalid("recovery existing file handle absent"));
        }
        // SAFETY: successful NtCreateFile transferred one new owned handle.
        let file = unsafe { File::from_raw_handle(handle) };
        if status_block.Information != FILE_OPENED as usize {
            return Err(super::invalid(
                "recovery file must be existing opened object",
            ));
        }
        regular(&file, false)?;
        let file_key = key(&file)?;
        let value = ReacquiredNodeFile {
            file,
            parent: self.file.try_clone()?,
            key: file_key,
            parent_key,
        };
        value.verify()?;
        Ok(FreshRecoveredMutationFile { acquired: value })
    }
}

impl FreshRecoveredMutationFile {
    pub fn verify(&self) -> io::Result<()> {
        self.acquired.verify()
    }
    pub fn key(&self) -> io::Result<FileKey> {
        self.acquired.key()
    }
    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.acquired.parent_key()
    }
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        self.acquired.matches_path(path)
    }
    pub fn exact_bytes(&self, bound: u64) -> io::Result<Vec<u8>> {
        self.acquired.exact_bytes(bound)
    }
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.verify()?;
        self.acquired.file.metadata()
    }
}

impl FreshRecoveredMutationFile {
    pub fn rename_no_replace_in(
        &self,
        parent: &LockedDirectoryMutation,
        name: &str,
    ) -> io::Result<()> {
        use std::mem::{offset_of, size_of};
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{RtlNtStatusToDosError, HANDLE, STATUS_SUCCESS},
            Storage::FileSystem::FILE_RENAME_INFO,
            System::IO::IO_STATUS_BLOCK,
        };
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtSetInformationFile(
                handle: HANDLE,
                status: *mut IO_STATUS_BLOCK,
                information: *const std::ffi::c_void,
                length: u32,
                class: u32,
            ) -> i32;
        }
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.ends_with(['.', ' '])
            || name
                .chars()
                .any(|ch| ch.is_control() || "<>:\"/\\|?*".contains(ch))
        {
            return Err(super::invalid(
                "relative rename single safe component required",
            ));
        }
        self.verify()?;
        parent.original_creation()?.verify()?;
        if self.key()?.volume != parent.key()?.volume {
            return Err(super::invalid("relative rename same volume required"));
        }
        let encoded: Vec<u16> = name.encode_utf16().collect();
        let bytes = encoded
            .len()
            .checked_mul(2)
            .ok_or_else(|| super::invalid("relative rename name overflow"))?;
        let length = offset_of!(FILE_RENAME_INFO, FileName)
            .checked_add(bytes)
            .ok_or_else(|| super::invalid("relative rename structure overflow"))?
            .max(size_of::<FILE_RENAME_INFO>());
        let size = u32::try_from(length)
            .map_err(|_| super::invalid("relative rename structure too large"))?;
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        let header = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        let mut status = IO_STATUS_BLOCK::default();
        // SAFETY: both native handles stay owned; aligned storage has a sized
        // zeroed ABI header and counted single-component UTF16 tail. RootDirectory
        // is the exact retained destination, ReplaceIfExists remains false.
        let result = unsafe {
            std::ptr::write(header, FILE_RENAME_INFO::default());
            (*header).RootDirectory = parent.file.as_raw_handle() as HANDLE;
            (*header).FileNameLength = bytes as u32;
            std::ptr::copy_nonoverlapping(
                encoded.as_ptr(),
                std::ptr::addr_of_mut!((*header).FileName).cast(),
                encoded.len(),
            );
            NtSetInformationFile(
                self.acquired.file.as_raw_handle() as HANDLE,
                &mut status,
                header.cast(),
                size,
                10,
            )
        };
        if result != STATUS_SUCCESS {
            // SAFETY: conversion accepts the returned NTSTATUS without pointers.
            let error = unsafe { RtlNtStatusToDosError(result) };
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        self.verify()?;
        parent.original_creation()?.verify()?;
        Ok(())
    }
}

impl ReacquiredNodeFile {
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.verify()?;
        self.file.metadata()
    }
}

impl LockedDirectoryMutation {
    /// Reduce the same continuously retained CREATE handle to a directory read
    /// guard. No pathname is reopened and the creator remains held by the caller.
    pub fn duplicate_read_guard(&self) -> io::Result<LockedDirectory> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::{
            Foundation::{DuplicateHandle, GENERIC_READ, HANDLE},
            System::Threading::GetCurrentProcess,
        };
        self.original_creation()?.verify()?;
        let mut output: HANDLE = std::ptr::null_mut();
        // SAFETY: both process handles and retained source are live; output is
        // sized, non-inherited, and READ access cannot expand mutation authority.
        let success = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                self.file.as_raw_handle() as HANDLE,
                process,
                &mut output,
                GENERIC_READ,
                0,
                0,
            )
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        if output.is_null() {
            return Err(super::invalid("directory read duplicate absent"));
        }
        // SAFETY: successful duplication transfers one new owned handle.
        let file = unsafe { File::from_raw_handle(output) };
        regular(&file, true)?;
        if key(&file)? != self.key()? {
            return Err(super::invalid("directory duplicate key differs"));
        }
        Ok(LockedDirectory { file })
    }
}
fn rename_held_object_to_parent(
    file: &File,
    parent: &LockedDirectory,
    name: &str,
    directory: bool,
) -> io::Result<File> {
    use std::mem::{offset_of, size_of};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::{RtlNtStatusToDosError, HANDLE, STATUS_SUCCESS},
        Storage::FileSystem::FILE_RENAME_INFO,
        System::IO::IO_STATUS_BLOCK,
    };
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetInformationFile(
            handle: HANDLE,
            status: *mut IO_STATUS_BLOCK,
            information: *const std::ffi::c_void,
            length: u32,
            class: u32,
        ) -> i32;
    }
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return Err(super::invalid("namespace relative rename safe component"));
    }
    regular(file, directory)?;
    regular(&parent.file, true)?;
    parent.require_case_insensitive()?;
    if key(file)?.volume != parent.key()?.volume {
        return Err(super::invalid("namespace relative rename same held volume"));
    }
    // Retain the new parent before the effect. A later error never drops the
    // old file guard or turns a pathname into recovered cleanup authority.
    let retained_parent = parent.file.try_clone()?;
    let encoded: Vec<u16> = name.encode_utf16().collect();
    let bytes = encoded
        .len()
        .checked_mul(2)
        .ok_or_else(|| super::invalid("namespace name size"))?;
    let length = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(bytes)
        .ok_or_else(|| super::invalid("namespace rename structure size"))?
        .max(size_of::<FILE_RENAME_INFO>());
    let size =
        u32::try_from(length).map_err(|_| super::invalid("namespace rename size conversion"))?;
    let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
    let header = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: aligned zeroed header and counted UTF16 tail remain live; both
    // native handles are retained, exact RootDirectory and replace=false.
    let result = unsafe {
        std::ptr::write(header, FILE_RENAME_INFO::default());
        (*header).RootDirectory = parent.file.as_raw_handle() as HANDLE;
        (*header).FileNameLength = bytes as u32;
        std::ptr::copy_nonoverlapping(
            encoded.as_ptr(),
            std::ptr::addr_of_mut!((*header).FileName).cast(),
            encoded.len(),
        );
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut status,
            header.cast(),
            size,
            10,
        )
    };
    if result != STATUS_SUCCESS {
        // SAFETY: pointer-free conversion of the returned NTSTATUS.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    regular(file, directory)?;
    regular(&retained_parent, true)?;
    Ok(retained_parent)
}
impl FreshRecoveredMutationFile {
    pub fn rename_no_replace_to_parent(
        &mut self,
        parent: &LockedDirectory,
        name: &str,
    ) -> io::Result<()> {
        self.verify()?;
        let held = rename_held_object_to_parent(&self.acquired.file, parent, name, false)?;
        self.acquired.parent_key = key(&held)?;
        self.acquired.parent = held;
        self.verify()
    }
}
impl SealedOriginalFile {
    pub fn rename_no_replace_to_parent(
        &mut self,
        parent: &LockedDirectory,
        name: &str,
    ) -> io::Result<()> {
        self.verify_original()?;
        let held = rename_held_object_to_parent(&self.file, parent, name, false)?;
        self.current_parent = Some(held);
        self.verify_original()
    }
}

impl LockedDirectoryMutation {
    /// Only an actual retained CREATE is eligible. Original CREATE lineage
    /// remains historical; the caller independently binds the new parent slot.
    pub fn rename_created_directory_to_parent(
        &self,
        parent: &LockedDirectory,
        name: &str,
    ) -> io::Result<()> {
        self.original_creation()?.verify()?;
        rename_held_object_to_parent(&self.file, parent, name, true)?;
        self.original_creation()?.verify()
    }
}

impl LockedDirectory {
    /// Another read guard for the same continuously retained native directory.
    /// The source and duplicate share the kernel exclusion and cannot mint CREATE provenance.
    pub fn duplicate_read_guard(&self) -> io::Result<Self> {
        regular(&self.file, true)?;
        self.require_case_insensitive()?;
        let file = self.file.try_clone()?;
        if key(&file)? != self.key()? {
            return Err(super::invalid("held directory duplicate identity"));
        }
        Ok(Self { file })
    }
}
