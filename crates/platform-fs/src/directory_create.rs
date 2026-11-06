use super::{
    invalid, key, regular, require_case_insensitive, require_ntfs, LockedDirectory,
    LockedDirectoryMutation,
};
use crate::FileKey;
use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE},
    Storage::FileSystem::{GetDriveTypeW, DELETE, FILE_SHARE_READ},
    System::WindowsProgramming::DRIVE_FIXED,
};

pub(super) struct DirectoryCreationLineage {
    parent: File,
    original_key: FileKey,
    original_parent_key: FileKey,
    created_component: String,
}

/// Borrowed lineage from an actual native directory CREATE. Reopened mutation
/// guards cannot mint this proof. It does not freeze membership or grant durable
/// Journal ownership, and the original component is historical after rename.
pub struct OriginalDirectoryCreation<'a> {
    creator: &'a LockedDirectoryMutation,
    lineage: &'a DirectoryCreationLineage,
}

impl OriginalDirectoryCreation<'_> {
    pub fn key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.lineage.original_key)
    }

    pub fn parent_key(&self) -> io::Result<FileKey> {
        self.verify()?;
        Ok(self.lineage.original_parent_key)
    }

    /// The CREATE component is not evidence of the current pathname occupant.
    pub fn created_component(&self) -> &str {
        &self.lineage.created_component
    }

    pub fn verify(&self) -> io::Result<()> {
        let lineage = self.lineage;
        regular(&self.creator.file, true)?;
        regular(&lineage.parent, true)?;
        require_case_insensitive(&self.creator.file)?;
        require_case_insensitive(&lineage.parent)?;
        if key(&self.creator.file)? != lineage.original_key
            || key(&lineage.parent)? != lineage.original_parent_key
        {
            return Err(invalid("original directory creator lineage changed"));
        }
        Ok(())
    }
}

impl LockedDirectory {
    /// Create a new child through this exact retained parent handle.
    /// Caller must durably journal intent first and retain all root ancestors.
    /// Creation success alone is not durable restart-safe ownership.
    pub fn create_new_child(&self, name: &str) -> io::Result<LockedDirectoryMutation> {
        create_new_directory_child(&self.file, name)
    }
}

impl LockedDirectoryMutation {
    /// Only an actual CREATE retains original lineage and the immediate parent.
    /// This is not recovery/adoption authority or an all-ancestors guard.
    pub fn original_creation(&self) -> io::Result<OriginalDirectoryCreation<'_>> {
        let lineage = self
            .original_creation
            .as_ref()
            .ok_or_else(|| invalid("reopened directory has no original creator lineage"))?;
        let proof = OriginalDirectoryCreation {
            creator: self,
            lineage,
        };
        proof.verify()?;
        Ok(proof)
    }

    /// A newly created parent's original handle can create its own children.
    /// Failures preserve possibly created orphans; no pathname cleanup/adoption.
    /// Publish parents before opening descendants that may block parent rename.
    pub fn create_new_child(&self, name: &str) -> io::Result<Self> {
        create_new_directory_child(&self.file, name)
    }
}

fn local_ntfs_from_handle(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_OPENED, VOLUME_NAME_GUID,
    };
    let mut name = vec![0u16; 32768];
    // SAFETY: file owns a live handle; name is a sized writable UTF-16 buffer.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as HANDLE,
            name.as_mut_ptr(),
            name.len() as u32,
            FILE_NAME_OPENED | VOLUME_NAME_GUID,
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let prefix: Vec<u16> = r"\\?\Volume{".encode_utf16().collect();
    if length >= name.len() || !name[..length].starts_with(&prefix) {
        return Err(invalid("retained directory volume GUID is unavailable"));
    }
    let end = name[..length]
        .iter()
        .position(|&unit| unit == b'}' as u16)
        .filter(|&end| name.get(end + 1) == Some(&(b'\\' as u16)))
        .ok_or_else(|| invalid("retained directory volume root is unavailable"))?;
    name.truncate(end + 2);
    name.push(0);
    // SAFETY: the successful final-path query supplied this terminated GUID root.
    if unsafe { GetDriveTypeW(name.as_ptr()) } != DRIVE_FIXED {
        return Err(invalid("directory creation requires a fixed local volume"));
    }
    require_ntfs(file)
}

pub(super) enum NewChildKind {
    Directory,
    File,
}

fn create_new_directory_child(file: &File, name: &str) -> io::Result<LockedDirectoryMutation> {
    let original_parent_key = key(file)?;
    let created = create_new_child(file, name, NewChildKind::Directory)?;
    let original_key = key(&created)?;
    let held = LockedDirectoryMutation {
        file: created,
        original_creation: Some(DirectoryCreationLineage {
            parent: file.try_clone()?,
            original_key,
            original_parent_key,
            created_component: name.into(),
        }),
    };
    held.original_creation()?.verify()?;
    Ok(held)
}

pub(super) fn create_new_child(file: &File, name: &str, kind: NewChildKind) -> io::Result<File> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::{
        Wdk::{
            Foundation::OBJECT_ATTRIBUTES,
            Storage::FileSystem::{
                NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
                FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
            },
        },
        Win32::{
            Foundation::{
                RtlNtStatusToDosError, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, STATUS_SUCCESS,
                UNICODE_STRING,
            },
            Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, SYNCHRONIZE},
            System::{WindowsProgramming::FILE_CREATED, IO::IO_STATUS_BLOCK},
        },
    };
    validate_directory_component(name)?;
    regular(file, true)?;
    require_case_insensitive(file)?;
    local_ntfs_from_handle(file)?;
    let parent_key = key(file)?;
    let (access, share, options, directory) = match kind {
        NewChildKind::Directory => (
            GENERIC_READ | DELETE | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_DIRECTORY_FILE,
            true,
        ),
        NewChildKind::File => (
            GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
            0,
            FILE_NON_DIRECTORY_FILE,
            false,
        ),
    };
    let mut encoded: Vec<u16> = name.encode_utf16().collect();
    let bytes = u16::try_from(
        encoded
            .len()
            .checked_mul(2)
            .ok_or_else(|| invalid("directory component too long"))?,
    )
    .map_err(|_| invalid("directory component too long"))?;
    let unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: encoded.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: file.as_raw_handle() as HANDLE,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = ptr::null_mut();
    // SAFETY: parent owns a live real-directory handle. The single-component
    // UTF-16 buffer, counted string and attributes remain live and aligned
    // throughout synchronous creation; fixed internal kind flags select only
    // new file/directory creation and handle/status are sized writable outputs.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            FILE_CREATE,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: conversion takes only the NTSTATUS returned by the syscall.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(invalid("native create returned no owned handle"));
    }
    // SAFETY: successful synchronous creation returned one owned native handle.
    // File assumes ownership once and closes it on every later error path.
    let created = unsafe { File::from_raw_handle(handle) };
    // SAFETY: synchronous completion initialized the status member of the union.
    let completion = unsafe { status_block.Anonymous.Status };
    if status != STATUS_SUCCESS
        || completion != STATUS_SUCCESS
        || status_block.Information != FILE_CREATED as usize
    {
        return Err(invalid("new native creation ownership unavailable"));
    }
    regular(&created, directory)?;
    if directory {
        require_case_insensitive(&created)?;
    }
    if key(&created)?.volume != parent_key.volume {
        return Err(invalid("created native volume changed"));
    }
    Ok(created)
}

fn validate_directory_component(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return Err(invalid("unsafe directory component"));
    }
    let stem = name.split('.').next().unwrap_or("").to_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "CONIN$"
            | "CONOUT$"
            | "COM\u{b9}"
            | "COM\u{b2}"
            | "COM\u{b3}"
            | "LPT\u{b9}"
            | "LPT\u{b2}"
            | "LPT\u{b3}"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
    }) || [".sync-tmp", ".sync-extend", ".git"]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        return Err(invalid("reserved directory component"));
    }
    Ok(())
}
