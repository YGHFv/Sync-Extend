use crate::FileKey;
use std::{
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, HANDLE},
    Storage::FileSystem::{
        FileCaseSensitiveInfo, FileDispositionInfo, FileIdInfo, FileRenameInfo, GetDriveTypeW,
        GetFileInformationByHandle, GetFileInformationByHandleEx, GetVolumeInformationByHandleW,
        GetVolumePathNameW, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, DELETE,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_CASE_SENSITIVE_INFO, FILE_DISPOSITION_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_RENAME_INFO,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::WindowsProgramming::DRIVE_FIXED,
};

#[path = "directory_create.rs"]
mod directory_create;
#[path = "owned_file.rs"]
mod owned_file;
pub use owned_file::{OriginalFileCreation, OwnedFileCreation};

fn key(file: &File) -> io::Result<FileKey> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: file owns a live handle; info is an aligned, sized writable output.
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            ptr::from_mut(&mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileKey {
        volume: info.VolumeSerialNumber,
        id: u128::from_le_bytes(info.FileId.Identifier),
    })
}

impl FileKey {
    pub fn from_file(file: &File) -> io::Result<Self> {
        key(file)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn regular(file: &File, directory: bool) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(invalid(
            "expected a real directory or regular non-reparse file",
        ));
    }
    if !directory && regular_file_link_count(file)? != 1 {
        return Err(invalid("file mutation requires a single-link file"));
    }
    Ok(())
}

/// Validate an already retained handle as a regular non-reparse single-link file.
pub fn verify_regular_file(file: &File) -> io::Result<()> {
    regular(file, false)
}

/// Read alias multiplicity from the retained regular-file handle, not its path.
pub fn regular_file_link_count(file: &File) -> io::Result<u32> {
    use std::os::windows::fs::MetadataExt;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid("expected a regular non-reparse file"));
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a live handle and info is sized, aligned writable output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.nNumberOfLinks == 0 {
        return Err(invalid("regular file link count is unavailable"));
    }
    Ok(info.nNumberOfLinks)
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut name: Vec<_> = path.as_os_str().encode_wide().collect();
    if !path.is_absolute() || name.contains(&0) {
        return Err(invalid("an absolute non-NUL path is required"));
    }
    name.push(0);
    Ok(name)
}

fn local_ntfs(file: &File, path: &Path) -> io::Result<()> {
    let name = wide(path)?;
    let mut root = [0u16; 32768];
    // SAFETY: name is terminated and root is a sized writable output buffer.
    if unsafe { GetVolumePathNameW(name.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful GetVolumePathNameW returned a terminated volume path.
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err(invalid("file mutation requires a fixed local volume"));
    }
    require_ntfs(file)
}

fn require_ntfs(file: &File) -> io::Result<()> {
    let mut filesystem = [0u16; 32];
    // SAFETY: handle is live; optional outputs are null and filesystem is sized.
    let result = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if filesystem[..5] != [b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0] {
        return Err(invalid("file mutation requires NTFS"));
    }
    Ok(())
}

pub struct LockedDirectory {
    file: File,
}

impl LockedDirectory {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            // Metadata-only opens do not enforce Windows sharing exclusion.
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular(&file, true)?;
        Ok(Self { file })
    }

    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    /// Require the retained directory to live on a fixed local NTFS volume.
    pub fn require_local_ntfs(&self, path: &Path) -> io::Result<()> {
        local_ntfs(&self.file, path)
    }

    pub fn require_case_insensitive(&self) -> io::Result<()> {
        require_case_insensitive(&self.file)
    }
}

/// Exact local NTFS directory handle; child membership is not frozen.
/// Application callers must journal intent before rename or empty disposition.
pub struct LockedDirectoryMutation {
    file: File,
}

impl LockedDirectoryMutation {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular(&file, true)?;
        local_ntfs(&file, path)?;
        let held = Self { file };
        held.require_case_insensitive()?;
        Ok(held)
    }

    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    pub fn require_case_insensitive(&self) -> io::Result<()> {
        require_case_insensitive(&self.file)
    }

    /// Rename only the held directory, never replace a named target.
    /// Caller must independently retain and validate destination ancestors.
    pub fn rename_no_replace(&self, destination: &Path) -> io::Result<()> {
        regular(&self.file, true)?;
        self.require_case_insensitive()?;
        rename_no_replace(&self.file, destination)
    }

    /// Request disposition of the exact held EMPTY directory.
    /// A successful request is not absence until all compatible handles close.
    /// NTFS rejects nonempty directories; never recurse or delete their children.
    pub fn delete_empty_on_close(&self) -> io::Result<()> {
        regular(&self.file, true)?;
        self.require_case_insensitive()?;
        request_delete_on_close(&self.file)
    }
}

fn require_case_insensitive(file: &File) -> io::Result<()> {
    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    // SAFETY: file is a retained directory handle; info is aligned writable
    // storage of the exact size required by FileCaseSensitiveInfo.
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileCaseSensitiveInfo,
            ptr::from_mut(&mut info).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.Flags != 0 {
        return Err(invalid("mutation requires case-insensitive parents"));
    }
    Ok(())
}

pub struct LockedFile {
    file: File,
}

/// A single-link local NTFS read handle that excludes concurrent write/delete opens.
pub struct GuardedReadFile {
    file: File,
}

impl GuardedReadFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular(&file, false)?;
        local_ntfs(&file, path)?;
        Ok(Self { file })
    }

    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    pub fn reader(&self) -> &File {
        &self.file
    }

    pub fn verify_single_link(&self) -> io::Result<()> {
        regular(&self.file, false)
    }
}

impl LockedFile {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular(&file, false)?;
        local_ntfs(&file, path)?;
        Ok(Self { file })
    }

    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    pub fn reader(&self) -> &File {
        &self.file
    }

    /// Mark this protected single-link file for deletion when all handles close.
    pub fn delete_on_close(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        request_delete_on_close(&self.file)
    }

    pub fn rename_no_replace(&self, destination: &Path) -> io::Result<()> {
        rename_no_replace(&self.file, destination)
    }
}

fn request_delete_on_close(file: &File) -> io::Result<()> {
    let mut info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: file owns a live DELETE-capable handle; info is correctly
    // aligned and sized for FileDispositionInfo. No pathname is retargeted.
    let result = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            ptr::from_mut(&mut info).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn rename_no_replace(file: &File, destination: &Path) -> io::Result<()> {
    let name = wide(destination)?;
    let name_bytes = name
        .len()
        .saturating_sub(1)
        .checked_mul(2)
        .ok_or_else(|| invalid("name too long"))?;
    let length = offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes + 2)
        .ok_or_else(|| invalid("name too long"))?
        .max(size_of::<FILE_RENAME_INFO>());
    let length_u32 = u32::try_from(length).map_err(|_| invalid("name too long"))?;
    // Word storage supplies the alignment required by the ABI header.
    let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
    let header = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: storage is aligned and large enough for the header and UTF-16
    // tail including a terminator required by the Win32 wrapper (not counted
    // in FileNameLength). Name remains live. The live source handle owns
    // DELETE access. RootDirectory is null; no destination replacement.
    let result = unsafe {
        ptr::write(header, FILE_RENAME_INFO::default());
        (*header).FileNameLength = name_bytes as u32;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*header).FileName).cast(),
            name.len(),
        );
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileRenameInfo,
            header.cast(),
            length_u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
