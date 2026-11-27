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
        FileCaseSensitiveInfo, FileDispositionInfo, FileDispositionInfoEx, FileIdInfo,
        FileRenameInfo, GetDriveTypeW, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetVolumeInformationByHandleW, GetVolumePathNameW, SetFileInformationByHandle,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_CASE_SENSITIVE_INFO,
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_RENAME_INFO, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::WindowsProgramming::DRIVE_FIXED,
};

#[path = "directory_create.rs"]
mod directory_create;
pub use directory_create::OriginalDirectoryCreation;
#[path = "protected_artifact_windows.rs"]
mod protected_artifact;
pub use protected_artifact::{
    SealedWindowsProtectedArtifact, WindowsFailedArtifactCreation,
    WindowsProtectedArtifactCreateFailure, WindowsProtectedArtifactCreator,
    WindowsProtectedArtifactParent, WindowsProtectedArtifactSealFailure,
};
#[path = "owned_file.rs"]
mod owned_file;
pub use owned_file::{
    FreshExclusiveSqliteFile, OriginalFileCreation, OriginalFileSealFailure, OwnedFileCreation,
    PublishedOriginalFile, ReacquiredNodeFile, ReacquiredNodeLock,
    ReleasedOriginalCoordinationFile, ReleasedOriginalFileIdentity, ReleasedOriginalReadFile,
    SealedOriginalFile,
};

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

/// Same-object identity/read handoff shared by original creators. A metadata
/// witness must stay live while an incompatible exclusive HANDLE is closed.
/// The fixed choices grant no namespace CREATE or recovered mutation rights.
fn reopen_same_file_object(source: &File, expected: FileKey, read: bool) -> io::Result<File> {
    reopen_same_file_object_retaining(source, expected, read)
        .map_err(crate::WindowsOriginalResourceOpenFailure::retain_and_report)
}

fn reopen_same_file_object_retaining(
    source: &File,
    expected: FileKey,
    read: bool,
) -> Result<File, crate::WindowsOriginalResourceOpenFailure> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, Storage::FileSystem::ReOpenFile};
    let before = |error| crate::WindowsOriginalResourceOpenFailure {
        error,
        original_resources: None,
    };
    regular(source, false).map_err(before)?;
    if key(source).map_err(before)? != expected {
        return Err(before(invalid(
            "same-object handoff source identity differs",
        )));
    }
    // SAFETY: source owns the original live object. Fixed read/identity access
    // and sharing flags create another handle to it without pathname resolution.
    let handle = unsafe {
        ReOpenFile(
            source.as_raw_handle() as HANDLE,
            if read { GENERIC_READ } else { 0 },
            if read {
                FILE_SHARE_READ
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            },
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(before(io::Error::last_os_error()));
    }
    // SAFETY: successful ReOpenFile returned one newly owned HANDLE.
    let reopened = unsafe { File::from_raw_handle(handle) };
    let checked = (|| -> io::Result<()> {
        regular(&reopened, false)?;
        if key(&reopened)? != expected {
            return Err(invalid("same-object handoff retained identity differs"));
        }
        Ok(())
    })();
    if let Err(error) = checked {
        let mut terminal = crate::WindowsOriginalCloseAttempt::new();
        terminal.close_file(reopened);
        return Err(crate::WindowsOriginalResourceOpenFailure {
            error,
            original_resources: terminal.finish().err(),
        });
    }
    Ok(reopened)
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

/// Metadata-only non-following slot witness; not original creator authority.
pub fn regular_file_matches_path(file: &File, path: &Path) -> io::Result<bool> {
    let slot = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    regular(&slot, false)?;
    regular(file, false)?;
    Ok(key(&slot)? == key(file)?)
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
    /// Consume only this original held directory HANDLE. Failed CloseHandle
    /// returns the same original directory; no replacement scope is issued.
    pub fn close_original(self) -> Result<(), (Self, io::Error)> {
        match crate::original_resource_close::close_owned_original_file(self.file) {
            Ok(()) => Ok(()),
            Err((file, error)) => Err((Self { file }, error)),
        }
    }

    pub(crate) fn into_terminal_original_file(self) -> File {
        self.file
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_retaining(path).map_err(
            crate::original_resource_close::WindowsOriginalResourceOpenFailure::retain_and_report,
        )
    }

    pub fn open_retaining(
        path: &Path,
    ) -> Result<Self, crate::original_resource_close::WindowsOriginalResourceOpenFailure> {
        let before = |error| crate::original_resource_close::WindowsOriginalResourceOpenFailure {
            error,
            original_resources: None,
        };
        let file = OpenOptions::new()
            // Metadata-only opens do not enforce Windows sharing exclusion.
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(before)?;
        if let Err(error) = regular(&file, true) {
            let mut close = crate::WindowsOriginalCloseAttempt::new();
            close.close_file(file);
            return Err(
                crate::original_resource_close::WindowsOriginalResourceOpenFailure {
                    error,
                    original_resources: close.finish().err(),
                },
            );
        }
        Ok(Self { file })
    }

    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    /// Read-only exact slot witness; this grants no creator or mutation authority.
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        directory_matches_path(&self.file, path)
    }

    /// Require the retained directory to live on a fixed local NTFS volume.
    pub fn require_local_ntfs(&self, path: &Path) -> io::Result<()> {
        local_ntfs(&self.file, path)
    }

    /// Before child CREATE, require this actual retained directory to have the
    /// sole current-user, protected full-access OI/CI ACE.
    pub fn require_current_user_private(&self) -> io::Result<()> {
        current_user_file::verify_current_user_private_directory(&self.file)
    }

    /// Audit a current-user inherited SQLite sidecar against this proven parent.
    /// The caller separately binds the child HANDLE to its exact fixed slot.
    pub fn verify_current_user_private_child_file(&self, file: &File) -> io::Result<()> {
        self.require_current_user_private()?;
        current_user_file::verify_current_user_private_inherited_file(file)
    }

    pub fn require_case_insensitive(&self) -> io::Result<()> {
        require_case_insensitive(&self.file)
    }
}

/// Exact local NTFS directory handle; child membership is not frozen.
/// Application callers must journal intent before rename or empty disposition.
pub struct LockedDirectoryMutation {
    file: File,
    original_creation: Option<directory_create::DirectoryCreationLineage>,
}

impl LockedDirectoryMutation {
    /// End the actual directory HANDLE and, when present, its original CREATE
    /// lineage parent. Independent closes continue after the first failure.
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.close_file(self.file);
        if let Some(lineage) = self.original_creation {
            lineage.close_into_attempt(attempt);
        }
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular(&file, true)?;
        local_ntfs(&file, path)?;
        let held = Self {
            file,
            original_creation: None,
        };
        held.require_case_insensitive()?;
        Ok(held)
    }

    pub fn key(&self) -> io::Result<FileKey> {
        key(&self.file)
    }

    /// Check the held directory's current slot without releasing its original handle.
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        directory_matches_path(&self.file, path)
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

fn directory_matches_path(file: &File, path: &Path) -> io::Result<bool> {
    let slot = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    regular(&slot, true)?;
    regular(file, true)?;
    Ok(key(&slot)? == key(file)?)
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
    /// Resource-only ending of this actual read HANDLE. It cannot mint any
    /// original reader, creator, target owner, permission or resumed scope.
    pub fn close_original(self) -> Result<(), (Self, io::Error)> {
        match crate::original_resource_close::close_owned_original_file(self.file) {
            Ok(()) => Ok(()),
            Err((file, error)) => Err((Self { file }, error)),
        }
    }

    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.close_file(self.file);
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_retaining(path).map_err(
            crate::original_resource_close::WindowsOriginalResourceOpenFailure::retain_and_report,
        )
    }

    pub fn open_retaining(
        path: &Path,
    ) -> Result<Self, crate::original_resource_close::WindowsOriginalResourceOpenFailure> {
        let before = |error| crate::original_resource_close::WindowsOriginalResourceOpenFailure {
            error,
            original_resources: None,
        };
        let file = OpenOptions::new()
            .access_mode(GENERIC_READ)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(before)?;
        if let Err(error) = regular(&file, false).and_then(|_| local_ntfs(&file, path)) {
            let mut close = crate::WindowsOriginalCloseAttempt::new();
            close.close_file(file);
            return Err(
                crate::original_resource_close::WindowsOriginalResourceOpenFailure {
                    error,
                    original_resources: close.finish().err(),
                },
            );
        }
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

    /// Observe a non-following named slot while this mutation-excluding handle
    /// remains live. This is not a new original-creation or ownership proof.
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        let slot = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        regular(&slot, false)?;
        regular(&self.file, false)?;
        Ok(key(&slot)? == key(&self.file)?)
    }

    /// Mark this protected single-link file for deletion when all handles close.
    pub fn delete_on_close(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        request_delete_on_close(&self.file)
    }

    /// Dispose an already-authorized retained original even when its preserved
    /// metadata is readonly. Keep the original DELETE-capable handle and normal
    /// close semantics; neither alter attributes nor reopen a pathname.
    pub fn delete_readonly_on_close(&self) -> io::Result<()> {
        regular(&self.file, false)?;
        let mut info = FILE_DISPOSITION_INFO_EX {
            Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        };
        // SAFETY: this live original handle has DELETE access, and info is
        // correctly aligned and sized for FileDispositionInfoEx. Unsupported
        // systems return their actual error without a pathname fallback.
        let result = unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle() as HANDLE,
                FileDispositionInfoEx,
                ptr::from_mut(&mut info).cast(),
                size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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

#[path = "sqlite_native_identity.rs"]
mod sqlite_native_identity;
pub use sqlite_native_identity::sqlite_main_file_identity;

impl GuardedReadFile {
    /// Metadata-only non-following slot observation while the original read
    /// exclusion remains held. This creates no new owner or creator grant.
    pub fn matches_path(&self, path: &Path) -> io::Result<bool> {
        self.verify_single_link()?;
        regular_file_matches_path(&self.file, path)
    }
}

/// Retain the exact held directory with reduced read rights. This is an
/// observer, with no CREATE, rename or disposition method.
pub struct RetainedWriterDirectory {
    pub(crate) directory: LockedDirectory,
    pub(crate) path: std::path::PathBuf,
    pub(crate) key: FileKey,
}

impl RetainedWriterDirectory {
    /// End the exact original observer HANDLE without a pathname operation.
    pub fn close_into_attempt(self, attempt: &mut crate::WindowsOriginalCloseAttempt) {
        attempt.close_directory(self.directory);
    }
}

fn retain_writer_directory(file: &File, path: &Path) -> io::Result<RetainedWriterDirectory> {
    retain_writer_directory_retaining(file, path)
        .map_err(crate::WindowsOriginalResourceOpenFailure::retain_and_report)
}

fn retain_writer_directory_retaining(
    file: &File,
    path: &Path,
) -> Result<RetainedWriterDirectory, crate::WindowsOriginalResourceOpenFailure> {
    let mut terminal = crate::WindowsOriginalCloseAttempt::new();
    retain_writer_directory_into_attempt(file, path, &mut terminal).map_err(|error| {
        crate::WindowsOriginalResourceOpenFailure {
            error,
            original_resources: terminal.finish().err(),
        }
    })
}

fn retain_writer_directory_into_attempt(
    file: &File,
    path: &Path,
    terminal: &mut crate::WindowsOriginalCloseAttempt,
) -> io::Result<RetainedWriterDirectory> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{Foundation::DuplicateHandle, System::Threading::GetCurrentProcess};
    let checked = (|| -> io::Result<FileKey> {
        if !path.is_absolute() || !directory_matches_path(file, path)? {
            return Err(invalid("original writer directory slot differs"));
        }
        regular(file, true)?;
        require_case_insensitive(file)?;
        local_ntfs(file, path)?;
        key(file)
    })();
    let original_key = checked?;
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: file is a live retained directory. The output receives one owned,
    // noninherited READ-only duplicate; WRITE and DELETE are not requested.
    let success = unsafe {
        let process = GetCurrentProcess();
        DuplicateHandle(
            process,
            file.as_raw_handle() as HANDLE,
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
    // SAFETY: successful DuplicateHandle returned one new handle owned here.
    let observed = unsafe { File::from_raw_handle(handle) };
    let checked = (|| -> io::Result<()> {
        regular(&observed, true)?;
        if key(&observed)? != original_key || !directory_matches_path(&observed, path)? {
            return Err(invalid("retained writer directory object differs"));
        }
        Ok(())
    })();
    if let Err(error) = checked {
        terminal.close_file(observed);
        return Err(error);
    }
    Ok(RetainedWriterDirectory {
        directory: LockedDirectory { file: observed },
        path: path.to_owned(),
        key: original_key,
    })
}

impl LockedDirectory {
    /// Duplicate an existing directory guard; no pathname opens grant rights.
    pub fn retain_writer_directory(&self, path: &Path) -> io::Result<RetainedWriterDirectory> {
        retain_writer_directory(&self.file, path)
    }

    pub fn retain_writer_directory_retaining(
        &self,
        path: &Path,
    ) -> Result<RetainedWriterDirectory, crate::WindowsOriginalResourceOpenFailure> {
        retain_writer_directory_retaining(&self.file, path)
    }

    /// The caller's existing aggregate preserves both successful native closes
    /// and the exact refused HANDLE from a failed observer preparation.
    pub fn retain_writer_directory_into_attempt(
        &self,
        path: &Path,
        terminal: &mut crate::WindowsOriginalCloseAttempt,
    ) -> io::Result<RetainedWriterDirectory> {
        retain_writer_directory_into_attempt(&self.file, path, terminal)
    }
}

#[path = "sqlite_main_bytes.rs"]
mod sqlite_main_bytes;
#[path = "sqlite_wal_identity.rs"]
mod sqlite_wal_identity;
pub use sqlite_main_bytes::{sqlite_main_exact_bytes, sqlite_retain_actual_wal};
pub use sqlite_wal_identity::sqlite_wal_file_identity;

pub use owned_file::{
    OriginalSqliteMainHandoff, OriginalSqliteMainHandoffFailure, OriginalSqliteSidecarHandoff,
    OriginalSqliteSidecarHandoffFailure, OriginalSqliteSidecarKind,
};

#[path = "sqlite_original.rs"]
mod sqlite_original;
pub use sqlite_original::{
    OriginalReadonlySqliteCloseFailure, OriginalReadonlySqliteConnection,
    OriginalReadonlySqliteOpenFailure, OriginalSqliteConnection, OriginalSqliteOpenFailure,
    OriginalSqliteQuery, OriginalSqliteReadBudget, OriginalSqliteResourceCloseFailure,
    OriginalSqliteRows, OriginalSqliteStatement, OriginalSqliteValue,
};

#[path = "current_user_file.rs"]
mod current_user_file;
pub use current_user_file::{capture_current_user_private_acl, verify_current_user_private_file};

#[path = "fresh_native_sqlite.rs"]
mod fresh_native_sqlite;
pub use fresh_native_sqlite::FreshNativeSqliteConnection;

#[path = "fresh_native_wal.rs"]
mod fresh_native_wal;
pub use fresh_native_wal::{
    FreshNativeRetentionLease, FreshNativeWalCloseFailure, FreshNativeWalConnection,
    FreshNativeWalOpenFailure, FRESH_NATIVE_WAL_SHM_CAPACITY,
};

pub use owned_file::FreshRecoveredMutationFile;

#[path = "sqlite_payload_allocation.rs"]
mod sqlite_payload_allocation;
pub use sqlite_payload_allocation::{
    OriginalSqlitePayloadAllocation, OriginalSqlitePayloadAllocationBounds,
    OriginalSqlitePayloadAllocationFailure,
};
