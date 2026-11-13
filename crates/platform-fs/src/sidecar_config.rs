//! A secret configuration file owned by the invocation's kernel lifetime.
use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub struct SidecarConfig {
    file: File,
    path: PathBuf,
    #[cfg(windows)]
    _parents: Vec<crate::LockedDirectory>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    _owner: File,
}

impl SidecarConfig {
    pub fn create(state: &Path, instance: &str, bytes: &[u8]) -> io::Result<Self> {
        if !state.is_absolute()
            || bytes.len() > 65536
            || instance.len() != 32
            || !instance.bytes().all(|byte| byte.is_ascii_hexdigit())
            || state.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(io::Error::other(
                "bounded private sidecar configuration required",
            ));
        }
        #[cfg(windows)]
        {
            use std::{
                mem::size_of,
                os::windows::{ffi::OsStrExt, io::FromRawHandle},
                ptr,
            };
            use windows_sys::Win32::{
                Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
                Security::{
                    Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
                },
                Storage::FileSystem::{
                    CreateFileW, CREATE_NEW, DELETE, FILE_FLAG_DELETE_ON_CLOSE,
                    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
                },
            };
            let mut parents = Vec::new();
            let paths: Vec<_> = state.ancestors().collect();
            for parent in paths.into_iter().rev() {
                let held = crate::LockedDirectory::open(parent)?;
                if !held.matches_path(parent)? {
                    return Err(io::Error::other("configuration ancestor changed"));
                }
                parents.push(held);
            }
            parents.last().unwrap().require_local_ntfs(state)?;
            parents.last().unwrap().require_case_insensitive()?;
            let path = state.join(format!("sidecar-{instance}.toml"));
            let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;OW)\0".encode_utf16().collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: terminated SDDL is live; the output receives one allocated descriptor.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            // SAFETY: bounded terminated path and descriptor remain live through exclusive CREATE.
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE | DELETE,
                    FILE_SHARE_READ,
                    &attributes,
                    CREATE_NEW,
                    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_DELETE_ON_CLOSE,
                    ptr::null_mut(),
                )
            };
            let error = (handle == INVALID_HANDLE_VALUE).then(io::Error::last_os_error);
            // SAFETY: descriptor is precisely the allocation returned by the SDDL conversion.
            unsafe { LocalFree(descriptor) };
            if let Some(error) = error {
                return Err(error);
            }
            // SAFETY: successful exclusive CREATE transfers one newly owned handle.
            let mut file = unsafe { File::from_raw_handle(handle) };
            file.write_all(bytes)?;
            file.sync_all()?;
            crate::verify_regular_file(&file)?;
            Ok(Self {
                file,
                path,
                _parents: parents,
            })
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            let owner = crate::acquire_sidecar_owner(state)?;
            let mut file = crate::create_anonymous_upload(state)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            let path = PathBuf::from(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                file.as_raw_fd()
            ));
            Ok(Self {
                file,
                path,
                _owner: owner,
            })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "private sidecar config unavailable",
            ))
        }
    }

    pub fn path(&self) -> io::Result<&Path> {
        #[cfg(windows)]
        {
            crate::verify_regular_file(&self.file)?;
            if !crate::regular_file_matches_path(&self.file, &self.path)? {
                return Err(io::Error::other("sidecar config slot changed"));
            }
        }
        if !self.file.metadata()?.is_file() {
            return Err(io::Error::other("sidecar config handle differs"));
        }
        Ok(&self.path)
    }
}
