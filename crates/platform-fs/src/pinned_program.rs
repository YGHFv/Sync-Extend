//! Execute the exact held bytes without returning to an unguarded binary pathname.
use std::{fs::File, io, path::Path, process::Command};

pub struct PinnedProgram {
    #[cfg(windows)]
    path: std::path::PathBuf,
    #[cfg(windows)]
    file: crate::GuardedReadFile,
    #[cfg(windows)]
    _parents: Vec<crate::LockedDirectory>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    file: File,
}

impl PinnedProgram {
    pub fn open(path: &Path, max_bytes: u64) -> io::Result<Self> {
        if !path.is_absolute()
            || max_bytes == 0
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(io::Error::other(
                "absolute normalized pinned program required",
            ));
        }
        #[cfg(windows)]
        {
            let mut parents = Vec::new();
            let paths: Vec<_> = path
                .parent()
                .ok_or_else(|| io::Error::other("program parent absent"))?
                .ancestors()
                .collect();
            for parent in paths.into_iter().rev() {
                let held = crate::LockedDirectory::open(parent)?;
                if !held.matches_path(parent)? {
                    return Err(io::Error::other("program ancestor changed"));
                }
                parents.push(held);
            }
            let file = crate::GuardedReadFile::open(path)?;
            if file.reader().metadata()?.len() > max_bytes {
                return Err(io::Error::other("program size limit"));
            }
            Ok(Self {
                path: path.to_owned(),
                file,
                _parents: parents,
            })
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::{
                ffi::CString,
                io::{Read, Seek, SeekFrom},
                os::{
                    fd::{AsRawFd, FromRawFd},
                    unix::fs::{MetadataExt, OpenOptionsExt},
                },
            };
            let source = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            let metadata = source.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > max_bytes {
                return Err(io::Error::other("single-link bounded program required"));
            }
            let name = CString::new("sync-extend-pinned-program").unwrap();
            // Android API 26 has no exported memfd_create libc symbol. The
            // kernel syscall is available independently; ENOSYS or policy
            // refusal remains an error, never an unsealed pathname fallback.
            // SAFETY: the terminated name is live, SYS_memfd_create takes a
            // name pointer and flags, and successful calls return an owned fd.
            #[cfg(target_os = "android")]
            let descriptor = unsafe {
                libc::syscall(
                    libc::SYS_memfd_create,
                    name.as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                ) as libc::c_int
            };
            // SAFETY: the terminated name is live and flags request one sealed-memory handle.
            #[cfg(target_os = "linux")]
            let descriptor = unsafe {
                libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful memfd_create transfers one newly owned descriptor.
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            let count = io::copy(&mut source.take(max_bytes.saturating_add(1)), &mut file)?;
            if count > max_bytes {
                return Err(io::Error::other("program size changed past limit"));
            }
            // SAFETY: the live private descriptor has no mapped writers; seal its exact bytes.
            if unsafe {
                libc::fcntl(
                    file.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_WRITE
                        | libc::F_SEAL_GROW
                        | libc::F_SEAL_SHRINK
                        | libc::F_SEAL_SEAL,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            file.seek(SeekFrom::Start(0))?;
            Ok(Self { file })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        {
            let _ = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "pinned program unavailable",
            ))
        }
    }

    pub fn reader(&self) -> &File {
        #[cfg(windows)]
        {
            self.file.reader()
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            &self.file
        }
    }

    /// The caller must retain this object through spawn and execution.
    pub fn command(&self) -> Command {
        #[cfg(windows)]
        {
            Command::new(&self.path)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            Command::new(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
    }
}
