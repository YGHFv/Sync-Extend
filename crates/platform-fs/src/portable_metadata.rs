use std::{fs::File, io};

pub const WINDOWS_NTFS_TIME_RESOLUTION_NANOS: u32 = 100;
pub const UNIX_NANOSECOND_TIME_RESOLUTION_NANOS: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableTime {
    pub seconds: i64,
    pub nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedReason {
    Platform,
    Filesystem,
    Permission,
    Api,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturedTime {
    Unsupported(UnsupportedReason),
    Value(PortableTime),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturedFlag {
    Unsupported(UnsupportedReason),
    Value(bool),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturedFileMetadata {
    pub modified: PortableTime,
    pub readonly: bool,
    pub creation: CapturedTime,
    pub unix_executable: CapturedFlag,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableMetadataCapabilities {
    pub modified_resolution_nanos: u32,
    pub creation_resolution_nanos: Option<u32>,
    pub readonly_supported: bool,
    pub unix_executable_supported: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableMetadataCapture {
    pub metadata: CapturedFileMetadata,
    pub capabilities: PortableMetadataCapabilities,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortableMetadataApplication {
    pub requested: CapturedFileMetadata,
    pub observed: CapturedFileMetadata,
    pub capabilities: PortableMetadataCapabilities,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn validate_time(value: PortableTime) -> io::Result<()> {
    if value.nanos >= 1_000_000_000 {
        return Err(invalid("portable metadata nanoseconds out of range"));
    }
    Ok(())
}

fn quantize(value: PortableTime, resolution: u32) -> PortableTime {
    PortableTime {
        seconds: value.seconds,
        nanos: value.nanos / resolution * resolution,
    }
}

fn require_supported_time(value: CapturedTime, resolution: Option<u32>) -> io::Result<()> {
    if matches!(value, CapturedTime::Value(_)) && resolution.is_none() {
        return Err(unsupported(
            "requested portable creation time is not supported on this platform",
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod platform {
    use super::{
        invalid, quantize, require_supported_time, validate_time, CapturedFileMetadata,
        CapturedFlag, CapturedTime, PortableMetadataApplication, PortableMetadataCapabilities,
        PortableMetadataCapture, PortableTime, UnsupportedReason,
        WINDOWS_NTFS_TIME_RESOLUTION_NANOS,
    };
    use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle, ptr};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
            FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO,
        },
    };

    const WINDOWS_EPOCH_TO_UNIX_SECONDS: i64 = 11_644_473_600;

    const CAPABILITIES: PortableMetadataCapabilities = PortableMetadataCapabilities {
        modified_resolution_nanos: WINDOWS_NTFS_TIME_RESOLUTION_NANOS,
        creation_resolution_nanos: Some(WINDOWS_NTFS_TIME_RESOLUTION_NANOS),
        readonly_supported: true,
        unix_executable_supported: false,
    };

    fn query(file: &File) -> io::Result<FILE_BASIC_INFO> {
        let mut info = FILE_BASIC_INFO::default();
        // SAFETY: file owns a live HANDLE; info is an aligned, sized output.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileBasicInfo,
                ptr::from_mut(&mut info).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    fn set(file: &File, info: &FILE_BASIC_INFO) -> io::Result<()> {
        // SAFETY: file owns a live HANDLE; info is an aligned, sized input.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle() as HANDLE,
                FileBasicInfo,
                ptr::from_ref(info).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn from_filetime(ticks: i64) -> io::Result<PortableTime> {
        let seconds = ticks
            .div_euclid(10_000_000)
            .checked_sub(WINDOWS_EPOCH_TO_UNIX_SECONDS)
            .ok_or_else(|| invalid("portable file time seconds overflow"))?;
        let nanos = u32::try_from(ticks.rem_euclid(10_000_000))
            .map_err(|_| invalid("portable file time remainder"))?
            .checked_mul(100)
            .ok_or_else(|| invalid("portable file time nanoseconds overflow"))?;
        Ok(PortableTime { seconds, nanos })
    }

    fn to_filetime(value: PortableTime) -> io::Result<i64> {
        validate_time(value)?;
        let ticks = value
            .seconds
            .checked_add(WINDOWS_EPOCH_TO_UNIX_SECONDS)
            .and_then(|seconds| seconds.checked_mul(10_000_000))
            .and_then(|ticks| ticks.checked_add(i64::from(value.nanos / 100)))
            .ok_or_else(|| invalid("portable file time ticks overflow"))?;
        Ok(ticks)
    }

    fn capture_metadata(file: &File) -> io::Result<PortableMetadataCapture> {
        let info = query(file)?;
        Ok(PortableMetadataCapture {
            metadata: CapturedFileMetadata {
                modified: from_filetime(info.LastWriteTime)?,
                readonly: info.FileAttributes & FILE_ATTRIBUTE_READONLY != 0,
                creation: CapturedTime::Value(from_filetime(info.CreationTime)?),
                unix_executable: CapturedFlag::Unsupported(UnsupportedReason::Platform),
            },
            capabilities: CAPABILITIES,
        })
    }

    pub(super) fn capture(file: &File) -> io::Result<PortableMetadataCapture> {
        capture_metadata(file)
    }

    pub(super) fn apply(
        file: &File,
        requested: &CapturedFileMetadata,
    ) -> io::Result<PortableMetadataApplication> {
        validate_time(requested.modified)?;
        require_supported_time(requested.creation, CAPABILITIES.creation_resolution_nanos)?;
        if matches!(requested.unix_executable, CapturedFlag::Value(_)) {
            return Err(super::unsupported(
                "requested Unix executable bit is not supported on Windows",
            ));
        }
        let current = query(file)?;
        let mut times = current;
        times.LastWriteTime = to_filetime(quantize(
            requested.modified,
            WINDOWS_NTFS_TIME_RESOLUTION_NANOS,
        ))?;
        if let CapturedTime::Value(creation) = requested.creation {
            times.CreationTime =
                to_filetime(quantize(creation, WINDOWS_NTFS_TIME_RESOLUTION_NANOS))?;
        }
        set(file, &times)?;

        let mut attributes = query(file)?;
        if requested.readonly {
            attributes.FileAttributes |= FILE_ATTRIBUTE_READONLY;
        } else {
            attributes.FileAttributes &= !FILE_ATTRIBUTE_READONLY;
        }
        set(file, &attributes)?;

        let observed = capture_metadata(file)?;
        let expected_modified = quantize(requested.modified, WINDOWS_NTFS_TIME_RESOLUTION_NANOS);
        let creation_matches = match requested.creation {
            CapturedTime::Value(creation) => {
                observed.metadata.creation
                    == CapturedTime::Value(quantize(creation, WINDOWS_NTFS_TIME_RESOLUTION_NANOS))
            }
            CapturedTime::Unsupported(_) => true,
        };
        if observed.metadata.modified != expected_modified
            || observed.metadata.readonly != requested.readonly
            || !creation_matches
        {
            return Err(invalid(
                "portable metadata did not survive actual NTFS apply and recheck",
            ));
        }
        Ok(PortableMetadataApplication {
            requested: *requested,
            observed: observed.metadata,
            capabilities: observed.capabilities,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::{
        invalid, quantize, require_supported_time, validate_time, CapturedFileMetadata,
        CapturedFlag, CapturedTime, PortableMetadataApplication, PortableMetadataCapabilities,
        PortableMetadataCapture, PortableTime, UnsupportedReason,
        UNIX_NANOSECOND_TIME_RESOLUTION_NANOS,
    };
    use std::{fs::File, io, os::fd::AsRawFd, os::unix::fs::MetadataExt};

    const CAPABILITIES: PortableMetadataCapabilities = PortableMetadataCapabilities {
        modified_resolution_nanos: UNIX_NANOSECOND_TIME_RESOLUTION_NANOS,
        creation_resolution_nanos: None,
        readonly_supported: true,
        unix_executable_supported: true,
    };

    fn capture_metadata(file: &File) -> io::Result<PortableMetadataCapture> {
        let metadata = file.metadata()?;
        Ok(PortableMetadataCapture {
            metadata: CapturedFileMetadata {
                modified: PortableTime {
                    seconds: metadata.mtime(),
                    nanos: u32::try_from(metadata.mtime_nsec())
                        .map_err(|_| invalid("portable Unix mtime nanoseconds"))?,
                },
                readonly: metadata.mode() & 0o200 == 0,
                creation: CapturedTime::Unsupported(UnsupportedReason::Platform),
                unix_executable: CapturedFlag::Value(metadata.mode() & 0o111 != 0),
            },
            capabilities: CAPABILITIES,
        })
    }

    pub(super) fn capture(file: &File) -> io::Result<PortableMetadataCapture> {
        capture_metadata(file)
    }

    pub(super) fn apply(
        file: &File,
        requested: &CapturedFileMetadata,
    ) -> io::Result<PortableMetadataApplication> {
        validate_time(requested.modified)?;
        require_supported_time(requested.creation, CAPABILITIES.creation_resolution_nanos)?;
        let current = file.metadata()?;
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: requested.modified.seconds,
                tv_nsec: libc::c_long::from(requested.modified.nanos),
            },
        ];
        // SAFETY: file owns a live regular descriptor; times is a valid pair.
        if unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut mode = current.mode() & 0o7777;
        if requested.readonly {
            mode &= !0o222;
        } else {
            mode |= 0o200;
        }
        if let CapturedFlag::Value(executable) = requested.unix_executable {
            if executable {
                mode |= 0o100;
            } else {
                mode &= !0o111;
            }
        }
        // SAFETY: file owns a live regular descriptor; mode is a bounded mode_t.
        if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let observed = capture_metadata(file)?;
        let executable_matches = match requested.unix_executable {
            CapturedFlag::Value(executable) => {
                observed.metadata.unix_executable == CapturedFlag::Value(executable)
            }
            CapturedFlag::Unsupported(_) => true,
        };
        if observed.metadata.modified
            != quantize(requested.modified, UNIX_NANOSECOND_TIME_RESOLUTION_NANOS)
            || observed.metadata.readonly != requested.readonly
            || !executable_matches
        {
            return Err(invalid(
                "portable metadata did not survive actual Unix apply and recheck",
            ));
        }
        Ok(PortableMetadataApplication {
            requested: *requested,
            observed: observed.metadata,
            capabilities: observed.capabilities,
        })
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
mod platform {
    use super::{CapturedFileMetadata, PortableMetadataApplication, PortableMetadataCapture};
    use std::{fs::File, io};

    pub(super) fn capture(_file: &File) -> io::Result<PortableMetadataCapture> {
        Err(super::unsupported(
            "portable file metadata capture is unsupported on this platform",
        ))
    }

    pub(super) fn apply(
        _file: &File,
        _requested: &CapturedFileMetadata,
    ) -> io::Result<PortableMetadataApplication> {
        Err(super::unsupported(
            "portable file metadata apply is unsupported on this platform",
        ))
    }
}

pub fn capture(file: &File) -> io::Result<PortableMetadataCapture> {
    platform::capture(file)
}

/// Applies supported times first, readonly last, then re-observes through the
/// same live handle. This function has no pathname input and never synthesizes
/// a current time after failure.
pub fn apply(
    file: &File,
    requested: &CapturedFileMetadata,
) -> io::Result<PortableMetadataApplication> {
    platform::apply(file, requested)
}
