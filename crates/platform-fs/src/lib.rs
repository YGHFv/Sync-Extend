//! Narrow handle-based filesystem primitives. Application crates forbid unsafe.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
mod unix_noreplace;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use unix_noreplace::{probe_no_replace, NoReplaceProbeReport, UnixFileKey};

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(windows)]
pub use windows::{
    regular_file_link_count, verify_regular_file, GuardedReadFile, LockedDirectory,
    LockedDirectoryMutation, LockedFile, OwnedFileCreation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileKey {
    pub volume: u64,
    pub id: u128,
}

impl std::fmt::Display for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "windows:{}:{}", self.volume, self.id)
    }
}
