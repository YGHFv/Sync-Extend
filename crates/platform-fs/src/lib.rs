//! Narrow handle-based filesystem primitives. Application crates forbid unsafe.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
mod unix_noreplace;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use unix_noreplace::{
    acquire_sidecar_owner, create_anonymous_upload, probe_no_replace, NoReplaceProbeReport,
    UnixFileKey,
};

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(windows)]
pub use windows::{
    regular_file_link_count, regular_file_matches_path, verify_regular_file, GuardedReadFile,
    LockedDirectory, LockedDirectoryMutation, LockedFile, OriginalDirectoryCreation,
    OriginalFileCreation, OwnedFileCreation,
};

#[allow(unsafe_code)]
mod managed_process;
pub use managed_process::{read_available, ManagedChild};

#[allow(unsafe_code)]
mod pinned_program;
pub use pinned_program::PinnedProgram;

#[allow(unsafe_code)]
mod sidecar_config;
pub use sidecar_config::SidecarConfig;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows_service;
#[cfg(windows)]
pub use windows_service::{
    report_service_ready, run_windows_service, service_stop_requested, ServiceReporter,
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
