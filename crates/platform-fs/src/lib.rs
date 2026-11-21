//! Narrow handle-based filesystem primitives. Application crates forbid unsafe.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
mod unix_noreplace;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use unix_noreplace::{
    acquire_sidecar_owner, create_anonymous_upload, probe_no_replace, NoReplaceProbeReport,
    UnixFileKey,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
mod unix_sqlite_ledger;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use unix_sqlite_ledger::{UnixSqliteLedger, UnixSqliteLedgerConnection};

#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
mod local_control;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use local_control::{
    request_local_control, LocalControlConnection, LocalControlListener, LocalControlOperation,
    LocalControlResponse,
};

#[cfg(target_os = "linux")]
pub use unix_noreplace::{
    HeldPrivateDirectory, HeldPrivateOriginal, HeldPrivateVolume, LinuxCleanupAbsenceObservation,
    LinuxMetadataBudget, LinuxMetadataFileReceipt, LinuxMetadataLimits, LinuxMetadataReceipt,
    LinuxMetadataVfs, LinuxNamespaceCapability, LinuxNativeAttempt, LinuxOutsideCleanupBoundary,
    OriginalCreateAllocationObservation, OriginalCreateVacatedObservation, OriginalOutsideIntent,
    OriginalPairFrozenObservation, OriginalPrivateMountTopologyObservation,
    OriginalPrivateVolumeFile, OriginalRetainedVolumeFile, OutsidePrivateIntentOwner,
    PreparedOriginalPairFreeze,
};

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux_write_lease;

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(windows)]
pub use windows::{
    regular_file_link_count, regular_file_matches_path, sqlite_main_file_identity,
    verify_regular_file, FreshExclusiveSqliteFile, GuardedReadFile, LockedDirectory,
    LockedDirectoryMutation, LockedFile, OriginalDirectoryCreation, OriginalFileCreation,
    OwnedFileCreation, PublishedOriginalFile, ReacquiredNodeFile, ReacquiredNodeLock,
    ReleasedOriginalCoordinationFile, ReleasedOriginalFileIdentity, ReleasedOriginalReadFile,
    RetainedWriterDirectory, SealedOriginalFile,
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
mod held_disk_space;
#[cfg(windows)]
pub use held_disk_space::{held_disk_space, HeldDiskSpace};
mod writer_owner;
pub use writer_owner::WriterOwner;

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

#[cfg(windows)]
pub use windows::{sqlite_main_exact_bytes, sqlite_retain_actual_wal, sqlite_wal_file_identity};

#[cfg(windows)]
pub use windows::{
    OriginalSqliteMainHandoff, OriginalSqliteMainHandoffFailure, OriginalSqliteSidecarHandoff,
    OriginalSqliteSidecarHandoffFailure, OriginalSqliteSidecarKind,
};

#[cfg(windows)]
pub use windows::{
    OriginalSqliteConnection, OriginalSqliteOpenFailure, OriginalSqliteQuery,
    OriginalSqliteReadBudget, OriginalSqliteRows, OriginalSqliteStatement, OriginalSqliteValue,
};

#[cfg(windows)]
pub use windows::capture_current_user_private_acl;
#[cfg(windows)]
pub use windows::verify_current_user_private_file;

#[cfg(windows)]
pub use windows::FreshNativeSqliteConnection;

#[cfg(windows)]
pub use windows::FreshNativeRetentionLease;
#[cfg(windows)]
pub use windows::FreshNativeWalConnection;

#[cfg(windows)]
pub use windows::FreshRecoveredMutationFile;

#[cfg(windows)]
pub use windows::{
    OriginalSqlitePayloadAllocation, OriginalSqlitePayloadAllocationBounds,
    OriginalSqlitePayloadAllocationFailure,
};

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux_guardian;
#[cfg(target_os = "linux")]
pub use linux_guardian::{
    take_inherited_descriptor, OriginalPairTerminalRelease, OutsideGuardian, OutsideHelperChild,
    OutsideHelperExitObservation, OutsideHelperProgram, OutsideHelperSession,
    OutsidePreparationGate, OutsidePreparationPair, OutsideSupervisor, ThawObservation,
};
