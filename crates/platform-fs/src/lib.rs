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
pub use unix_sqlite_ledger::{
    UnixSqliteLedger, UnixSqliteLedgerClosed, UnixSqliteLedgerConnection,
    UnixSqliteLedgerFileObservation, UnixSqliteLedgerObservation,
};

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod readonly_journal;
#[cfg(target_os = "linux")]
pub use readonly_journal::{ReadOnlyControlInput, ReadOnlyJournalFiles};

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
    LinuxStorageCas, LinuxStorageCasCoordination, LinuxStorageCasCoordinationGuard,
    LinuxStorageCasCoordinationLoan, LinuxStorageCasDirectoryGuard, LinuxStorageCasExpectedLayout,
    LinuxStorageCasFileGuard, LinuxStorageCasFileObservation, LinuxStorageCasInventory,
    LinuxStorageCasLimits, LinuxStorageCasObservation, LinuxStorageCasStaged,
    LinuxStorageOutsideFileClosed, LinuxStorageRetirementBoundary,
    LinuxStorageRetirementClosedBoundary, LinuxStorageRetirementClosedObservation,
    LinuxStorageRetirementCreatorReceipt, LinuxStorageRetirementInventoryContext,
    LinuxStorageRetirementInventoryPhase, LinuxStorageRetirementInventoryPrefix,
    LinuxStorageRetirementMarkerObservation, LinuxStorageRetirementMarkerUnlinkObservation,
    LinuxStorageRetirementMoveObservation, LinuxStorageRetirementPayloadSlot,
    LinuxStorageRetirementUnlinkObservation, OriginalCreateAllocationObservation,
    OriginalCreateVacatedObservation, OriginalOutsideIntent, OriginalPairFrozenObservation,
    OriginalPrivateMountTopologyObservation, OriginalPrivateVolumeFile, OriginalRetainedVolumeFile,
    OutsidePrivateIntentOwner, PreparedOriginalPairFreeze,
};

/// A borrow of the same original description after a successful exclusive
/// flock. Only the actual coordination guard can issue this value.
#[cfg(target_os = "linux")]
pub struct LinuxStorageCasExclusiveCoordination<'a> {
    pub(crate) guard: &'a LinuxStorageCasCoordinationGuard,
}

/// Owns one original payload FD and its mandatory lease. Every inspection
/// operation also requires a borrow of the original exclusive description
/// that acquired it; matching keys on a reopened description are insufficient.
#[cfg(target_os = "linux")]
pub struct LinuxStorageCasRetirementInspection {
    pub(crate) original: LinuxStorageCasFileGuard,
    pub(crate) possession: std::sync::Arc<()>,
    pub(crate) layout: LinuxStorageCasObservation,
}

#[cfg(target_os = "linux")]
mod publication_epoch;
#[cfg(target_os = "linux")]
pub use publication_epoch::{
    LinuxPendingSuccessor, LinuxPublicationEpoch, LinuxPublicationWorktreeIdentity,
    LinuxPublicationWorktreeLock,
};

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux_write_lease;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod protected_artifact_unix;
#[cfg(windows)]
#[allow(unsafe_code)]
mod windows;
#[cfg(target_os = "linux")]
pub use protected_artifact_unix::{
    SealedUnixProtectedArtifact, UnixFailedArtifactCreation, UnixProtectedArtifactCreateFailure,
    UnixProtectedArtifactCreator, UnixProtectedArtifactKey, UnixProtectedArtifactParent,
    UnixProtectedArtifactSealFailure, UnixProtectedArtifactSource,
};
#[cfg(windows)]
pub use windows::{
    regular_file_link_count, regular_file_matches_path, sqlite_main_file_identity,
    verify_regular_file, FreshExclusiveSqliteFile, GuardedReadFile, LockedDirectory,
    LockedDirectoryMutation, LockedFile, OriginalDirectoryCreation, OriginalFileCreation,
    OriginalFileSealFailure, OwnedFileCreation, PublishedOriginalFile, ReacquiredNodeFile,
    ReacquiredNodeLock, ReleasedOriginalCoordinationFile, ReleasedOriginalFileIdentity,
    ReleasedOriginalReadFile, RetainedWriterDirectory, SealedOriginalFile,
};
#[cfg(windows)]
pub use windows::{
    SealedWindowsProtectedArtifact, WindowsFailedArtifactCreation,
    WindowsProtectedArtifactCreateFailure, WindowsProtectedArtifactCreator,
    WindowsProtectedArtifactParent, WindowsProtectedArtifactSealFailure,
};

#[cfg(windows)]
#[allow(unsafe_code)]
mod original_resource_close;
#[cfg(windows)]
pub use original_resource_close::{
    close_original_tcp_listener, close_original_tcp_stream, ClosedWindowsOriginalResources,
    ClosedWindowsOriginalSocket, OriginalDeploymentOwnerInput, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure, WindowsOriginalResourceOpenFailure,
};
#[cfg(windows)]
pub use writer_owner::{
    WriterCaptureCloseFailure, WriterCaptureOpenFailure, WriterOriginalCreationFailure,
};

#[allow(unsafe_code)]
mod managed_process;
pub use managed_process::{read_available, ManagedChild};

#[allow(unsafe_code)]
mod managed_rpc;
pub use managed_rpc::{ManagedRpcBinding, ManagedRpcOwner};

#[allow(unsafe_code)]
mod portable_metadata;
pub use portable_metadata::{
    apply as apply_portable_file_metadata, capture as capture_portable_file_metadata,
    CapturedFileMetadata, CapturedFlag, CapturedTime, PortableMetadataApplication,
    PortableMetadataCapabilities, PortableMetadataCapture, PortableTime, UnsupportedReason,
    UNIX_NANOSECOND_TIME_RESOLUTION_NANOS, WINDOWS_NTFS_TIME_RESOLUTION_NANOS,
};

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
    OriginalReadonlySqliteCloseFailure, OriginalReadonlySqliteConnection,
    OriginalReadonlySqliteOpenFailure, OriginalSqliteConnection, OriginalSqliteOpenFailure,
    OriginalSqliteQuery, OriginalSqliteReadBudget, OriginalSqliteResourceCloseFailure,
    OriginalSqliteRows, OriginalSqliteStatement, OriginalSqliteValue,
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
pub use windows::{
    FreshNativeWalCloseFailure, FreshNativeWalConnection, FreshNativeWalOpenFailure,
    FRESH_NATIVE_WAL_SHM_CAPACITY,
};

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
