//! Portable metadata capture/apply through an already-open file handle.
use crate::{JournalError, Result};
use std::fs::File;
use sync_extend_core_model::{
    PortableEntryMetadata, PortableMetadataUnsupportedReason, PortableReadonly, PortableTimestamp,
    PortableUnixExecutable,
};

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn unsupported_reason(
    reason: sync_extend_platform_fs::UnsupportedReason,
) -> PortableMetadataUnsupportedReason {
    match reason {
        sync_extend_platform_fs::UnsupportedReason::Platform => {
            PortableMetadataUnsupportedReason::Platform
        }
        sync_extend_platform_fs::UnsupportedReason::Filesystem => {
            PortableMetadataUnsupportedReason::Filesystem
        }
        sync_extend_platform_fs::UnsupportedReason::Permission => {
            PortableMetadataUnsupportedReason::Permission
        }
        sync_extend_platform_fs::UnsupportedReason::Api => PortableMetadataUnsupportedReason::Api,
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn portable_time(value: sync_extend_platform_fs::PortableTime) -> Result<PortableTimestamp> {
    Ok(PortableTimestamp::captured(value.seconds, value.nanos)?)
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn portable_captured_time(
    value: sync_extend_platform_fs::CapturedTime,
) -> Result<PortableTimestamp> {
    match value {
        sync_extend_platform_fs::CapturedTime::Unsupported(reason) => {
            Ok(PortableTimestamp::Unsupported {
                reason: unsupported_reason(reason),
            })
        }
        sync_extend_platform_fs::CapturedTime::Value(value) => portable_time(value),
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn portable_captured_flag(value: sync_extend_platform_fs::CapturedFlag) -> PortableUnixExecutable {
    match value {
        sync_extend_platform_fs::CapturedFlag::Unsupported(reason) => {
            PortableUnixExecutable::Unsupported {
                reason: unsupported_reason(reason),
            }
        }
        sync_extend_platform_fs::CapturedFlag::Value(value) => {
            PortableUnixExecutable::captured(value)
        }
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn platform_time(value: PortableTimestamp) -> Result<sync_extend_platform_fs::PortableTime> {
    let (seconds, nanos) = value.captured_value().ok_or(JournalError::Invariant(
        "portable metadata time is not captured",
    ))?;
    Ok(sync_extend_platform_fs::PortableTime { seconds, nanos })
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn platform_unsupported(
    reason: PortableMetadataUnsupportedReason,
) -> sync_extend_platform_fs::UnsupportedReason {
    match reason {
        PortableMetadataUnsupportedReason::Platform => {
            sync_extend_platform_fs::UnsupportedReason::Platform
        }
        PortableMetadataUnsupportedReason::Filesystem => {
            sync_extend_platform_fs::UnsupportedReason::Filesystem
        }
        PortableMetadataUnsupportedReason::Permission => {
            sync_extend_platform_fs::UnsupportedReason::Permission
        }
        PortableMetadataUnsupportedReason::Api => sync_extend_platform_fs::UnsupportedReason::Api,
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn platform_captured_time(
    value: PortableTimestamp,
) -> Result<sync_extend_platform_fs::CapturedTime> {
    match value {
        PortableTimestamp::Captured { .. } => Ok(sync_extend_platform_fs::CapturedTime::Value(
            platform_time(value)?,
        )),
        PortableTimestamp::Unsupported { reason } => Ok(
            sync_extend_platform_fs::CapturedTime::Unsupported(platform_unsupported(reason)),
        ),
        PortableTimestamp::Unknown => {
            Err(JournalError::Invariant("portable metadata time is unknown"))
        }
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn platform_captured_flag(value: PortableUnixExecutable) -> sync_extend_platform_fs::CapturedFlag {
    match value {
        PortableUnixExecutable::Captured { executable } => {
            sync_extend_platform_fs::CapturedFlag::Value(executable)
        }
        PortableUnixExecutable::Unsupported { reason } => {
            sync_extend_platform_fs::CapturedFlag::Unsupported(platform_unsupported(reason))
        }
        PortableUnixExecutable::Unknown => sync_extend_platform_fs::CapturedFlag::Unsupported(
            sync_extend_platform_fs::UnsupportedReason::Api,
        ),
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
pub(crate) fn capture(file: &File) -> Result<Option<PortableEntryMetadata>> {
    let capture = sync_extend_platform_fs::capture_portable_file_metadata(file)?;
    let mut metadata = PortableEntryMetadata::new(
        portable_time(capture.metadata.modified)?,
        PortableReadonly::captured(capture.metadata.readonly),
    );
    metadata.creation = Some(portable_captured_time(capture.metadata.creation)?);
    metadata.unix_executable = Some(portable_captured_flag(capture.metadata.unix_executable));
    metadata.validate()?;
    Ok(Some(metadata))
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
pub(crate) fn apply(file: &File, metadata: &PortableEntryMetadata) -> Result<()> {
    metadata.validate()?;
    let requested = sync_extend_platform_fs::CapturedFileMetadata {
        modified: platform_time(metadata.modified)?,
        readonly: metadata.readonly.value().ok_or(JournalError::Invariant(
            "portable readonly metadata is unknown",
        ))?,
        creation: metadata
            .creation
            .map(platform_captured_time)
            .transpose()?
            .unwrap_or(sync_extend_platform_fs::CapturedTime::Unsupported(
                sync_extend_platform_fs::UnsupportedReason::Api,
            )),
        unix_executable: metadata
            .unix_executable
            .map(platform_captured_flag)
            .unwrap_or(sync_extend_platform_fs::CapturedFlag::Unsupported(
                sync_extend_platform_fs::UnsupportedReason::Api,
            )),
    };
    sync_extend_platform_fs::apply_portable_file_metadata(file, &requested)?;
    let observed = capture(file)?.ok_or(JournalError::Invariant(
        "portable metadata capture unavailable",
    ))?;
    if !metadata.matches_observed(&observed) {
        return Err(JournalError::Invariant(
            "portable metadata did not survive apply recheck",
        ));
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub(crate) fn capture(_file: &File) -> Result<Option<PortableEntryMetadata>> {
    Ok(None)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub(crate) fn apply(_file: &File, _metadata: &PortableEntryMetadata) -> Result<()> {
    Err(JournalError::Invariant(
        "portable metadata apply is unsupported on this platform",
    ))
}
