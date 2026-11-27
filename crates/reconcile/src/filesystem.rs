use crate::{check_ancestors, ReconcileError, Result};
use same_file::Handle;
use std::{
    fs::{self, File, Metadata},
    path::Path,
};
use sync_extend_cas::is_reparse;
use sync_extend_core_model::{
    ContentId, PortableEntryMetadata, PortableMetadataUnsupportedReason, PortableReadonly,
    PortableTimestamp, PortableUnixExecutable,
};

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn portable_unsupported_reason(
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
    PortableTimestamp::captured(value.seconds, value.nanos).map_err(Into::into)
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn portable_captured_time(
    value: sync_extend_platform_fs::CapturedTime,
) -> Result<PortableTimestamp> {
    match value {
        sync_extend_platform_fs::CapturedTime::Unsupported(reason) => {
            Ok(PortableTimestamp::Unsupported {
                reason: portable_unsupported_reason(reason),
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
                reason: portable_unsupported_reason(reason),
            }
        }
        sync_extend_platform_fs::CapturedFlag::Value(value) => {
            PortableUnixExecutable::captured(value)
        }
    }
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
pub(crate) fn portable_metadata(file: &File) -> Result<Option<PortableEntryMetadata>> {
    let capture = sync_extend_platform_fs::capture_portable_file_metadata(file)?;
    Ok(Some(portable_metadata_from_capture(capture)?))
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
pub(crate) fn portable_metadata_from_capture(
    capture: sync_extend_platform_fs::PortableMetadataCapture,
) -> Result<PortableEntryMetadata> {
    let mut metadata = PortableEntryMetadata::new(
        portable_time(capture.metadata.modified)?,
        PortableReadonly::captured(capture.metadata.readonly),
    );
    metadata.creation = Some(portable_captured_time(capture.metadata.creation)?);
    metadata.unix_executable = Some(portable_captured_flag(capture.metadata.unix_executable));
    metadata.validate()?;
    Ok(metadata)
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn platform_time(value: PortableTimestamp) -> Result<sync_extend_platform_fs::PortableTime> {
    let (seconds, nanos) = value.captured_value().ok_or(ReconcileError::Invariant(
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
        PortableTimestamp::Unknown => Err(ReconcileError::Invariant(
            "portable metadata time is unknown",
        )),
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
pub(crate) fn platform_metadata_for_apply(
    metadata: &PortableEntryMetadata,
) -> Result<sync_extend_platform_fs::CapturedFileMetadata> {
    metadata.validate()?;
    Ok(sync_extend_platform_fs::CapturedFileMetadata {
        modified: platform_time(metadata.modified)?,
        readonly: metadata.readonly.value().ok_or(ReconcileError::Invariant(
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
    })
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
pub(crate) fn apply_portable_metadata(file: &File, metadata: &PortableEntryMetadata) -> Result<()> {
    let requested = platform_metadata_for_apply(metadata)?;
    sync_extend_platform_fs::apply_portable_file_metadata(file, &requested)?;
    let observed = portable_metadata(file)?.ok_or(ReconcileError::Invariant(
        "portable metadata capture unavailable",
    ))?;
    if !metadata_matches_observed(metadata, &observed) {
        return Err(ReconcileError::Unstable);
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub(crate) fn portable_metadata(_file: &File) -> Result<Option<PortableEntryMetadata>> {
    Ok(None)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub(crate) fn platform_metadata_for_apply(
    _metadata: &PortableEntryMetadata,
) -> Result<sync_extend_platform_fs::CapturedFileMetadata> {
    Err(ReconcileError::Invariant(
        "portable metadata apply is unsupported on this platform",
    ))
}

pub(crate) fn metadata_matches_observed(
    expected: &PortableEntryMetadata,
    observed: &PortableEntryMetadata,
) -> bool {
    expected.matches_observed(observed)
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
pub(crate) fn apply_portable_metadata(
    _file: &File,
    _metadata: &PortableEntryMetadata,
) -> Result<()> {
    Err(ReconcileError::Invariant(
        "portable metadata apply is unsupported on this platform",
    ))
}

pub(crate) struct PathIdentity {
    handle: Handle,
    pub(crate) physical: ContentId,
}

impl PathIdentity {
    #[cfg(windows)]
    pub(crate) fn close_stopped_capture(
        self,
        attempt: &mut sync_extend_platform_fs::WindowsOriginalCloseAttempt,
    ) {
        let _ = self.close_original_into_attempt(attempt);
    }

    #[cfg(windows)]
    pub(crate) fn close_original_into_attempt(
        self,
        attempt: &mut sync_extend_platform_fs::WindowsOriginalCloseAttempt,
    ) -> ContentId {
        let Self { handle, physical } = self;
        attempt.close_identity_handle(handle);
        physical
    }

    #[cfg(windows)]
    pub(crate) fn capture_original_into_attempt(
        path: &Path,
        attempt: &mut sync_extend_platform_fs::WindowsOriginalCloseAttempt,
    ) -> Result<Self> {
        let mut original = None;
        let mut observer = None;
        let mut physical = None;
        let prepared = (|| -> Result<()> {
            check_ancestors(path)?;
            original = Some(Handle::from_path(path)?);
            physical = Some(physical_identity(path)?);
            check_ancestors(path)?;
            observer = Some(Handle::from_path(path)?);
            if original.as_ref() != observer.as_ref()
                || physical.as_ref() != Some(&physical_identity(path)?)
            {
                return Err(ReconcileError::Unstable);
            }
            Ok(())
        })();
        if let Some(observer) = observer.take() {
            attempt.close_identity_handle(observer);
        }
        if let Err(error) = prepared {
            if let Some(original) = original.take() {
                attempt.close_identity_handle(original);
            }
            return Err(error);
        }
        if attempt.has_retained_originals() {
            if let Some(original) = original.take() {
                attempt.close_identity_handle(original);
            }
            return Err(ReconcileError::Invariant(
                "original identity observation terminal remains incomplete",
            ));
        }
        Ok(Self {
            handle: original
                .take()
                .expect("prepared same original identity handle"),
            physical: physical
                .take()
                .expect("prepared original physical identity"),
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn original_descriptor(&self) -> &File {
        self.handle.as_file()
    }

    pub(crate) fn capture(path: &Path) -> Result<Self> {
        check_ancestors(path)?;
        let handle = Handle::from_path(path)?;
        let physical = physical_identity(path)?;
        let identity = Self { handle, physical };
        identity.verify(path)?;
        Ok(identity)
    }

    pub(crate) fn verify(&self, path: &Path) -> Result<()> {
        check_ancestors(path)?;
        if self.handle != Handle::from_path(path)? || self.physical != physical_identity(path)? {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }
}

pub(crate) struct ObservedFile {
    pub(crate) file: File,
    pub(crate) identity: PathIdentity,
    pub(crate) metadata: Metadata,
    pub(crate) portable: Option<PortableEntryMetadata>,
}

impl ObservedFile {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        check_ancestors(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(ReconcileError::Invariant(
                "expected a regular non-link file",
            ));
        }
        let physical = physical_identity(path)?;
        let file = File::open(path)?;
        let handle = Handle::from_file(file.try_clone()?)?;
        let portable = portable_metadata(&file)?;
        let observed = Self {
            file,
            identity: PathIdentity { handle, physical },
            metadata,
            portable,
        };
        observed.verify(path)?;
        Ok(observed)
    }

    pub(crate) fn verify(&self, path: &Path) -> Result<()> {
        self.identity.verify(path)?;
        if !same_metadata(&self.metadata, &self.file.metadata()?)
            || !same_metadata(&self.metadata, &fs::symlink_metadata(path)?)
            || portable_metadata(&self.file)? != self.portable
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }
}

pub(crate) fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    a.len() == b.len()
        && a.modified()
            .ok()
            .zip(b.modified().ok())
            .is_some_and(|(a, b)| a == b)
        && a.file_type() == b.file_type()
        && !b.file_type().is_symlink()
        && !is_reparse(b)
}

pub(crate) fn physical_identity(path: &Path) -> Result<ContentId> {
    check_ancestors(path)?;
    let id = file_id::get_file_id(path)?;
    let text = match id {
        file_id::FileId::Inode {
            device_id,
            inode_number,
        } => format!("inode:{device_id}:{inode_number}"),
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => format!("windows:{volume_serial_number}:{file_id}"),
        file_id::FileId::LowRes { .. } => {
            return Err(ReconcileError::Invariant(
                "high-resolution Windows file identity is unavailable",
            ))
        }
    };
    Ok(ContentId::hash(text.as_bytes()))
}
