use crate::{ModelError, Result};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PORTABLE_ENTRY_METADATA_VERSION: u32 = 1;
pub const MAX_PORTABLE_ENTRY_METADATA_BYTES: usize = 4096;
pub const PORTABLE_METADATA_CAPABILITY_VERSION: u32 = 1;

/// A bounded, signed Unix timestamp. Negative seconds are real pre-epoch
/// values, not an unknown marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableTimestamp {
    Unknown,
    Unsupported {
        reason: PortableMetadataUnsupportedReason,
    },
    Captured {
        seconds: i64,
        nanos: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableMetadataUnsupportedReason {
    Platform,
    Filesystem,
    Permission,
    Api,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableReadonly {
    Unknown,
    False,
    True,
}

impl PortableReadonly {
    pub fn captured(value: bool) -> Self {
        if value {
            Self::True
        } else {
            Self::False
        }
    }

    pub fn value(self) -> Option<bool> {
        match self {
            Self::Unknown => None,
            Self::False => Some(false),
            Self::True => Some(true),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableUnixExecutable {
    Unknown,
    Unsupported {
        reason: PortableMetadataUnsupportedReason,
    },
    Captured {
        executable: bool,
    },
}

/// Portable file metadata stored in signed Entry history. ACLs, alternate data
/// streams, EFS, UID/GID and raw platform mode are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEntryMetadata {
    pub format_version: u32,
    pub modified: PortableTimestamp,
    pub readonly: PortableReadonly,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation: Option<PortableTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_executable: Option<PortableUnixExecutable>,
}

impl PortableTimestamp {
    pub fn captured(seconds: i64, nanos: u32) -> Result<Self> {
        if nanos >= 1_000_000_000 {
            return Err(ModelError::InvalidData(
                "portable timestamp nanoseconds out of range",
            ));
        }
        Ok(Self::Captured { seconds, nanos })
    }

    pub fn from_system_time(value: SystemTime) -> Result<Self> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let seconds = i64::try_from(duration.as_secs()).map_err(|_| {
                    ModelError::InvalidData("portable timestamp seconds out of range")
                })?;
                Self::captured(seconds, duration.subsec_nanos())
            }
            Err(error) => {
                let duration = error.duration();
                if duration.subsec_nanos() == 0 {
                    let seconds = i64::try_from(duration.as_secs()).map_err(|_| {
                        ModelError::InvalidData("portable timestamp seconds out of range")
                    })?;
                    Self::captured(
                        seconds.checked_neg().ok_or(ModelError::InvalidData(
                            "portable timestamp seconds out of range",
                        ))?,
                        0,
                    )
                } else {
                    let whole = i64::try_from(duration.as_secs())
                        .ok()
                        .and_then(|seconds| seconds.checked_add(1))
                        .and_then(|seconds| seconds.checked_neg())
                        .ok_or(ModelError::InvalidData(
                            "portable timestamp seconds out of range",
                        ))?;
                    Self::captured(whole, 1_000_000_000 - duration.subsec_nanos())
                }
            }
        }
    }

    pub fn to_system_time(self) -> Option<SystemTime> {
        let Self::Captured { seconds, nanos } = self else {
            return None;
        };
        if nanos >= 1_000_000_000 {
            return None;
        }
        if seconds >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(seconds as u64, nanos))
        } else {
            let before = seconds.checked_neg()? as u64;
            let duration = if nanos == 0 {
                Duration::new(before, 0)
            } else {
                Duration::new(before.checked_sub(1)?, 1_000_000_000 - nanos)
            };
            UNIX_EPOCH.checked_sub(duration)
        }
    }

    pub fn captured_value(self) -> Option<(i64, u32)> {
        match self {
            Self::Captured { seconds, nanos } => Some((seconds, nanos)),
            Self::Unknown | Self::Unsupported { .. } => None,
        }
    }
}

impl PortableUnixExecutable {
    pub fn captured(value: bool) -> Self {
        Self::Captured { executable: value }
    }

    pub fn value(self) -> Option<bool> {
        match self {
            Self::Captured { executable } => Some(executable),
            Self::Unknown | Self::Unsupported { .. } => None,
        }
    }
}

impl PortableEntryMetadata {
    pub fn new(modified: PortableTimestamp, readonly: PortableReadonly) -> Self {
        Self {
            format_version: PORTABLE_ENTRY_METADATA_VERSION,
            modified,
            readonly,
            creation: None,
            unix_executable: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.format_version != PORTABLE_ENTRY_METADATA_VERSION {
            return Err(ModelError::InvalidData(
                "unsupported portable entry metadata version",
            ));
        }
        validate_timestamp(self.modified)?;
        if let Some(creation) = self.creation {
            validate_timestamp(creation)?;
        }
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_PORTABLE_ENTRY_METADATA_BYTES {
            return Err(ModelError::InvalidData(
                "portable entry metadata byte limit",
            ));
        }
        Ok(())
    }

    /// Projects only values that were actually captured. Unknown or
    /// unsupported fields stay absent instead of being synthesized.
    pub fn captured_modified_and_readonly(&self) -> Option<(i64, u32, bool)> {
        let (seconds, nanos) = self.modified.captured_value()?;
        let readonly = self.readonly.value()?;
        Some((seconds, nanos, readonly))
    }
}

/// A field's implemented support on the running platform. `Supported` means
/// the capture/apply/verify routine exists; it does not certify every
/// filesystem. `Unknown` is used where this release has no actual result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableMetadataSupport {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableMetadataFieldCapability {
    pub modified: PortableMetadataSupport,
    pub creation: PortableMetadataSupport,
    pub readonly: PortableMetadataSupport,
    pub unix_executable: PortableMetadataSupport,
}

/// Reasons are disclosed only for fields this build cannot handle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableMetadataUnsupportedFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation: Option<PortableMetadataUnsupportedReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_executable: Option<PortableMetadataUnsupportedReason>,
}

impl PortableMetadataUnsupportedFields {
    pub fn none() -> Self {
        Self {
            creation: None,
            unix_executable: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.creation.is_none() && self.unix_executable.is_none()
    }
}

/// Names the exact platform evidence that backs the capability matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortableMetadataCertification {
    WindowsNtfsActualGroupedAcceptance,
    UnixImplementedNotVerifiedInThisRelease,
    UnsupportedPlatform,
}

/// Bounded, versioned disclosure for diagnostics and read-only dashboard
/// clients. It never grants native authority and never claims that a
/// particular file was applied or verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableMetadataCapabilityMatrix {
    pub format_version: u32,
    pub capture: PortableMetadataFieldCapability,
    pub apply: PortableMetadataFieldCapability,
    pub verify: PortableMetadataFieldCapability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_precision_ns: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "PortableMetadataUnsupportedFields::is_empty"
    )]
    pub unsupported: PortableMetadataUnsupportedFields,
    pub certification: PortableMetadataCertification,
}

impl PortableMetadataCapabilityMatrix {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != PORTABLE_METADATA_CAPABILITY_VERSION {
            return Err(ModelError::InvalidData(
                "unsupported portable metadata capability version",
            ));
        }
        if let Some(precision) = self.timestamp_precision_ns {
            if precision == 0 || precision > 1_000_000_000 {
                return Err(ModelError::InvalidData(
                    "portable metadata timestamp precision out of range",
                ));
            }
        }
        Ok(())
    }
}

fn validate_timestamp(value: PortableTimestamp) -> Result<()> {
    if let PortableTimestamp::Captured { nanos, .. } = value {
        if nanos >= 1_000_000_000 {
            return Err(ModelError::InvalidData(
                "portable timestamp nanoseconds out of range",
            ));
        }
    }
    Ok(())
}
