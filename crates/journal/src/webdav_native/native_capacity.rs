//! Native logical peak is independent of SQLite row/byte reservations.
use crate::{JournalError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
    Manifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativePeak {
    pub additional_namespace_paths: u64,
    pub additional_directory_objects: u64,
    pub additional_file_objects: u64,
    pub additional_logical_file_bytes: u64,
    pub prospective_namespace_paths: u64,
    pub payload_file_lengths: Vec<u64>,
}
fn invalid() -> JournalError {
    JournalError::Invariant("complete original DAV native object and byte peak")
}
impl NativePeak {
    pub(super) fn derive(baseline: &Manifest, plan: &WebDavNativePlan) -> Result<Self> {
        let mut directories = 2_u64;
        let mut paths = 3_u64;
        let mut payload_file_lengths = vec![97];
        let mut logical = 97_u64;
        for step in plan.steps() {
            match &step.action {
                WebDavNativeAction::QuarantineOriginal { .. } => {
                    paths = paths.checked_add(1).ok_or_else(invalid)?
                }
                WebDavNativeAction::CreateDirectory { .. } => {
                    directories = directories.checked_add(1).ok_or_else(invalid)?;
                    paths = paths.checked_add(1).ok_or_else(invalid)?;
                }
                WebDavNativeAction::PublishFile { entry } => {
                    let length = entry.content.as_ref().ok_or_else(invalid)?.length;
                    payload_file_lengths.push(length);
                    logical = logical.checked_add(length).ok_or_else(invalid)?;
                    paths = paths.checked_add(2).ok_or_else(invalid)?;
                }
                _ => {}
            }
        }
        // Existing root and exact marker directory + space-id + writer.lock.
        let prospective_namespace_paths = (baseline.entries.len() as u64)
            .checked_add(4)
            .and_then(|count| count.checked_add(paths))
            .ok_or_else(invalid)?;
        Ok(Self {
            additional_namespace_paths: paths,
            additional_directory_objects: directories,
            additional_file_objects: payload_file_lengths.len() as u64,
            additional_logical_file_bytes: logical,
            prospective_namespace_paths,
            payload_file_lengths,
        })
    }
    #[cfg(windows)]
    pub(super) fn allocation_peak(&self, unit: u64) -> Result<u64> {
        if unit == 0 {
            return Err(invalid());
        }
        let file_bytes = self
            .payload_file_lengths
            .iter()
            .try_fold(0_u64, |sum, length| {
                let allocated = length
                    .checked_add(unit - 1)
                    .and_then(|value| value.checked_div(unit))
                    .and_then(|value| value.checked_mul(unit))
                    .ok_or_else(invalid)?;
                sum.checked_add(allocated).ok_or_else(invalid)
            })?;
        // Two allocation units per path cover explicit object bookkeeping conservatively.
        // This is admission headroom, never a guarantee against external volume consumers.
        file_bytes
            .checked_add(
                self.additional_namespace_paths
                    .checked_mul(unit)
                    .and_then(|value| value.checked_mul(2))
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)
    }
}

/// Independent immutable native handles, separate from namespace and SQL rows.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeHandles {
    pub original_objects: u64,
    pub process_owner_handles: u64,
    pub additional_creator_handles: u64,
    pub transient_seal_handles: u64,
    pub maximum_live_handles: u64,
    pub admission_limit: u64,
}
impl NativeHandles {
    pub(super) fn derive(
        bindings: &[super::initial_binding::InitialHeldBinding],
        native: &NativePeak,
        admission_limit: usize,
    ) -> Result<Self> {
        use super::initial_binding::InitialBindingRole as R;
        let find = |role: fn(&R) -> bool| -> Result<&std::path::Path> {
            let mut found = bindings.iter().filter(|binding| role(&binding.role));
            let first = found.next().ok_or_else(invalid)?;
            if found.next().is_some() {
                return Err(invalid());
            }
            Ok(std::path::Path::new(&first.absolute_path))
        };
        let data = find(|role| matches!(role, R::DataRoot))?;
        let worktree_owner = find(|role| matches!(role, R::MarkerDirectory))?;
        if !data.is_absolute()
            || !worktree_owner.is_absolute()
            || admission_limit == 0
            || admission_limit > crate::limits::MAX_ENTRIES
        {
            return Err(invalid());
        }
        // WriterOwner holds its lock file plus every actual absolute ancestor.
        let process_owner_handles = (data.ancestors().count() as u64)
            .checked_add(worktree_owner.ancestors().count() as u64)
            .and_then(|count| count.checked_add(2))
            .ok_or_else(invalid)?;
        let original_objects = bindings.len() as u64;
        let additional_creator_handles = native
            .additional_directory_objects
            .checked_add(native.additional_file_objects)
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(invalid)?;
        // seal_original keeps one reduced-right duplicate live while closing
        // its original writer. Only one serial marker/payload is sealed at once.
        let transient_seal_handles = u64::from(native.additional_file_objects != 0);
        let maximum_live_handles = original_objects
            .checked_add(process_owner_handles)
            .and_then(|count| count.checked_add(additional_creator_handles))
            .and_then(|count| count.checked_add(transient_seal_handles))
            .ok_or_else(invalid)?;
        if maximum_live_handles > admission_limit as u64 {
            return Err(invalid());
        }
        Ok(Self {
            original_objects,
            process_owner_handles,
            additional_creator_handles,
            transient_seal_handles,
            maximum_live_handles,
            admission_limit: admission_limit as u64,
        })
    }
}

#[cfg(windows)]
pub(super) fn rounded_allocation(length: u64, unit: u64) -> Result<u64> {
    if unit == 0 {
        return Err(invalid());
    }
    length
        .checked_add(unit - 1)
        .and_then(|value| value.checked_div(unit))
        .and_then(|value| value.checked_mul(unit))
        .ok_or_else(invalid)
}
