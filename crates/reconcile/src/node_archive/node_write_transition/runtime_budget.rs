//! Shared native gates and conservative per-allocation runtime liabilities.
use crate::{ReconcileError, Result};

pub(crate) const ORIGINAL_WRITE_SIDECAR_LIMIT: u64 = 8 * 1024 * 1024;
pub(crate) const ORIGINAL_WRITE_MAIN_GROWTH: u64 = 8 * 1024 * 1024;
pub(crate) const ORIGINAL_WRITE_MAIN_MAXIMUM: u64 = 256 * 1024 * 1024;
pub(crate) const ORIGINAL_WRITE_FRAMES_MAXIMUM: u64 = 1024 * 1024;
pub(crate) const ORIGINAL_WRITE_OWNER_MAXIMUM: u64 = 65536;
pub(crate) const ORIGINAL_WRITE_FILE_MAXIMUM: u64 = 8 * 1024 * 1024;
pub(crate) const ORIGINAL_WRITE_OPERATION_MAXIMUM: usize = 128;
pub(crate) const ORIGINAL_WRITE_CAS_EVIDENCE_MAXIMUM: usize = 1024;
pub(crate) const ORIGINAL_WRITE_CAS_RECEIPT_MAXIMUM: u64 = 64 * 1024;
pub(crate) const ORIGINAL_WRITE_RECEIPT_MAXIMUM: u64 = 256 * 1024;
pub(crate) const FRESH_HISTORY_GENERATION_MAXIMUM: usize = 64;
pub(crate) const FRESH_OPERATION_MAXIMUM: u32 = 128;
pub(crate) const FRESH_CONTENT_AGGREGATE_MAXIMUM: u64 = 64 * 1024 * 1024;
pub(crate) const FRESH_RECEIPT_AGGREGATE_MAXIMUM: u64 = 4 * 1024 * 1024;
pub(crate) const FRESH_RECEIPT_COUNT_MAXIMUM: usize = 384;
pub(crate) const FRESH_HELD_HISTORY_AGGREGATE_MAXIMUM: u64 = 256 * 1024 * 1024;
pub(crate) const FRESH_HELD_HISTORY_OBJECT_MAXIMUM: usize = 4096;
pub(crate) const FRESH_WORK_DIRECTORY_MAXIMUM: usize = 128;
pub(crate) const FRESH_CAS_OBJECT_MAXIMUM: usize = 128 * 128;

/// Prospective allocation envelopes, consumed using each actual filesystem's
/// observed allocation unit. They carry no original file or creator rights.
pub struct DeploymentNativeRuntimeLiability {
    pub data_files: Vec<u64>,
    pub worktree_files: Vec<u64>,
    pub external_files: Vec<u64>,
    pub maximum_generations: u64,
}

/// For <=N positive files whose total lengths <=B, independent rounding is
/// bounded by ceil(B/unit)+(N-1) units. B plus N-1 one-byte slots expresses
/// that bound without inventing a filesystem or its allocation unit.
fn reserve_group(target: &mut Vec<u64>, bytes: u64, files: usize) -> Result<()> {
    if files == 0 {
        return Err(ReconcileError::Invariant(
            "native allocation group is empty",
        ));
    }
    target
        .try_reserve(files)
        .map_err(|_| ReconcileError::ResourceLimit("native allocation liability vector"))?;
    target.push(bytes);
    target.extend(std::iter::repeat_n(1, files - 1));
    Ok(())
}

impl super::super::PreparedOriginalNodeRestore {
    pub fn deployment_native_runtime_liability(
        &self,
        max_generations: u64,
    ) -> Result<DeploymentNativeRuntimeLiability> {
        self.future_file_bytes_by_root()?;
        let maximum_generations = FRESH_HISTORY_GENERATION_MAXIMUM as u64;
        if max_generations == 0 || max_generations > maximum_generations {
            return Err(ReconcileError::ResourceLimit(
                "deployment generations exceed the actual native history gate",
            ));
        }
        let growth = self
            .original_first_write_main_limit()?
            .checked_sub(self.original_journal_bytes())
            .ok_or(ReconcileError::Invariant("native original main growth"))?;
        let mut result = DeploymentNativeRuntimeLiability {
            data_files: vec![
                growth,
                ORIGINAL_WRITE_SIDECAR_LIMIT,
                ORIGINAL_WRITE_SIDECAR_LIMIT,
                super::original_native_shm_capacity(),
            ],
            worktree_files: Vec::new(),
            external_files: vec![ORIGINAL_WRITE_FRAMES_MAXIMUM, ORIGINAL_WRITE_OWNER_MAXIMUM],
            maximum_generations,
        };
        let initial_content = ORIGINAL_WRITE_FILE_MAXIMUM
            .checked_mul(ORIGINAL_WRITE_OPERATION_MAXIMUM as u64)
            .ok_or(ReconcileError::ResourceLimit(
                "initial native content liability overflow",
            ))?;
        reserve_group(
            &mut result.data_files,
            initial_content,
            ORIGINAL_WRITE_CAS_EVIDENCE_MAXIMUM,
        )?;
        reserve_group(
            &mut result.worktree_files,
            initial_content,
            ORIGINAL_WRITE_OPERATION_MAXIMUM,
        )?;
        result.external_files.extend(std::iter::repeat_n(
            ORIGINAL_WRITE_RECEIPT_MAXIMUM,
            ORIGINAL_WRITE_OPERATION_MAXIMUM,
        ));
        result.external_files.extend(std::iter::repeat_n(
            ORIGINAL_WRITE_CAS_RECEIPT_MAXIMUM,
            ORIGINAL_WRITE_CAS_EVIDENCE_MAXIMUM,
        ));
        reserve_group(
            &mut result.external_files,
            FRESH_HELD_HISTORY_AGGREGATE_MAXIMUM,
            FRESH_HELD_HISTORY_OBJECT_MAXIMUM,
        )?;
        // Non-final FastCDC chunks have MIN_CHUNK bytes; each operation has
        // at most one smaller tail. The explicit native count gate also holds.
        let cas_files =
            usize::try_from(FRESH_CONTENT_AGGREGATE_MAXIMUM / sync_extend_cas::MIN_CHUNK as u64)
                .map_err(|_| ReconcileError::ResourceLimit("native chunk liability count"))?
                .checked_add(FRESH_OPERATION_MAXIMUM as usize)
                .ok_or(ReconcileError::ResourceLimit("native chunk count overflow"))?
                .min(FRESH_CAS_OBJECT_MAXIMUM);
        for _ in 0..max_generations {
            reserve_group(
                &mut result.data_files,
                FRESH_CONTENT_AGGREGATE_MAXIMUM,
                cas_files,
            )?;
            reserve_group(
                &mut result.worktree_files,
                FRESH_CONTENT_AGGREGATE_MAXIMUM,
                FRESH_OPERATION_MAXIMUM as usize,
            )?;
            // Directories and retained-original slots have distinct allocation
            // rounding; a two-hex-character CAS bucket namespace has 16^2 slots.
            result
                .worktree_files
                .extend(std::iter::repeat_n(1, FRESH_WORK_DIRECTORY_MAXIMUM));
            result
                .data_files
                .extend(std::iter::repeat_n(1, 16usize.pow(2)));
            result
                .external_files
                .extend(std::iter::repeat_n(1, FRESH_OPERATION_MAXIMUM as usize));
            result.external_files.push(ORIGINAL_WRITE_FRAMES_MAXIMUM);
            result.external_files.push(ORIGINAL_WRITE_OWNER_MAXIMUM);
            reserve_group(
                &mut result.external_files,
                FRESH_RECEIPT_AGGREGATE_MAXIMUM,
                FRESH_RECEIPT_COUNT_MAXIMUM,
            )?;
        }
        for files in [
            &result.data_files,
            &result.worktree_files,
            &result.external_files,
        ] {
            files.iter().try_fold(0u64, |sum, bytes| {
                sum.checked_add(*bytes).ok_or(ReconcileError::ResourceLimit(
                    "native liability sum overflow",
                ))
            })?;
        }
        Ok(result)
    }
}
