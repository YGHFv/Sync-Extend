use crate::{ModelError, Result};
use serde::{Deserialize, Serialize};

pub const MAX_ENTRIES: usize = 1_000_000;
pub const MAX_CHUNKS: usize = 1_000_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalLimits {
    pub max_scan_entries: usize,
    pub max_scan_bytes: u64,
    pub max_scan_chunks: usize,
    pub max_file_bytes: u64,
    pub max_staging_bytes: u64,
    pub max_internal_worktree_bytes: u64,
    pub max_storage_entries: usize,
}

impl Default for LocalLimits {
    fn default() -> Self {
        Self {
            max_scan_entries: MAX_ENTRIES,
            max_scan_bytes: 1024 * 1024 * 1024 * 1024,
            max_scan_chunks: MAX_CHUNKS,
            max_file_bytes: 64 * 1024 * 1024 * 1024,
            max_staging_bytes: 10 * 1024 * 1024 * 1024,
            max_internal_worktree_bytes: 10 * 1024 * 1024 * 1024,
            max_storage_entries: MAX_ENTRIES,
        }
    }
}

impl LocalLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_scan_entries == 0
            || self.max_scan_entries > MAX_ENTRIES
            || self.max_scan_chunks == 0
            || self.max_scan_chunks > MAX_CHUNKS
            || self.max_scan_bytes == 0
            || self.max_file_bytes == 0
            || self.max_file_bytes > MAX_CHUNKS as u64 * 4 * 1024 * 1024
            || self.max_staging_bytes == 0
            || self.max_internal_worktree_bytes == 0
            || self.max_storage_entries == 0
            || self.max_storage_entries > MAX_ENTRIES
        {
            return Err(ModelError::InvalidConfig("invalid local resource limits"));
        }
        Ok(())
    }
}
