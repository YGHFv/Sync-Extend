//! Ext4 blocks on an already-created original inode, not a pre-CREATE reservation.
use super::OriginalPrivateVolumeFile;
use crate::UnixFileKey;
use std::{
    io,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

pub struct OriginalCreateAllocationObservation {
    original_key: UnixFileKey,
    original_parent: UnixFileKey,
    payload_bound: u64,
    allocated_bytes: u64,
}

impl OriginalCreateAllocationObservation {
    pub fn original_key(&self) -> UnixFileKey {
        self.original_key
    }
    pub fn original_parent_key(&self) -> UnixFileKey {
        self.original_parent
    }
    pub fn payload_bound(&self) -> u64 {
        self.payload_bound
    }
    pub fn observed_inode_allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }
    pub fn before_create_budget_reserved(&self) -> bool {
        false
    }
}

impl OriginalPrivateVolumeFile<'_, '_> {
    /// Allocate on the exact already-created inode while keeping the empty
    /// logical length. On any uncertain failure preserve the inode and poison
    /// this holder. This grants no namespace, future inode or cleanup authority.
    pub fn observe_preallocated_original_payload(
        &mut self,
        payload_bound: u64,
    ) -> io::Result<OriginalCreateAllocationObservation> {
        self.verify()?;
        if self.bytes_written != 0 || payload_bound == 0 || payload_bound > self.max_bytes {
            return Err(super::super::super::unsupported(
                "original preallocation requires empty bounded CREATE",
            ));
        }
        self.poisoned = true;
        let bytes = i64::try_from(payload_bound).map_err(|_| {
            super::super::super::unsupported("original preallocation byte conversion")
        })?;
        // SAFETY: exact retained original CREATE file descriptor; bounded
        // offset/length and KEEP_SIZE leave logical bytes empty.
        if unsafe { libc::fallocate(self.file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, bytes) }
            != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.file.sync_all()?;
        self.parent.sync()?;
        let metadata = self.file.metadata()?;
        let allocated_bytes = metadata.blocks().checked_mul(512).ok_or_else(|| {
            super::super::super::unsupported("original preallocation block overflow")
        })?;
        if metadata.len() != 0 || allocated_bytes < payload_bound {
            return Err(super::super::super::unsupported(
                "original preallocation physical blocks insufficient",
            ));
        }
        self.poisoned = false;
        if let Err(error) = self.verify() {
            self.poisoned = true;
            return Err(error);
        }
        Ok(OriginalCreateAllocationObservation {
            original_key: self.created_key,
            original_parent: self.created_parent,
            payload_bound,
            allocated_bytes,
        })
    }
}
