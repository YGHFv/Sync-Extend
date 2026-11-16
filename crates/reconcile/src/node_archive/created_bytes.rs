//! Shared exact original CREATE content audit for section and current-file receipts.
use crate::{ReconcileError, Result};
use std::io::{Read, Seek, SeekFrom};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::{FileKey, OwnedFileCreation};

pub(super) fn verify(
    creator: &OwnedFileCreation,
    key: FileKey,
    parent_key: FileKey,
    expected_length: u64,
    expected_digest: &ContentId,
) -> Result<()> {
    let original = creator.original_creation()?;
    if original.key()? != key || original.parent_key()? != parent_key {
        return Err(ReconcileError::Invariant(
            "node original CREATE lineage differs",
        ));
    }
    creator.verify_single_link()?;
    if creator.reader().metadata()?.len() != expected_length {
        return Err(ReconcileError::Invariant(
            "node original complete file length differs",
        ));
    }
    let mut reader = creator.reader().try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut limited = reader.take(expected_length.saturating_add(1));
    let mut hasher = blake3::Hasher::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        creator.verify_single_link()?;
        let size = limited.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        count = count
            .checked_add(size as u64)
            .filter(|count| *count <= expected_length)
            .ok_or(ReconcileError::Invariant("node original created file grew"))?;
        hasher.update(&buffer[..size]);
    }
    creator.verify_single_link()?;
    original.verify()?;
    if count != expected_length
        || creator.reader().metadata()?.len() != expected_length
        || hasher.finalize().to_hex().as_str() != expected_digest.as_str()
    {
        return Err(ReconcileError::Invariant(
            "node original complete created bytes differ",
        ));
    }
    Ok(())
}
