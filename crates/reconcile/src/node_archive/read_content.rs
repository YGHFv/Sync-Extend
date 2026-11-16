//! Application full content verification after same-original readonly handoff.
use super::original_content::OriginalContentReader;
use crate::{ReconcileError, Result};
use std::io::{Read, Seek, SeekFrom};
use sync_extend_core_model::ContentId;

pub(super) fn verify(
    original: &impl OriginalContentReader,
    bytes: u64,
    digest: &ContentId,
) -> Result<()> {
    original.verify_identity()?;
    if original.reader().metadata()?.len() != bytes {
        return Err(ReconcileError::Invariant(
            "original handoff complete length differs",
        ));
    }
    let mut reader = original.reader().try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut limited = reader.take(bytes.saturating_add(1));
    let mut hasher = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        original.verify_identity()?;
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|count| *count <= bytes)
            .ok_or(ReconcileError::Invariant("original handoff file grew"))?;
        hasher.update(&buffer[..count]);
    }
    original.verify_identity()?;
    if total != bytes
        || original.reader().metadata()?.len() != bytes
        || hasher.finalize().to_hex().as_str() != digest.as_str()
    {
        return Err(ReconcileError::Invariant(
            "original handoff complete bytes differ",
        ));
    }
    Ok(())
}
