//! Restore validated Journal bytes only into a retained fresh native creator.
//! This owns an image file; it does not restore CAS, identities, native owners,
//! publish a pathname, reopen a Journal, or authorize replacement and cleanup.
use super::{JournalBackupImage, JournalError, Result};
use std::io::{Read, Seek, SeekFrom, Write};
use sync_extend_platform_fs::{FileKey, OwnedFileCreation};

/// Holds the original CREATE and parent handles after exact bytes are synced.
/// The caller must separately publish and record this original file through a
/// durable protocol; no recovered pathname can construct this receipt.
pub struct CreatedJournalRestore<'a> {
    creator: &'a OwnedFileCreation,
    key: FileKey,
    parent_key: FileKey,
    digest: String,
    schema_version: u32,
    bytes: u64,
}

impl CreatedJournalRestore<'_> {
    pub fn key(&self) -> FileKey {
        self.key
    }

    pub fn parent_key(&self) -> FileKey {
        self.parent_key
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Recheck the original live file, its parent lineage and complete bytes.
    /// This method cannot turn another same-byte pathname into the original.
    pub fn verify(&self) -> Result<()> {
        let lineage = self.creator.original_creation()?;
        if lineage.key()? != self.key || lineage.parent_key()? != self.parent_key {
            return Err(JournalError::Invariant("restore original CREATE differs"));
        }
        verify_bytes(self.creator, self.bytes, &self.digest)
    }

    /// Borrow the held original for a separately journaled native protocol.
    /// Its mutable writer is never exposed by the restore receipt.
    pub fn original(&self) -> Result<sync_extend_platform_fs::OriginalFileCreation<'_>> {
        self.verify()?;
        self.creator.original_creation().map_err(Into::into)
    }
}

fn verify_bytes(creator: &OwnedFileCreation, expected_bytes: u64, digest: &str) -> Result<()> {
    creator.verify_single_link()?;
    if creator.reader().metadata()?.len() != expected_bytes {
        return Err(JournalError::Invariant("restore complete length differs"));
    }
    let mut reader = creator.reader().try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut limited = reader.take(expected_bytes.saturating_add(1));
    let mut hasher = blake3::Hasher::new();
    let mut read_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        creator.verify_single_link()?;
        let count = limited.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(count as u64)
            .ok_or(JournalError::Invariant("restore byte count overflow"))?;
        if read_bytes > expected_bytes {
            return Err(JournalError::Invariant("restore grew beyond image"));
        }
        hasher.update(&buffer[..count]);
    }
    creator.verify_single_link()?;
    if read_bytes != expected_bytes
        || creator.reader().metadata()?.len() != expected_bytes
        || hasher.finalize().to_hex().as_str() != digest
    {
        return Err(JournalError::Invariant("restore original bytes differ"));
    }
    Ok(())
}

impl JournalBackupImage {
    /// Borrow the caller's actual fresh empty CREATE and retain it after sync.
    /// Failure leaves both the possible partial original and its live creator;
    /// no pathname is removed, adopted, overwritten, or reported as published.
    pub fn restore_created<'a>(
        &self,
        creator: &'a mut OwnedFileCreation,
    ) -> Result<CreatedJournalRestore<'a>> {
        let lineage = creator.original_creation()?;
        let key = lineage.key()?;
        let parent_key = lineage.parent_key()?;
        creator.verify_single_link()?;
        if creator.reader().metadata()?.len() != 0 {
            return Err(JournalError::Invariant(
                "restore requires empty fresh CREATE",
            ));
        }
        creator.writer().seek(SeekFrom::Start(0))?;
        checkpoint("restore_created_empty");
        for (index, chunk) in self.bytes().chunks(64 * 1024).enumerate() {
            creator.verify_single_link()?;
            creator.writer().write_all(chunk)?;
            if index == 0 {
                checkpoint("restore_created_first_chunk");
            }
        }
        creator.writer().flush()?;
        creator.writer().sync_all()?;
        checkpoint("restore_created_synced");
        let restored = CreatedJournalRestore {
            creator,
            key,
            parent_key,
            digest: self.digest().to_owned(),
            schema_version: self.schema_version(),
            bytes: self.bytes().len() as u64,
        };
        restored.verify()?;
        checkpoint("restore_created_verified");
        Ok(restored)
    }
}

fn checkpoint(phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{phase}");
        while !std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
            .is_some_and(|path| std::path::Path::new(&path).is_file())
        {
            std::thread::park_timeout(std::time::Duration::from_millis(25));
        }
    }
    let _ = phase;
}
