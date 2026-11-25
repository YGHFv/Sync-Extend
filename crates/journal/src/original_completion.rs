//! Immutable complete Journal observations from actual retained readonly originals.
use crate::{Journal, JournalError, NodeInspectionBounds, Result};
use rusqlite::{Transaction, TransactionBehavior};
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_platform_fs::FileKey;

impl Journal {
    pub fn original_completion_main_identity(&self) -> Result<(FileKey, FileKey)> {
        self.verify_original_created_image()?;
        let original = self
            .original_restored_image
            .as_ref()
            .ok_or(JournalError::Invariant(
                "completion original main identity absent",
            ))?;
        Ok((original.key()?, original.parent_key()?))
    }

    pub fn original_completion_cas_identity(&self) -> Result<(FileKey, FileKey)> {
        self.verify_original_created_image()?;
        let original = self
            .original_cas_coordination
            .as_ref()
            .ok_or(JournalError::Invariant(
                "completion original coordination sentinel absent",
            ))?;
        let path = self
            .database_path
            .parent()
            .ok_or(JournalError::Invariant(
                "completion original Journal parent absent",
            ))?
            .join("cas-access.lock");
        original.verify(&path)?;
        Ok((original.original_key()?, original.original_parent_key()?))
    }

    /// Read exact actual protected original bytes, never serialize a changed
    /// header or allocate a second writable image of the target database.
    pub fn original_completion_image_bytes(&self) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        self.verify_original_created_image()?;
        let protected = self
            .original_read_protection
            .as_ref()
            .ok_or(JournalError::Invariant(
                "completion original main readonly protection absent",
            ))?;
        protected.verify_identity()?;
        let length = protected.reader().metadata()?.len();
        if !(512..=256 * 1024 * 1024).contains(&length) {
            return Err(JournalError::Invariant(
                "completion original main byte bound",
            ));
        }
        let mut file = protected.reader().try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.take(length + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != length || bytes.get(18..20) != Some(&[1, 1]) {
            return Err(JournalError::Invariant(
                "completion original main standalone bytes differ",
            ));
        }
        protected.verify_identity()?;
        self.verify_original_created_image()?;
        Ok(bytes)
    }

    pub fn original_completion_rows_digest(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<ContentId> {
        let mut observed = self.open_original_coordination_connection()?;
        let bounds = NodeInspectionBounds {
            max_entries: max,
            capacity: crate::JournalCapacityLimits {
                inventory: crate::TreeRestoreInventoryLimits {
                    max_rows: max,
                    max_logical_bytes: max as u64 * 1024,
                },
                max_rows: max as u64,
                max_logical_bytes: max as u64 * 1024,
            },
            max_vm_instructions: 100_000_000,
            max_query_time: std::time::Duration::from_secs(60),
        };
        let result = (|| {
            bounds.configure_original_connection(&mut observed.connection)?;
            let snapshot =
                Transaction::new_unchecked(&observed.connection, TransactionBehavior::Deferred)?;
            let original = observed.read_view().audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            let digest = completion_rows_hash(&original.rows)?;
            snapshot.rollback()?;
            observed.verify_original_created_image()?;
            self.verify_original_created_image()?;
            Ok(digest)
        })();
        observed.finish_original_coordination_observation(result)
    }
}

impl crate::JournalBackupImage {
    pub fn original_completion_rows_digest(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<ContentId> {
        self.with_audited_readonly(space, bounds, |connection| {
            let original = crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            }
            .audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            completion_rows_hash(&original.rows)
        })
    }
}
fn completion_rows_hash<T: serde::Serialize + ?Sized>(rows: &T) -> Result<ContentId> {
    use std::io::{self, Write};
    struct Hash {
        state: blake3::Hasher,
        remaining: usize,
    }
    impl Write for Hash {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("completion typedrow JSON byte budget"))?;
            self.state.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut hash = Hash {
        state: blake3::Hasher::new(),
        remaining: 256 * 1024 * 1024,
    };
    serde_json::to_writer(&mut hash, rows)?;
    Ok(ContentId::from_hasher(&hash.state))
}
