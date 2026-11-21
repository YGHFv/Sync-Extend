//! Bounded retained snapshot metadata from a closed, unchanged source.
//! The owned memory connection has no pathname, migration or writer authority.
#[cfg(target_os = "linux")]
use crate::ReadOnlyJournal;
use crate::{JournalError, MAX_OPERATION_BYTES, Result, RetainedSnapshot, SnapshotPruning};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, Manifest, SnapshotId, SpaceId, limits};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadOnlySnapshotPreviewLimits {
    pub max_journal_bytes: u64,
    pub max_manifest_bytes: usize,
    pub max_entries: usize,
    pub max_chunk_visits: usize,
    pub max_reference_rows: usize,
    pub max_vm_instructions: u64,
    pub max_query_millis: u64,
}

impl ReadOnlySnapshotPreviewLimits {
    pub fn validate(self) -> Result<()> {
        if !(4096..=512 * 1024 * 1024).contains(&self.max_journal_bytes)
            || !(64..=MAX_OPERATION_BYTES).contains(&self.max_manifest_bytes)
            || !(1..=limits::MAX_ENTRIES).contains(&self.max_entries)
            || !(1..=limits::MAX_CHUNKS).contains(&self.max_chunk_visits)
            || !(1..=limits::MAX_CHUNKS).contains(&self.max_reference_rows)
            || !(1_000..=250_000_000).contains(&self.max_vm_instructions)
            || !(1..=60_000).contains(&self.max_query_millis)
        {
            return Err(JournalError::Invariant(
                "explicit bounded readonly snapshot preview limits required",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ReadOnlySnapshotPreviewSource {
    pub snapshot_id: SnapshotId,
    pub metadata: Option<RetainedSnapshot>,
    pub pruning: Option<SnapshotPruning>,
}

#[derive(Clone, Debug)]
pub struct ReadOnlyRestorePreviewSource {
    pub space_id: SpaceId,
    pub current_snapshot: Option<SnapshotId>,
    pub baseline: Option<ReadOnlySnapshotPreviewSource>,
    pub target: ReadOnlySnapshotPreviewSource,
    pub source_image_bytes: u64,
    pub source_image_digest: ContentId,
    pub memory_header_projected: bool,
}

pub fn validate_preview_manifest(
    manifest: &Manifest,
    bounds: ReadOnlySnapshotPreviewLimits,
) -> Result<()> {
    bounds.validate()?;
    if manifest.entries.len() > bounds.max_entries || manifest.tombstones.len() > bounds.max_entries
    {
        return Err(JournalError::Invariant(
            "readonly snapshot preview manifest entry budget exceeded",
        ));
    }
    let mut visits = 0usize;
    for entry in manifest.entries.values() {
        if let Some(content) = &entry.content {
            visits = visits
                .checked_add(content.chunks.len())
                .filter(|visits| *visits <= bounds.max_chunk_visits)
                .ok_or(JournalError::Invariant(
                    "readonly snapshot preview chunk visit budget exceeded",
                ))?;
        }
    }
    struct BoundedLength {
        length: usize,
        limit: usize,
    }
    impl std::io::Write for BoundedLength {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.length = self
                .length
                .checked_add(bytes.len())
                .filter(|length| *length <= self.limit)
                .ok_or_else(|| std::io::Error::other("readonly preview manifest byte budget"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Bound canonical metadata before root() can allocate its encoding. The
    // public pure projector applies the same limit to supplied typed sources.
    serde_json::to_writer(
        BoundedLength {
            length: 0,
            limit: bounds.max_manifest_bytes,
        },
        manifest,
    )?;
    manifest.validate()?;
    Ok(())
}

/// This wrapper retains the physical source while its ordinary ReadOnlyJournal
/// borrows a standalone memory image. The general Journal reader is unchanged.
#[cfg(target_os = "linux")]
pub struct ReadOnlyRestorePreviewJournal {
    journal: ReadOnlyJournal,
    files: sync_extend_platform_fs::ReadOnlyJournalFiles,
    bounds: ReadOnlySnapshotPreviewLimits,
    source_image_bytes: u64,
    source_image_digest: ContentId,
    memory_header_projected: bool,
}

#[cfg(target_os = "linux")]
impl ReadOnlyRestorePreviewJournal {
    pub fn open(path: &std::path::Path, bounds: ReadOnlySnapshotPreviewLimits) -> Result<Self> {
        bounds.validate()?;
        // The dedicated retained O_PATH chain refuses every intermediate alias
        // before touching a descendant. A leaf-first pathname metadata check
        // would follow intermediate links and can update their access times.
        // Its fixed-slot preflight also refuses metadata-owner and SHM inputs;
        // those live capabilities cannot be reconstructed from portable bytes.
        let files =
            sync_extend_platform_fs::ReadOnlyJournalFiles::open(path, bounds.max_journal_bytes)?;
        Self::from_existing_files(files, bounds)
    }

    /// Consume the exact original preflight guard after parsing the bounded
    /// control input, preserving its one flock instead of reopening the source.
    pub fn from_existing_files(
        files: sync_extend_platform_fs::ReadOnlyJournalFiles,
        bounds: ReadOnlySnapshotPreviewLimits,
    ) -> Result<Self> {
        use rusqlite::{Connection, MAIN_DB, limits::Limit};
        use std::{io::Cursor, time::Duration};
        bounds.validate()?;
        files.check_main_bound(bounds.max_journal_bytes)?;
        let mut bytes = files.read_main()?;
        if bytes.get(..16) != Some(b"SQLite format 3\0")
            || !matches!(bytes.get(18..20), Some([1, 1] | [2, 2]))
        {
            return Err(JournalError::Invariant(
                "readonly snapshot preview requires a recognized closed-main SQLite header",
            ));
        }
        let source_image_bytes = bytes.len() as u64;
        let source_image_digest = ContentId::hash(&bytes);
        let memory_header_projected = bytes[18..20] == [2, 2];
        // All recovery/SHM checks and writer exclusion precede this conversion.
        // Only the owned copy changes: SQLite interprets checkpointed WAL-mode
        // main pages as a standalone immutable memory database.
        bytes[18] = 1;
        bytes[19] = 1;
        let mut connection = Connection::open_in_memory()?;
        let image_length = bytes.len();
        connection.deserialize_read_exact(MAIN_DB, Cursor::new(bytes), image_length, true)?;
        for (category, limit) in [
            (
                Limit::SQLITE_LIMIT_LENGTH,
                (bounds.max_manifest_bytes + 65_536) as i32,
            ),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 65_536),
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
            (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        ] {
            connection.set_limit(category, limit)?;
            if connection.limit(category)? > limit {
                return Err(JournalError::Invariant(
                    "readonly snapshot preview SQLite limit was not applied",
                ));
            }
        }
        let started = std::time::Instant::now();
        let mut remaining = bounds.max_vm_instructions;
        connection.progress_handler(
            1_000,
            Some(move || {
                if remaining < 1_000
                    || started.elapsed() >= Duration::from_millis(bounds.max_query_millis)
                {
                    return true;
                }
                remaining -= 1_000;
                false
            }),
        )?;
        connection.busy_timeout(Duration::ZERO)?;
        connection.pragma_update(None, "query_only", true)?;
        connection.pragma_update(None, "trusted_schema", false)?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.pragma_update(None, "cache_size", -8_192i32)?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != crate::SCHEMA_VERSION {
            return Err(JournalError::Invariant(
                "readonly snapshot preview requires schema 67 without migration",
            ));
        }
        let reader = Self {
            journal: ReadOnlyJournal { connection },
            files,
            bounds,
            source_image_bytes,
            source_image_digest,
            memory_header_projected,
        };
        reader.verify()?;
        Ok(reader)
    }

    pub fn verify(&self) -> Result<()> {
        self.files.verify()?;
        let current = self.files.read_main()?;
        if current.len() as u64 != self.source_image_bytes
            || ContentId::hash(&current) != self.source_image_digest
        {
            return Err(JournalError::Invariant(
                "readonly snapshot preview physical source bytes changed",
            ));
        }
        Ok(())
    }

    /// Target, current root, optional expected baseline and all pruning/reference
    /// audits share this one deferred read transaction. No rows or pins are written.
    pub fn snapshots(
        &self,
        target: &SnapshotId,
        expected_baseline: Option<&SnapshotId>,
    ) -> Result<ReadOnlyRestorePreviewSource> {
        use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
        self.verify()?;
        let transaction =
            Transaction::new_unchecked(&self.journal.connection, TransactionBehavior::Deferred)?;
        let result = (|| {
            let space: String = self.journal.connection.query_row(
                "SELECT CASE WHEN length(CAST(value AS BLOB))<=64 THEN value ELSE '' END
                 FROM local_state WHERE key='space_id'",
                [],
                |row| row.get(0),
            )?;
            let space_id: SpaceId = space.parse()?;
            let current: Option<String> = self
                .journal
                .connection
                .query_row(
                    "SELECT CASE WHEN length(CAST(snapshot_id AS BLOB))<=64 THEN snapshot_id ELSE '' END
                     FROM current_manifests WHERE space_id=?1",
                    [space_id.as_str()],
                    |row| row.get(0),
                )
                .optional()?;
            let current_snapshot = current.map(|value| value.parse()).transpose()?;
            if let Some(current) = &current_snapshot {
                let current_source = self.snapshot(&space_id, current)?;
                if current_source.metadata.is_none() || current_source.pruning.is_some() {
                    return Err(JournalError::Invariant(
                        "readonly snapshot preview current root is missing or pruned",
                    ));
                }
            }
            let baseline_id = expected_baseline.or(current_snapshot.as_ref());
            let baseline = baseline_id
                .map(|id| self.snapshot(&space_id, id))
                .transpose()?;
            let target = self.snapshot(&space_id, target)?;
            Ok(ReadOnlyRestorePreviewSource {
                space_id,
                current_snapshot,
                baseline,
                target,
                source_image_bytes: self.source_image_bytes,
                source_image_digest: self.source_image_digest.clone(),
                memory_header_projected: self.memory_header_projected,
            })
        })();
        transaction.rollback()?;
        self.verify()?;
        result
    }

    fn preflight_manifest(&self, space: &SpaceId, id: &SnapshotId) -> Result<()> {
        use rusqlite::params;
        let (json, length): (String, i64) = self.journal.connection.query_row(
            "SELECT CASE WHEN length(CAST(manifest AS BLOB))<=?3 THEN manifest ELSE '' END,
             length(CAST(manifest AS BLOB)) FROM snapshots WHERE space_id=?1 AND snapshot_id=?2",
            params![
                space.as_str(),
                id.as_str(),
                self.bounds.max_manifest_bytes as i64
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if !(1..=self.bounds.max_manifest_bytes as i64).contains(&length) {
            return Err(JournalError::Invariant(
                "readonly snapshot preview manifest byte budget exceeded",
            ));
        }
        let manifest: Manifest = serde_json::from_str(&json)?;
        validate_preview_manifest(&manifest, self.bounds)?;
        if manifest.space_id != *space || manifest.root()? != *id {
            return Err(JournalError::Invariant(
                "readonly snapshot preview manifest scope or hash mismatch",
            ));
        }
        Ok(())
    }

    fn snapshot(&self, space: &SpaceId, id: &SnapshotId) -> Result<ReadOnlySnapshotPreviewSource> {
        use rusqlite::{OptionalExtension, params};
        let stored_space: Option<String> = self
            .journal
            .connection
            .query_row(
                "SELECT space_id FROM snapshots WHERE snapshot_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_space) = stored_space else {
            let orphan: bool = self.journal.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM snapshot_objects WHERE snapshot_id=?1)
                 OR EXISTS(SELECT 1 FROM snapshot_prunings WHERE snapshot_id=?1)",
                [id.as_str()],
                |row| row.get(0),
            )?;
            if orphan {
                return Err(JournalError::Invariant(
                    "readonly snapshot preview missing snapshot has orphan metadata",
                ));
            }
            return Ok(ReadOnlySnapshotPreviewSource {
                snapshot_id: id.clone(),
                metadata: None,
                pruning: None,
            });
        };
        if stored_space != space.as_str() {
            return Err(JournalError::Invariant(
                "readonly snapshot preview snapshot belongs to another space",
            ));
        }
        self.preflight_manifest(space, id)?;
        let references: i64 = self.journal.connection.query_row(
            "SELECT count(*) FROM snapshot_objects WHERE snapshot_id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        if references < 0 || references as u64 > self.bounds.max_reference_rows as u64 {
            return Err(JournalError::Invariant(
                "readonly snapshot preview reference row budget exceeded",
            ));
        }
        let pruning: Option<(String, i64)> = self
            .journal
            .connection
            .query_row(
                "SELECT baseline_root,length(CAST(intent AS BLOB))
                 FROM snapshot_prunings WHERE space_id=?1 AND snapshot_id=?2",
                params![space.as_str(), id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((baseline, length)) = pruning {
            if !(1..=self.bounds.max_manifest_bytes as i64).contains(&length) {
                return Err(JournalError::Invariant(
                    "readonly snapshot preview pruning byte budget exceeded",
                ));
            }
            self.preflight_manifest(space, &baseline.parse()?)?;
        }
        // Reuse the original typed retained/pruned audit, including strict state,
        // timestamp, lock, protection closure and pruning dependency validation.
        let metadata =
            crate::snapshot_retention::audit_snapshot(&self.journal.connection, space, id)?;
        let pruning = crate::snapshot_pruning::pruning(&self.journal.connection, space, id)?;
        Ok(ReadOnlySnapshotPreviewSource {
            snapshot_id: id.clone(),
            metadata: Some(metadata),
            pruning,
        })
    }
}
