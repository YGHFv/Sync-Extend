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

    /// v2 additionally retains the actual current manifest in the same snapshot,
    /// so a stale expected baseline cannot stand in for occupied destinations.
    pub fn selection_snapshots(
        &self,
        target: &SnapshotId,
        expected_baseline: Option<&SnapshotId>,
    ) -> Result<(
        ReadOnlyRestorePreviewSource,
        Option<ReadOnlySnapshotPreviewSource>,
    )> {
        use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
        self.verify()?;
        let transaction =
            Transaction::new_unchecked(&self.journal.connection, TransactionBehavior::Deferred)?;
        let reader = PreviewMetadataReader::new(&self.journal.connection, self.bounds);
        let result = (|| {
            let space: String = self.journal.connection.query_row(
                "SELECT CASE WHEN length(CAST(value AS BLOB))<=64 THEN value ELSE '' END
                 FROM local_state WHERE key='space_id'",
                [],
                |row| row.get(0),
            )?;
            let space_id: SpaceId = space.parse()?;
            let current: Option<String> = self.journal.connection.query_row(
                "SELECT CASE WHEN length(CAST(snapshot_id AS BLOB))<=64 THEN snapshot_id ELSE '' END
                 FROM current_manifests WHERE space_id=?1", [space_id.as_str()], |row| row.get(0),
            ).optional()?;
            let current_snapshot: Option<SnapshotId> = current.map(|id| id.parse()).transpose()?;
            let current_source = current_snapshot
                .as_ref()
                .map(|id| reader.current_snapshot(&space_id, id))
                .transpose()?;
            let baseline = match expected_baseline.or(current_snapshot.as_ref()) {
                Some(id) if current_snapshot.as_ref() == Some(id) => current_source.clone(),
                Some(id) => Some(reader.snapshot(&space_id, id)?),
                None => None,
            };
            let target = reader.snapshot(&space_id, target)?;
            Ok((
                ReadOnlyRestorePreviewSource {
                    space_id,
                    current_snapshot,
                    baseline,
                    target,
                    source_image_bytes: self.source_image_bytes,
                    source_image_digest: self.source_image_digest.clone(),
                    memory_header_projected: self.memory_header_projected,
                },
                current_source,
            ))
        })();
        transaction.rollback()?;
        self.verify()?;
        result
    }

    fn snapshot(&self, space: &SpaceId, id: &SnapshotId) -> Result<ReadOnlySnapshotPreviewSource> {
        let mut reader = PreviewMetadataReader::new(&self.journal.connection, self.bounds);
        // The v1 physical source budget retains its original interpretation.
        reader.aggregate_metadata_budget = false;
        reader.snapshot(space, id)
    }
}

/// Shares the original typed audits between closed memory images and the actual
/// live owner connection. It never opens a database, worktree or CAS.
struct PreviewMetadataReader<'a> {
    connection: &'a rusqlite::Connection,
    bounds: ReadOnlySnapshotPreviewLimits,
    metadata_bytes: std::cell::Cell<u64>,
    aggregate_metadata_budget: bool,
}

impl<'a> PreviewMetadataReader<'a> {
    fn new(connection: &'a rusqlite::Connection, bounds: ReadOnlySnapshotPreviewLimits) -> Self {
        Self {
            connection,
            bounds,
            metadata_bytes: std::cell::Cell::new(0),
            aggregate_metadata_budget: true,
        }
    }

    fn charge_metadata(&self, bytes: u64) -> Result<()> {
        if !self.aggregate_metadata_budget {
            return Ok(());
        }
        let total = self
            .metadata_bytes
            .get()
            .checked_add(bytes)
            .filter(|total| *total <= self.bounds.max_journal_bytes)
            .ok_or(JournalError::Invariant(
                "restore preview aggregate metadata byte budget",
            ))?;
        self.metadata_bytes.set(total);
        Ok(())
    }

    fn preflight_manifest(&self, space: &SpaceId, id: &SnapshotId, copies: u64) -> Result<()> {
        use rusqlite::params;
        let (json, length): (String, i64) = self.connection.query_row(
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
        // Count both this bounded preflight and the following original typed
        // audit's same manifest encoding, before the audit can allocate it.
        self.charge_metadata((length as u64).checked_mul(copies).ok_or(
            JournalError::Invariant("restore preview metadata byte overflow"),
        )?)?;
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
            .connection
            .query_row(
                "SELECT space_id FROM snapshots WHERE snapshot_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_space) = stored_space else {
            let orphan: bool = self.connection.query_row(
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
        self.preflight_manifest(space, id, 2)?;
        let references: i64 = self.connection.query_row(
            "SELECT count(*) FROM snapshot_objects WHERE snapshot_id=?1",
            [id.as_str()],
            |row| row.get(0),
        )?;
        if references < 0 || references as u64 > self.bounds.max_reference_rows as u64 {
            return Err(JournalError::Invariant(
                "readonly snapshot preview reference row budget exceeded",
            ));
        }
        self.charge_metadata((references as u64).checked_mul(128).ok_or(
            JournalError::Invariant("restore preview reference byte overflow"),
        )?)?;
        let pruning: Option<(String, i64)> = self
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
            // The original retained audit and returned pruning description each
            // parse this intent and its baseline; charge both before either.
            self.charge_metadata((length as u64) * 2)?;
            self.preflight_manifest(space, &baseline.parse()?, 3)?;
        }
        // Reuse the original typed retained/pruned audit, including strict state,
        // timestamp, lock, protection closure and pruning dependency validation.
        let metadata = crate::snapshot_retention::audit_snapshot(self.connection, space, id)?;
        let pruning = crate::snapshot_pruning::pruning(self.connection, space, id)?;
        Ok(ReadOnlySnapshotPreviewSource {
            snapshot_id: id.clone(),
            metadata: Some(metadata),
            pruning,
        })
    }

    fn current_snapshot(
        &self,
        space: &SpaceId,
        id: &SnapshotId,
    ) -> Result<ReadOnlySnapshotPreviewSource> {
        let source = self.snapshot(space, id)?;
        let Some(snapshot) = &source.metadata else {
            return Err(JournalError::Invariant(
                "restore preview current root missing",
            ));
        };
        if source.pruning.is_some() {
            return Err(JournalError::Invariant(
                "restore preview current root pruned",
            ));
        }
        let (json, length): (String, i64) = self.connection.query_row(
            "SELECT CASE WHEN length(CAST(s.manifest AS BLOB))<=?2 THEN s.manifest ELSE '' END,
             length(CAST(s.manifest AS BLOB)) FROM current_manifests c
             JOIN snapshots s USING(snapshot_id) WHERE c.space_id=?1",
            rusqlite::params![space.as_str(), self.bounds.max_manifest_bytes as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if !(1..=self.bounds.max_manifest_bytes as i64).contains(&length) {
            return Err(JournalError::Invariant(
                "restore preview current manifest byte budget",
            ));
        }
        self.charge_metadata(length as u64)?;
        let manifest: Manifest = serde_json::from_str(&json)?;
        validate_preview_manifest(&manifest, self.bounds)?;
        if manifest != snapshot.manifest {
            return Err(JournalError::Invariant(
                "restore preview current and retained manifest differ",
            ));
        }
        Ok(source)
    }

    fn current(
        &self,
        space: &SpaceId,
    ) -> Result<(Option<SnapshotId>, Option<ReadOnlySnapshotPreviewSource>)> {
        use rusqlite::OptionalExtension;
        let current: Option<String> = self.connection.query_row(
            "SELECT CASE WHEN length(CAST(snapshot_id AS BLOB))<=64 THEN snapshot_id ELSE '' END
             FROM current_manifests WHERE space_id=?1", [space.as_str()], |row| row.get(0),
        ).optional()?;
        let current: Option<SnapshotId> = current.map(|id| id.parse()).transpose()?;
        let source = current
            .as_ref()
            .map(|id| self.current_snapshot(space, id))
            .transpose()?;
        Ok((current, source))
    }
}

impl crate::Journal {
    /// Read only this retained live owner connection in one Deferred transaction.
    /// The tuple deliberately contains no physical image size/hash: hot WAL data
    /// cannot be described as the R05p closed-main memory image.
    pub fn restore_preview_metadata(
        &mut self,
        expected_space: &SpaceId,
        target: &SnapshotId,
        expected_baseline: Option<&SnapshotId>,
        bounds: ReadOnlySnapshotPreviewLimits,
        deadline: std::time::Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(
        SpaceId,
        Option<SnapshotId>,
        Option<ReadOnlySnapshotPreviewSource>,
        Option<ReadOnlySnapshotPreviewSource>,
        ReadOnlySnapshotPreviewSource,
    )> {
        with_live_preview_reader(
            &mut self.connection,
            expected_space,
            bounds,
            deadline,
            cancelled,
            |reader, space| {
                let (current, current_source) = reader.current(space)?;
                let baseline = match expected_baseline.or(current.as_ref()) {
                    Some(id) if current.as_ref() == Some(id) => current_source.clone(),
                    Some(id) => Some(reader.snapshot(space, id)?),
                    None => None,
                };
                let target_source = if current.as_ref() == Some(target) {
                    current_source
                        .clone()
                        .ok_or(JournalError::Invariant("live preview current absent"))?
                } else if baseline
                    .as_ref()
                    .is_some_and(|source| source.snapshot_id == *target)
                {
                    baseline
                        .clone()
                        .ok_or(JournalError::Invariant("live preview baseline absent"))?
                } else {
                    reader.snapshot(space, target)?
                };
                Ok((
                    space.clone(),
                    current,
                    current_source,
                    baseline,
                    target_source,
                ))
            },
        )
    }

    /// Bounded typed history for the actual owner's snapshot selector. The
    /// consumer retains only portable metadata, never these manifests or CAS.
    pub fn restore_preview_context(
        &mut self,
        expected_space: &SpaceId,
        bounds: ReadOnlySnapshotPreviewLimits,
        deadline: std::time::Instant,
        cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(
        SpaceId,
        Option<SnapshotId>,
        Vec<ReadOnlySnapshotPreviewSource>,
        bool,
    )> {
        const MAX_SNAPSHOTS: usize = 128;
        with_live_preview_reader(
            &mut self.connection,
            expected_space,
            bounds,
            deadline,
            cancelled,
            |reader, space| {
                let (current, current_source) = reader.current(space)?;
                let mut statement = reader.connection.prepare(
                "SELECT CASE WHEN length(CAST(snapshot_id AS BLOB))<=64 THEN snapshot_id ELSE '' END
                 FROM snapshots WHERE space_id=?1 ORDER BY created_at_ms DESC,snapshot_id DESC LIMIT ?2",
            )?;
                let ids: Vec<String> = statement
                    .query_map(
                        rusqlite::params![space.as_str(), (MAX_SNAPSHOTS + 1) as i64],
                        |row| row.get(0),
                    )?
                    .collect::<std::result::Result<_, _>>()?;
                let ids: Vec<SnapshotId> = ids
                    .into_iter()
                    .map(|id| id.parse())
                    .collect::<std::result::Result<_, _>>()?;
                let records = ids
                    .iter()
                    .filter(|id| current.as_ref() != Some(*id))
                    .count()
                    + usize::from(current_source.is_some());
                let mut snapshots: Vec<_> = current_source.into_iter().collect();
                for id in ids {
                    if current.as_ref() == Some(&id) {
                        continue;
                    }
                    if snapshots.len() >= MAX_SNAPSHOTS {
                        break;
                    }
                    snapshots.push(reader.snapshot(space, &id)?);
                }
                Ok((space.clone(), current, snapshots, records > MAX_SNAPSHOTS))
            },
        )
    }
}

/// One owner connection, one Deferred transaction, and a temporary bounded VM
/// guard shared by preview and pure context observations.
#[cfg(windows)]
type PreviewOwnerConnection = crate::original_readonly_close::JournalConnectionOwner;
#[cfg(not(windows))]
type PreviewOwnerConnection = rusqlite::Connection;

fn with_live_preview_reader<T>(
    connection: &mut PreviewOwnerConnection,
    expected_space: &SpaceId,
    bounds: ReadOnlySnapshotPreviewLimits,
    deadline: std::time::Instant,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    read: impl FnOnce(&PreviewMetadataReader<'_>, &SpaceId) -> Result<T>,
) -> Result<T> {
    use rusqlite::limits::Limit;
    use std::{
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };
    bounds.validate()?;
    if !connection.is_autocommit()
        || Instant::now() >= deadline
        || cancelled.load(Ordering::Acquire)
    {
        return Err(JournalError::Invariant("live owner preview is unavailable"));
    }
    // General owner Journal connections have no persistent progress hook.
    // Restore every temporary connection limit and timeout on all exits.
    struct QueryGuard<'a> {
        connection: &'a mut PreviewOwnerConnection,
        limits: Vec<(Limit, i32)>,
        busy_ms: u64,
        restored: bool,
    }
    impl QueryGuard<'_> {
        fn restore(&mut self) -> Result<()> {
            self.connection.progress_handler(0, None::<fn() -> bool>)?;
            for (category, limit) in &self.limits {
                self.connection.set_limit(*category, *limit)?;
                if self.connection.limit(*category)? != *limit {
                    return Err(JournalError::Invariant(
                        "live preview owner SQLite limit restoration differs",
                    ));
                }
            }
            self.connection
                .busy_timeout(Duration::from_millis(self.busy_ms))?;
            let restored_busy_ms: i64 =
                self.connection
                    .pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
            if u64::try_from(restored_busy_ms).ok() != Some(self.busy_ms)
                || !self.connection.is_autocommit()
            {
                return Err(JournalError::Invariant(
                    "live preview owner timeout or transaction restoration differs",
                ));
            }
            self.restored = true;
            Ok(())
        }
    }
    impl Drop for QueryGuard<'_> {
        fn drop(&mut self) {
            if self.restored {
                return;
            }
            // Error-path fallback only. Success is returned solely after the
            // fallible restore() has rechecked the original owner settings.
            let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
            if !self.connection.is_autocommit() {
                let _ = self.connection.execute_batch("ROLLBACK");
            }
            for (category, limit) in &self.limits {
                let _ = self.connection.set_limit(*category, *limit);
            }
            let _ = self
                .connection
                .busy_timeout(Duration::from_millis(self.busy_ms));
        }
    }
    let busy_ms: i64 = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let busy_ms = u64::try_from(busy_ms)
        .map_err(|_| JournalError::Invariant("live preview owner busy timeout is invalid"))?;
    let mut guard = QueryGuard {
        connection,
        limits: Vec::new(),
        busy_ms,
        restored: false,
    };
    for (category, limit) in [
        (
            Limit::SQLITE_LIMIT_LENGTH,
            (bounds.max_manifest_bytes + 65_536) as i32,
        ),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 65_536),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        guard
            .limits
            .push((category, guard.connection.limit(category)?));
        guard.connection.set_limit(category, limit)?;
    }
    guard.connection.busy_timeout(Duration::ZERO)?;
    let started = Instant::now();
    let mut remaining = bounds.max_vm_instructions;
    let interrupted = cancelled.clone();
    guard.connection.progress_handler(
        1_000,
        Some(move || {
            if remaining < 1_000
                || Instant::now() >= deadline
                || started.elapsed() >= Duration::from_millis(bounds.max_query_millis)
                || interrupted.load(Ordering::Acquire)
            {
                return true;
            }
            remaining -= 1_000;
            false
        }),
    )?;
    // The exclusive owner borrow lets the guard clear the callback before
    // rollback. No second connection or transaction wrapper retains a shared
    // borrow across that cleanup boundary.
    guard.connection.execute_batch("BEGIN DEFERRED")?;
    let reader = PreviewMetadataReader::new(guard.connection, bounds);
    let result = (|| {
        let version: u32 = reader
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != crate::SCHEMA_VERSION {
            return Err(JournalError::Invariant("live preview schema differs"));
        }
        let recorded_space: String = reader.connection.query_row(
            "SELECT CASE WHEN length(CAST(value AS BLOB))<=64 THEN value ELSE '' END
                 FROM local_state WHERE key='space_id'",
            [],
            |row| row.get(0),
        )?;
        let space: SpaceId = recorded_space.parse()?;
        if space != *expected_space {
            return Err(JournalError::Invariant("live owner preview space differs"));
        }
        let result = read(&reader, &space)?;
        if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
            return Err(JournalError::Invariant("live owner preview expired"));
        }
        Ok(result)
    })();
    drop(reader);
    // Rollback must remain available after the query budget expires.
    let cleared = guard.connection.progress_handler(0, None::<fn() -> bool>);
    let rolled_back = guard.connection.execute_batch("ROLLBACK");
    // Attempt fallible restoration even if rollback itself was refused.
    let restored = guard.restore();
    cleared?;
    rolled_back?;
    restored?;
    result
}
