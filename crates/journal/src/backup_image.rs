//! Bounded standalone Journal images from one pinned SQLite read transaction.
//! This image covers only the Journal. CAS, private identities, native objects,
//! retained descriptors and a complete node backup require separate protocols.
use super::{Journal, JournalError, Result, SCHEMA_VERSION};
use rusqlite::{backup::Backup, backup::StepResult, Connection, MAIN_DB};

const MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;
const MIN_IMAGE_BYTES: usize = 512;

/// Immutable validated database bytes. No filesystem pathname is adopted or
/// replaced by this type; callers must use an independently owned destination.
pub struct JournalBackupImage {
    bytes: Vec<u8>,
    schema_version: u32,
    digest: String,
}

impl JournalBackupImage {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// BLAKE3 digest of the complete standalone database image.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Verify an independently obtained bounded image before restoring it to a
    /// fresh node. This grants no permission to overwrite an existing Journal.
    pub fn verify(bytes: Vec<u8>, expected_digest: &str, max_bytes: usize) -> Result<Self> {
        limit(max_bytes)?;
        if bytes.len() < MIN_IMAGE_BYTES || bytes.len() > max_bytes {
            return Err(JournalError::Invariant("backup image size outside bound"));
        }
        if expected_digest.len() != 64
            || !expected_digest
                .bytes()
                .all(|value| value.is_ascii_hexdigit() && !value.is_ascii_uppercase())
            || blake3::hash(&bytes).to_hex().as_str() != expected_digest
        {
            return Err(JournalError::Invariant("backup image digest differs"));
        }
        if bytes.get(..16) != Some(b"SQLite format 3\0") || bytes.get(18..20) != Some(&[1, 1]) {
            return Err(JournalError::Invariant(
                "standalone SQLite backup header required",
            ));
        }
        let mut database = Connection::open_in_memory()?;
        database.deserialize_read_exact(
            MAIN_DB,
            std::io::Cursor::new(&bytes),
            bytes.len(),
            true,
        )?;
        let version = validate(&database)?;
        Ok(Self {
            bytes,
            schema_version: version,
            digest: expected_digest.to_owned(),
        })
    }
}

fn limit(max_bytes: usize) -> Result<()> {
    if !(MIN_IMAGE_BYTES..=MAX_IMAGE_BYTES).contains(&max_bytes) {
        return Err(JournalError::Invariant(
            "explicit bounded backup byte limit required",
        ));
    }
    Ok(())
}

fn validate(database: &Connection) -> Result<u32> {
    let version: u32 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if !(1..=SCHEMA_VERSION).contains(&version) {
        return Err(JournalError::Invariant("backup schema version unsupported"));
    }
    let mut integrity = database.prepare("PRAGMA integrity_check")?;
    let messages = integrity
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if messages != ["ok"] {
        return Err(JournalError::Invariant(
            "backup SQLite integrity check failed",
        ));
    }
    let mut foreign = database.prepare("PRAGMA foreign_key_check")?;
    if foreign.query([])?.next()?.is_some() {
        return Err(JournalError::Invariant(
            "backup SQLite foreign key check failed",
        ));
    }
    // A valid arbitrary SQLite file is not a Journal backup.
    for table in [
        "local_state",
        "operations",
        "snapshots",
        "current_manifests",
        "receive_cursors",
    ] {
        let exists: bool = database.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(JournalError::Invariant("backup Journal table absent"));
        }
    }
    schema_catalog::validate_schema(database, version)?;
    Ok(version)
}

// Generated exclusively from the accepted parent's production migration list.
// The included SQL paths are part of the explicit production source manifest.
mod schema_catalog;

impl Journal {
    /// Export one consistent current database state without checkpointing,
    /// rewriting the live database, or borrowing a caller's write transaction.
    /// A busy/locked copy fails immediately; there is no unbounded retry loop.
    pub fn backup_image(&self, max_bytes: usize) -> Result<JournalBackupImage> {
        limit(max_bytes)?;
        if !self.connection.is_autocommit() {
            return Err(JournalError::Invariant("caller transaction refuses backup"));
        }
        let read = self.connection.unchecked_transaction()?;
        // This read fixes the snapshot before counting pages or invoking backup.
        let _: i64 = read.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
        let page_size: i64 = read.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let pages: i64 = read.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size = u64::try_from(page_size)
            .map_err(|_| JournalError::Invariant("backup negative page size"))?;
        let pages = u64::try_from(pages)
            .map_err(|_| JournalError::Invariant("backup negative page count"))?;
        let image_size = pages
            .checked_mul(page_size)
            .ok_or(JournalError::Invariant("backup image page budget overflow"))?;
        if image_size < MIN_IMAGE_BYTES as u64 || image_size > max_bytes as u64 {
            return Err(JournalError::Invariant("backup image page budget exceeded"));
        }
        let mut copy = Connection::open_in_memory()?;
        {
            let backup = Backup::new(&read, &mut copy)?;
            let mut finished = false;
            // A pinned source snapshot cannot grow/restart while being copied.
            // Even a library/kernel regression cannot turn this into an endless loop.
            let max_steps = pages.div_ceil(64).saturating_add(1);
            for _ in 0..max_steps {
                match backup.step(64)? {
                    StepResult::Done => {
                        finished = true;
                        break;
                    }
                    StepResult::More => {}
                    _ => return Err(JournalError::Invariant("backup source busy or locked")),
                }
            }
            if !finished {
                return Err(JournalError::Invariant(
                    "backup copy exceeded page step bound",
                ));
            }
        }
        read.rollback()?;
        // SQLite backup copies the source WAL header. Convert this separate
        // in-memory database to rollback journaling before serializing it,
        // without touching the live source database or its WAL.
        let mode: String = copy.query_row("PRAGMA journal_mode=MEMORY", [], |row| row.get(0))?;
        if mode != "memory" {
            return Err(JournalError::Invariant(
                "standalone backup memory journal mode refused",
            ));
        }
        validate(&copy)?;
        let mut bytes = copy.serialize(MAIN_DB)?.to_vec();
        // sqlite3_backup already copied all committed WAL pages into this
        // independent memory database. SQLite serialization can retain the
        // original WAL header even after journal_mode=MEMORY. Only these owned
        // complete bytes are normalized; the live source database is untouched.
        if bytes.get(..16) != Some(b"SQLite format 3\0")
            || !matches!(bytes.get(18..20), Some([1, 1] | [2, 2]))
        {
            return Err(JournalError::Invariant("backup copy header unsupported"));
        }
        bytes[18..20].copy_from_slice(&[1, 1]);
        // Independent deserialize verifies that the image is self-contained;
        // WAL-only state and an unsupported image header cannot be accepted.
        let digest = blake3::hash(&bytes).to_hex().to_string();
        JournalBackupImage::verify(bytes, &digest, max_bytes)
    }
}

#[cfg(windows)]
mod restore_created;
#[cfg(windows)]
pub use restore_created::CreatedJournalRestore;

mod readonly;
pub use readonly::NodeInspectionBounds;

mod map_worktree;
mod portable_scope;
pub use portable_scope::PortableNodeImageScope;

mod detached_history;
pub use detached_history::{
    DetachedOriginalNodeHistory, OriginalHistoryContentReference,
    OriginalNodeHistoryMappingEvidence, RetainedOriginalNodeHistory,
};
