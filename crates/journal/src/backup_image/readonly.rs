//! Read-only image audits borrow the original Journal view, never writer gates.
use crate::{JournalCapacityLimits, JournalError, JournalReadView, JournalStoredRow, Result};
use rusqlite::{limits::Limit, Connection, Transaction, TransactionBehavior, MAIN_DB};
use std::time::{Duration, Instant};
use sync_extend_core_model::SpaceId;

/// SQL work limits complement the existing bounded physical row/byte preflight.
/// They do not certify peak process memory or native recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeInspectionBounds {
    pub max_entries: usize,
    pub capacity: JournalCapacityLimits,
    pub max_vm_instructions: u64,
    pub max_query_time: Duration,
}

impl NodeInspectionBounds {
    fn validate(self) -> Result<()> {
        crate::tree_storage_inventory::validate_limits(self.max_entries, self.capacity.inventory)?;
        if self.capacity.max_rows == 0
            || self.capacity.max_rows > self.max_entries as u64
            || self.capacity.max_logical_bytes == 0
            || self.capacity.max_logical_bytes > self.max_entries as u64 * 1024
            || !(1_000..=250_000_000).contains(&self.max_vm_instructions)
            || self.max_query_time.is_zero()
            || self.max_query_time > Duration::from_secs(300)
        {
            return Err(JournalError::Invariant(
                "explicit bounded node inspection required",
            ));
        }
        Ok(())
    }
}

impl super::JournalBackupImage {
    /// First owned-image entry applies the complete current node audit before
    /// constructing an immutable image. No unbounded legacy verify precedes it.
    pub fn from_current_node_image(
        bytes: Vec<u8>,
        expected_digest: &str,
        max_image_bytes: usize,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<Self> {
        let (version, ()) = Self::inspect_current_node_image(
            &bytes,
            expected_digest,
            max_image_bytes,
            space,
            bounds,
            |_| Ok(()),
        )?;
        Ok(Self {
            bytes,
            schema_version: version,
            digest: expected_digest.to_owned(),
        })
    }

    /// Move already validated owned bytes without cloning the complete image.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Bounded first entry for an untrusted node archive's borrowed Journal bytes.
    /// Length, digest and standalone header precede SQLite allocation/inspection.
    /// The same VM/time limits cover first integrity/catalog validation and all audits.
    pub fn inspect_current_node_image<T>(
        bytes: &[u8],
        expected_digest: &str,
        max_image_bytes: usize,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        inspect: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<(u32, T)> {
        Self::inspect_current_node_image_with_audit_rows(
            bytes,
            expected_digest,
            max_image_bytes,
            space,
            bounds,
            |connection, _, _| inspect(connection),
        )
    }

    /// One complete audit supplies both the bounded stored rows and the
    /// original reference states to the caller. No second audit is implied.
    pub fn inspect_current_node_image_with_audit_rows<T>(
        bytes: &[u8],
        expected_digest: &str,
        max_image_bytes: usize,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        inspect: impl FnOnce(
            &Connection,
            &[JournalStoredRow],
            &[crate::ReferenceReservation],
        ) -> Result<T>,
    ) -> Result<(u32, T)> {
        bounds.validate()?;
        super::limit(max_image_bytes)?;
        if bytes.len() < super::MIN_IMAGE_BYTES || bytes.len() > max_image_bytes {
            return Err(JournalError::Invariant(
                "node image size outside explicit bound",
            ));
        }
        if expected_digest.len() != 64
            || !expected_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || blake3::hash(bytes).to_hex().as_str() != expected_digest
            || bytes.get(..16) != Some(b"SQLite format 3\0")
            || bytes.get(18..20) != Some(&[1, 1])
        {
            return Err(JournalError::Invariant(
                "node standalone image header or digest differs",
            ));
        }
        let mut database = Connection::open_in_memory()?;
        database.deserialize_read_exact(MAIN_DB, std::io::Cursor::new(bytes), bytes.len(), true)?;
        configure_inspection(&mut database, bounds)?;
        let version = super::validate(&database)?;
        if version != crate::SCHEMA_VERSION {
            return Err(JournalError::Invariant(
                "node audit requires actual current schema",
            ));
        }
        let transaction = Transaction::new_unchecked(&database, TransactionBehavior::Deferred)?;
        let view = JournalReadView {
            connection: &database,
        };
        // Original audits remain mandatory even if an archive-specific callback is empty.
        let snapshot =
            view.audit_original_provenance_capacity(space, bounds.max_entries, bounds.capacity)?;
        let references = view.reference_reservations(space, bounds.max_entries)?;
        let result = inspect(&database, &snapshot.rows, &references)?;
        transaction.rollback()?;
        Ok((version, result))
    }

    /// Return owned reference states from the complete original Journal audit.
    /// Length/digest/bounds precede allocation; no Connection or writer escapes.
    pub fn inspect_current_node_reference_reservations(
        bytes: &[u8],
        expected_digest: &str,
        max_image_bytes: usize,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<Vec<crate::ReferenceReservation>> {
        Self::inspect_current_node_image(
            bytes,
            expected_digest,
            max_image_bytes,
            space,
            bounds,
            |connection| {
                crate::JournalReadView { connection }
                    .reference_reservations(space, bounds.max_entries)
            },
        )
        .map(|(_, references)| references)
    }

    pub fn with_audited_readonly<T>(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        inspect: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        Self::inspect_current_node_image(
            self.bytes(),
            self.digest(),
            self.bytes().len(),
            space,
            bounds,
            inspect,
        )
        .map(|(_, result)| result)
    }
}

pub(super) fn configure_inspection(
    connection: &mut Connection,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    bounds.validate()?;
    // Apply limits before the first untrusted integrity/catalog/payload query.
    for (category, limit) in [
        (Limit::SQLITE_LIMIT_LENGTH, 32 * 1024 * 1024),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
    ] {
        connection.set_limit(category, limit)?;
        if connection.limit(category)? > limit {
            return Err(JournalError::Invariant("node SQL limit not applied"));
        }
    }
    let started = Instant::now();
    let mut remaining = bounds.max_vm_instructions;
    connection.progress_handler(
        1_000,
        Some(move || {
            if remaining < 1_000 || started.elapsed() >= bounds.max_query_time {
                return true;
            }
            remaining -= 1_000;
            false
        }),
    )?;
    connection.pragma_update(None, "query_only", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "cache_size", -8_192i32)?;
    Ok(())
}

impl NodeInspectionBounds {
    #[cfg(windows)]
    pub(crate) fn configure_original_connection(self, connection: &mut Connection) -> Result<()> {
        configure_inspection(connection, self)?;
        connection.busy_timeout(Duration::ZERO)?;
        Ok(())
    }
}
