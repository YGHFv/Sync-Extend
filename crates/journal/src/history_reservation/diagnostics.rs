//! Restart inspection is descriptive and never adopts a persisted invocation.
use super::{KEY, Stored, cancel, liability, phase_chain};
use crate::{Journal, JournalError, JournalStoredRow, Result};
use rusqlite::{Transaction, TransactionBehavior};
use serde::Serialize;
use sync_extend_core_model::{ContentId, EntryId, FileManifest, SnapshotId, SpaceId};

#[derive(Debug, Serialize)]
pub struct OriginalLocalHistoryAttemptDiagnostic {
    pub state: &'static str,
    pub attempt: EntryId,
    pub baseline: SnapshotId,
    pub planned: SnapshotId,
    pub exact_record_digest: ContentId,
    pub native_authority: bool,
    pub restart_adoption_available: bool,
    pub cleanup_authority: bool,
}

impl crate::JournalBackupImage {
    /// Recognize pre-effect original reservation rows and return the reserved
    /// file so the archive verifier can include its pending CAS references.
    pub fn verify_recovered_node_local_state(
        rows: &[JournalStoredRow],
        space: &SpaceId,
        bounds: crate::NodeInspectionBounds,
    ) -> Result<Option<FileManifest>> {
        let pending = pending_original_history(rows, space, bounds.max_entries)?;
        let pending_keys = if let Some((_, stored)) = &pending {
            phase_chain::validate_rows(rows)?;
            Some((
                format!("{}{}", liability::PREFIX, stored.attempt),
                format!("{}{}", phase_chain::PREFIX, stored.attempt),
            ))
        } else {
            None
        };
        crate::read_lease::recovery_hold::validate_rows(rows)?;
        let mut has_cancellations = false;
        for row in rows.iter().filter(|row| row.table() == "local_state") {
            match row.primary_key() {
                [key] if matches!(key.as_str(), "space_id" | "device_id" | "worktree" | KEY) => (),
                [key] if key == crate::read_lease::recovery_hold::KEY => (),
                [key]
                    if pending_keys
                        .as_ref()
                        .is_some_and(|(liability, cursor)| key == liability || key == cursor) => {}
                [key] if key.starts_with(cancel::NAMESPACE) => {
                    has_cancellations = true;
                }
                _ => {
                    return Err(JournalError::Invariant(
                        "node original Journal has unsupported local state",
                    ));
                }
            }
        }
        if has_cancellations {
            Self::recovered_original_attempt_diagnostics_from_audited_rows(rows, space, bounds)?;
        }
        pending
            .map(|(_, stored)| pending_original_history_file(stored))
            .transpose()
    }
}

fn field<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant(
            "original history diagnostic expected text",
        )),
    }
}

impl Journal {
    /// One consistent read transaction; no token/receipt/owner reconstruction.
    pub fn original_local_history_attempt_diagnostics(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Vec<OriginalLocalHistoryAttemptDiagnostic>> {
        crate::storage_policy::validate(max)?;
        let read = || -> Result<Vec<OriginalLocalHistoryAttemptDiagnostic>> {
            let bounds = self.writer_capacity_limits(max)?;
            let view = self
                .read_view()
                .audit_local_commit_capacity(space, bounds)?;
            audit_recovered_attempt_rows(&view.rows, space, max)
        };
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let result = read()?;
            tx.commit()?;
            Ok(result)
        } else {
            read()
        }
    }

    /// Report the exact future file held by a persisted reservation. Its other
    /// files are identical to the current baseline and already have snapshot pins.
    pub fn original_pending_history_file(
        &self,
        space: &SpaceId,
        max: usize,
    ) -> Result<Option<FileManifest>> {
        crate::storage_policy::validate(max)?;
        let read = || {
            let pending: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.local_state WHERE key=?1)",
                [KEY],
                |row| row.get(0),
            )?;
            if !pending {
                return Ok(None);
            }
            let bounds = self.writer_capacity_limits(max)?;
            let view = self
                .read_view()
                .audit_local_commit_capacity(space, bounds)?;
            pending_original_history(&view.rows, space, max)?
                .map(|(_, stored)| pending_original_history_file(stored))
                .transpose()
        };
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let result = read()?;
            tx.commit()?;
            Ok(result)
        } else {
            read()
        }
    }
}

fn pending_original_history<'a>(
    rows: &'a [JournalStoredRow],
    space: &SpaceId,
    max: usize,
) -> Result<Option<(&'a str, Stored)>> {
    let Some(row) = rows
        .iter()
        .find(|row| row.table() == "local_state" && row.primary_key() == [KEY])
    else {
        return Ok(None);
    };
    let json = field(row, "value")?;
    super::persisted_charge(json, max)?;
    super::verify_original_capacity_context(json, rows)?;
    let stored: Stored = serde_json::from_str(json)?;
    if stored.baseline.space_id != *space {
        return Err(JournalError::Invariant(
            "original history diagnostic foreign space",
        ));
    }
    Ok(Some((json, stored)))
}

fn pending_original_history_file(stored: Stored) -> Result<FileManifest> {
    stored
        .planned
        .entries
        .into_values()
        .find(|entry| entry.path == stored.future_path)
        .and_then(|entry| entry.content)
        .ok_or(JournalError::Invariant("original reserved file absent"))
}

/// Live Journal and immutable recovery images use this exact original typed parser.
pub(crate) fn audit_recovered_attempt_rows(
    rows: &[JournalStoredRow],
    space: &SpaceId,
    max: usize,
) -> Result<Vec<OriginalLocalHistoryAttemptDiagnostic>> {
    crate::storage_policy::validate(max)?;
    let mut result = cancel::diagnostics(rows)?;
    if let Some((json, stored)) = pending_original_history(rows, space, max)? {
        result.push(OriginalLocalHistoryAttemptDiagnostic {
            state: "pending_live_issuer_unavailable_after_restart",
            attempt: stored.attempt,
            baseline: stored.baseline.root()?,
            planned: stored.planned.root()?,
            exact_record_digest: ContentId::hash(json.as_bytes()),
            native_authority: false,
            restart_adoption_available: false,
            cleanup_authority: false,
        });
    }
    if result.len() > max {
        return Err(JournalError::Invariant(
            "original history diagnostic count bound",
        ));
    }
    result.sort_by(|a, b| a.attempt.cmp(&b.attempt));
    Ok(result)
}
