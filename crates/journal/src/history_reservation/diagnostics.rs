//! Restart inspection is descriptive and never adopts a persisted invocation.
use super::{cancel, Stored, KEY};
use crate::{Journal, JournalError, JournalStoredRow, Result};
use rusqlite::{Transaction, TransactionBehavior};
use serde::Serialize;
use sync_extend_core_model::{ContentId, EntryId, SnapshotId, SpaceId};

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
}

/// Live Journal and immutable recovery images use this exact original typed parser.
pub(crate) fn audit_recovered_attempt_rows(
    rows: &[JournalStoredRow],
    space: &SpaceId,
    max: usize,
) -> Result<Vec<OriginalLocalHistoryAttemptDiagnostic>> {
    crate::storage_policy::validate(max)?;
    let mut result = cancel::diagnostics(&rows)?;
    for row in rows
        .iter()
        .filter(|row| row.table() == "local_state" && row.primary_key() == [KEY.to_owned()])
    {
        let json = field(row, "value")?;
        super::persisted_charge(json, max)?;
        super::verify_original_capacity_context(json, &rows)?;
        let stored: Stored = serde_json::from_str(json)?;
        if stored.baseline.space_id != *space {
            return Err(JournalError::Invariant(
                "original history diagnostic foreign space",
            ));
        }
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
