//! Descriptive terminal history only; bytes never issue native or restart rights.
use super::{OriginalLocalHistoryReservation, Stored, KEY};
use crate::{Journal, JournalError, Result};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, Manifest, SnapshotId, SpaceId};

const NAMESPACE: &str = "original.local-history.cancelled.";
const PREFIX: &str = "original.local-history.cancelled.v1.";
const MAX_TERMINAL_BYTES: usize = 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalBody {
    version: u32,
    attempt: EntryId,
    space: SpaceId,
    device: DeviceId,
    worktree_digest: ContentId,
    baseline: SnapshotId,
    planned: SnapshotId,
    reservation_digest: ContentId,
    observations_digest: ContentId,
    operations_digest: ContentId,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    body: TerminalBody,
    body_digest: ContentId,
}

pub struct OriginalHistoryCancellationReceipt {
    attempt: EntryId,
    baseline: SnapshotId,
    exact_terminal_digest: ContentId,
    exact_terminal_json: String,
}

impl OriginalHistoryCancellationReceipt {
    pub fn original_attempt(&self) -> &EntryId {
        &self.attempt
    }
    pub fn baseline(&self) -> &SnapshotId {
        &self.baseline
    }
    pub fn exact_terminal_digest(&self) -> &ContentId {
        &self.exact_terminal_digest
    }
    pub fn exact_terminal_json(&self) -> &str {
        &self.exact_terminal_json
    }
}

fn parse(key: &str, json: &str) -> Result<Terminal> {
    if json.len() > MAX_TERMINAL_BYTES || key.len() != PREFIX.len() + 32 {
        return Err(JournalError::Invariant(
            "original cancellation terminal byte or key bound",
        ));
    }
    let terminal: Terminal = serde_json::from_str(json)?;
    if terminal.body.version != 1
        || key != format!("{PREFIX}{}", terminal.body.attempt)
        || terminal.body.baseline == terminal.body.planned
        || terminal.body_digest != ContentId::hash(&serde_json::to_vec(&terminal.body)?)
        || serde_json::to_string(&terminal)? != json
    {
        return Err(JournalError::Invariant(
            "original cancellation terminal schema hash or canonical bytes",
        ));
    }
    crate::sql_integer(terminal.body.timestamp)?;
    Ok(terminal)
}

fn context(terminal: &Terminal, space: &str, device: &str, worktree: &str) -> Result<()> {
    if terminal.body.space.as_str() != space
        || terminal.body.device.as_str() != device
        || worktree.is_empty()
        || terminal.body.worktree_digest != ContentId::hash(worktree.as_bytes())
    {
        return Err(JournalError::Invariant(
            "original cancellation terminal foreign local identity",
        ));
    }
    Ok(())
}

fn baseline(terminal: &Terminal, json: &str) -> Result<()> {
    if json.len() > crate::MAX_OPERATION_BYTES {
        return Err(JournalError::Invariant(
            "original cancellation baseline byte bound",
        ));
    }
    let manifest: Manifest = serde_json::from_str(json)?;
    manifest.validate()?;
    if manifest.root()? != terminal.body.baseline || manifest.space_id != terminal.body.space {
        return Err(JournalError::Invariant(
            "original cancellation original baseline snapshot changed",
        ));
    }
    Ok(())
}

fn field<'a>(row: &'a crate::JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant(
            "original cancellation context text required",
        )),
    }
}

pub(crate) fn validate_rows(rows: &[crate::JournalStoredRow]) -> Result<()> {
    for row in rows.iter().filter(|row| {
        row.table() == "local_state"
            && row
                .primary_key()
                .first()
                .is_some_and(|key| key.starts_with(NAMESPACE))
    }) {
        let key = row.primary_key().first().ok_or(JournalError::Invariant(
            "original cancellation terminal key absent",
        ))?;
        let terminal = parse(key, field(row, "value")?)?;
        let state = |key: &str| -> Result<&str> {
            let row = rows
                .iter()
                .find(|row| row.table() == "local_state" && row.primary_key() == [key.to_owned()])
                .ok_or(JournalError::Invariant(
                    "original cancellation local identity absent",
                ))?;
            field(row, "value")
        };
        context(
            &terminal,
            state("space_id")?,
            state("device_id")?,
            state("worktree")?,
        )?;
        let snapshot = rows
            .iter()
            .find(|row| {
                row.table() == "snapshots"
                    && row.primary_key() == [terminal.body.baseline.to_string()]
            })
            .ok_or(JournalError::Invariant(
                "original cancellation original snapshot absent",
            ))?;
        baseline(&terminal, field(snapshot, "manifest")?)?;
        if let Some(pending) = rows
            .iter()
            .find(|row| row.table() == "local_state" && row.primary_key() == [KEY.to_owned()])
        {
            let stored: Stored = serde_json::from_str(field(pending, "value")?)?;
            if stored.attempt == terminal.body.attempt {
                return Err(JournalError::Invariant(
                    "original history attempt is pending and cancelled",
                ));
            }
        }
    }
    Ok(())
}

/// Validate all descriptive terminals before a generic state/GC/budget read.
/// Digest checking detects corruption; it is not an exclusion of raw SQL writers.
pub(crate) fn validate_connection(
    connection: &rusqlite::Connection,
) -> Result<sync_extend_core_model::tree_storage_capacity::TreeStorageCharge> {
    let _original_read_snapshot = if connection.is_autocommit() {
        Some(Transaction::new_unchecked(
            connection,
            TransactionBehavior::Deferred,
        )?)
    } else {
        None
    };
    let mut charge = sync_extend_core_model::tree_storage_capacity::TreeStorageCharge {
        rows: 0,
        logical_bytes: 0,
    };
    let mut query = connection.prepare(
        "SELECT key,length(CAST(value AS BLOB)),value FROM local_state WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT ?3",
    )?;
    let mut rows = query.query(params![
        i64::try_from(NAMESPACE.len())
            .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?,
        NAMESPACE,
        i64::try_from(sync_extend_core_model::limits::MAX_ENTRIES + 1)
            .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?
    ])?;
    while let Some(row) = rows.next()? {
        let length: i64 = row.get(1)?;
        if length < 0
            || length as u64 > MAX_TERMINAL_BYTES as u64
            || charge.rows >= sync_extend_core_model::limits::MAX_ENTRIES as u64
        {
            return Err(JournalError::Invariant(
                "original cancellation terminal inventory bound",
            ));
        }
        let key: String = row.get(0)?;
        let json: String = row.get(2)?;
        let terminal = parse(&key, &json)?;
        let state = |key: &str| -> Result<String> {
            Ok(connection.query_row(
                "SELECT value FROM local_state WHERE key=?1",
                [key],
                |row| row.get(0),
            )?)
        };
        context(
            &terminal,
            &state("space_id")?,
            &state("device_id")?,
            &state("worktree")?,
        )?;
        let manifest: String = connection.query_row(
            "SELECT manifest FROM snapshots WHERE snapshot_id=?1",
            [terminal.body.baseline.as_str()],
            |row| row.get(0),
        )?;
        baseline(&terminal, &manifest)?;
        let pending: Option<String> = connection
            .query_row("SELECT value FROM local_state WHERE key=?1", [KEY], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(json) = pending {
            let stored: Stored = serde_json::from_str(&json)?;
            if stored.attempt == terminal.body.attempt {
                return Err(JournalError::Invariant(
                    "original history attempt has two states",
                ));
            }
        }
        charge.rows = charge.rows.checked_add(1).ok_or(JournalError::Invariant(
            "original cancellation row overflow",
        ))?;
        charge.logical_bytes = charge
            .logical_bytes
            .checked_add((key.len() + json.len()) as u64)
            .ok_or(JournalError::Invariant(
                "original cancellation byte overflow",
            ))?;
    }
    Ok(charge)
}

impl Journal {
    /// Original live reservation only, after caller observes unchanged full tree.
    /// This changes ordinary history metadata and never removes a native object.
    pub fn cancel_original_history_reservation(
        &mut self,
        reservation: OriginalLocalHistoryReservation,
        unchanged: &Manifest,
        max: usize,
    ) -> Result<OriginalHistoryCancellationReceipt> {
        if !std::sync::Arc::ptr_eq(&self.original_local_history_issuer, &reservation.issuer) {
            return Err(JournalError::Invariant(
                "original cancel requires live original Journal issuer",
            ));
        }
        let stored: Stored = serde_json::from_str(&reservation.exact_json)?;
        stored.validate(max)?;
        if stored.baseline != *unchanged
            || stored.attempt != reservation.attempt
            || serde_json::to_string(&stored)? != reservation.exact_json
        {
            return Err(JournalError::Invariant(
                "original cancellation full reservation differs",
            ));
        }
        let bounds = self.writer_capacity_limits(max)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&stored.baseline.space_id, bounds)?;
        super::verify_original_capacity_context(&reservation.exact_json, &before.rows)?;
        let worktree: String = tx.query_row(
            "SELECT value FROM local_state WHERE key='worktree'",
            [],
            |row| row.get(0),
        )?;
        if ContentId::hash(worktree.as_bytes()) != stored.original_worktree_digest {
            return Err(JournalError::Invariant(
                "original cancellation exact reserved worktree differs",
            ));
        }
        let body = TerminalBody {
            version: 1,
            attempt: stored.attempt.clone(),
            space: stored.baseline.space_id.clone(),
            device: stored.original_device.clone(),
            worktree_digest: stored.original_worktree_digest.clone(),
            baseline: stored.baseline.root()?,
            planned: stored.planned.root()?,
            reservation_digest: ContentId::hash(reservation.exact_json.as_bytes()),
            observations_digest: ContentId::hash(
                &crate::rename_observation::serialize_observation(&stored.observations)?,
            ),
            operations_digest: ContentId::hash(&serde_json::to_vec(&stored.operations)?),
            timestamp: stored.timestamp,
        };
        let terminal_key = format!("{PREFIX}{}", stored.attempt);
        let body_digest = ContentId::hash(&serde_json::to_vec(&body)?);
        let terminal_bytes = serde_json::to_string(&Terminal { body, body_digest })?;
        parse(&terminal_key, &terminal_bytes)?;
        if tx.execute(
            "DELETE FROM local_state WHERE key=?1 AND value=?2",
            params![KEY, reservation.exact_json],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "original reservation cancellation slot differs",
            ));
        }
        tx.execute(
            "INSERT INTO local_state VALUES (?1,?2)",
            params![terminal_key, terminal_bytes],
        )?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&stored.baseline.space_id, bounds)?;
        if !after.report.within_accounted_limits()
            || before.rows.len() != after.rows.len()
            || before
                .rows
                .iter()
                .filter(|row| {
                    !(row.table() == "local_state" && row.primary_key() == [KEY.to_owned()])
                })
                .any(|row| {
                    !after.rows.iter().any(|current| {
                        row.table() == current.table()
                            && row.primary_key() == current.primary_key()
                            && row.columns() == current.columns()
                    })
                })
        {
            return Err(JournalError::Invariant(
                "original cancellation collateral rows or capacity",
            ));
        }
        let baseline = stored.baseline.root()?;
        tx.commit()?;
        Ok(OriginalHistoryCancellationReceipt {
            attempt: stored.attempt,
            baseline,
            exact_terminal_digest: ContentId::hash(terminal_bytes.as_bytes()),
            exact_terminal_json: terminal_bytes,
        })
    }
}

pub(super) fn diagnostics(
    rows: &[crate::JournalStoredRow],
) -> Result<Vec<super::OriginalLocalHistoryAttemptDiagnostic>> {
    validate_rows(rows)?;
    let mut result = Vec::new();
    for row in rows.iter().filter(|row| {
        row.table() == "local_state"
            && row
                .primary_key()
                .first()
                .is_some_and(|key| key.starts_with(NAMESPACE))
    }) {
        let key = row.primary_key().first().ok_or(JournalError::Invariant(
            "original terminal diagnostic key absent",
        ))?;
        let json = field(row, "value")?;
        let terminal = parse(key, json)?;
        result.push(super::OriginalLocalHistoryAttemptDiagnostic {
            state: "cancelled_metadata_only",
            attempt: terminal.body.attempt,
            baseline: terminal.body.baseline,
            planned: terminal.body.planned,
            exact_record_digest: ContentId::hash(json.as_bytes()),
            native_authority: false,
            restart_adoption_available: false,
            cleanup_authority: false,
        });
    }
    Ok(result)
}
