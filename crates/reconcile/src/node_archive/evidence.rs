//! Restart evidence inspection deliberately returns no living attempts.
use super::{LedgerBounds, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use rusqlite::{Connection, Transaction, TransactionBehavior, MAIN_DB};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_journal::Result as SqlResult;
use sync_extend_platform_fs::GuardedReadFile;

pub struct NodeLedgerEvidence {
    archive_digest: ContentId,
    ledger_id: SpaceId,
    records: u64,
    record_bytes: u64,
    terminal_hash: String,
}
impl NodeLedgerEvidence {
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
    pub fn ledger_id(&self) -> &SpaceId {
        &self.ledger_id
    }
    pub fn records(&self) -> u64 {
        self.records
    }
    pub fn record_bytes(&self) -> u64 {
        self.record_bytes
    }
    pub fn terminal_hash(&self) -> &str {
        &self.terminal_hash
    }
}

impl VerifiedNodeStateArchive {
    /// Exact retained read-only bytes -> bounded memory inspection, never opens
    /// writable SQLite or consumes recovered rows as native ownership authority.
    /// Hot rollback journals, WAL or SHM evidence is retained and rejected.
    pub fn inspect_external_ledger_evidence(
        &self,
        path: &Path,
        bounds: LedgerBounds,
    ) -> Result<NodeLedgerEvidence> {
        super::ledger::bounds::validate(bounds).map_err(ReconcileError::from)?;
        let parent = path.parent().ok_or(ReconcileError::Invariant(
            "external ledger evidence parent absent",
        ))?;
        let ancestors = super::external::hold_ancestors(parent)?;
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            match std::fs::symlink_metadata(Path::new(&sidecar)) {
                Ok(_) => {
                    return Err(ReconcileError::Invariant(
                        "external ledger sidecars require separate recovery evidence protocol",
                    ))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
        let original = GuardedReadFile::open(path)?;
        original.verify_single_link()?;
        if !original.matches_path(path)? {
            return Err(ReconcileError::Invariant(
                "external ledger evidence original changed",
            ));
        }
        let bytes = original.reader().metadata()?.len();
        if bytes < 512 || bytes > bounds.max_database_bytes {
            return Err(ReconcileError::ResourceLimit(
                "external ledger evidence database bytes",
            ));
        }
        let mut reader = original.reader().try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut image = Vec::new();
        reader
            .take(bounds.max_database_bytes + 1)
            .read_to_end(&mut image)?;
        if image.len() as u64 != bytes
            || image.get(..16) != Some(b"SQLite format 3\0")
            || image.get(18..20) != Some(&[1, 1])
        {
            return Err(ReconcileError::Invariant(
                "external ledger evidence standalone bytes",
            ));
        }
        let inspected = (|| -> SqlResult<NodeLedgerEvidence> {
            let mut connection = Connection::open_in_memory()?;
            connection.deserialize_read_exact(
                MAIN_DB,
                std::io::Cursor::new(&image),
                image.len(),
                true,
            )?;
            super::ledger::bounds::configure(&mut connection, bounds)?;
            connection.pragma_update(None, "query_only", true)?;
            let transaction =
                Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)?;
            let ledger_id =
                super::ledger::schema::audit_image(&transaction, self.digest(), bounds)?;
            let state = super::ledger::records::verify_chain(
                &transaction,
                self.digest(),
                &ledger_id,
                bounds,
            )?;
            transaction.rollback()?;
            Ok(NodeLedgerEvidence {
                archive_digest: self.digest().clone(),
                ledger_id,
                records: state.count,
                record_bytes: state.record_bytes,
                terminal_hash: state.previous,
            })
        })()
        .map_err(ReconcileError::from)?;
        original.verify_single_link()?;
        if !original.matches_path(path)? || original.reader().metadata()?.len() != bytes {
            return Err(ReconcileError::Invariant(
                "external ledger evidence changed during audit",
            ));
        }
        for (path, held, key) in &ancestors {
            if held.key()? != *key || !held.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "external evidence ancestor changed",
                ));
            }
        }
        Ok(inspected)
    }
}
