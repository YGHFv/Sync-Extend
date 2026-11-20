//! Read exact guarded ledger bytes with no SQLite target open or live issuer recovery.
use super::{LedgerBounds, OriginalNodeRestartClassification, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, MAIN_DB};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::GuardedReadFile;

fn no_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::symlink_metadata(Path::new(&name)) {
            Ok(_) => {
                return Err(ReconcileError::Invariant(
                    "restart evidence sidecar refusal",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
impl VerifiedNodeStateArchive {
    /// Completed is immutable evidence about the old commit, never current native
    /// ownership, current target bytes, continuation, adoption or cleanup authority.
    pub fn classify_original_node_restart(
        &self,
        path: &Path,
        limits: LedgerBounds,
        inspection: sync_extend_journal::NodeInspectionBounds,
    ) -> Result<OriginalNodeRestartClassification> {
        let inspected = (|| -> Result<OriginalNodeRestartClassification> {
            super::ledger::bounds::validate(limits)?;
            let parent = path
                .parent()
                .ok_or(ReconcileError::Invariant("restart ledger parent absent"))?;
            let ancestors = super::external::hold_ancestors(parent)?;
            no_sidecars(path)?;
            let original = GuardedReadFile::open(path)?;
            original.verify_single_link()?;
            if !original.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "restart original ledger slot differs",
                ));
            }
            let length = original.reader().metadata()?.len();
            if length < 512 || length > limits.max_database_bytes {
                return Err(ReconcileError::ResourceLimit(
                    "restart original ledger image budget",
                ));
            }
            let mut reader = original.reader().try_clone()?;
            reader.seek(SeekFrom::Start(0))?;
            let mut image = Vec::new();
            reader.take(length + 1).read_to_end(&mut image)?;
            if image.len() as u64 != length
                || image.get(..16) != Some(b"SQLite format 3\0")
                || image.get(18..20) != Some(&[1, 1])
            {
                return Err(ReconcileError::Invariant(
                    "restart original standalone ledger bytes differ",
                ));
            }
            let mut connection = Connection::open_in_memory()?;
            connection.deserialize_read_exact(
                MAIN_DB,
                std::io::Cursor::new(&image),
                image.len(),
                true,
            )?;
            super::ledger::configure_completion_connection(&mut connection, limits)?;
            connection.pragma_update(None, "query_only", true)?;
            let snapshot = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)?;
            let version: u32 =
                snapshot.pragma_query_value(None, "user_version", |row| row.get(0))?;
            let ledger: sync_extend_core_model::SpaceId = if version == 2 {
                super::ledger::schema::audit_image(&snapshot, self.digest(), limits)?
            } else if version == 3 {
                let scope: String = snapshot.query_row(
                    "SELECT ledger_id FROM main.restore_scope WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )?;
                let ledger = scope.parse()?;
                super::durable_schema::audit_current(
                    &snapshot,
                    self.digest(),
                    &ledger,
                    limits.max_database_bytes,
                    false,
                )?;
                ledger
            } else {
                return Err(ReconcileError::Invariant(
                    "restart exact known ledger schema required",
                ));
            };
            let chain =
                super::ledger::records::verify_chain(&snapshot, self.digest(), &ledger, limits)?;
            let row: Option<(String, String, String, Vec<u8>, String)> =
                if version == 3 {
                    snapshot.query_row(
                    "SELECT archive_digest,ledger_id,original_terminal,manifest,manifest_hash \
                     FROM main.restore_completions WHERE singleton=1", [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
                ).optional()?
                } else {
                    None
                };
            let classification = if let Some((archive, stored_ledger, terminal, bytes, hash)) = row
            {
                let digest: ContentId = hash.parse()?;
                let manifest = super::ledger::parse_completion_manifest(
                    &bytes,
                    &digest,
                    limits.max_record_bytes as usize,
                )?;
                if archive != self.digest().as_str()
                    || stored_ledger != ledger.as_str()
                    || terminal != chain.previous
                    || chain
                        .record_bytes
                        .checked_add(bytes.len() as u64)
                        .is_none_or(|size| size > limits.max_record_bytes)
                {
                    return Err(ReconcileError::Invariant(
                        "restart exact completion scope/aggregate differs",
                    ));
                }
                super::ledger::verify_completion_objects_connection(
                    &snapshot,
                    &manifest,
                    self.digest(),
                    &ledger,
                    limits,
                )?;
                manifest.verify_archive_source(self, inspection)?;
                OriginalNodeRestartClassification::CompletedEvidence {
                    records: chain.count,
                    original_terminal: chain.previous.parse()?,
                    completion_digest: digest,
                    read_lease_hold: manifest.read_lease_hold,
                }
            } else {
                OriginalNodeRestartClassification::PartialEvidence {
                    records: chain.count,
                    original_terminal: chain.previous.parse()?,
                }
            };
            snapshot.rollback()?;
            no_sidecars(path)?;
            original.verify_single_link()?;
            if !original.matches_path(path)? || original.reader().metadata()?.len() != length {
                return Err(ReconcileError::Invariant(
                    "restart retained original changed during inspection",
                ));
            }
            for (path, held, key) in ancestors {
                if held.key()? != key || !held.matches_path(&path)? {
                    return Err(ReconcileError::Invariant(
                        "restart original ancestor changed",
                    ));
                }
            }
            Ok(classification)
        })();
        match inspected {
            Ok(value) => Ok(value),
            Err(error) => Ok(OriginalNodeRestartClassification::RefusedEvidence {
                reason: error.to_string().chars().take(1024).collect(),
            }),
        }
    }
}
