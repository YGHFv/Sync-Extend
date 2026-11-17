//! Bounded original main-table descriptions; no persisted row becomes an issuer.
use crate::{JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use sync_extend_core_model::{ContentId, SpaceId};

#[derive(Serialize)]
pub struct RecoveredHistoryTable {
    pub table: String,
    pub retained_rows: u64,
    pub retained_logical_bytes: u64,
    pub original_rows_digest: ContentId,
}

#[derive(Serialize)]
pub struct RecoveredHistoryTables {
    pub image_digest: ContentId,
    pub tables: Vec<RecoveredHistoryTable>,
    pub retained_rows: u64,
    pub retained_logical_bytes: u64,
    pub catalog_digest: ContentId,
    pub native_authority: bool,
    pub cleanup_authority: bool,
    pub gc_release_authority: bool,
    pub pending_resume_authority: bool,
}

impl JournalBackupImage {
    /// Uses every named table in the original audited catalog. Current/cursor
    /// cells and local_state are kept in the whole-image audit but excluded
    /// from retained history summaries because explicit new sessions evolve them.
    /// Summaries preserve original row digests and never infer completion from
    /// the existence of a phase or reconstruct holders from original keys.
    pub fn recovered_history_tables(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<RecoveredHistoryTables> {
        self.with_audited_readonly(space, bounds, |connection| {
            let audit = crate::JournalReadView { connection }.audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            let (tables, retained_rows, retained_logical_bytes) =
                summarize_original_tables(&audit.rows, bounds, true)?;
            let encoded = serde_json::to_vec(&tables)?;
            if encoded.len() as u64 > bounds.capacity.max_logical_bytes {
                return Err(JournalError::Invariant(
                    "recovered history original summary byte bound",
                ));
            }
            Ok(RecoveredHistoryTables {
                image_digest: ContentId::hash(self.bytes()),
                tables,
                retained_rows,
                retained_logical_bytes,
                catalog_digest: ContentId::hash(&encoded),
                native_authority: false,
                cleanup_authority: false,
                gc_release_authority: false,
                pending_resume_authority: false,
            })
        })
    }
}

/// Every original main user table, including mutable state, cursors and native
/// history stored in local_state. Counts describe this immutable image only.
#[derive(Serialize)]
pub struct RecoveredMainTable {
    pub table: String,
    pub stored_rows: u64,
    pub stored_logical_bytes: u64,
    pub original_rows_digest: ContentId,
}

#[derive(Serialize)]
pub struct RecoveredMainTables {
    pub image_digest: ContentId,
    pub tables: Vec<RecoveredMainTable>,
    pub stored_rows: u64,
    pub stored_logical_bytes: u64,
    pub catalog_digest: ContentId,
    pub native_authority: bool,
    pub cleanup_authority: bool,
    pub gc_release_authority: bool,
    pub pending_resume_authority: bool,
}

impl JournalBackupImage {
    /// The complete original catalog shares the retained query's exact row
    /// summarizer. Whole-image provenance and capacity checks run first.
    /// No column values or secrets are returned, and rows confer no issuer.
    pub fn recovered_main_tables(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<RecoveredMainTables> {
        self.with_audited_readonly(space, bounds, |connection| {
            let audit = crate::JournalReadView { connection }.audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            let (history_tables, stored_rows, stored_logical_bytes) =
                summarize_original_tables(&audit.rows, bounds, false)?;
            let tables: Vec<_> = history_tables
                .into_iter()
                .map(|table| RecoveredMainTable {
                    table: table.table,
                    stored_rows: table.retained_rows,
                    stored_logical_bytes: table.retained_logical_bytes,
                    original_rows_digest: table.original_rows_digest,
                })
                .collect();
            let encoded = serde_json::to_vec(&tables)?;
            if encoded.len() as u64 > bounds.capacity.max_logical_bytes {
                return Err(JournalError::Invariant(
                    "recovered main original summary byte bound",
                ));
            }
            Ok(RecoveredMainTables {
                image_digest: ContentId::hash(self.bytes()),
                tables,
                stored_rows,
                stored_logical_bytes,
                catalog_digest: ContentId::hash(&encoded),
                native_authority: false,
                cleanup_authority: false,
                gc_release_authority: false,
                pending_resume_authority: false,
            })
        })
    }
}

/// The retained view keeps its original exclusions and digest domain. The
/// complete view includes the same original catalog without those exclusions.
fn summarize_original_tables(
    rows: &[crate::JournalStoredRow],
    bounds: NodeInspectionBounds,
    exclude_runtime: bool,
) -> Result<(Vec<RecoveredHistoryTable>, u64, u64)> {
    let mut catalog = BTreeMap::new();
    for spec in crate::storage_inventory::tables() {
        if exclude_runtime
            && matches!(
                spec.name,
                "local_state" | "current_manifests" | "receive_cursors"
            )
        {
            continue;
        }
        let mut digest = blake3::Hasher::new();
        digest.update(b"sync-extend.recovered-history-table.v1");
        digest.update(&(spec.name.len() as u64).to_le_bytes());
        digest.update(spec.name.as_bytes());
        if catalog.insert(spec.name, (0u64, 0u64, digest)).is_some() {
            return Err(JournalError::Invariant(
                "recovered table original catalog duplicate",
            ));
        }
    }
    let mut retained_rows = 0u64;
    let mut retained_logical_bytes = 0u64;
    for row in rows {
        if exclude_runtime
            && matches!(
                row.table(),
                "local_state" | "current_manifests" | "receive_cursors"
            )
        {
            continue;
        }
        let (count, bytes, digest) = catalog.get_mut(row.table()).ok_or(
            JournalError::Invariant("recovered table original catalog row absent"),
        )?;
        retained_rows = retained_rows
            .checked_add(1)
            .filter(|count| *count <= bounds.capacity.max_rows)
            .ok_or(JournalError::Invariant(
                "recovered table original total row bound",
            ))?;
        retained_logical_bytes = retained_logical_bytes
            .checked_add(row.logical_bytes())
            .filter(|bytes| *bytes <= bounds.capacity.max_logical_bytes)
            .ok_or(JournalError::Invariant(
                "recovered table original total byte bound",
            ))?;
        *count = count.checked_add(1).ok_or(JournalError::Invariant(
            "recovered table original table row overflow",
        ))?;
        *bytes = bytes
            .checked_add(row.logical_bytes())
            .ok_or(JournalError::Invariant(
                "recovered table original table byte overflow",
            ))?;
        // The original audit fingerprint includes table, exact primary
        // key and typed column values. Values are not emitted here.
        digest.update(row.fingerprint().as_str().as_bytes());
    }
    let tables: Vec<_> = catalog
        .into_iter()
        .map(|(table, (count, bytes, digest))| RecoveredHistoryTable {
            table: table.into(),
            retained_rows: count,
            retained_logical_bytes: bytes,
            original_rows_digest: ContentId::from_hasher(&digest),
        })
        .collect();
    Ok((tables, retained_rows, retained_logical_bytes))
}
