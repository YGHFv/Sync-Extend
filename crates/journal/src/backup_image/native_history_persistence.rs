//! Schema-70 persistence for an already audited inert native history source.
//!
//! The persisted representation is descriptive. It can never reconstruct the
//! sealed proof's issuer, and no row in this module grants release, GC, native,
//! cleanup, pending-resume or successor authority.
use super::native_history_family_registry::NativeHistoryFamilyRegistry;
use super::native_history_source_proof::{
    ImmutableNativeHistorySourceProof, NativeHistoryCasReference, NativeHistoryHoldSpec,
    NativeHistoryProjectionPlan, NativeHistoryReferenceKind, NativeHistoryRootColumnMapping,
    NativeHistoryRowKey, NativeHistorySourceTable,
};
use crate::{
    Journal, JournalCapacityLimits, JournalError, JournalStorageColumn, JournalStorageColumnValue,
    JournalStoredRow, NodeInspectionBounds, Result, TreeRestoreInventoryLimits,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SpaceId};

pub(crate) use super::native_history_source_audit::AuditedArchivedProjection;
mod fresh_writer;
pub(crate) mod schema;
pub use fresh_writer::{
    NativeHistoryFreshWriter, NativeHistoryFreshWriterAdmissionRequest,
    NativeHistoryFreshWriterAuthorityObservation, NativeHistoryFreshWriterInspection,
    NativeHistoryFreshWriterState,
};

const FORMAT_VERSION: u32 = 1;
const MAX_SOURCE_ROWS: usize = 100_000;

pub(crate) fn migrate_schema73(connection: &mut Connection) -> Result<()> {
    super::native_history_source_audit::migrate_schema73(connection)
}

pub(crate) fn migrate_schema74(connection: &mut Connection) -> Result<()> {
    super::native_history_source_audit::migrate_schema74(connection)
}

/// The complete native-history persistence inventory. Storage-role capacity
/// audits may accept these rows only when the exact fresh-writer/source
/// contract below owns every one of them.
pub(crate) const STORAGE_ROLE_OWNER_TABLES: &[&str] = &[
    "native_history_sources",
    "native_history_source_tables",
    "native_history_source_rows",
    "native_history_holds",
    "native_history_hold_rows",
    "native_history_hold_objects",
    "native_history_projection_rows",
    "native_history_projection_root_columns",
    "native_history_fresh_writers",
    "native_history_fresh_writer_events",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeHistorySourceBinding {
    source_digest: ContentId,
    image_digest: ContentId,
    space: SpaceId,
    tables: usize,
    rows: usize,
    owners: usize,
    projection_rows: usize,
    root_columns: usize,
}

impl NativeHistorySourceBinding {
    pub fn source_digest(&self) -> &ContentId {
        &self.source_digest
    }
    pub fn image_digest(&self) -> &ContentId {
        &self.image_digest
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn tables(&self) -> usize {
        self.tables
    }
    pub fn rows(&self) -> usize {
        self.rows
    }
    pub fn owners(&self) -> usize {
        self.owners
    }
    pub fn projection_rows(&self) -> usize {
        self.projection_rows
    }
    pub fn root_columns(&self) -> usize {
        self.root_columns
    }
}

/// Exact values reconstructed from immutable schema-70 source rows.
/// This is an inspection result, not a newly sealed issuer or access token.
pub struct PersistedNativeHistorySource {
    registry: NativeHistoryFamilyRegistry,
    source_digest: ContentId,
    image: Vec<u8>,
    image_digest: ContentId,
    catalog_digest: ContentId,
    rows_digest: ContentId,
    registry_digest: ContentId,
    space: SpaceId,
    tables: Vec<NativeHistorySourceTable>,
    rows: Vec<JournalStoredRow>,
    owners: Vec<NativeHistoryHoldSpec>,
    projection: NativeHistoryProjectionPlan,
    bounds: NodeInspectionBounds,
    logical_bytes: u64,
}

impl PersistedNativeHistorySource {
    pub fn source_schema(&self) -> u32 {
        self.registry.source_schema()
    }
    pub fn source_digest(&self) -> &ContentId {
        &self.source_digest
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn source_image(&self) -> &[u8] {
        &self.image
    }
    pub fn source_image_digest(&self) -> &ContentId {
        &self.image_digest
    }
    pub fn source_catalog_digest(&self) -> &ContentId {
        &self.catalog_digest
    }
    pub fn source_rows_digest(&self) -> &ContentId {
        &self.rows_digest
    }
    pub fn registry_digest(&self) -> &ContentId {
        &self.registry_digest
    }
    pub fn tables(&self) -> &[NativeHistorySourceTable] {
        &self.tables
    }
    pub fn rows(&self) -> &[JournalStoredRow] {
        &self.rows
    }
    pub fn owners(&self) -> &[NativeHistoryHoldSpec] {
        &self.owners
    }
    pub fn projection(&self) -> &NativeHistoryProjectionPlan {
        &self.projection
    }
    pub fn inspection_bounds(&self) -> NodeInspectionBounds {
        self.bounds
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn registry(&self) -> NativeHistoryFamilyRegistry {
        self.registry
    }
    pub fn binding(&self) -> NativeHistorySourceBinding {
        NativeHistorySourceBinding {
            source_digest: self.source_digest.clone(),
            image_digest: self.image_digest.clone(),
            space: self.space.clone(),
            tables: self.tables.len(),
            rows: self.rows.len(),
            owners: self.owners.len(),
            projection_rows: self.projection.portable_rows().len(),
            root_columns: self.projection.root_columns().len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHistoryAuthorityObservation {
    source_digest: ContentId,
    release: bool,
    gc: bool,
    cleanup: bool,
    native_issuance: bool,
    pending_resume: bool,
    persisted_successor: bool,
}

impl NativeHistoryAuthorityObservation {
    pub fn source_digest(&self) -> &ContentId {
        &self.source_digest
    }
    pub fn release_available(&self) -> bool {
        self.release
    }
    pub fn gc_available(&self) -> bool {
        self.gc
    }
    pub fn cleanup_available(&self) -> bool {
        self.cleanup
    }
    pub fn native_issuance_available(&self) -> bool {
        self.native_issuance
    }
    pub fn pending_resume_available(&self) -> bool {
        self.pending_resume
    }
    pub fn persisted_successor_available(&self) -> bool {
        self.persisted_successor
    }
    pub fn all_refused(&self) -> bool {
        !self.release
            && !self.gc
            && !self.cleanup
            && !self.native_issuance
            && !self.pending_resume
            && !self.persisted_successor
    }
}

struct InspectionBudget(NodeInspectionBounds);
impl Serialize for InspectionBudget {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        (
            self.0.max_entries,
            self.0.capacity,
            self.0.max_vm_instructions,
            self.0.max_query_time.as_nanos(),
        )
            .serialize(serializer)
    }
}

struct BoundedHashWriter {
    hasher: blake3::Hasher,
    bytes: u64,
    max: u64,
}
impl Write for BoundedHashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= self.max)
            .ok_or_else(|| std::io::Error::other("native history encoded byte bound"))?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_digest<T: Serialize>(value: &T, max: u64) -> Result<(ContentId, u64)> {
    let mut writer = BoundedHashWriter {
        hasher: blake3::Hasher::new(),
        bytes: 0,
        max,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok((ContentId::from_hasher(&writer.hasher), writer.bytes))
}

fn hash<T: Serialize>(value: &T) -> Result<ContentId> {
    Ok(ContentId::hash(&serde_json::to_vec(value)?))
}

fn reference_kind(value: NativeHistoryReferenceKind) -> &'static str {
    match value {
        NativeHistoryReferenceKind::CasChunk => "cas_chunk",
        NativeHistoryReferenceKind::FileContentDigest => "file_content_digest",
        NativeHistoryReferenceKind::NativeMarkerDigest => "native_marker_digest",
    }
}

fn parse_reference_kind(value: &str) -> Result<NativeHistoryReferenceKind> {
    match value {
        "cas_chunk" => Ok(NativeHistoryReferenceKind::CasChunk),
        "file_content_digest" => Ok(NativeHistoryReferenceKind::FileContentDigest),
        "native_marker_digest" => Ok(NativeHistoryReferenceKind::NativeMarkerDigest),
        _ => Err(JournalError::Invariant(
            "persisted native history reference kind",
        )),
    }
}

fn source_table_digest(
    table: &str,
    rows: u64,
    logical_bytes: u64,
    values: &[&JournalStoredRow],
) -> ContentId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-extend.native-history-original-table.v1");
    hasher.update(&(table.len() as u64).to_le_bytes());
    hasher.update(table.as_bytes());
    hasher.update(&rows.to_le_bytes());
    hasher.update(&logical_bytes.to_le_bytes());
    for value in values {
        hasher.update(value.fingerprint().as_str().as_bytes());
    }
    ContentId::from_hasher(&hasher)
}

fn source_digest(parts: &PersistedNativeHistorySource) -> Result<ContentId> {
    Ok(hash(&(
        "sync-extend.immutable-native-history-source-proof.v1",
        parts.registry.source_schema(),
        &parts.space,
        &parts.image_digest,
        &parts.catalog_digest,
        &parts.rows_digest,
        &parts.registry_digest,
        &parts.tables,
        parts
            .owners
            .iter()
            .map(NativeHistoryHoldSpec::digest)
            .collect::<Vec<_>>(),
        parts.projection.digest(),
        InspectionBudget(parts.bounds),
    ))?)
}

fn rows_digest(
    registry: NativeHistoryFamilyRegistry,
    space: &SpaceId,
    tables: &[NativeHistorySourceTable],
    rows: &[JournalStoredRow],
) -> Result<ContentId> {
    hash(&(
        "sync-extend.native-history-all-original-rows.v1",
        registry.source_schema(),
        space,
        tables,
        rows.iter()
            .map(JournalStoredRow::fingerprint)
            .collect::<Vec<_>>(),
    ))
}

impl Journal {
    /// Persist one sealed audit in a single transaction. Re-persisting the same
    /// source is an inspection-only no-op; a conflicting source is refused.
    pub fn persist_native_history_source(
        &mut self,
        proof: ImmutableNativeHistorySourceProof,
    ) -> Result<NativeHistorySourceBinding> {
        let parts = proof.proof_parts();
        parts.bounds.validate()?;
        let registry = parts.registry;
        registry.verify_complete()?;
        if parts.tables.len() != registry.table_count()
            || parts.rows.len() > MAX_SOURCE_ROWS
            || parts.rows.len() as u64 > parts.bounds.capacity.max_rows
            || parts.rows.len() > parts.bounds.capacity.inventory.max_rows
            || parts.owners.is_empty()
            || parts.owners.len() > parts.bounds.max_entries
            || parts.projection.portable_rows().len() > parts.bounds.max_entries
            || parts.projection.root_columns().len() > 1
        {
            return Err(JournalError::Invariant(
                "native history source persistence bounds",
            ));
        }
        let logical_bytes = parts.rows.iter().try_fold(0u64, |total, row| {
            total
                .checked_add(row.logical_bytes())
                .ok_or(JournalError::Invariant(
                    "native history persisted row bytes overflow",
                ))
        })?;
        if logical_bytes > parts.bounds.capacity.max_logical_bytes
            || logical_bytes > parts.bounds.capacity.inventory.max_logical_bytes
        {
            return Err(JournalError::Invariant(
                "native history persisted source logical bytes",
            ));
        }
        let key_ordinals = key_ordinals(registry, &parts.rows)?;
        let row_specs = registry.row_specs();
        for (index, table) in parts.tables.iter().enumerate() {
            let spec = row_specs.get(index).ok_or(JournalError::Invariant(
                "native history persisted table order",
            ))?;
            if table.table() != spec.name {
                return Err(JournalError::Invariant(
                    "persisted native history table order differs",
                ));
            }
        }
        let table_rows = table_row_groups(&parts.tables, &parts.rows)?;
        for (index, table) in parts.tables.iter().enumerate() {
            let values = table_rows.get(index).ok_or(JournalError::Invariant(
                "persisted native history table rows",
            ))?;
            if source_table_digest(table.table(), table.rows(), table.logical_bytes(), values)
                != *table.digest()
            {
                return Err(JournalError::Invariant(
                    "native history persisted table digest",
                ));
            }
        }
        if let Some(existing) = self
            .inspect_native_history_source(parts.source_digest.clone())
            .ok()
        {
            if existing.source_image() != parts.image
                || existing.source_digest() != &parts.source_digest
                || existing.source_rows_digest() != &parts.rows_digest
                || existing.owners().len() != parts.owners.len()
            {
                return Err(JournalError::Invariant(
                    "native history source re-persist differs",
                ));
            }
            return Ok(existing.binding());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO native_history_sources(
                source_digest,format_version,source_schema,space_id,image,image_digest,
                catalog_digest,rows_digest,registry_digest,table_count,row_count,hold_count,
                projection_row_count,root_mapping_count,logical_bytes,bound_max_entries,
                bound_inventory_rows,bound_inventory_logical_bytes,bound_rows,
                bound_logical_bytes,bound_vm_instructions,bound_query_nanos)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)",
            params![
                parts.source_digest.as_str(),
                FORMAT_VERSION,
                registry.source_schema(),
                parts.space.as_str(),
                parts.image,
                parts.image_digest.as_str(),
                parts.catalog_digest.as_str(),
                parts.rows_digest.as_str(),
                parts.registry_digest.as_str(),
                i64::try_from(parts.tables.len()).map_err(|_| JournalError::Invariant(
                    "native history table count"
                ))?,
                i64::try_from(parts.rows.len()).map_err(|_| JournalError::Invariant(
                    "native history row count"
                ))?,
                i64::try_from(parts.owners.len()).map_err(|_| JournalError::Invariant(
                    "native history hold count"
                ))?,
                i64::try_from(parts.projection.portable_rows().len()).map_err(|_| JournalError::Invariant(
                    "native history projection count"
                ))?,
                i64::try_from(parts.projection.root_columns().len()).map_err(|_| JournalError::Invariant(
                    "native history root count"
                ))?,
                i64::try_from(logical_bytes).map_err(|_| JournalError::Invariant(
                    "native history logical bytes"
                ))?,
                i64::try_from(parts.bounds.max_entries).map_err(|_| JournalError::Invariant(
                    "native history max entries"
                ))?,
                i64::try_from(parts.bounds.capacity.inventory.max_rows).map_err(|_| JournalError::Invariant(
                    "native history inventory rows"
                ))?,
                i64::try_from(parts.bounds.capacity.inventory.max_logical_bytes).map_err(|_| JournalError::Invariant(
                    "native history inventory bytes"
                ))?,
                i64::try_from(parts.bounds.capacity.max_rows).map_err(|_| JournalError::Invariant(
                    "native history capacity rows"
                ))?,
                i64::try_from(parts.bounds.capacity.max_logical_bytes).map_err(|_| JournalError::Invariant(
                    "native history capacity bytes"
                ))?,
                i64::try_from(parts.bounds.max_vm_instructions).map_err(|_| JournalError::Invariant(
                    "native history VM bound"
                ))?,
                i64::try_from(parts.bounds.max_query_time.as_nanos()).map_err(|_| JournalError::Invariant(
                    "native history query bound"
                ))?,
            ],
        )?;
        for (ordinal, table) in parts.tables.iter().enumerate() {
            tx.execute(
                "INSERT INTO native_history_source_tables(
                    source_digest,ordinal,table_name,row_count,logical_bytes,digest)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    parts.source_digest.as_str(),
                    i64::try_from(ordinal)
                        .map_err(|_| JournalError::Invariant("native history table ordinal"))?,
                    table.table(),
                    i64::try_from(table.rows())
                        .map_err(|_| JournalError::Invariant("native history table rows"))?,
                    i64::try_from(table.logical_bytes())
                        .map_err(|_| JournalError::Invariant("native history table bytes"))?,
                    table.digest().as_str(),
                ],
            )?;
        }
        for (ordinal, row) in parts.rows.iter().enumerate() {
            let key = row.primary_key();
            tx.execute(
                "INSERT INTO native_history_source_rows(
                    source_digest,ordinal,table_name,primary_key,columns_json,logical_bytes,fingerprint)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    parts.source_digest.as_str(),
                    i64::try_from(ordinal).map_err(|_| JournalError::Invariant(
                        "native history row ordinal"
                    ))?,
                    row.table(),
                    serde_json::to_string(&key)?,
                    serde_json::to_string(row.columns())?,
                    i64::try_from(row.logical_bytes()).map_err(|_| JournalError::Invariant(
                        "native history row bytes"
                    ))?,
                    row.fingerprint().as_str(),
                ],
            )?;
        }
        for (ordinal, owner) in parts.owners.iter().enumerate() {
            tx.execute(
                "INSERT INTO native_history_holds(
                    source_digest,ordinal,family,anchor_table,anchor_key,row_count,object_count,digest)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    parts.source_digest.as_str(),
                    i64::try_from(ordinal).map_err(|_| JournalError::Invariant(
                        "native history hold ordinal"
                    ))?,
                    owner.family(),
                    owner.anchor_table(),
                    serde_json::to_string(&owner.anchor_key())?,
                    i64::try_from(owner.source_rows().len()).map_err(|_| JournalError::Invariant(
                        "native history hold rows"
                    ))?,
                    i64::try_from(owner.objects().len()).map_err(|_| JournalError::Invariant(
                        "native history hold objects"
                    ))?,
                    owner.digest().as_str(),
                ],
            )?;
            for (hold_row_ordinal, row) in owner.source_rows().iter().enumerate() {
                let row_ordinal = *key_ordinals.get(row).ok_or(JournalError::Invariant(
                    "native history hold source row absent",
                ))?;
                tx.execute(
                    "INSERT INTO native_history_hold_rows(
                        source_digest,hold_ordinal,ordinal,row_ordinal)
                     VALUES(?1,?2,?3,?4)",
                    params![
                        parts.source_digest.as_str(),
                        i64::try_from(ordinal)
                            .map_err(|_| JournalError::Invariant("native history hold ordinal"))?,
                        i64::try_from(hold_row_ordinal).map_err(|_| JournalError::Invariant(
                            "native history hold row ordinal"
                        ))?,
                        i64::try_from(row_ordinal).map_err(|_| JournalError::Invariant(
                            "native history source row ordinal"
                        ))?,
                    ],
                )?;
            }
            for (object_ordinal, object) in owner.objects().iter().enumerate() {
                let source = NativeHistoryRowKey {
                    table: registry.table(reference_source_table(object))?.table,
                    primary_key: object.source_key().to_vec(),
                };
                let source_row_ordinal = *key_ordinals.get(&source).ok_or(
                    JournalError::Invariant("native history object source row absent"),
                )?;
                tx.execute(
                    "INSERT INTO native_history_hold_objects(
                        source_digest,hold_ordinal,ordinal,kind,content_id,length,
                        source_row_ordinal,source_column)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        parts.source_digest.as_str(),
                        i64::try_from(ordinal)
                            .map_err(|_| JournalError::Invariant("native history hold ordinal"))?,
                        i64::try_from(object_ordinal).map_err(|_| JournalError::Invariant(
                            "native history object ordinal"
                        ))?,
                        reference_kind(object.kind()),
                        object.content_id().as_str(),
                        i64::try_from(object.length())
                            .map_err(|_| JournalError::Invariant("native history object length"))?,
                        i64::try_from(source_row_ordinal).map_err(|_| JournalError::Invariant(
                            "native history object row ordinal"
                        ))?,
                        object.source_column(),
                    ],
                )?;
            }
        }
        for (ordinal, key) in parts.projection.portable_rows().iter().enumerate() {
            let row_ordinal = *key_ordinals.get(key).ok_or(JournalError::Invariant(
                "native history projection source row absent",
            ))?;
            tx.execute(
                "INSERT INTO native_history_projection_rows(source_digest,ordinal,row_ordinal)
                 VALUES(?1,?2,?3)",
                params![
                    parts.source_digest.as_str(),
                    i64::try_from(ordinal).map_err(|_| JournalError::Invariant(
                        "native history projection ordinal"
                    ))?,
                    i64::try_from(row_ordinal).map_err(|_| JournalError::Invariant(
                        "native history projection row ordinal"
                    ))?,
                ],
            )?;
        }
        for (ordinal, mapping) in parts.projection.root_columns().iter().enumerate() {
            let source = NativeHistoryRowKey {
                table: registry.table(mapping.table())?.table,
                primary_key: mapping.primary_key().to_vec(),
            };
            let row_ordinal = *key_ordinals.get(&source).ok_or(JournalError::Invariant(
                "native history root source row absent",
            ))?;
            tx.execute(
                "INSERT INTO native_history_projection_root_columns(
                    source_digest,ordinal,row_ordinal,column_name,original_value,projected_value)
                 VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    parts.source_digest.as_str(),
                    i64::try_from(ordinal)
                        .map_err(|_| JournalError::Invariant("native history root ordinal"))?,
                    i64::try_from(row_ordinal)
                        .map_err(|_| JournalError::Invariant("native history root row ordinal"))?,
                    mapping.column(),
                    mapping.original(),
                    mapping.projected(),
                ],
            )?;
        }
        tx.commit()?;
        self.inspect_native_history_source(parts.source_digest.clone())
            .map(|source| source.binding())
    }

    /// Reconstruct every persisted byte, digest, row and owner hold without
    /// entering any writer, release, GC or native issuance path.
    pub fn inspect_native_history_source(
        &self,
        source_digest: ContentId,
    ) -> Result<PersistedNativeHistorySource> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let result = inspect_source(&tx, &source_digest);
        tx.rollback()?;
        result
    }

    /// Return the fixed all-false authority observation for an inert source.
    pub fn observe_native_history_authority(
        &self,
        source_digest: ContentId,
    ) -> Result<NativeHistoryAuthorityObservation> {
        self.inspect_native_history_source(source_digest.clone())?;
        Ok(NativeHistoryAuthorityObservation {
            source_digest,
            release: false,
            gc: false,
            cleanup: false,
            native_issuance: false,
            pending_resume: false,
            persisted_successor: false,
        })
    }

    /// Explicit zero-effect refusal retained for callers that used to hold a
    /// reusable native/cleanup capability.
    pub fn release_native_history_hold(
        &self,
        source_digest: ContentId,
        _hold_ordinal: usize,
    ) -> Result<()> {
        self.inspect_native_history_source(source_digest)?;
        Err(JournalError::Invariant(
            "inert native history hold cannot be released",
        ))
    }

    pub fn admit_native_history_gc(&self, source_digest: ContentId, _: &ContentId) -> Result<()> {
        self.inspect_native_history_source(source_digest)?;
        Err(JournalError::Invariant(
            "inert native history source cannot enter GC",
        ))
    }

    pub fn delete_native_history_source(&self, source_digest: ContentId) -> Result<()> {
        self.inspect_native_history_source(source_digest)?;
        Err(JournalError::Invariant(
            "inert native history source cannot be deleted",
        ))
    }

    pub fn issue_native_history_source_authority(&self, source_digest: ContentId) -> Result<()> {
        self.inspect_native_history_source(source_digest)?;
        Err(JournalError::Invariant(
            "inert native history source issues no native authority",
        ))
    }
}

fn reference_source_table(reference: &NativeHistoryCasReference) -> &str {
    reference.source_table()
}

fn key_ordinals(
    registry: NativeHistoryFamilyRegistry,
    rows: &[JournalStoredRow],
) -> Result<BTreeMap<NativeHistoryRowKey, usize>> {
    let mut result = BTreeMap::new();
    for (ordinal, row) in rows.iter().enumerate() {
        let key = NativeHistoryRowKey {
            table: registry.table(row.table())?.table,
            primary_key: row.primary_key().to_vec(),
        };
        if result.insert(key, ordinal).is_some() {
            return Err(JournalError::Invariant(
                "native history duplicate persisted row key",
            ));
        }
    }
    Ok(result)
}

fn table_row_groups<'a>(
    tables: &[NativeHistorySourceTable],
    rows: &'a [JournalStoredRow],
) -> Result<Vec<Vec<&'a JournalStoredRow>>> {
    let mut result = Vec::with_capacity(tables.len());
    let mut offset = 0usize;
    for table in tables {
        let count = usize::try_from(table.rows())
            .map_err(|_| JournalError::Invariant("native history persisted table row count"))?;
        let end = offset
            .checked_add(count)
            .filter(|end| *end <= rows.len())
            .ok_or(JournalError::Invariant(
                "native history persisted table row slice",
            ))?;
        let values = &rows[offset..end];
        if values.iter().any(|row| row.table() != table.table()) {
            return Err(JournalError::Invariant(
                "native history persisted table row order",
            ));
        }
        let bytes = values.iter().try_fold(0u64, |total, row| {
            total
                .checked_add(row.logical_bytes())
                .ok_or(JournalError::Invariant(
                    "native history persisted table bytes",
                ))
        })?;
        if bytes != table.logical_bytes() {
            return Err(JournalError::Invariant(
                "native history persisted table byte count",
            ));
        }
        result.push(values.iter().collect());
        offset = end;
    }
    if offset != rows.len() {
        return Err(JournalError::Invariant(
            "native history persisted table row total",
        ));
    }
    Ok(result)
}

fn parse_key(value: String) -> Result<Vec<String>> {
    if value.len() > 65_536 {
        return Err(JournalError::Invariant(
            "persisted native history key bytes",
        ));
    }
    Ok(serde_json::from_str(&value)?)
}

/// Accept native-history rows into a storage-role capacity audit only when
/// every row belongs to the exact fresh-writer/source contract for this
/// worktree-free identity.
///
/// Rule:
/// 1. every fresh writer names this exact space and device;
/// 2. every fresh writer validates its complete event chain and source binding;
/// 3. every persisted source is referenced by one of those writers;
/// 4. every source is the exact storage identity (`space_id`, `device_id`,
///    `storage_role=storage-v1`, no worktree) and validates its complete image,
///    table, row, hold, object and projection digests;
/// 5. every dependency row references a validated source/writer.
///
/// A row that cannot be attributed this way is a genuine foreign client/native
/// owner and must still refuse the storage-only adapter.
pub(crate) fn validate_storage_role_owners(
    connection: &Connection,
    space: &SpaceId,
    device: &DeviceId,
) -> Result<()> {
    let writer_rows = connection
        .prepare(
            "SELECT writer_id,source_digest,space_id,device_id
             FROM native_history_fresh_writers ORDER BY writer_id",
        )?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut referenced_sources = BTreeSet::new();
    for (writer_id, source_digest, writer_space, writer_device) in writer_rows {
        if writer_space != space.as_str() || writer_device != device.as_str() {
            return Err(JournalError::Invariant(
                "storage role foreign native history writer identity",
            ));
        }
        let writer_id: EntryId = writer_id.parse()?;
        let source_digest: ContentId = source_digest.parse()?;
        let inspection = fresh_writer::inspect_writer_connection(connection, &writer_id)?;
        if inspection.source_digest() != &source_digest
            || inspection.space() != space
            || inspection.device() != device
        {
            return Err(JournalError::Invariant(
                "storage role native history writer contract differs",
            ));
        }
        referenced_sources.insert(source_digest);
    }

    let source_rows = connection
        .prepare("SELECT source_digest FROM native_history_sources ORDER BY source_digest")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut validated_sources = BTreeSet::new();
    for digest in source_rows {
        let digest: ContentId = digest.parse()?;
        if !referenced_sources.contains(&digest) {
            return Err(JournalError::Invariant(
                "storage role native history source has no fresh writer",
            ));
        }
        let source = inspect_source(connection, &digest)?;
        if source.space() != space {
            return Err(JournalError::Invariant(
                "storage role foreign native history source space",
            ));
        }
        let keys: BTreeSet<&str> = source
            .rows()
            .iter()
            .filter(|row| row.table() == "local_state")
            .filter_map(|row| row.primary_key().first().map(String::as_str))
            .collect();
        if keys != BTreeSet::from(["device_id", "space_id", "storage_role"]) {
            return Err(JournalError::Invariant(
                "storage role native history source identity keys",
            ));
        }
        if source_local_state(&source, "space_id")? != Some(space.as_str())
            || source_local_state(&source, "device_id")? != Some(device.as_str())
            || source_local_state(&source, "storage_role")? != Some("storage-v1")
            || source_local_state(&source, "worktree")?.is_some()
        {
            return Err(JournalError::Invariant(
                "storage role foreign native history source identity",
            ));
        }
        validated_sources.insert(digest);
    }
    if validated_sources != referenced_sources {
        return Err(JournalError::Invariant(
            "storage role native history source contract differs",
        ));
    }

    for table in [
        "native_history_source_tables",
        "native_history_source_rows",
        "native_history_holds",
        "native_history_hold_rows",
        "native_history_hold_objects",
        "native_history_projection_rows",
        "native_history_projection_root_columns",
    ] {
        let foreign: bool = connection.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM main.{table}
                 WHERE source_digest NOT IN
                   (SELECT source_digest FROM main.native_history_sources))"
            ),
            [],
            |row| row.get(0),
        )?;
        if foreign {
            return Err(JournalError::Invariant(
                "storage role foreign native history dependency row",
            ));
        }
    }
    for table in ["native_history_hold_rows", "native_history_hold_objects"] {
        let foreign: bool = connection.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM main.{table}
                 WHERE (source_digest,hold_ordinal) NOT IN
                   (SELECT source_digest,ordinal FROM main.native_history_holds))"
            ),
            [],
            |row| row.get(0),
        )?;
        if foreign {
            return Err(JournalError::Invariant(
                "storage role foreign native history hold row",
            ));
        }
    }
    let orphan_events: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.native_history_fresh_writer_events
         WHERE writer_id NOT IN
           (SELECT writer_id FROM main.native_history_fresh_writers))",
        [],
        |row| row.get(0),
    )?;
    if orphan_events {
        return Err(JournalError::Invariant(
            "storage role foreign native history writer event",
        ));
    }
    Ok(())
}

fn source_local_state<'a>(
    source: &'a PersistedNativeHistorySource,
    key: &str,
) -> Result<Option<&'a str>> {
    let Some(row) = source
        .rows()
        .iter()
        .find(|row| row.table() == "local_state" && row.primary_key() == [key])
    else {
        return Ok(None);
    };
    let Some(column) = row.columns().iter().find(|column| column.name == "value") else {
        return Err(JournalError::Invariant(
            "persisted native history source identity value absent",
        ));
    };
    match &column.value {
        JournalStorageColumnValue::Text(value) => Ok(Some(value)),
        _ => Err(JournalError::Invariant(
            "persisted native history source identity value type",
        )),
    }
}

pub(super) fn inspect_source(
    connection: &Connection,
    expected: &ContentId,
) -> Result<PersistedNativeHistorySource> {
    // Bound the blob before rusqlite allocates its owned representation. The
    // recursive source auditor also reserves the complete sibling aggregate.
    let image_length: u64 = connection.query_row(
        "SELECT length(image) FROM native_history_sources WHERE source_digest=?1",
        [expected.as_str()],
        |row| crate::sql_u64(row, 0),
    )?;
    if !(512..=NativeHistoryFamilyRegistry::MAX_AGGREGATE_IMAGE_BYTES as u64)
        .contains(&image_length)
    {
        return Err(JournalError::Invariant(
            "persisted native history image length bound",
        ));
    }
    let header = connection
        .query_row(
            "SELECT format_version,source_schema,space_id,image,image_digest,catalog_digest,
                    rows_digest,registry_digest,table_count,row_count,hold_count,
                    projection_row_count,root_mapping_count,logical_bytes,bound_max_entries,
                    bound_inventory_rows,bound_inventory_logical_bytes,bound_rows,
                    bound_logical_bytes,bound_vm_instructions,bound_query_nanos
             FROM native_history_sources WHERE source_digest=?1",
            [expected.as_str()],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    crate::sql_u64(row, 8)?,
                    crate::sql_u64(row, 9)?,
                    crate::sql_u64(row, 10)?,
                    crate::sql_u64(row, 11)?,
                    crate::sql_u64(row, 12)?,
                    crate::sql_u64(row, 13)?,
                    crate::sql_u64(row, 14)?,
                    crate::sql_u64(row, 15)?,
                    crate::sql_u64(row, 16)?,
                    crate::sql_u64(row, 17)?,
                    crate::sql_u64(row, 18)?,
                    crate::sql_u64(row, 19)?,
                    crate::sql_u64(row, 20)?,
                ))
            },
        )
        .optional()?
        .ok_or(JournalError::Invariant(
            "persisted native history source absent",
        ))?;
    let registry = NativeHistoryFamilyRegistry::for_schema(header.1)?;
    if header.0 != FORMAT_VERSION {
        return Err(JournalError::Invariant(
            "persisted native history source format or schema",
        ));
    }
    if header.8 != registry.table_count() as u64
        || header.9 > MAX_SOURCE_ROWS as u64
        || header.10 == 0
        || header.10 > MAX_SOURCE_ROWS as u64
        || header.11 > MAX_SOURCE_ROWS as u64
        || header.12 > 1
    {
        return Err(JournalError::Invariant(
            "persisted native history source count bounds",
        ));
    }
    let bounds = NodeInspectionBounds {
        max_entries: usize::try_from(header.14)
            .map_err(|_| JournalError::Invariant("persisted native history max entries"))?,
        capacity: JournalCapacityLimits {
            inventory: TreeRestoreInventoryLimits {
                max_rows: usize::try_from(header.15).map_err(|_| {
                    JournalError::Invariant("persisted native history inventory rows")
                })?,
                max_logical_bytes: header.16,
            },
            max_rows: header.17,
            max_logical_bytes: header.18,
        },
        max_vm_instructions: header.19,
        max_query_time: std::time::Duration::from_nanos(header.20),
    };
    bounds.validate()?;
    if header.9 > bounds.capacity.max_rows
        || header.13 > bounds.capacity.max_logical_bytes
        || header.10 > bounds.max_entries as u64
        || header.11 > bounds.max_entries as u64
        || header.12 > bounds.max_entries as u64
    {
        return Err(JournalError::Invariant(
            "persisted native history source exceeds stored bounds",
        ));
    }
    let image_digest = header.4.parse::<ContentId>()?;
    let catalog_digest = header.5.parse::<ContentId>()?;
    let expected_rows_digest = header.6.parse::<ContentId>()?;
    let expected_registry_digest = header.7.parse::<ContentId>()?;
    if ContentId::hash(&header.3) != image_digest {
        return Err(JournalError::Invariant(
            "persisted native history image digest differs",
        ));
    }
    let space = header.2.parse::<SpaceId>()?;
    let row_specs = registry.row_specs();
    let tables = connection
        .prepare(
            "SELECT ordinal,table_name,row_count,logical_bytes,digest
             FROM native_history_source_tables WHERE source_digest=?1 ORDER BY ordinal",
        )?
        .query_map([expected.as_str()], |row| {
            Ok((
                crate::sql_u64(row, 0)?,
                row.get::<_, String>(1)?,
                crate::sql_u64(row, 2)?,
                crate::sql_u64(row, 3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if tables.len() != registry.table_count() {
        return Err(JournalError::Invariant(
            "persisted native history table inventory count",
        ));
    }
    let mut source_tables = Vec::with_capacity(tables.len());
    for (index, (ordinal, name, rows, bytes, digest)) in tables.into_iter().enumerate() {
        if ordinal != index as u64 {
            return Err(JournalError::Invariant(
                "persisted native history table ordinal",
            ));
        }
        let spec = row_specs.get(index).ok_or(JournalError::Invariant(
            "persisted native history table order",
        ))?;
        if spec.name != name {
            return Err(JournalError::Invariant(
                "persisted native history table identity",
            ));
        }
        source_tables.push(NativeHistorySourceTable {
            table: spec.name,
            rows,
            logical_bytes: bytes,
            digest: digest.parse::<ContentId>()?,
        });
    }
    let rows = connection
        .prepare(
            "SELECT ordinal,table_name,primary_key,columns_json,logical_bytes,fingerprint
             FROM native_history_source_rows WHERE source_digest=?1 ORDER BY ordinal LIMIT ?2",
        )?
        .query_map(params![expected.as_str(), header.9 as i64 + 1], |row| {
            Ok((
                crate::sql_u64(row, 0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                crate::sql_u64(row, 4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() as u64 != header.9 {
        return Err(JournalError::Invariant(
            "persisted native history row count",
        ));
    }
    let mut source_rows = Vec::with_capacity(rows.len());
    for (index, (ordinal, table, primary_key, columns, logical_bytes, fingerprint)) in
        rows.into_iter().enumerate()
    {
        if ordinal != index as u64 {
            return Err(JournalError::Invariant(
                "persisted native history row ordinal",
            ));
        }
        let rule = registry.table(&table)?;
        let columns: Vec<JournalStorageColumn> = serde_json::from_str(&columns)?;
        if columns.len() != rule.columns.len()
            || columns
                .iter()
                .zip(rule.columns)
                .any(|(column, spec)| column.name != spec.name)
        {
            return Err(JournalError::Invariant(
                "persisted native history row column layout",
            ));
        }
        source_rows.push(JournalStoredRow::from_persisted(
            rule.table,
            parse_key(primary_key)?,
            columns,
            logical_bytes,
            fingerprint.parse::<ContentId>()?,
        )?);
    }
    let grouped = table_row_groups(&source_tables, &source_rows)?;
    for (table, values) in source_tables.iter().zip(&grouped) {
        if values.len() as u64 != table.rows()
            || source_table_digest(table.table(), table.rows(), table.logical_bytes(), values)
                != *table.digest()
        {
            return Err(JournalError::Invariant(
                "persisted native history table rows or digest",
            ));
        }
    }
    let mut hold_rows: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for row in connection
        .prepare(
            "SELECT hold_ordinal,ordinal,row_ordinal FROM native_history_hold_rows
             WHERE source_digest=?1 ORDER BY hold_ordinal,ordinal",
        )?
        .query_map([expected.as_str()], |row| {
            Ok((
                crate::sql_u64(row, 0)?,
                crate::sql_u64(row, 1)?,
                crate::sql_u64(row, 2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    {
        let values = hold_rows.entry(row.0).or_default();
        if row.1 != values.len() as u64 {
            return Err(JournalError::Invariant(
                "persisted native history hold row ordinal",
            ));
        }
        values.push(row.2);
    }
    let mut hold_objects: BTreeMap<u64, Vec<PersistedObject>> = BTreeMap::new();
    for row in connection
        .prepare(
            "SELECT hold_ordinal,ordinal,kind,content_id,length,source_row_ordinal,source_column
             FROM native_history_hold_objects WHERE source_digest=?1
             ORDER BY hold_ordinal,ordinal",
        )?
        .query_map([expected.as_str()], |row| {
            Ok((
                crate::sql_u64(row, 0)?,
                crate::sql_u64(row, 1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                crate::sql_u64(row, 4)?,
                crate::sql_u64(row, 5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    {
        let values = hold_objects.entry(row.0).or_default();
        if row.1 != values.len() as u64 {
            return Err(JournalError::Invariant(
                "persisted native history hold object ordinal",
            ));
        }
        values.push(PersistedObject {
            kind: parse_reference_kind(&row.2)?,
            content_id: row.3.parse::<ContentId>()?,
            length: row.4,
            source_row: row.5,
            source_column: row.6,
        });
    }
    let stored_holds = connection
        .prepare(
            "SELECT ordinal,family,anchor_table,anchor_key,row_count,object_count,digest
             FROM native_history_holds WHERE source_digest=?1 ORDER BY ordinal",
        )?
        .query_map([expected.as_str()], |row| {
            Ok((
                crate::sql_u64(row, 0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                crate::sql_u64(row, 4)?,
                crate::sql_u64(row, 5)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if stored_holds.len() as u64 != header.10 {
        return Err(JournalError::Invariant(
            "persisted native history hold count",
        ));
    }
    let mut owners = Vec::with_capacity(stored_holds.len());
    let mut held_rows = BTreeSet::new();
    for (index, (ordinal, family, anchor_table, anchor_key, row_count, object_count, digest)) in
        stored_holds.into_iter().enumerate()
    {
        if ordinal != index as u64 {
            return Err(JournalError::Invariant(
                "persisted native history hold ordinal",
            ));
        }
        let rule = registry.table(&anchor_table)?;
        if rule.family != family {
            return Err(JournalError::Invariant(
                "persisted native history hold family",
            ));
        }
        let anchor = NativeHistoryRowKey {
            table: rule.table,
            primary_key: parse_key(anchor_key)?,
        };
        let row_ordinals = hold_rows.remove(&ordinal).unwrap_or_default();
        if row_ordinals.len() as u64 != row_count {
            return Err(JournalError::Invariant(
                "persisted native history hold row count",
            ));
        }
        let held_source_rows = row_ordinals
            .into_iter()
            .map(|ordinal| {
                let row = source_rows
                    .get(usize::try_from(ordinal).map_err(|_| {
                        JournalError::Invariant("persisted native history hold row index")
                    })?)
                    .ok_or(JournalError::Invariant(
                        "persisted native history hold row absent",
                    ))?;
                if !held_rows.insert(ordinal) {
                    return Err(JournalError::Invariant(
                        "persisted native history row held twice",
                    ));
                }
                Ok(NativeHistoryRowKey {
                    table: rule_for_row(&registry, row)?.table,
                    primary_key: row.primary_key().to_vec(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if !held_source_rows.contains(&anchor) {
            return Err(JournalError::Invariant(
                "persisted native history hold anchor absent",
            ));
        }
        let held_source_keys: BTreeSet<_> = held_source_rows.iter().cloned().collect();
        let objects = hold_objects
            .remove(&ordinal)
            .unwrap_or_default()
            .into_iter()
            .map(|object| {
                let row = source_rows
                    .get(usize::try_from(object.source_row).map_err(|_| {
                        JournalError::Invariant("persisted native history object row index")
                    })?)
                    .ok_or(JournalError::Invariant(
                        "persisted native history object row absent",
                    ))?;
                let source = NativeHistoryRowKey {
                    table: rule_for_row(&registry, row)?.table,
                    primary_key: row.primary_key().to_vec(),
                };
                if !held_source_keys.contains(&source) {
                    return Err(JournalError::Invariant(
                        "persisted native history object row not held",
                    ));
                }
                Ok(NativeHistoryCasReference {
                    kind: object.kind,
                    content_id: object.content_id,
                    length: object.length,
                    source,
                    source_column: object.source_column,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if objects.len() as u64 != object_count {
            return Err(JournalError::Invariant(
                "persisted native history hold object count",
            ));
        }
        let (actual, _) = bounded_digest(
            &(
                "sync-extend.native-history-original-owner-hold.v1",
                family,
                &anchor,
                &held_source_rows,
                &objects,
            ),
            bounds.capacity.inventory.max_logical_bytes,
        )?;
        if actual != digest.parse::<ContentId>()? {
            return Err(JournalError::Invariant(
                "persisted native history hold digest",
            ));
        }
        owners.push(NativeHistoryHoldSpec {
            family: rule.family,
            anchor,
            source_rows: held_source_rows,
            objects,
            digest: actual,
        });
    }
    if !hold_rows.is_empty() || !hold_objects.is_empty() || held_rows.len() != source_rows.len() {
        return Err(JournalError::Invariant(
            "persisted native history owner partition",
        ));
    }
    let projection_rows = connection
        .prepare(
            "SELECT ordinal,row_ordinal FROM native_history_projection_rows
             WHERE source_digest=?1 ORDER BY ordinal",
        )?
        .query_map([expected.as_str()], |row| {
            Ok((crate::sql_u64(row, 0)?, crate::sql_u64(row, 1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if projection_rows.len() as u64 != header.11 {
        return Err(JournalError::Invariant(
            "persisted native history projection count",
        ));
    }
    let mut portable_rows = Vec::with_capacity(projection_rows.len());
    for (index, (ordinal, row_ordinal)) in projection_rows.into_iter().enumerate() {
        if ordinal != index as u64 {
            return Err(JournalError::Invariant(
                "persisted native history projection ordinal",
            ));
        }
        let row =
            source_rows
                .get(usize::try_from(row_ordinal).map_err(|_| {
                    JournalError::Invariant("persisted native history projection row")
                })?)
                .ok_or(JournalError::Invariant(
                    "persisted native history projection row absent",
                ))?;
        portable_rows.push(NativeHistoryRowKey {
            table: rule_for_row(&registry, row)?.table,
            primary_key: row.primary_key().to_vec(),
        });
    }
    if portable_rows
        .windows(2)
        .any(|window| window[0] >= window[1])
    {
        return Err(JournalError::Invariant(
            "persisted native history projection order",
        ));
    }
    let root_columns = connection
        .prepare(
            "SELECT ordinal,row_ordinal,column_name,original_value,projected_value
             FROM native_history_projection_root_columns
             WHERE source_digest=?1 ORDER BY ordinal",
        )?
        .query_map([expected.as_str()], |row| {
            Ok((
                crate::sql_u64(row, 0)?,
                crate::sql_u64(row, 1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if root_columns.len() as u64 != header.12 {
        return Err(JournalError::Invariant(
            "persisted native history root count",
        ));
    }
    let mut mappings = Vec::with_capacity(root_columns.len());
    for (index, (ordinal, row_ordinal, column_name, original, projected)) in
        root_columns.into_iter().enumerate()
    {
        if ordinal != index as u64 || column_name.is_empty() || original == projected {
            return Err(JournalError::Invariant(
                "persisted native history root mapping",
            ));
        }
        let row = source_rows
            .get(
                usize::try_from(row_ordinal)
                    .map_err(|_| JournalError::Invariant("persisted native history root row"))?,
            )
            .ok_or(JournalError::Invariant(
                "persisted native history root row absent",
            ))?;
        let rule = rule_for_row(&registry, row)?;
        let column = rule
            .columns
            .iter()
            .find(|column| column.name == column_name)
            .ok_or(JournalError::Invariant(
                "persisted native history root column absent",
            ))?;
        if !rule.root_bound_columns.contains(&column.name) {
            return Err(JournalError::Invariant(
                "persisted native history root column unbound",
            ));
        }
        mappings.push(NativeHistoryRootColumnMapping {
            source: NativeHistoryRowKey {
                table: rule.table,
                primary_key: row.primary_key().to_vec(),
            },
            column: column.name,
            original,
            projected,
        });
    }
    let (projection_digest, _) = bounded_digest(
        &(
            "sync-extend.native-history-independent-active-projection.v1",
            &portable_rows,
            &mappings,
        ),
        bounds.capacity.inventory.max_logical_bytes,
    )?;
    let projection = NativeHistoryProjectionPlan {
        portable_rows,
        root_columns: mappings,
        digest: projection_digest,
    };
    let actual_rows_digest = rows_digest(registry, &space, &source_tables, &source_rows)?;
    let actual_registry_digest = registry.digest()?;
    if actual_rows_digest != expected_rows_digest
        || actual_registry_digest != expected_registry_digest
    {
        return Err(JournalError::Invariant(
            "persisted native history row or registry digest",
        ));
    }
    let mut result = PersistedNativeHistorySource {
        registry,
        source_digest: expected.clone(),
        image: header.3,
        image_digest,
        catalog_digest,
        rows_digest: actual_rows_digest,
        registry_digest: actual_registry_digest,
        space,
        tables: source_tables,
        rows: source_rows,
        owners,
        projection,
        bounds,
        logical_bytes: header.13,
    };
    if source_digest(&result)? != *expected {
        return Err(JournalError::Invariant(
            "persisted native history complete source digest",
        ));
    }
    let actual_logical = result.rows.iter().try_fold(0u64, |total, row| {
        total
            .checked_add(row.logical_bytes())
            .ok_or(JournalError::Invariant(
                "persisted native history logical bytes overflow",
            ))
    })?;
    if actual_logical != result.logical_bytes {
        return Err(JournalError::Invariant(
            "persisted native history logical bytes",
        ));
    }
    result.bounds = bounds;
    Ok(result)
}

pub(super) fn audit_nested_writers(
    connection: &Connection,
    source: &PersistedNativeHistorySource,
    space: &SpaceId,
    device: &DeviceId,
) -> Result<()> {
    fresh_writer::audit_nested_writers(connection, source, space, device)
}

fn rule_for_row(
    registry: &NativeHistoryFamilyRegistry,
    row: &JournalStoredRow,
) -> Result<&'static super::native_history_family_registry::NativeHistoryTableRule> {
    registry.table(row.table())
}

struct PersistedObject {
    kind: NativeHistoryReferenceKind,
    content_id: ContentId,
    length: u64,
    source_row: u64,
    source_column: String,
}

pub(crate) fn holds_content(connection: &Connection, content: &ContentId) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.native_history_hold_objects WHERE content_id=?1)",
        [content.as_str()],
        |row| row.get(0),
    )?)
}
