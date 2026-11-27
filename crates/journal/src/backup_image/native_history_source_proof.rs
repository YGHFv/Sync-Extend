//! Sealed immutable schema-69 source data, never a recovered native issuer.
use super::{
    NodeInspectionBounds, native_history_family_registry::NativeHistoryFamilyRegistry,
    native_history_source_audit::AuditedNativeHistorySource,
};
use crate::{JournalBackupImage, JournalStoredRow, Result};
use serde::Serialize;
use sync_extend_core_model::{ContentId, SpaceId};

/// A natural key in the untouched original image. It is descriptive data.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NativeHistoryRowKey {
    pub(super) table: &'static str,
    pub(super) primary_key: Vec<String>,
}

impl NativeHistoryRowKey {
    pub fn table(&self) -> &'static str {
        self.table
    }
    pub fn primary_key(&self) -> &[String] {
        &self.primary_key
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeHistoryReferenceKind {
    /// The content-addressed object is a chunk, with its exact original length.
    CasChunk,
    /// A whole-file hash identifies bytes assembled from the recorded chunks.
    /// It is not necessarily the address of an independently stored CAS object.
    FileContentDigest,
    /// An original marker hash is retained as physical metadata only.
    NativeMarkerDigest,
}

impl NativeHistoryReferenceKind {
    pub fn is_cas_object(self) -> bool {
        matches!(self, Self::CasChunk)
    }
}

/// One reference attributed to one original owner and one exact source cell.
/// Distinct owners may contain the same ID; they never share a hold identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NativeHistoryCasReference {
    pub(super) kind: NativeHistoryReferenceKind,
    pub(super) content_id: ContentId,
    pub(super) length: u64,
    pub(super) source: NativeHistoryRowKey,
    pub(super) source_column: String,
}

impl NativeHistoryCasReference {
    pub fn kind(&self) -> NativeHistoryReferenceKind {
        self.kind
    }
    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn source_table(&self) -> &str {
        self.source.table()
    }
    pub fn source_key(&self) -> &[String] {
        self.source.primary_key()
    }
    pub fn source_column(&self) -> &str {
        &self.source_column
    }
}

/// Every header creates its own immutable hold, including an empty scope.
/// This object neither releases the original references nor adopts its issuer.
#[derive(Debug, Serialize)]
pub struct NativeHistoryHoldSpec {
    pub(super) family: &'static str,
    pub(super) anchor: NativeHistoryRowKey,
    pub(super) source_rows: Vec<NativeHistoryRowKey>,
    pub(super) objects: Vec<NativeHistoryCasReference>,
    pub(super) digest: ContentId,
}

impl NativeHistoryHoldSpec {
    pub fn family(&self) -> &str {
        self.family
    }
    pub fn anchor_table(&self) -> &str {
        self.anchor.table()
    }
    pub fn anchor_key(&self) -> &[String] {
        self.anchor.primary_key()
    }
    pub fn source_rows(&self) -> &[NativeHistoryRowKey] {
        &self.source_rows
    }
    pub fn objects(&self) -> &[NativeHistoryCasReference] {
        &self.objects
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
}

#[derive(Debug, Serialize)]
pub struct NativeHistorySourceTable {
    pub(super) table: &'static str,
    pub(super) rows: u64,
    pub(super) logical_bytes: u64,
    pub(super) digest: ContentId,
}

impl NativeHistorySourceTable {
    pub fn table(&self) -> &str {
        self.table
    }
    pub fn rows(&self) -> u64 {
        self.rows
    }
    pub fn logical_bytes(&self) -> u64 {
        self.logical_bytes
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
}

/// Explicit input data. The audit checks this against the actual identity row.
/// Native keys, generations, listener policy and signatures are never mapped.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeHistoryRootMapping {
    original_worktree: String,
    projected_worktree: String,
}

impl NativeHistoryRootMapping {
    pub fn worktree(original_worktree: String, projected_worktree: String) -> Self {
        Self {
            original_worktree,
            projected_worktree,
        }
    }
    pub fn original_worktree(&self) -> &str {
        &self.original_worktree
    }
    pub fn projected_worktree(&self) -> &str {
        &self.projected_worktree
    }
}

#[derive(Debug, Serialize)]
pub struct NativeHistoryRootColumnMapping {
    pub(super) source: NativeHistoryRowKey,
    pub(super) column: &'static str,
    pub(super) original: String,
    pub(super) projected: String,
}

impl NativeHistoryRootColumnMapping {
    pub fn table(&self) -> &str {
        self.source.table()
    }
    pub fn primary_key(&self) -> &[String] {
        self.source.primary_key()
    }
    pub fn column(&self) -> &str {
        self.column
    }
    pub fn original(&self) -> &str {
        &self.original
    }
    pub fn projected(&self) -> &str {
        &self.projected
    }
}

/// Selects safe original rows for an independently built active image.
/// Native, GC execution, pending and recovery session rows remain in source.
/// The plan contains no SQL and provides no writable original Connection.
#[derive(Debug, Serialize)]
pub struct NativeHistoryProjectionPlan {
    pub(super) portable_rows: Vec<NativeHistoryRowKey>,
    pub(super) root_columns: Vec<NativeHistoryRootColumnMapping>,
    pub(super) digest: ContentId,
}

impl NativeHistoryProjectionPlan {
    pub fn portable_rows(&self) -> &[NativeHistoryRowKey] {
        &self.portable_rows
    }
    pub fn root_columns(&self) -> &[NativeHistoryRootColumnMapping] {
        &self.root_columns
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
}

// This representation is not itself a source proof. Only the private fields
// of AuditedNativeHistorySource can seal a successfully checked generation.
pub(super) struct NativeHistoryProofParts {
    pub(super) registry: NativeHistoryFamilyRegistry,
    pub(super) image: Vec<u8>,
    pub(super) space: SpaceId,
    pub(super) image_digest: ContentId,
    pub(super) catalog_digest: ContentId,
    pub(super) rows_digest: ContentId,
    pub(super) source_digest: ContentId,
    pub(super) registry_digest: ContentId,
    pub(super) tables: Vec<NativeHistorySourceTable>,
    pub(super) rows: Vec<JournalStoredRow>,
    pub(super) owners: Vec<NativeHistoryHoldSpec>,
    pub(super) projection: NativeHistoryProjectionPlan,
    pub(super) bounds: NodeInspectionBounds,
}

/// Constructed exclusively by a successful bounded audit of its owned bytes.
/// No Deserialize, JSON constructor, raw mutable connection or native token
/// decoder exists. A persisted description cannot recreate this proof.
pub struct ImmutableNativeHistorySourceProof {
    source: NativeHistoryProofParts,
}

impl ImmutableNativeHistorySourceProof {
    pub(super) fn from_audit(audit: AuditedNativeHistorySource) -> Self {
        Self {
            source: audit.into_parts(),
        }
    }
    pub fn source_schema(&self) -> u32 {
        self.source.registry.source_schema()
    }
    pub fn space(&self) -> &SpaceId {
        &self.source.space
    }
    pub fn source_image(&self) -> &[u8] {
        &self.source.image
    }
    pub fn source_image_digest(&self) -> &ContentId {
        &self.source.image_digest
    }
    pub fn source_catalog_digest(&self) -> &ContentId {
        &self.source.catalog_digest
    }
    pub fn source_rows_digest(&self) -> &ContentId {
        &self.source.rows_digest
    }
    pub fn source_digest(&self) -> &ContentId {
        &self.source.source_digest
    }
    pub fn registry_digest(&self) -> &ContentId {
        &self.source.registry_digest
    }
    pub fn tables(&self) -> &[NativeHistorySourceTable] {
        &self.source.tables
    }
    pub fn rows(&self) -> &[JournalStoredRow] {
        &self.source.rows
    }
    pub fn owners(&self) -> &[NativeHistoryHoldSpec] {
        &self.source.owners
    }
    pub fn projection(&self) -> &NativeHistoryProjectionPlan {
        &self.source.projection
    }
    pub fn inspection_bounds(&self) -> NodeInspectionBounds {
        self.source.bounds
    }
    pub fn registry(&self) -> NativeHistoryFamilyRegistry {
        self.source.registry
    }
    pub(super) fn proof_parts(&self) -> &NativeHistoryProofParts {
        &self.source
    }
}

impl JournalBackupImage {
    /// First-entry legacy inspection is independent of the current writable
    /// schema. The owned standalone image is retained byte for byte.
    pub fn audit_native_history_source(
        bytes: Vec<u8>,
        expected_digest: &str,
        max_image_bytes: usize,
        space: &SpaceId,
        roots: &[NativeHistoryRootMapping],
        bounds: NodeInspectionBounds,
    ) -> Result<ImmutableNativeHistorySourceProof> {
        super::native_history_source_audit::audit(
            bytes,
            expected_digest,
            max_image_bytes,
            space,
            roots,
            bounds,
        )
        .map(ImmutableNativeHistorySourceProof::from_audit)
    }
}
