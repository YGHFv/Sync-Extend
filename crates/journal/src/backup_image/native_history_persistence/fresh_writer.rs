//! A fresh writer session over the safe active projection of an inert native
//! history source. Old pending, native, cleanup, GC and successor authority is
//! never copied; only this new session's own create/replace/close/reopen
//! transitions are recorded.
use super::super::native_history_source_proof::{
    NativeHistoryRootColumnMapping, NativeHistoryRowKey,
};
use super::PersistedNativeHistorySource;
use crate::backup_image::native_history_family_registry::NativeHistoryFamilyRegistry;
use crate::{
    Journal, JournalError, JournalStorageColumn, JournalStorageColumnValue, JournalStoredRow,
    Result,
};
use rusqlite::{
    params,
    types::{Value, ValueRef},
    Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SpaceId};

const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeHistoryFreshWriterState {
    Admitted,
    Created,
    Replaced,
    Closed,
    Reopened,
}

impl NativeHistoryFreshWriterState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::Created => "created",
            Self::Replaced => "replaced",
            Self::Closed => "closed",
            Self::Reopened => "reopened",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "admitted" => Ok(Self::Admitted),
            "created" => Ok(Self::Created),
            "replaced" => Ok(Self::Replaced),
            "closed" => Ok(Self::Closed),
            "reopened" => Ok(Self::Reopened),
            _ => Err(JournalError::Invariant(
                "persisted native history fresh writer state",
            )),
        }
    }

    fn is_active(self) -> bool {
        matches!(self, Self::Created | Self::Replaced | Self::Reopened)
    }
}

/// Explicit, non-authoritative admission input. The returned writer token is
/// the only way to enter this new session's lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHistoryFreshWriterAdmissionRequest {
    pub source_digest: ContentId,
    pub creator: EntryId,
    pub device: DeviceId,
    pub worktree: String,
    pub nonce: EntryId,
}

/// One fresh writer session. It contains no old issuer, lease, pending or GC
/// capability; all transitions are checked against both this token and the
/// immutable schema-70 rows.
pub struct NativeHistoryFreshWriter {
    writer_id: EntryId,
    source_digest: ContentId,
    projection_digest: ContentId,
    image_digest: ContentId,
    space: SpaceId,
    device: DeviceId,
    worktree: String,
    creator: EntryId,
    state: NativeHistoryFreshWriterState,
    created_snapshot: Option<ContentId>,
    replaced_snapshot: Option<ContentId>,
}

impl NativeHistoryFreshWriter {
    pub fn writer_id(&self) -> &EntryId {
        &self.writer_id
    }
    pub fn source_digest(&self) -> &ContentId {
        &self.source_digest
    }
    pub fn projection_digest(&self) -> &ContentId {
        &self.projection_digest
    }
    pub fn image_digest(&self) -> &ContentId {
        &self.image_digest
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
    pub fn worktree(&self) -> &str {
        &self.worktree
    }
    pub fn creator(&self) -> &EntryId {
        &self.creator
    }
    pub fn state(&self) -> NativeHistoryFreshWriterState {
        self.state
    }
    pub fn created_snapshot(&self) -> Option<&ContentId> {
        self.created_snapshot.as_ref()
    }
    pub fn replaced_snapshot(&self) -> Option<&ContentId> {
        self.replaced_snapshot.as_ref()
    }
    fn require(&self, expected: NativeHistoryFreshWriterState) -> Result<()> {
        if self.state != expected {
            return Err(JournalError::Invariant(
                "native history fresh writer state transition",
            ));
        }
        Ok(())
    }
    fn require_active(&self) -> Result<()> {
        if !self.state.is_active() {
            return Err(JournalError::Invariant(
                "native history fresh writer is not active",
            ));
        }
        Ok(())
    }
    fn last_snapshot(&self) -> Result<ContentId> {
        self.replaced_snapshot
            .clone()
            .or_else(|| self.created_snapshot.clone())
            .ok_or(JournalError::Invariant(
                "native history fresh writer snapshot absent",
            ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeHistoryFreshWriterInspection {
    writer_id: EntryId,
    source_digest: ContentId,
    projection_digest: ContentId,
    image_digest: ContentId,
    space: SpaceId,
    device: DeviceId,
    worktree: String,
    creator: EntryId,
    nonce_hash: ContentId,
    state: NativeHistoryFreshWriterState,
    created_snapshot: Option<ContentId>,
    replaced_snapshot: Option<ContentId>,
    events: usize,
    head_hash: ContentId,
    chain_digest: ContentId,
}

impl NativeHistoryFreshWriterInspection {
    pub fn writer_id(&self) -> &EntryId {
        &self.writer_id
    }
    pub fn source_digest(&self) -> &ContentId {
        &self.source_digest
    }
    pub fn projection_digest(&self) -> &ContentId {
        &self.projection_digest
    }
    pub fn image_digest(&self) -> &ContentId {
        &self.image_digest
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
    pub fn worktree(&self) -> &str {
        &self.worktree
    }
    pub fn creator(&self) -> &EntryId {
        &self.creator
    }
    pub fn nonce_hash(&self) -> &ContentId {
        &self.nonce_hash
    }
    pub fn state(&self) -> NativeHistoryFreshWriterState {
        self.state
    }
    pub fn created_snapshot(&self) -> Option<&ContentId> {
        self.created_snapshot.as_ref()
    }
    pub fn replaced_snapshot(&self) -> Option<&ContentId> {
        self.replaced_snapshot.as_ref()
    }
    pub fn events(&self) -> usize {
        self.events
    }
    pub fn head_hash(&self) -> &ContentId {
        &self.head_hash
    }
    pub fn chain_digest(&self) -> &ContentId {
        &self.chain_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativeHistoryFreshWriterAuthorityObservation {
    state: NativeHistoryFreshWriterState,
    old_pending_resume: bool,
    old_native_issuance: bool,
    old_cleanup: bool,
    old_gc: bool,
    old_persisted_successor: bool,
    fresh_creation: bool,
    fresh_replacement: bool,
    fresh_close: bool,
    fresh_reopen: bool,
}

impl NativeHistoryFreshWriterAuthorityObservation {
    pub fn state(self) -> NativeHistoryFreshWriterState {
        self.state
    }
    pub fn old_pending_resume(self) -> bool {
        self.old_pending_resume
    }
    pub fn old_native_issuance(self) -> bool {
        self.old_native_issuance
    }
    pub fn old_cleanup(self) -> bool {
        self.old_cleanup
    }
    pub fn old_gc(self) -> bool {
        self.old_gc
    }
    pub fn old_persisted_successor(self) -> bool {
        self.old_persisted_successor
    }
    pub fn fresh_creation(self) -> bool {
        self.fresh_creation
    }
    pub fn fresh_replacement(self) -> bool {
        self.fresh_replacement
    }
    pub fn fresh_close(self) -> bool {
        self.fresh_close
    }
    pub fn fresh_reopen(self) -> bool {
        self.fresh_reopen
    }
    pub fn all_old_refused(self) -> bool {
        !self.old_pending_resume
            && !self.old_native_issuance
            && !self.old_cleanup
            && !self.old_gc
            && !self.old_persisted_successor
    }
}

#[derive(Serialize)]
struct EventBody<'a> {
    format_version: u32,
    writer_id: &'a str,
    source_digest: &'a str,
    kind: &'a str,
    snapshot: Option<&'a str>,
    observed_at_ms: i64,
}

#[derive(Deserialize)]
struct StoredEventBody {
    format_version: u32,
    writer_id: String,
    source_digest: String,
    kind: String,
    snapshot: Option<String>,
    observed_at_ms: i64,
}

struct StoredWriter {
    source_digest: ContentId,
    projection_digest: ContentId,
    image_digest: ContentId,
    space: SpaceId,
    device: DeviceId,
    worktree: String,
    creator: EntryId,
    nonce_hash: ContentId,
    state: NativeHistoryFreshWriterState,
    created_snapshot: Option<ContentId>,
    replaced_snapshot: Option<ContentId>,
    admitted_at_ms: i64,
    updated_at_ms: i64,
}

struct StoredEvent {
    sequence: i64,
    event: String,
    previous_hash: ContentId,
    event_hash: ContentId,
    observed_at_ms: i64,
}

impl Journal {
    /// Admit exactly one new writer for one inert source and one creator. This
    /// creates no target row and copies no old authorization.
    pub fn admit_native_history_fresh_writer(
        &mut self,
        request: NativeHistoryFreshWriterAdmissionRequest,
    ) -> Result<NativeHistoryFreshWriter> {
        let source = self.inspect_native_history_source(request.source_digest.clone())?;
        let authority = self.observe_native_history_authority(request.source_digest.clone())?;
        if !authority.all_refused() {
            return Err(JournalError::Invariant(
                "inert native history source exposed old authority",
            ));
        }
        validate_absolute_root(&request.worktree)?;
        let mapping = root_mapping(&source)?;
        if let Some(mapping) = mapping {
            if mapping.projected() != request.worktree {
                return Err(JournalError::Invariant(
                    "native history fresh writer projected root differs",
                ));
            }
        } else if local_value(&source, "worktree")?.is_some() {
            return Err(JournalError::Invariant(
                "native history fresh writer explicit root mapping required",
            ));
        }
        if let Some(stored) = local_value(&source, "device_id")? {
            if stored != request.device.as_str() {
                return Err(JournalError::Invariant(
                    "native history fresh writer device differs",
                ));
            }
        }
        let admitted_at_ms = crate::deletion_retention::local_now_ms()?;
        let writer_id = fresh_writer_id(&request, admitted_at_ms)?;
        let nonce_hash = fresh_writer_nonce_hash(&writer_id, &request.nonce, admitted_at_ms)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT writer_id FROM native_history_fresh_writers
                 WHERE writer_id=?1 OR (source_digest=?2 AND creator_id=?3)",
                params![
                    writer_id.as_str(),
                    request.source_digest.as_str(),
                    request.creator.as_str()
                ],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Err(JournalError::Invariant(
                "native history fresh writer already admitted",
            ));
        }
        tx.execute(
            "INSERT INTO native_history_fresh_writers(
                writer_id,source_digest,projection_digest,image_digest,space_id,device_id,
                worktree,creator_id,nonce_hash,state,created_snapshot,replaced_snapshot,
                admitted_at_ms,updated_at_ms)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'admitted',NULL,NULL,?10,?10)",
            params![
                writer_id.as_str(),
                source.source_digest().as_str(),
                source.projection().digest().as_str(),
                source.source_image_digest().as_str(),
                source.space().as_str(),
                request.device.as_str(),
                request.worktree,
                request.creator.as_str(),
                nonce_hash.as_str(),
                admitted_at_ms,
            ],
        )?;
        append_event(
            &tx,
            source.source_digest(),
            &writer_id,
            &nonce_hash,
            "admitted",
            None,
            admitted_at_ms,
        )?;
        tx.commit()?;
        Ok(NativeHistoryFreshWriter {
            writer_id,
            source_digest: source.source_digest().clone(),
            projection_digest: source.projection().digest().clone(),
            image_digest: source.source_image_digest().clone(),
            space: source.space().clone(),
            device: request.device,
            worktree: request.worktree,
            creator: request.creator,
            state: NativeHistoryFreshWriterState::Admitted,
            created_snapshot: None,
            replaced_snapshot: None,
        })
    }

    /// Materialize the safe active projection in an empty target and record the
    /// first write. This write happens in one transaction with the writer
    /// transition; a failure leaves neither target rows nor a created record.
    pub fn create_native_history_fresh_writer(
        &mut self,
        writer: &mut NativeHistoryFreshWriter,
    ) -> Result<ContentId> {
        writer.require(NativeHistoryFreshWriterState::Admitted)?;
        let source = self.inspect_native_history_source(writer.source_digest.clone())?;
        verify_writer_source(writer, &source)?;
        let mapping = root_mapping(&source)?;
        if let Some(mapping) = mapping {
            if mapping.projected() != writer.worktree {
                return Err(JournalError::Invariant(
                    "native history fresh writer projected root differs",
                ));
            }
        }
        let tables = projection_tables(&source);
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        tx.pragma_update(None, "defer_foreign_keys", true)?;
        let stored = load_writer(&tx, &writer.writer_id)?;
        verify_writer_token(writer, &stored, NativeHistoryFreshWriterState::Admitted)?;
        for table in &tables {
            if table_has_rows(&tx, table)? {
                return Err(JournalError::Invariant(
                    "native history fresh writer target table is not empty",
                ));
            }
        }
        let mut rows = BTreeMap::new();
        for row in source.rows() {
            rows.insert(row_key(row)?, row);
        }
        for key in source.projection().portable_rows() {
            let row = rows.get(key).ok_or(JournalError::Invariant(
                "native history fresh writer projection row absent",
            ))?;
            let mut columns = row.columns().to_vec();
            apply_root_mapping(&key, &mut columns, mapping)?;
            insert_row(&tx, row.table(), &columns)?;
        }
        let snapshot = target_snapshot(&tx, &tables, &source)?;
        let at_ms = monotonic_now(stored.updated_at_ms)?;
        let changed = tx.execute(
            "UPDATE native_history_fresh_writers
             SET state='created',created_snapshot=?2,replaced_snapshot=NULL,updated_at_ms=?3
             WHERE writer_id=?1 AND state='admitted'
               AND created_snapshot IS NULL AND replaced_snapshot IS NULL",
            params![writer.writer_id.as_str(), snapshot.as_str(), at_ms],
        )?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "native history fresh writer create transition",
            ));
        }
        append_event(
            &tx,
            &source.source_digest,
            &writer.writer_id,
            &stored.nonce_hash,
            "created",
            Some(&snapshot),
            at_ms,
        )?;
        tx.commit()?;
        writer.state = NativeHistoryFreshWriterState::Created;
        writer.created_snapshot = Some(snapshot.clone());
        writer.replaced_snapshot = None;
        Ok(snapshot)
    }

    /// Record a replacement after the caller has actually changed the target
    /// through ordinary writer paths. The supplied digest must be the complete
    /// post-change snapshot of every projected table, and it must differ from
    /// the created snapshot.
    pub fn replace_native_history_fresh_writer(
        &mut self,
        writer: &mut NativeHistoryFreshWriter,
        expected_snapshot: ContentId,
    ) -> Result<()> {
        writer.require(NativeHistoryFreshWriterState::Created)?;
        let source = self.inspect_native_history_source(writer.source_digest.clone())?;
        verify_writer_source(writer, &source)?;
        let tables = projection_tables(&source);
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let stored = load_writer(&tx, &writer.writer_id)?;
        verify_writer_token(writer, &stored, NativeHistoryFreshWriterState::Created)?;
        let actual = target_snapshot(&tx, &tables, &source)?;
        if actual != expected_snapshot
            || Some(&actual) == stored.created_snapshot.as_ref()
            || stored.replaced_snapshot.is_some()
        {
            return Err(JournalError::Invariant(
                "native history fresh writer replacement snapshot differs",
            ));
        }
        let at_ms = monotonic_now(stored.updated_at_ms)?;
        let changed = tx.execute(
            "UPDATE native_history_fresh_writers
             SET state='replaced',replaced_snapshot=?2,updated_at_ms=?3
             WHERE writer_id=?1 AND state='created' AND created_snapshot=?4",
            params![
                writer.writer_id.as_str(),
                actual.as_str(),
                at_ms,
                stored
                    .created_snapshot
                    .as_ref()
                    .ok_or(JournalError::Invariant(
                        "native history fresh writer created snapshot absent"
                    ))?
                    .as_str(),
            ],
        )?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "native history fresh writer replace transition",
            ));
        }
        append_event(
            &tx,
            &source.source_digest,
            &writer.writer_id,
            &stored.nonce_hash,
            "replaced",
            Some(&actual),
            at_ms,
        )?;
        tx.commit()?;
        writer.state = NativeHistoryFreshWriterState::Replaced;
        writer.replaced_snapshot = Some(actual);
        Ok(())
    }

    /// Close only after the target still matches the last recorded snapshot.
    pub fn close_native_history_fresh_writer(
        &mut self,
        writer: &mut NativeHistoryFreshWriter,
    ) -> Result<()> {
        writer.require_active()?;
        let source = self.inspect_native_history_source(writer.source_digest.clone())?;
        verify_writer_source(writer, &source)?;
        let expected = writer.last_snapshot()?;
        let tables = projection_tables(&source);
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let stored = load_writer(&tx, &writer.writer_id)?;
        verify_writer_token(writer, &stored, writer.state)?;
        if stored.created_snapshot.as_ref() != writer.created_snapshot.as_ref()
            || stored.replaced_snapshot.as_ref() != writer.replaced_snapshot.as_ref()
        {
            return Err(JournalError::Invariant(
                "native history fresh writer close snapshot binding",
            ));
        }
        let actual = target_snapshot(&tx, &tables, &source)?;
        if actual != expected {
            return Err(JournalError::Invariant(
                "native history fresh writer target changed before close",
            ));
        }
        let at_ms = monotonic_now(stored.updated_at_ms)?;
        let changed = tx.execute(
            "UPDATE native_history_fresh_writers
             SET state='closed',updated_at_ms=?2
             WHERE writer_id=?1 AND state=?3
               AND created_snapshot IS ?4 AND replaced_snapshot IS ?5",
            params![
                writer.writer_id.as_str(),
                at_ms,
                writer.state.as_str(),
                writer.created_snapshot.as_ref().map(ContentId::as_str),
                writer.replaced_snapshot.as_ref().map(ContentId::as_str),
            ],
        )?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "native history fresh writer close transition",
            ));
        }
        append_event(
            &tx,
            &source.source_digest,
            &writer.writer_id,
            &stored.nonce_hash,
            "closed",
            None,
            at_ms,
        )?;
        tx.commit()?;
        writer.state = NativeHistoryFreshWriterState::Closed;
        Ok(())
    }

    /// Reopen the same fresh session only after a close and after proving the
    /// target snapshot and inert source are unchanged.
    pub fn reopen_native_history_fresh_writer(
        &mut self,
        writer: &mut NativeHistoryFreshWriter,
    ) -> Result<()> {
        writer.require(NativeHistoryFreshWriterState::Closed)?;
        let source = self.inspect_native_history_source(writer.source_digest.clone())?;
        verify_writer_source(writer, &source)?;
        let authority = self.observe_native_history_authority(writer.source_digest.clone())?;
        if !authority.all_refused() {
            return Err(JournalError::Invariant(
                "native history fresh writer reopen revived old authority",
            ));
        }
        let expected = writer.last_snapshot()?;
        let tables = projection_tables(&source);
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let stored = load_writer(&tx, &writer.writer_id)?;
        verify_writer_token(writer, &stored, NativeHistoryFreshWriterState::Closed)?;
        let actual = target_snapshot(&tx, &tables, &source)?;
        if actual != expected {
            return Err(JournalError::Invariant(
                "native history fresh writer target changed before reopen",
            ));
        }
        let at_ms = monotonic_now(stored.updated_at_ms)?;
        let changed = tx.execute(
            "UPDATE native_history_fresh_writers
             SET state='reopened',updated_at_ms=?2
             WHERE writer_id=?1 AND state='closed'
               AND created_snapshot IS ?3 AND replaced_snapshot IS ?4",
            params![
                writer.writer_id.as_str(),
                at_ms,
                writer.created_snapshot.as_ref().map(ContentId::as_str),
                writer.replaced_snapshot.as_ref().map(ContentId::as_str),
            ],
        )?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "native history fresh writer reopen transition",
            ));
        }
        append_event(
            &tx,
            &source.source_digest,
            &writer.writer_id,
            &stored.nonce_hash,
            "reopened",
            None,
            at_ms,
        )?;
        tx.commit()?;
        writer.state = NativeHistoryFreshWriterState::Reopened;
        Ok(())
    }

    pub fn inspect_native_history_fresh_writer(
        &self,
        writer_id: &EntryId,
    ) -> Result<NativeHistoryFreshWriterInspection> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let stored = load_writer(&tx, writer_id)?;
        let source = super::inspect_source(&tx, &stored.source_digest)?;
        let events = load_events(&tx, writer_id)?;
        tx.rollback()?;
        let inspection = verify_event_chain(writer_id, &stored, &source, &events)?;
        Ok(inspection)
    }

    pub fn observe_native_history_fresh_writer_authority(
        &self,
        writer_id: &EntryId,
    ) -> Result<NativeHistoryFreshWriterAuthorityObservation> {
        let inspection = self.inspect_native_history_fresh_writer(writer_id)?;
        let state = inspection.state;
        Ok(NativeHistoryFreshWriterAuthorityObservation {
            state,
            old_pending_resume: false,
            old_native_issuance: false,
            old_cleanup: false,
            old_gc: false,
            old_persisted_successor: false,
            fresh_creation: state == NativeHistoryFreshWriterState::Admitted,
            fresh_replacement: state == NativeHistoryFreshWriterState::Created,
            fresh_close: state.is_active(),
            fresh_reopen: state == NativeHistoryFreshWriterState::Closed,
        })
    }

    /// Recreate only this new session's local token after a reopen. The token
    /// still contains no old pending, native, cleanup, GC or successor object.
    pub fn resume_native_history_fresh_writer(
        &self,
        writer_id: &EntryId,
    ) -> Result<NativeHistoryFreshWriter> {
        let inspection = self.inspect_native_history_fresh_writer(writer_id)?;
        let authority = self.observe_native_history_authority(inspection.source_digest.clone())?;
        if !authority.all_refused() {
            return Err(JournalError::Invariant(
                "native history fresh writer resume revived old authority",
            ));
        }
        Ok(NativeHistoryFreshWriter {
            writer_id: inspection.writer_id,
            source_digest: inspection.source_digest,
            projection_digest: inspection.projection_digest,
            image_digest: inspection.image_digest,
            space: inspection.space,
            device: inspection.device,
            worktree: inspection.worktree,
            creator: inspection.creator,
            state: inspection.state,
            created_snapshot: inspection.created_snapshot,
            replaced_snapshot: inspection.replaced_snapshot,
        })
    }

    /// Inspect the complete current target snapshot for one fresh writer.
    pub fn native_history_fresh_writer_target_snapshot(
        &self,
        writer_id: &EntryId,
    ) -> Result<ContentId> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let stored = load_writer(&tx, writer_id)?;
        let source = super::inspect_source(&tx, &stored.source_digest)?;
        let snapshot = target_snapshot(&tx, &projection_tables(&source), &source)?;
        tx.rollback()?;
        Ok(snapshot)
    }
}

fn fresh_writer_id(
    request: &NativeHistoryFreshWriterAdmissionRequest,
    admitted_at_ms: i64,
) -> Result<EntryId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-extend.native-history-fresh-writer-id.v1");
    hasher.update(request.source_digest.as_str().as_bytes());
    hasher.update(request.creator.as_str().as_bytes());
    hasher.update(request.device.as_str().as_bytes());
    hasher.update(request.worktree.as_bytes());
    hasher.update(request.nonce.as_str().as_bytes());
    hasher.update(&admitted_at_ms.to_le_bytes());
    let digest = ContentId::from_hasher(&hasher);
    digest.as_str()[..32].parse().map_err(JournalError::from)
}

fn fresh_writer_nonce_hash(
    writer_id: &EntryId,
    nonce: &EntryId,
    admitted_at_ms: i64,
) -> Result<ContentId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-extend.native-history-fresh-writer-nonce.v1");
    hasher.update(writer_id.as_str().as_bytes());
    hasher.update(nonce.as_str().as_bytes());
    hasher.update(&admitted_at_ms.to_le_bytes());
    Ok(ContentId::from_hasher(&hasher))
}

fn validate_absolute_root(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 32_768
        || value.contains('\0')
        || !Path::new(value).is_absolute()
        || Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(JournalError::Invariant(
            "native history fresh writer absolute root required",
        ));
    }
    Ok(())
}

fn root_mapping(
    source: &PersistedNativeHistorySource,
) -> Result<Option<&NativeHistoryRootColumnMapping>> {
    match source.projection().root_columns() {
        [] => Ok(None),
        [mapping] => Ok(Some(mapping)),
        _ => Err(JournalError::Invariant(
            "native history fresh writer root mapping count",
        )),
    }
}

fn local_value<'a>(source: &'a PersistedNativeHistorySource, key: &str) -> Result<Option<&'a str>> {
    for row in source
        .rows()
        .iter()
        .filter(|row| row.table() == "local_state")
    {
        let row_key = row
            .columns()
            .iter()
            .find(|column| column.name == "key")
            .and_then(|column| match &column.value {
                JournalStorageColumnValue::Text(value) => Some(value.as_str()),
                _ => None,
            });
        if row_key != Some(key) {
            continue;
        }
        return row
            .columns()
            .iter()
            .find(|column| column.name == "value")
            .map(|column| match &column.value {
                JournalStorageColumnValue::Text(value) => Ok(value.as_str()),
                _ => Err(JournalError::Invariant(
                    "native history fresh writer local value type",
                )),
            })
            .transpose();
    }
    Ok(None)
}

fn verify_writer_source(
    writer: &NativeHistoryFreshWriter,
    source: &PersistedNativeHistorySource,
) -> Result<()> {
    if writer.source_digest != *source.source_digest()
        || writer.projection_digest != *source.projection().digest()
        || writer.image_digest != *source.source_image_digest()
        || writer.space != *source.space()
    {
        return Err(JournalError::Invariant(
            "native history fresh writer source binding differs",
        ));
    }
    if let Some(stored) = local_value(source, "device_id")? {
        if stored != writer.device.as_str() {
            return Err(JournalError::Invariant(
                "native history fresh writer device differs",
            ));
        }
    }
    Ok(())
}

fn verify_writer_token(
    writer: &NativeHistoryFreshWriter,
    stored: &StoredWriter,
    state: NativeHistoryFreshWriterState,
) -> Result<()> {
    if writer.source_digest != stored.source_digest
        || writer.projection_digest != stored.projection_digest
        || writer.image_digest != stored.image_digest
        || writer.space != stored.space
        || writer.device != stored.device
        || writer.worktree != stored.worktree
        || writer.creator != stored.creator
        || writer.state != stored.state
        || stored.state != state
        || writer.created_snapshot != stored.created_snapshot
        || writer.replaced_snapshot != stored.replaced_snapshot
    {
        return Err(JournalError::Invariant(
            "native history fresh writer token differs",
        ));
    }
    Ok(())
}

fn load_writer(connection: &Connection, writer_id: &EntryId) -> Result<StoredWriter> {
    connection
        .query_row(
            "SELECT source_digest,projection_digest,image_digest,space_id,device_id,worktree,
                    creator_id,nonce_hash,state,created_snapshot,replaced_snapshot,
                    admitted_at_ms,updated_at_ms
             FROM native_history_fresh_writers WHERE writer_id=?1",
            [writer_id.as_str()],
            |row| {
                let state: String = row.get(8)?;
                let created: Option<String> = row.get(9)?;
                let replaced: Option<String> = row.get(10)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    state,
                    created,
                    replaced,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()?
        .map(
            |(
                source_digest,
                projection_digest,
                image_digest,
                space,
                device,
                worktree,
                creator,
                nonce_hash,
                state,
                created_snapshot,
                replaced_snapshot,
                admitted_at_ms,
                updated_at_ms,
            )|
             -> Result<StoredWriter> {
                Ok(StoredWriter {
                    source_digest: source_digest.parse()?,
                    projection_digest: projection_digest.parse()?,
                    image_digest: image_digest.parse()?,
                    space: space.parse()?,
                    device: device.parse()?,
                    worktree,
                    creator: creator.parse()?,
                    nonce_hash: nonce_hash.parse()?,
                    state: NativeHistoryFreshWriterState::parse(&state)?,
                    created_snapshot: created_snapshot.map(|value| value.parse()).transpose()?,
                    replaced_snapshot: replaced_snapshot.map(|value| value.parse()).transpose()?,
                    admitted_at_ms,
                    updated_at_ms,
                })
            },
        )
        .transpose()?
        .ok_or(JournalError::Invariant(
            "native history fresh writer absent",
        ))
}

fn load_events(connection: &Connection, writer_id: &EntryId) -> Result<Vec<StoredEvent>> {
    connection
        .prepare(
            "SELECT sequence,event,previous_hash,event_hash,observed_at_ms
             FROM native_history_fresh_writer_events WHERE writer_id=?1 ORDER BY sequence",
        )?
        .query_map([writer_id.as_str()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .map(|row| {
            let (sequence, event, previous_hash, event_hash, observed_at_ms) = row?;
            Ok(StoredEvent {
                sequence,
                event,
                previous_hash: previous_hash.parse()?,
                event_hash: event_hash.parse()?,
                observed_at_ms,
            })
        })
        .collect()
}

fn append_event(
    tx: &Transaction<'_>,
    source_digest: &ContentId,
    writer_id: &EntryId,
    nonce_hash: &ContentId,
    kind: &str,
    snapshot: Option<&ContentId>,
    observed_at_ms: i64,
) -> Result<ContentId> {
    let last: Option<(i64, String)> = tx
        .query_row(
            "SELECT sequence,event_hash FROM native_history_fresh_writer_events
             WHERE writer_id=?1 ORDER BY sequence DESC LIMIT 1",
            [writer_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (sequence, previous_hash) = match last {
        Some((sequence, hash)) => (sequence + 1, hash.parse::<ContentId>()?),
        None => (1, nonce_hash.clone()),
    };
    let body = EventBody {
        format_version: FORMAT_VERSION,
        writer_id: writer_id.as_str(),
        source_digest: source_digest.as_str(),
        kind,
        snapshot: snapshot.map(ContentId::as_str),
        observed_at_ms,
    };
    let event = serde_json::to_string(&body)?;
    let event_hash = event_hash(&previous_hash, &event);
    tx.execute(
        "INSERT INTO native_history_fresh_writer_events(
            writer_id,sequence,event,previous_hash,event_hash,observed_at_ms)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            writer_id.as_str(),
            sequence,
            event,
            previous_hash.as_str(),
            event_hash.as_str(),
            observed_at_ms,
        ],
    )?;
    Ok(event_hash)
}

fn event_hash(previous: &ContentId, event: &str) -> ContentId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-extend.native-history-fresh-writer-event.v1");
    hasher.update(previous.as_str().as_bytes());
    hasher.update(event.as_bytes());
    ContentId::from_hasher(&hasher)
}

fn verify_event_chain(
    writer_id: &EntryId,
    stored: &StoredWriter,
    source: &PersistedNativeHistorySource,
    events: &[StoredEvent],
) -> Result<NativeHistoryFreshWriterInspection> {
    if stored.source_digest != *source.source_digest()
        || stored.projection_digest != *source.projection().digest()
        || stored.image_digest != *source.source_image_digest()
        || stored.space != *source.space()
    {
        return Err(JournalError::Invariant(
            "persisted native history fresh writer source binding differs",
        ));
    }
    if events.is_empty() {
        return Err(JournalError::Invariant(
            "persisted native history fresh writer events absent",
        ));
    }
    let mut expected_state = NativeHistoryFreshWriterState::Admitted;
    let mut expected_previous = stored.nonce_hash.clone();
    let mut created_snapshot = None;
    let mut replaced_snapshot = None;
    let mut prior_observed = stored.admitted_at_ms;
    let mut chain_hasher = blake3::Hasher::new();
    chain_hasher.update(b"sync-extend.native-history-fresh-writer-chain.v1");
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as i64 + 1
            || event.previous_hash != expected_previous
            || event.observed_at_ms < prior_observed
            || event_hash(&event.previous_hash, &event.event) != event.event_hash
        {
            return Err(JournalError::Invariant(
                "persisted native history fresh writer event chain",
            ));
        }
        let body: StoredEventBody = serde_json::from_str(&event.event)?;
        if body.format_version != FORMAT_VERSION
            || body.writer_id != writer_id.as_str()
            || body.source_digest != stored.source_digest.as_str()
        {
            return Err(JournalError::Invariant(
                "persisted native history fresh writer event body",
            ));
        }
        let snapshot = body
            .snapshot
            .as_deref()
            .map(str::parse::<ContentId>)
            .transpose()?;
        if body.observed_at_ms != event.observed_at_ms {
            return Err(JournalError::Invariant(
                "persisted native history fresh writer event clock",
            ));
        }
        if index == 0 {
            if body.kind != "admitted" || snapshot.is_some() {
                return Err(JournalError::Invariant(
                    "persisted native history fresh writer first event",
                ));
            }
        } else {
            expected_state = match (expected_state, body.kind.as_str(), snapshot.is_some()) {
                (NativeHistoryFreshWriterState::Admitted, "created", true) => {
                    created_snapshot = snapshot.clone();
                    NativeHistoryFreshWriterState::Created
                }
                (NativeHistoryFreshWriterState::Created, "replaced", true) => {
                    replaced_snapshot = snapshot.clone();
                    NativeHistoryFreshWriterState::Replaced
                }
                (
                    NativeHistoryFreshWriterState::Created
                    | NativeHistoryFreshWriterState::Replaced
                    | NativeHistoryFreshWriterState::Reopened,
                    "closed",
                    false,
                ) => NativeHistoryFreshWriterState::Closed,
                (NativeHistoryFreshWriterState::Closed, "reopened", false) => {
                    NativeHistoryFreshWriterState::Reopened
                }
                _ => {
                    return Err(JournalError::Invariant(
                        "persisted native history fresh writer event transition",
                    ));
                }
            };
        }
        chain_hasher.update(event.event_hash.as_str().as_bytes());
        expected_previous = event.event_hash.clone();
        prior_observed = event.observed_at_ms;
    }
    if expected_state != stored.state
        || stored.created_snapshot != created_snapshot
        || stored.replaced_snapshot != replaced_snapshot
        || events.last().map(|event| event.observed_at_ms) != Some(stored.updated_at_ms)
    {
        return Err(JournalError::Invariant(
            "persisted native history fresh writer final state",
        ));
    }
    Ok(NativeHistoryFreshWriterInspection {
        writer_id: writer_id.clone(),
        source_digest: stored.source_digest.clone(),
        projection_digest: stored.projection_digest.clone(),
        image_digest: stored.image_digest.clone(),
        space: stored.space.clone(),
        device: stored.device.clone(),
        worktree: stored.worktree.clone(),
        creator: stored.creator.clone(),
        nonce_hash: stored.nonce_hash.clone(),
        state: stored.state,
        created_snapshot,
        replaced_snapshot,
        events: events.len(),
        head_hash: events.last().map(|event| event.event_hash.clone()).ok_or(
            JournalError::Invariant("persisted native history fresh writer head"),
        )?,
        chain_digest: ContentId::from_hasher(&chain_hasher),
    })
}

fn projection_tables(source: &PersistedNativeHistorySource) -> Vec<&'static str> {
    let mut tables = BTreeSet::new();
    for key in source.projection().portable_rows() {
        tables.insert(key.table());
    }
    tables.into_iter().collect()
}

fn row_key(row: &JournalStoredRow) -> Result<NativeHistoryRowKey> {
    let registry = NativeHistoryFamilyRegistry::schema69();
    Ok(NativeHistoryRowKey {
        table: registry.table(row.table())?.table,
        primary_key: row.primary_key().to_vec(),
    })
}

fn apply_root_mapping(
    key: &NativeHistoryRowKey,
    columns: &mut [JournalStorageColumn],
    mapping: Option<&NativeHistoryRootColumnMapping>,
) -> Result<()> {
    let Some(mapping) = mapping else {
        return Ok(());
    };
    if key.table() != mapping.table() || key.primary_key() != mapping.primary_key() {
        return Ok(());
    }
    let column = columns
        .iter_mut()
        .find(|column| column.name == mapping.column())
        .ok_or(JournalError::Invariant(
            "native history fresh writer root column absent",
        ))?;
    if column.value != JournalStorageColumnValue::Text(mapping.original().to_owned()) {
        return Err(JournalError::Invariant(
            "native history fresh writer root original differs",
        ));
    }
    column.value = JournalStorageColumnValue::Text(mapping.projected().to_owned());
    Ok(())
}

fn table_has_rows(connection: &Connection, table: &str) -> Result<bool> {
    let sql = format!(
        "SELECT EXISTS(SELECT 1 FROM main.{})",
        quote_identifier(table)?
    );
    Ok(connection.query_row(&sql, [], |row| row.get(0))?)
}

fn insert_row(tx: &Transaction<'_>, table: &str, columns: &[JournalStorageColumn]) -> Result<()> {
    let names = columns
        .iter()
        .map(|column| quote_identifier(&column.name))
        .collect::<Result<Vec<_>>>()?
        .join(",");
    let placeholders = (1..=columns.len())
        .map(|index| format!("?{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "INSERT INTO main.{} ({names}) VALUES ({placeholders})",
        quote_identifier(table)?
    );
    let values = columns
        .iter()
        .map(|column| stored_value(&column.value))
        .collect::<Result<Vec<_>>>()?;
    tx.execute(&sql, rusqlite::params_from_iter(values.iter()))?;
    Ok(())
}

fn quote_identifier(value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(JournalError::Invariant(
            "native history fresh writer identifier",
        ));
    }
    Ok(format!("\"{value}\""))
}

fn stored_value(value: &JournalStorageColumnValue) -> Result<Value> {
    Ok(match value {
        JournalStorageColumnValue::Null => Value::Null,
        JournalStorageColumnValue::Text(value) => Value::Text(value.clone()),
        JournalStorageColumnValue::Integer(value) => {
            Value::Integer(i64::try_from(*value).map_err(|_| {
                JournalError::Invariant("native history fresh writer integer value")
            })?)
        }
        JournalStorageColumnValue::Bytes(value) => Value::Blob(value.clone()),
    })
}

fn target_snapshot(
    connection: &Connection,
    tables: &[&'static str],
    source: &PersistedNativeHistorySource,
) -> Result<ContentId> {
    let registry = source.registry();
    let bounds = source.inspection_bounds();
    let max_rows = bounds
        .capacity
        .max_rows
        .min(
            u64::try_from(bounds.capacity.inventory.max_rows).map_err(|_| {
                JournalError::Invariant("native history fresh writer inventory row bound")
            })?,
        )
        .min(
            u64::try_from(bounds.max_entries)
                .map_err(|_| JournalError::Invariant("native history fresh writer entry bound"))?,
        );
    let max_bytes = bounds
        .capacity
        .max_logical_bytes
        .min(bounds.capacity.inventory.max_logical_bytes);
    let mut encoded_rows = Vec::new();
    let mut logical_bytes = 0u64;
    for table in tables {
        let rule = registry.table(table)?;
        let names = rule
            .columns
            .iter()
            .map(|column| quote_identifier(column.name))
            .collect::<Result<Vec<_>>>()?
            .join(",");
        let sql = format!("SELECT {names} FROM main.{}", quote_identifier(rule.table)?);
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            if encoded_rows.len() as u64 >= max_rows {
                return Err(JournalError::Invariant(
                    "native history fresh writer snapshot row bound",
                ));
            }
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&(rule.table.len() as u64).to_le_bytes());
            encoded.extend_from_slice(rule.table.as_bytes());
            encoded.extend_from_slice(&(rule.columns.len() as u64).to_le_bytes());
            for (index, column) in rule.columns.iter().enumerate() {
                encoded.extend_from_slice(&(column.name.len() as u64).to_le_bytes());
                encoded.extend_from_slice(column.name.as_bytes());
                encode_value(row.get_ref(index)?, &mut encoded)?;
            }
            logical_bytes = logical_bytes
                .checked_add(encoded.len() as u64 + 8)
                .filter(|value| *value <= max_bytes)
                .ok_or(JournalError::Invariant(
                    "native history fresh writer snapshot byte bound",
                ))?;
            encoded_rows.push(encoded);
        }
    }
    encoded_rows.sort();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-extend.native-history-fresh-writer-target-snapshot.v1");
    hasher.update(&(tables.len() as u64).to_le_bytes());
    for table in tables {
        hasher.update(&(table.len() as u64).to_le_bytes());
        hasher.update(table.as_bytes());
    }
    hasher.update(&(encoded_rows.len() as u64).to_le_bytes());
    for row in encoded_rows {
        hasher.update(&(row.len() as u64).to_le_bytes());
        hasher.update(&row);
    }
    Ok(ContentId::from_hasher(&hasher))
}

fn encode_value(value: ValueRef<'_>, encoded: &mut Vec<u8>) -> Result<()> {
    match value {
        ValueRef::Null => encoded.push(0),
        ValueRef::Integer(value) => {
            encoded.push(1);
            encoded.extend_from_slice(&value.to_le_bytes());
        }
        ValueRef::Real(_) => {
            return Err(JournalError::Invariant(
                "native history fresh writer snapshot real value",
            ));
        }
        ValueRef::Text(value) => {
            encoded.push(2);
            encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
            encoded.extend_from_slice(value);
        }
        ValueRef::Blob(value) => {
            encoded.push(3);
            encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
            encoded.extend_from_slice(value);
        }
    }
    Ok(())
}

fn monotonic_now(floor: i64) -> Result<i64> {
    Ok(crate::deletion_retention::local_now_ms()?.max(floor))
}
