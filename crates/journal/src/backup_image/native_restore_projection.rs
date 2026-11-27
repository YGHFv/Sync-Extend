//! Pure memory preparation; persisted logical events are not native creators.
use super::{JournalBackupImage, NativeHistoryRootMapping, NodeInspectionBounds};
use crate::{Journal, JournalError, NativeHistoryFreshWriterAdmissionRequest, Result};
use serde::Serialize;
use std::{path::Path, time::Instant};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SpaceId};

#[derive(Clone, Serialize)]
pub struct NativeHistoryPreparedProjectionEvidence {
    source_image: ContentId,
    source_digest: ContentId,
    projection_digest: ContentId,
    prepared_image: ContentId,
    inert_owner_count: usize,
    memory_preparation_writer: EntryId,
    target_native_creator_authority: bool,
}
impl NativeHistoryPreparedProjectionEvidence {
    pub fn source_digest(&self) -> &ContentId { &self.source_digest }
    pub fn projection_digest(&self) -> &ContentId { &self.projection_digest }
    pub fn inert_owner_count(&self) -> usize { self.inert_owner_count }
    pub fn target_native_creator_authority(&self) -> bool { false }
}

/// Contains an immutable prepared image and descriptive evidence only. Its
/// memory writer is closed logically; no filesystem original was created or
/// closed, and no persisted event grants target admission or restart authority.
pub struct PreparedNativeHistoryProjectionImage {
    image: JournalBackupImage,
    evidence: NativeHistoryPreparedProjectionEvidence,
}
impl PreparedNativeHistoryProjectionImage {
    pub fn image(&self) -> &JournalBackupImage { &self.image }
    pub fn evidence(&self) -> &NativeHistoryPreparedProjectionEvidence { &self.evidence }
    pub fn into_parts(self) -> (JournalBackupImage, NativeHistoryPreparedProjectionEvidence) {
        (self.image, self.evidence)
    }
}

impl crate::ReadOnlyJournal {
    /// Independent post-close inspection only. This does not reconstruct an
    /// original target owner, migration authority, or a writable session.
    pub fn audit_prepared_native_projection(
        &mut self,
        space: &SpaceId,
        source_digest: &ContentId,
        bounds: NodeInspectionBounds,
    ) -> Result<usize> {
        let started = Instant::now();
        let checked = (|| {
            super::readonly::configure_inspection(&mut self.connection, bounds)?;
            self.verify_readonly_files()?;
            let tx = self.connection.unchecked_transaction()?;
            if super::validate(&tx)? != crate::SCHEMA_VERSION {
                return Err(JournalError::Invariant("readonly prepared projection current catalog"));
            }
            self.read_view().audit_original_provenance_capacity(space, bounds.max_entries, bounds.capacity)?;
            let source = super::native_history_persistence::inspect_source(&tx, source_digest)?;
            if source.space() != space { return Err(JournalError::Invariant("readonly prepared projection source space")); }
            let owners = source.owners().len();
            tx.rollback()?;
            self.verify_readonly_files()?;
            Ok(owners)
        })();
        let cleared = self.connection.progress_handler(0, None::<fn() -> bool>);
        let owners = checked?;
        cleared?;
        if started.elapsed() >= bounds.max_query_time {
            return Err(JournalError::Invariant("readonly prepared projection completed after deadline"));
        }
        Ok(owners)
    }
}

fn normalized_root(path: &Path) -> Result<&str> {
    let value = path.to_str().ok_or(JournalError::Invariant("prepared projection UTF8 root"))?;
    if !path.is_absolute() || value.len() > 32_768 || value.contains(['\\', '\0'])
        || value.split('/').skip(1).any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(JournalError::Invariant("prepared projection exact normalized Unix root"));
    }
    Ok(value)
}

impl JournalBackupImage {
    /// Reuses the full original source audit and existing inert persistence and
    /// safe projection transitions. Only a private in-memory Journal is used;
    /// the explicit destination is data, never opened or canonicalized.
    pub fn prepare_native_history_projection(
        self,
        space: &SpaceId,
        device: &DeviceId,
        original_worktree: &Path,
        projected_worktree: &Path,
        bounds: NodeInspectionBounds,
        maximum_image_bytes: usize,
    ) -> Result<PreparedNativeHistoryProjectionImage> {
        bounds.validate()?;
        super::limit(maximum_image_bytes)?;
        let started = Instant::now();
        let duration = bounds.max_query_time;
        let check_deadline = || {
            if started.elapsed() >= duration {
                Err(JournalError::Invariant("prepared projection completed after deadline"))
            } else { Ok(()) }
        };
        let original = normalized_root(original_worktree)?;
        let projected = normalized_root(projected_worktree)?;
        if original == projected { return Err(JournalError::Invariant("independent prepared projection root")); }
        let expected_image = ContentId::hash(self.bytes());
        let expected_manifest = self.with_audited_readonly(space, bounds, |connection| {
            crate::JournalReadView { connection, dav_read_charge_cache: None }.current(space)
        })?;
        check_deadline()?;
        let digest = self.digest().to_owned();
        let proof = Self::audit_native_history_source(
            self.into_bytes(), &digest, maximum_image_bytes, space,
            &[NativeHistoryRootMapping::worktree(original.into(), projected.into())], bounds,
        )?;
        check_deadline()?;
        let projection_digest = proof.projection().digest().clone();
        let inert_owner_count = proof.owners().len();
        let source_digest = proof.source_digest().clone();
        let mut connection = rusqlite::Connection::open_in_memory()?;
        connection.execute_batch("PRAGMA temp_store=MEMORY;PRAGMA mmap_size=0;PRAGMA page_size=4096;")?;
        let maximum_pages = maximum_image_bytes / 4096;
        if maximum_pages == 0 { return Err(JournalError::Invariant("prepared projection page budget")); }
        for schema in ["main", "temp"] {
            connection.pragma_update(Some(schema), "max_page_count", crate::sql_integer(maximum_pages as u64)?)?;
            let applied = connection.pragma_query_value(Some(schema), "max_page_count", |row| crate::sql_u64(row, 0))?;
            if applied > maximum_pages as u64 { return Err(JournalError::Invariant("prepared projection page limit differs")); }
        }
        // The existing loader's explicit memory branch is the only constructor
        // used here. It neither opens a target pathname nor borrows target IO.
        let mut memory = Journal::initialize_connection_inner(
            Path::new(":memory:"), bounds.max_entries, connection, None, true,
        )?;
        check_deadline()?;
        // Schema migrations have their own finite constructor budgets and may
        // replace a progress hook. Install this meter only after that loader.
        // It measures SQL on this memory connection; nested immutable audits
        // use their existing independent VM bounds and the same outer wall
        // deadline is checked at each completed phase. No aggregate VM or peak
        // allocator bound across those independent connections is claimed.
        for schema in ["main", "temp"] {
            let pages = memory.connection.pragma_query_value(Some(schema), "page_count", |row| crate::sql_u64(row, 0))?;
            let limit = memory.connection.pragma_query_value(Some(schema), "max_page_count", |row| crate::sql_u64(row, 0))?;
            if pages > maximum_pages as u64 || limit > maximum_pages as u64 {
                return Err(JournalError::Invariant("prepared projection constructor page budget differs"));
            }
        }
        let mut remaining = bounds.max_vm_instructions;
        memory.connection.progress_handler(1000, Some(move || {
            if remaining < 1000 || started.elapsed() >= duration { true }
            else { remaining -= 1000; false }
        }))?;
        let binding = memory.persist_native_history_source(proof)?;
        check_deadline()?;
        if binding.source_digest() != &source_digest {
            return Err(JournalError::Invariant("prepared projection original source differs"));
        }
        let mut writer = memory.admit_native_history_fresh_writer(NativeHistoryFreshWriterAdmissionRequest {
            source_digest: source_digest.clone(), creator: EntryId::random()?,
            device: device.clone(), worktree: projected.into(), nonce: EntryId::random()?,
        })?;
        check_deadline()?;
        memory.create_native_history_fresh_writer(&mut writer)?;
        check_deadline()?;
        if memory.current(space)? != expected_manifest {
            return Err(JournalError::Invariant("prepared projection changed original current manifest"));
        }
        memory.close_native_history_fresh_writer(&mut writer)?;
        check_deadline()?;
        let source = memory.inspect_native_history_source(source_digest.clone())?;
        if source.source_image_digest() != &expected_image
            || ContentId::hash(source.source_image()) != expected_image
            || source.projection().digest() != &projection_digest
            || source.owners().len() != inert_owner_count
            || !memory.observe_native_history_authority(source_digest.clone())?.all_refused()
        {
            return Err(JournalError::Invariant("prepared projection inert source or authority differs"));
        }
        let image = memory.backup_image(maximum_image_bytes)?;
        memory.connection.progress_handler(0, None::<fn() -> bool>)?;
        check_deadline()?;
        // Reaudit the final owned image, including every persisted source, hold
        // and preparation event, with the ordinary complete current audit.
        let image_digest = ContentId::hash(image.bytes());
        let image = Self::from_current_node_image(image.into_bytes(), image_digest.as_str(),
            maximum_image_bytes, space, bounds)?;
        check_deadline()?;
        let evidence = NativeHistoryPreparedProjectionEvidence {
            source_image: expected_image, source_digest, projection_digest,
            prepared_image: image_digest, inert_owner_count,
            memory_preparation_writer: writer.writer_id().clone(), target_native_creator_authority: false,
        };
        Ok(PreparedNativeHistoryProjectionImage { image, evidence })
    }
}
