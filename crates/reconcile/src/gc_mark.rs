use crate::{
    fault::checkpoint,
    filesystem::ObservedFile,
    now_ms,
    storage::{Inventory, Region},
    LocalSpace, ReconcileError, Result,
};
use serde::Serialize;
use std::{io::Read, time::UNIX_EPOCH};
use sync_extend_core_model::*;
use sync_extend_journal::{gc_grace_until, GcCheck, GcMark, GcMarkAudit, GcObservation, GcState};

#[derive(Debug, Serialize)]
pub struct GcRevalidation {
    pub mark_id: EntryId,
    pub checked_at_ms: u64,
    pub check: GcCheck,
    pub deletion_authorized: bool,
    pub gc_enabled: bool,
}

impl LocalSpace {
    pub fn gc_marks(&self) -> Result<Vec<GcMarkAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .gc_marks(&self.space_id, self.limits.max_storage_entries)?)
    }

    fn gc_object_observation(
        &self,
        id: &ContentId,
        inventory: &Inventory,
    ) -> Result<GcObservation> {
        let path = self.cas.object_path(id);
        let entry = inventory
            .get(&path)
            .ok_or(ReconcileError::Invariant("GC object missing"))?;
        if entry.object.as_ref() != Some(id)
            || inventory
                .values()
                .filter(|e| e.identity == entry.identity)
                .count()
                != 1
            || !(1..=4 * 1024 * 1024).contains(&entry.length)
        {
            return Err(ReconcileError::Invariant(
                "GC object length/layout/internal alias",
            ));
        }
        let mut observed = ObservedFile::open(&path)?;
        if observed.identity.physical != entry.identity
            || observed.metadata.len() != entry.length
            || observed.metadata.modified()? != entry.modified
        {
            return Err(ReconcileError::Unstable);
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut observed.file)
            .take(entry.length + 1)
            .read_to_end(&mut bytes)?;
        observed.verify(&path)?;
        if bytes.len() as u64 != entry.length || ContentId::hash(&bytes) != *id {
            return Err(ReconcileError::Invariant("GC object content hash mismatch"));
        }
        let modified_at_ns = u64::try_from(
            entry
                .modified
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ReconcileError::Invariant("GC modification time before epoch"))?
                .as_nanos(),
        )
        .map_err(|_| ReconcileError::Invariant("GC modification time overflow"))?;
        Ok(GcObservation {
            physical_identity: entry.identity.clone(),
            length: entry.length as u32,
            modified_at_ns,
        })
    }

    pub fn mark_gc_object(&mut self, id: &ContentId, grace_secs: u64) -> Result<GcMarkAudit> {
        gc_grace_until(now_ms()?, grace_secs)?;
        self.storage_report()?;
        if self.journal.protected_objects()?.contains(id) {
            return Err(ReconcileError::Invariant("GC object is protected"));
        }
        checkpoint("before_gc_mark");
        self.storage_report()?;
        let inventory = self.storage_inventory(Region::Cas)?;
        let observation = self.gc_object_observation(id, &inventory)?;
        let now = now_ms()?;
        self.verify_root()?;
        let audit = self.journal.mark_gc_object(
            &GcMark {
                format_version: FORMAT_VERSION,
                mark_id: EntryId::random()?,
                space_id: self.space_id.clone(),
                content_id: id.clone(),
                observation,
                marked_at_ms: now,
                grace_until_ms: gc_grace_until(now, grace_secs)?,
            },
            self.limits.max_storage_entries,
        )?;
        checkpoint("after_gc_mark");
        Ok(audit)
    }

    pub fn cancel_gc_mark(&mut self, id: &EntryId) -> Result<GcMarkAudit> {
        self.gc_marks()?;
        checkpoint("before_gc_cancel");
        self.verify_root()?;
        let audit = self.journal.cancel_gc_mark(
            &self.space_id,
            id,
            now_ms()?,
            self.limits.max_storage_entries,
        )?;
        checkpoint("after_gc_cancel");
        Ok(audit)
    }

    pub fn revalidate_gc_mark(&mut self, id: &EntryId) -> Result<GcRevalidation> {
        let audit = self
            .gc_marks()?
            .into_iter()
            .find(|m| m.intent.mark_id == *id)
            .ok_or(ReconcileError::Invariant("unknown GC mark"))?;
        self.storage_report()?;
        checkpoint("before_gc_revalidate");
        self.storage_report()?;
        let mut check = GcCheck::UnreferencedAfterGraceObservationOnly;
        if audit.state == GcState::Marked {
            let inventory = self.storage_inventory(Region::Cas)?;
            let path = self.cas.object_path(&audit.intent.content_id);
            check = if !inventory.contains_key(&path) {
                GcCheck::Missing
            } else {
                let entry = &inventory[&path];
                if entry.identity != audit.intent.observation.physical_identity
                    || entry.length != u64::from(audit.intent.observation.length)
                    || entry
                        .modified
                        .duration_since(UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_nanos())
                        != Some(u128::from(audit.intent.observation.modified_at_ns))
                {
                    GcCheck::Changed
                } else {
                    match self.gc_object_observation(&audit.intent.content_id, &inventory) {
                        Ok(_) => GcCheck::UnreferencedAfterGraceObservationOnly,
                        Err(ReconcileError::Invariant("GC object content hash mismatch")) => {
                            GcCheck::Corrupt
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
        }
        self.verify_root()?;
        let now = now_ms()?;
        let check = self.journal.revalidate_gc_mark(
            &self.space_id,
            id,
            check,
            now,
            self.limits.max_storage_entries,
        )?;
        checkpoint("after_gc_revalidate");
        Ok(GcRevalidation {
            mark_id: id.clone(),
            checked_at_ms: now,
            check,
            deletion_authorized: false,
            gc_enabled: false,
        })
    }
}
