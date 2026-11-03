use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use sync_extend_core_model::limits::LocalLimits;
use sync_extend_core_model::{EntryId, SnapshotId};
use sync_extend_journal::{ReferenceReservation, ReferenceReservationIntent};

impl LocalSpace {
    pub fn reference_reservations(&self) -> Result<Vec<ReferenceReservation>> {
        self.verify_root()?;
        let owners = self
            .journal
            .reference_reservations(&self.space_id, self.limits.max_storage_entries)?;
        self.verify_root()?;
        Ok(owners)
    }

    /// Reserve exact expected chunks locally; does not import or start a worker.
    pub fn reserve_content(
        &mut self,
        intent: &ReferenceReservationIntent,
    ) -> Result<ReferenceReservation> {
        self.verify_root()?;
        if intent.scope.space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "reservation local space mismatch",
            ));
        }
        check_limits(intent, &self.limits)?;
        checkpoint("before_reference_reservation");
        let (guards, owner) = self.journal.with_reference_reservation(
            intent,
            self.limits.max_storage_entries,
            |_| -> Result<_> {
                checkpoint("after_reference_reservation_pins");
                self.verify_root()?;
                Ok(())
            },
        )?;
        checkpoint("after_reference_reservation_commit");
        drop(guards);
        self.verify_root()?;
        Ok(owner)
    }

    pub fn handoff_content(
        &mut self,
        owner_id: &EntryId,
        snapshot_id: &SnapshotId,
    ) -> Result<ReferenceReservation> {
        self.verify_root()?;
        checkpoint("before_reference_snapshot_handoff");
        let (guards, owner) = self.journal.with_reference_snapshot_handoff(
            &self.space_id,
            owner_id,
            snapshot_id,
            self.limits.max_storage_entries,
            |intent| -> Result<()> {
                checkpoint("after_reference_snapshot_handoff_lock");
                check_limits(intent, &self.limits)?;
                for file in &intent.scope.files {
                    self.cas.verify(file)?;
                }
                checkpoint("after_reference_snapshot_handoff_verify");
                self.verify_root()?;
                Ok(())
            },
        )?;
        checkpoint("after_reference_snapshot_handoff_commit");
        drop(guards);
        self.verify_root()?;
        Ok(owner)
    }
}

fn check_limits(intent: &ReferenceReservationIntent, limits: &LocalLimits) -> Result<()> {
    intent.scope.validate()?;
    if intent.scope.files.len() > limits.max_scan_entries {
        return Err(ReconcileError::ResourceLimit("reservation files"));
    }
    let mut bytes = 0u64;
    let mut chunks = 0usize;
    for file in &intent.scope.files {
        if file.length > limits.max_file_bytes {
            return Err(ReconcileError::ResourceLimit("reservation file bytes"));
        }
        bytes = bytes
            .checked_add(file.length)
            .filter(|n| *n <= limits.max_scan_bytes)
            .ok_or(ReconcileError::ResourceLimit("reservation logical bytes"))?;
        chunks = chunks
            .checked_add(file.chunks.len())
            .filter(|n| *n <= limits.max_scan_chunks)
            .ok_or(ReconcileError::ResourceLimit("reservation chunks"))?;
    }
    Ok(())
}
