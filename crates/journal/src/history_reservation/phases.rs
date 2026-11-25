//! Original live attempt phase observations, not restart/native/cleanup issuers.
use super::{OriginalLocalHistoryReservation, Stored};
use crate::{Journal, JournalError, Result};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sync_extend_core_model::{ContentId, EntryId};
use sync_extend_platform_fs::{
    HeldPrivateVolume, OriginalOutsideIntent, OriginalPrivateVolumeFile,
};

use super::phase_evidence::{PREFIX, Phase};

pub struct OriginalNativePhaseObservationReceipt {
    attempt: EntryId,
    stage: String,
    exact_json: String,
    exact_digest: ContentId,
}

impl OriginalNativePhaseObservationReceipt {
    pub fn attempt(&self) -> &EntryId {
        &self.attempt
    }
    pub fn stage(&self) -> &str {
        &self.stage
    }
    pub fn exact_json(&self) -> &str {
        &self.exact_json
    }
    pub fn exact_digest(&self) -> &ContentId {
        &self.exact_digest
    }
}

impl Journal {
    /// Checks the original live token against its own issued prefix. It returns
    /// no native/cleanup right and cannot reconstruct a token after restart.
    pub fn verify_original_live_native_phase_prefix(
        &self,
        reservation: &OriginalLocalHistoryReservation,
    ) -> Result<()> {
        if !std::sync::Arc::ptr_eq(&self.original_local_history_issuer, &reservation.issuer) {
            return Err(JournalError::Invariant(
                "original live phase prefix requires original issuer",
            ));
        }
        let issued = reservation
            .original_issued_phases
            .lock()
            .map_err(|_| JournalError::Invariant("original live native phase lock poisoned"))?;
        let _original_read_snapshot = if self.connection.is_autocommit() {
            Some(Transaction::new_unchecked(
                &self.connection,
                TransactionBehavior::Deferred,
            )?)
        } else {
            None
        };
        super::liability::verify_pending_connection(&self.connection, reservation.exact_json())?;
        super::phase_chain::verify_live_prefix(&self.connection, reservation, &issued)
    }

    pub fn observe_original_native_create_request(
        &mut self,
        reservation: &OriginalLocalHistoryReservation,
        intent: &OriginalOutsideIntent,
        volume: &HeldPrivateVolume,
        max: usize,
    ) -> Result<OriginalNativePhaseObservationReceipt> {
        intent.verify(volume)?;
        verify_intent(reservation, intent)?;
        let phase = Phase {
            version: 1,
            attempt: reservation.attempt.clone(),
            sequence: 1,
            predecessor: None,
            stage: "original_create_requested".to_owned(),
            original_reservation_digest: ContentId::hash(reservation.exact_json.as_bytes()),
            intent_digest: ContentId::hash(intent.exact_bytes()),
            original_file_key: None,
            original_parent_key: None,
            payload_digest: None,
            payload_bytes: 0,
            original_create_slot_absent: false,
        };
        self.append_original_native_phase(reservation, phase, max)
    }
    pub fn observe_original_native_created(
        &mut self,
        reservation: &OriginalLocalHistoryReservation,
        intent: &OriginalOutsideIntent,
        volume: &HeldPrivateVolume,
        creator: &OriginalPrivateVolumeFile<'_, '_>,
        max: usize,
    ) -> Result<OriginalNativePhaseObservationReceipt> {
        intent.verify(volume)?;
        verify_intent(reservation, intent)?;
        creator.verify()?;
        if !creator.exact_bytes()?.is_empty() {
            return Err(JournalError::Invariant(
                "original CREATE initial observation is not empty",
            ));
        }
        let original = creator.original_key()?;
        let parent = creator.original_parent_key()?;
        let phase = Phase {
            version: 1,
            attempt: reservation.attempt.clone(),
            sequence: 2,
            predecessor: None,
            stage: "original_create_observed".to_owned(),
            original_reservation_digest: ContentId::hash(reservation.exact_json.as_bytes()),
            intent_digest: ContentId::hash(intent.exact_bytes()),
            original_file_key: Some((original.device, original.inode)),
            original_parent_key: Some((parent.device, parent.inode)),
            payload_digest: Some(ContentId::hash(b"")),
            payload_bytes: 0,
            original_create_slot_absent: false,
        };
        let receipt = self.append_original_native_phase(reservation, phase, max)?;
        creator.verify()?;
        Ok(receipt)
    }
    /// Only the original live reservation/Journal and actual outside intent
    /// holders can append this observation. It grants no subsequent native right.
    pub fn observe_original_native_intent(
        &mut self,
        reservation: &OriginalLocalHistoryReservation,
        intent: &OriginalOutsideIntent,
        volume: &HeldPrivateVolume,
        max: usize,
    ) -> Result<OriginalNativePhaseObservationReceipt> {
        intent.verify(volume)?;
        verify_intent(reservation, intent)?;
        let phase = Phase {
            version: 1,
            attempt: reservation.attempt.clone(),
            sequence: 0,
            predecessor: None,
            stage: "outside_intent_synced".to_owned(),
            original_reservation_digest: ContentId::hash(reservation.exact_json.as_bytes()),
            intent_digest: ContentId::hash(intent.exact_bytes()),
            original_file_key: None,
            original_parent_key: None,
            payload_digest: None,
            payload_bytes: 0,
            original_create_slot_absent: false,
        };
        let receipt = self.append_original_native_phase(reservation, phase, max)?;
        intent.verify(volume)?;
        verify_intent(reservation, intent)?;
        Ok(receipt)
    }

    /// Actual original CREATE current slot/bytes plus vacated CREATE component.
    /// A failure after append preserves the record and never issues cleanup.
    pub fn observe_original_native_published(
        &mut self,
        reservation: &OriginalLocalHistoryReservation,
        intent: &OriginalOutsideIntent,
        volume: &HeldPrivateVolume,
        creator: &OriginalPrivateVolumeFile<'_, '_>,
        max: usize,
    ) -> Result<OriginalNativePhaseObservationReceipt> {
        intent.verify(volume)?;
        verify_intent(reservation, intent)?;
        creator.verify()?;
        let bytes = creator.exact_bytes()?;
        let original = creator.original_key()?;
        let parent = creator.original_parent_key()?;
        let absent = creator.observe_original_create_slot_absence()?;
        absent.verify()?;
        let stored: Stored = serde_json::from_str(reservation.exact_json())?;
        stored.validate(max)?;
        if ContentId::hash(&bytes) != stored.native_footprint.payload_digest
            || bytes.len() as u64 != stored.native_footprint.payload_bytes
        {
            return Err(JournalError::Invariant(
                "original native phase payload differs from original plan",
            ));
        }
        let phase = Phase {
            version: 1,
            attempt: reservation.attempt.clone(),
            sequence: 3,
            predecessor: None,
            stage: "original_create_published_and_source_absent".to_owned(),
            original_reservation_digest: ContentId::hash(reservation.exact_json.as_bytes()),
            intent_digest: ContentId::hash(intent.exact_bytes()),
            original_file_key: Some((original.device, original.inode)),
            original_parent_key: Some((parent.device, parent.inode)),
            payload_digest: Some(ContentId::hash(&bytes)),
            payload_bytes: bytes.len() as u64,
            original_create_slot_absent: true,
        };
        let receipt = self.append_original_native_phase(reservation, phase, max)?;
        creator.verify()?;
        intent.verify(volume)?;
        absent.verify()?;
        Ok(receipt)
    }

    fn append_original_native_phase(
        &mut self,
        reservation: &OriginalLocalHistoryReservation,
        mut phase: Phase,
        max: usize,
    ) -> Result<OriginalNativePhaseObservationReceipt> {
        if !std::sync::Arc::ptr_eq(&self.original_local_history_issuer, &reservation.issuer) {
            return Err(JournalError::Invariant(
                "original native phase requires original live Journal issuer",
            ));
        }
        let stored: Stored = serde_json::from_str(reservation.exact_json())?;
        stored.validate(max)?;

        if phase.attempt != stored.attempt || phase.sequence > 3 {
            return Err(JournalError::Invariant(
                "original native phase scope or budget",
            ));
        }

        let mut original_issued_phases = reservation
            .original_issued_phases
            .lock()
            .map_err(|_| JournalError::Invariant("original live native phase lock poisoned"))?;
        if original_issued_phases.len() != phase.sequence as usize {
            return Err(JournalError::Invariant(
                "original native append live sequence differs",
            ));
        }
        let bounds = self.writer_capacity_limits(max)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        super::liability::verify_pending_connection(&tx, reservation.exact_json())?;
        super::phase_chain::verify_live_prefix(&tx, reservation, &original_issued_phases)?;

        let before = self
            .read_view()
            .audit_local_commit_capacity(&stored.baseline.space_id, bounds)?;
        super::verify_original_capacity_context(reservation.exact_json(), &before.rows)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM local_state WHERE substr(key,1,?1)=?2",
            params![
                i64::try_from(format!("{PREFIX}{}.", stored.attempt).len())
                    .map_err(|_| JournalError::Invariant("original phase SQLite integer bound"))?,
                format!("{PREFIX}{}.", stored.attempt)
            ],
            |row| row.get(0),
        )?;
        if count != i64::from(phase.sequence) {
            return Err(JournalError::Invariant(
                "original native phase sequence is not contiguous",
            ));
        }
        let previous: Option<String> = if phase.sequence == 0 {
            None
        } else {
            tx.query_row(
                "SELECT value FROM local_state WHERE key=?1",
                [format!(
                    "{PREFIX}{}.{:04}",
                    stored.attempt,
                    phase.sequence - 1
                )],
                |row| row.get(0),
            )
            .optional()?
        };
        phase.predecessor = previous
            .as_ref()
            .map(|json| ContentId::hash(json.as_bytes()));
        let exact_json = serde_json::to_string(&phase)?;
        if exact_json.len() as u64 > stored.native_footprint.max_phase_record_bytes {
            return Err(JournalError::Invariant(
                "original native phase actual byte bound",
            ));
        }
        tx.execute(
            "INSERT INTO local_state VALUES (?1,?2)",
            params![
                format!("{PREFIX}{}.{:04}", stored.attempt, phase.sequence),
                exact_json
            ],
        )?;
        super::phase_chain::advance(&tx, &stored, &phase, &exact_json)?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&stored.baseline.space_id, bounds)?;
        if !after.report.within_accounted_limits()
            || after.rows.len() != before.rows.len() + 1
            || before
                .rows
                .iter()
                .filter(|row| !super::phase_chain::is_cursor_row(row, &stored.attempt))
                .any(|row| {
                    !after.rows.iter().any(|current| {
                        row.table() == current.table()
                            && row.primary_key() == current.primary_key()
                            && row.columns() == current.columns()
                    })
                })
        {
            return Err(JournalError::Invariant(
                "original native phase collateral rows or capacity",
            ));
        }
        let original_issued_json = exact_json.clone();
        tx.commit()?;
        original_issued_phases.push(original_issued_json);
        Ok(OriginalNativePhaseObservationReceipt {
            attempt: phase.attempt,
            stage: phase.stage,
            exact_digest: ContentId::hash(exact_json.as_bytes()),
            exact_json,
        })
    }
}

fn verify_intent(
    reservation: &OriginalLocalHistoryReservation,
    intent: &OriginalOutsideIntent,
) -> Result<()> {
    let parts: serde_json::Value = serde_json::from_slice(intent.exact_bytes())?;
    let parts = parts.as_array().ok_or(JournalError::Invariant(
        "original phase intent full array required",
    ))?;
    if parts.len() != 11 || parts[0] != 1u32 || parts[10].as_str() != Some(reservation.exact_json())
    {
        return Err(JournalError::Invariant(
            "original phase intent exact reservation differs",
        ));
    }
    let stored: Stored = serde_json::from_str(reservation.exact_json())?;
    if parts[1] != serde_json::to_value(&stored.planned.space_id)?
        || parts[2] != serde_json::to_value(&stored.original_device)?
        || parts[3] != serde_json::to_value(&stored.future_path)?
        || parts[4] != serde_json::to_value(&stored.baseline)?
        || parts[5] != serde_json::to_value(&stored.planned)?
        || parts[6] != serde_json::to_value(&stored.operations)?
        || parts[7].as_u64() != Some(stored.timestamp)
        || parts[8]
            .as_str()
            .map(|path| ContentId::hash(path.as_bytes()))
            != Some(stored.original_worktree_digest)
        || parts[9].as_str() != Some(stored.observations.scope.local_root_identity.as_str())
    {
        return Err(JournalError::Invariant(
            "original native phase complete intent scope differs",
        ));
    }
    Ok(())
}
