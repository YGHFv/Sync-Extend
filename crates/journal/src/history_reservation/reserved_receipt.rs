//! Commit receipt issued only by the original reserved history transaction.
use crate::LocalHistoryCommitReceipt;
use sync_extend_core_model::{ContentId, EntryId, SnapshotId};

/// No public constructor, Clone, Deserialize or conversion from ordinary history.
pub struct OriginalReservedHistoryCommitReceipt {
    history: LocalHistoryCommitReceipt,
    native_phase_chain: super::OriginalNativePhaseChain,
    attempt: EntryId,
    exact_reservation: String,
    _original_issuer: std::sync::Arc<()>,
}

impl OriginalReservedHistoryCommitReceipt {
    pub(super) fn issued(
        history: LocalHistoryCommitReceipt,
        reservation: super::OriginalLocalHistoryReservation,
        native_phase_chain: super::OriginalNativePhaseChain,
    ) -> Self {
        Self {
            history,
            native_phase_chain,
            attempt: reservation.attempt,
            exact_reservation: reservation.exact_json,
            _original_issuer: reservation.issuer,
        }
    }
    pub fn native_phase_chain(&self) -> &super::OriginalNativePhaseChain {
        &self.native_phase_chain
    }
    pub(super) fn verify_original_issuer(&self, issuer: &std::sync::Arc<()>) -> crate::Result<()> {
        if !std::sync::Arc::ptr_eq(issuer, &self._original_issuer) {
            return Err(crate::JournalError::Invariant(
                "original reserved receipt belongs to another Journal",
            ));
        }
        Ok(())
    }
    pub fn original_attempt(&self) -> &EntryId {
        &self.attempt
    }
    pub fn exact_reservation_json(&self) -> &str {
        &self.exact_reservation
    }
    pub fn baseline(&self) -> Option<&SnapshotId> {
        self.history.baseline()
    }
    pub fn snapshot(&self) -> &SnapshotId {
        self.history.snapshot()
    }
    pub fn snapshot_json(&self) -> &str {
        self.history.snapshot_json()
    }
    pub fn operation_json(&self) -> &[String] {
        self.history.operation_json()
    }
    pub fn observation_json(&self) -> Option<&str> {
        self.history.observation_json()
    }
    pub fn evidence_digest(&self) -> &ContentId {
        self.history.evidence_digest()
    }
}
