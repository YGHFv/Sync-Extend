//! Descriptive original reservation states from an audited immutable image.
use crate::{JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use sync_extend_core_model::SpaceId;

impl JournalBackupImage {
    /// Reuses the exact original live-Journal diagnostic parser and capacity
    /// checks. The returned values carry no native, cleanup or restart issuer.
    pub fn recovered_original_attempt_diagnostics(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<Vec<crate::OriginalLocalHistoryAttemptDiagnostic>> {
        self.with_audited_readonly(space, bounds, |connection| {
            let audit = crate::JournalReadView { connection }.audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            let result = crate::history_reservation::audit_recovered_attempt_rows(
                &audit.rows,
                space,
                bounds.max_entries,
            )?;
            if serde_json::to_vec(&result)?.len() as u64 > bounds.capacity.max_logical_bytes {
                return Err(JournalError::Invariant(
                    "recovered original attempt diagnostic summary byte bound",
                ));
            }
            Ok(result)
        })
    }
}
