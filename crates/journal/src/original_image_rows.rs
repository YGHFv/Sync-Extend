//! Bound actual original SQLite rows and full equality with mapped image.
use crate::{Journal, JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use rusqlite::{Transaction, TransactionBehavior};
use sync_extend_core_model::SpaceId;

impl Journal {
    #[cfg(windows)]
    pub fn verify_original_image_rows(
        &self,
        image: &JournalBackupImage,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<()> {
        // A separate actual sameobject connection owns its budget hook; no
        // caller connection/transaction/hook is altered.
        let mut actual_connection = self.open_original_coordination_connection()?;
        let result = (|| {
            // Reuse the complete original node inspection configuration, including
            // entry/row/byte bounds, busy/cache/temp settings and the first SQL hook.
            bounds.configure_original_connection(&mut actual_connection.connection)?;
            let transaction = Transaction::new_unchecked(
                &actual_connection.connection,
                TransactionBehavior::Deferred,
            )?;
            let actual = actual_connection
                .read_view()
                .audit_original_provenance_capacity(space, bounds.max_entries, bounds.capacity)?;
            image.with_audited_readonly(space, bounds, |connection| {
                let original = crate::JournalReadView {
                    connection,
                    dav_read_charge_cache: None,
                }
                .audit_original_provenance_capacity(
                    space,
                    bounds.max_entries,
                    bounds.capacity,
                )?;
                if actual.rows != original.rows {
                    return Err(JournalError::Invariant(
                        "actual original Journal complete row values differ",
                    ));
                }
                Ok(())
            })?;
            transaction.rollback()?;
            actual_connection.verify_original_created_image()?;
            self.verify_original_created_image()
        })();
        actual_connection.finish_original_coordination_observation(result)
    }
}
