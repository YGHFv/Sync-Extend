use crate::{storage_inventory::reader::invalid, storage_policy, Journal, Result};
use rusqlite::{Transaction, TransactionBehavior};
use serde::Serialize;
use sync_extend_core_model::EntryId;

/// Audited metadata only, never a CREATE, resume or mutation capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativePublicationStage {
    Legacy,
    Selected,
    Creating,
    Ready,
    Publishing,
    Observed,
    Final,
    Cleanup,
}

impl Journal {
    pub fn audit_native_publication_stage(&self, id: &EntryId) -> Result<NativePublicationStage> {
        if !self.connection.is_autocommit() {
            return Err(invalid("native status refuses caller-owned transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        let header = before.rows.iter().any(|row| {
            row.table() == "native_publication_headers" && row.primary_key() == [id.as_str()]
        });
        let stage = if header {
            [
                ("cleanup", NativePublicationStage::Cleanup),
                ("final", NativePublicationStage::Final),
                ("observed", NativePublicationStage::Observed),
                ("publishing", NativePublicationStage::Publishing),
                ("ready", NativePublicationStage::Ready),
            ]
            .into_iter()
            .find_map(|(phase, stage)| {
                before
                    .rows
                    .iter()
                    .any(|row| {
                        row.table() == "native_publication_phases"
                            && row.primary_key() == [id.as_str(), "0", phase]
                    })
                    .then_some(stage)
            })
            .unwrap_or(NativePublicationStage::Creating)
        } else if publication.intent.native_only {
            NativePublicationStage::Selected
        } else {
            NativePublicationStage::Legacy
        };
        let after = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid("native status changed stored state"));
        }
        tx.rollback()?;
        Ok(stage)
    }
}
