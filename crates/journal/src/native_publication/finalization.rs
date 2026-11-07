//! One atomic exact admitted history and original guarded native final receipt.
use super::NativePublicationObservation;
use crate::{
    native_publication::{issuance, physical, schema},
    storage_inventory::reader::{hash, invalid},
    storage_policy::{self, local_commit},
    Completion, Journal, JournalStorageColumn, JournalStorageColumnValue as ColumnValue,
    PublicationState, Result,
};
use rusqlite::{params_from_iter, types::Value, Transaction, TransactionBehavior};
use sync_extend_core_model::{EntryId, SnapshotId};

impl Journal {
    /// Read-only original final receipt replay. Later native edits do not renew
    /// mutation, cleanup or history authority and are never rewritten here.
    pub fn native_publication_final_snapshot(&self, id: &EntryId) -> Result<SnapshotId> {
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "native final replay refuses caller-owned transaction",
            ));
        }
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        if publication.state != PublicationState::Committed
            || !before.rows.iter().any(|row| {
                row.table() == "native_publication_phases"
                    && row.primary_key() == [id.as_str(), "0", "final"]
            })
        {
            return Err(invalid(
                "native final replay requires original committed receipt",
            ));
        }
        let root = publication
            .committed_snapshot
            .ok_or(invalid("native final snapshot missing"))?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid("native final replay changed stored state"));
        }
        tx.commit()?;
        Ok(root)
    }

    /// Commit only the original admitted local history while exact original
    /// target/source/content guards stay live. This does not clean native owners,
    /// apply remote operations or certify unrelated worktree entries.
    pub fn finalize_native_publication(
        &mut self,
        observation: NativePublicationObservation,
    ) -> Result<SnapshotId> {
        if !self.connection.is_autocommit() {
            return Err(invalid("native final refuses caller-owned transaction"));
        }
        observation.verify_content()?;
        let header = &observation.held.header;
        let intent = &header.intent;
        let completion = intent
            .completion
            .as_ref()
            .ok_or(invalid("native final original history missing"))?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        let publication = self.publication(&intent.transaction_id)?;
        if publication.intent != *intent
            || publication.state != PublicationState::Preparing
            || publication.cleaned
            || !before.rows.iter().any(|row| {
                row.table() == "native_publication_phases"
                    && row.primary_key() == [intent.transaction_id.as_str(), "0", "observed"]
            })
        {
            return Err(invalid("native final original observed owner differs"));
        }
        for content in completion.protected_objects.keys() {
            self.require_cas_access(content)?;
        }
        let json = serde_json::to_string(&completion.manifest)?;
        let operations = completion
            .operations
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut projection = local_commit::project_native_publication(
            &before,
            local_commit::Input {
                expected_root: Some(&intent.baseline_root),
                manifest: &completion.manifest,
                operations: &completion.operations,
                operation_json: &operations,
                snapshot_json: &json,
                timestamp: completion.timestamp_ms,
                observation_json: None,
            },
            intent,
        )?;
        let text = |value: &str| Value::Text(value.into());
        let values = vec![
            text(intent.transaction_id.as_str()),
            text(header.generation.as_str()),
            Value::Integer(0),
            text(hash(header)?.as_str()),
            text("final"),
            text(physical(&observation.held.payload_key)?.as_str()),
            text(intent.content.content_id.as_str()),
            text(hash(&intent.target_path)?.as_str()),
            Value::Integer(intent.created_at_ms as i64),
            text(&observation.held.owner_key.volume),
            text(&observation.held.owner_key.id),
            text(&header.parent.volume),
            text(&header.parent.id),
            text(intent.target_path.as_str()),
        ];
        let spec = schema::TABLES
            .iter()
            .find(|table| table.name == "native_publication_phases")
            .ok_or(invalid("native final phase schema missing"))?;
        let columns = spec
            .columns
            .iter()
            .zip(&values)
            .map(|(column, value)| {
                Ok(JournalStorageColumn {
                    name: column.name.into(),
                    value: match value {
                        Value::Text(value) => ColumnValue::Text(value.clone()),
                        Value::Integer(value) => ColumnValue::Integer(
                            u64::try_from(*value).map_err(|_| invalid("native final integer"))?,
                        ),
                        _ => return Err(invalid("native final SQL value")),
                    },
                })
            })
            .collect::<Result<_>>()?;
        projection.native_final_phase(&intent.transaction_id, columns)?;
        let mut authorized = vec![text("phases")];
        authorized.extend(values.clone());
        let _permit = issuance::permit(&self.native_issuance, authorized)?;
        if tx.execute(
            "INSERT INTO native_publication_phases VALUES
             (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            params_from_iter(&values),
        )? != 1
        {
            return Err(invalid("native final phase insertion missing"));
        }
        let root = if intent.remote.is_some() {
            self.commit_remote_publication_sql(&tx, intent)?
        } else {
            self.commit_history_sql(
                &tx,
                Some(&intent.baseline_root),
                &completion.manifest,
                &completion.operations,
                completion.timestamp_ms,
                Completion::NativePublication(&intent.transaction_id),
            )?
        };
        let after = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        projection.receipt(&after)?;
        observation.verify_content()?;
        tx.commit()?;
        Ok(root)
    }
}
