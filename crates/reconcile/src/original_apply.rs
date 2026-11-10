//! One explicit dependency-ready original operation; existing native drivers only.
use crate::LocalSpace;
#[cfg(windows)]
use crate::{fault::checkpoint, ReconcileError, Result};
use serde::Serialize;
#[cfg(windows)]
use sync_extend_core_model::{Change, EntryKind};
use sync_extend_core_model::{ContentId, OperationId, SnapshotId};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginalApplyState {
    AlreadyApplied,
    MissingDependencies,
    MissingContent,
    UnsupportedTree,
    NativePending,
    Applied,
}

#[derive(Serialize)]
pub struct OriginalApplyResult {
    pub request_id: ContentId,
    pub operation_id: OperationId,
    pub state: OriginalApplyState,
    pub applied_snapshot: Option<SnapshotId>,
    pub native_cleanup_complete: bool,
    pub pending_reason: Option<String>,
    pub signed_applied_receipt_issued: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    #[cfg(windows)]
    pub fn apply_original_operation(
        &mut self,
        request: &ContentId,
        operation: &OperationId,
    ) -> Result<OriginalApplyResult> {
        let envelope = self
            .original_content_inbox(self.limits.max_storage_entries)?
            .into_iter()
            .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(request))
            .ok_or(ReconcileError::Invariant(
                "original native inbox request absent",
            ))?;
        let signed = envelope
            .signed_page
            .page
            .operations
            .iter()
            .find(|s| &s.operation.op_id == operation)
            .ok_or(ReconcileError::Invariant(
                "original native operation outside signed page",
            ))?
            .clone();
        signed
            .verify(&envelope.source)
            .map_err(|_| ReconcileError::Invariant("original native individual signature"))?;
        let mut result = OriginalApplyResult {
            request_id: request.clone(),
            operation_id: operation.clone(),
            state: OriginalApplyState::NativePending,
            applied_snapshot: None,
            native_cleanup_complete: false,
            pending_reason: None,
            signed_applied_receipt_issued: false,
            remote_backup_complete: false,
        };
        let payload = &signed.operation.payload;
        let baseline = self.manifest()?.ok_or(ReconcileError::Invariant(
            "original native requires actual applied baseline",
        ))?;
        if baseline.version_vector.get(&payload.origin_device_id) >= payload.origin_seq {
            // A durable Final is applied history, not permission to abandon its
            // exact outstanding cleanup owner. Resume only this original driver.
            match &payload.change {
                Change::Put { .. } => {
                    let replacement = sync_extend_journal::remote_replace_transaction(operation)?;
                    if self
                        .remote_replace_receipts()?
                        .iter()
                        .any(|r| r.transaction_id == replacement)
                    {
                        let native = self.apply_signed_remote_replace(&envelope.source, &signed)?;
                        result.native_cleanup_complete = native.receipt.native_cleanup_complete;
                        result.pending_reason = native.pending_reason;
                    } else {
                        let id: sync_extend_core_model::EntryId =
                            ContentId::hash(format!("remote-native-v1:{operation}").as_bytes())
                                .as_str()[..32]
                                .parse()?;
                        if self.journal.find_publication(&id)?.is_some() {
                            let native = self.apply_signed_remote_put(&envelope.source, &signed)?;
                            result.native_cleanup_complete = native.native_cleanup_complete;
                            result.pending_reason = native.pending_reason;
                        }
                    }
                }
                Change::Delete { .. } => {
                    let id = sync_extend_journal::remote_delete_transaction(operation)?;
                    if self
                        .remote_delete_receipts()?
                        .iter()
                        .any(|r| r.transaction_id == id)
                    {
                        let native = self.apply_signed_remote_delete(&envelope.source, &signed)?;
                        result.native_cleanup_complete = native.receipt.native_cleanup_complete;
                        result.pending_reason = native.pending_reason;
                    }
                }
                Change::Rename { .. } => {
                    let id = sync_extend_journal::remote_rename_transaction(operation)?;
                    result.native_cleanup_complete = self
                        .remote_rename_receipts()?
                        .iter()
                        .any(|r| r.transaction_id == id && r.local_committed);
                }
            }
            let replay = self.replay_signed_remote_operation(&envelope.source, &signed)?;
            if replay.disposition != sync_extend_journal::RemoteReplayDisposition::AlreadyApplied {
                return Err(ReconcileError::Invariant(
                    "original claimed applied history differs",
                ));
            }
            result.state = OriginalApplyState::AlreadyApplied;
            result.applied_snapshot = Some(baseline.root()?);
            return Ok(result);
        }
        if !baseline.version_vector.dominates(&payload.causal)
            || baseline
                .version_vector
                .get(&payload.origin_device_id)
                .checked_add(1)
                != Some(payload.origin_seq)
        {
            result.state = OriginalApplyState::MissingDependencies;
            return Ok(result);
        }
        if self
            .journal
            .cursor(&self.space_id, &payload.origin_device_id)?
            < payload.origin_seq
        {
            return Err(ReconcileError::Invariant(
                "original native operation not actually received",
            ));
        }
        match &payload.change {
            Change::Put { entry } if entry.kind != EntryKind::File => {
                result.state = OriginalApplyState::UnsupportedTree;
                return Ok(result);
            }
            Change::Rename { entry_id, .. } | Change::Delete { entry_id }
                if baseline
                    .entries
                    .get(entry_id)
                    .is_some_and(|e| e.kind != EntryKind::File) =>
            {
                result.state = OriginalApplyState::UnsupportedTree;
                return Ok(result);
            }
            Change::Put { entry } => {
                let file = entry.content.as_ref().ok_or(ReconcileError::Invariant(
                    "original native file lacks exact manifest",
                ))?;
                self.check_publication_limits(file)?;
                for chunk in &file.chunks {
                    if !self.cas.object_path(&chunk.content_id).try_exists()? {
                        result.state = OriginalApplyState::MissingContent;
                        return Ok(result);
                    }
                }
                self.cas.verify(file)?;
            }
            _ => {}
        }
        checkpoint("before_original_native_dispatch");
        let committed;
        match &payload.change {
            Change::Put { entry } => {
                let replacement = sync_extend_journal::remote_replace_transaction(operation)?;
                let existing_replace = self
                    .remote_replace_receipts()?
                    .iter()
                    .any(|r| r.transaction_id == replacement);
                if existing_replace || baseline.entries.contains_key(&entry.entry_id) {
                    let native = self.apply_signed_remote_replace(&envelope.source, &signed)?;
                    committed = native.receipt.local_committed;
                    result.native_cleanup_complete = native.receipt.native_cleanup_complete;
                    result.pending_reason = native.pending_reason;
                } else {
                    let native = self.apply_signed_remote_put(&envelope.source, &signed)?;
                    committed = native.local_committed;
                    result.native_cleanup_complete = native.native_cleanup_complete;
                    result.pending_reason = native.pending_reason;
                }
            }
            Change::Rename { .. } => {
                let native = self.apply_signed_remote_rename(&envelope.source, &signed)?;
                committed = native.receipt.local_committed;
                result.native_cleanup_complete = native.receipt.local_committed;
                result.pending_reason = native.pending_reason;
            }
            Change::Delete { .. } => {
                let native = self.apply_signed_remote_delete(&envelope.source, &signed)?;
                committed = native.receipt.local_committed;
                result.native_cleanup_complete = native.receipt.native_cleanup_complete;
                result.pending_reason = native.pending_reason;
            }
        }
        checkpoint("after_original_native_dispatch");
        if committed {
            let current = self.manifest()?.ok_or(ReconcileError::Invariant(
                "original native Final lacks applied snapshot",
            ))?;
            if current.version_vector.get(&payload.origin_device_id) < payload.origin_seq {
                return Err(ReconcileError::Invariant(
                    "original native Final lacks applied frontier",
                ));
            }
            result.state = OriginalApplyState::Applied;
            result.applied_snapshot = Some(current.root()?);
        }
        self.verify_root()?;
        Ok(result)
    }
}
