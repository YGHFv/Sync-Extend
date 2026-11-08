//! Explicit original signed Replace with exact durable forward recovery.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::*;
use sync_extend_journal::{
    remote_replace_transaction, RemotePublicationProof, RemoteReplaceObservation,
    RemoteReplaceReceipt,
};
use sync_extend_transport::{PeerIdentity, SignedOperation};

#[derive(Serialize)]
pub struct RemoteReplaceResult {
    pub receipt: RemoteReplaceReceipt,
    pub pending_reason: Option<String>,
    pub automatic_sync: bool,
    pub remote_backup_complete: bool,
}
impl LocalSpace {
    fn replace_approval(&self, proof: &RemotePublicationProof) -> Result<()> {
        proof.verify()?;
        let peer = self.read_transport_peer(&proof.operation.payload.origin_device_id)?;
        if peer.public_key != proof.public_key
            || peer.space_id != self.space_id
            || peer.device_id == self.device_id
        {
            return Err(ReconcileError::Invariant(
                "remote Replace original approval differs",
            ));
        }
        Ok(())
    }
    fn replace_result(&self, id: &EntryId, error: Option<String>) -> Result<RemoteReplaceResult> {
        let receipt = self
            .journal
            .remote_replace_receipts(&self.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == *id)
            .ok_or(ReconcileError::Invariant(
                "remote Replace durable receipt missing",
            ))?;
        Ok(RemoteReplaceResult {
            receipt,
            pending_reason: error,
            automatic_sync: false,
            remote_backup_complete: false,
        })
    }
    pub fn remote_replace_receipts(&self) -> Result<Vec<RemoteReplaceReceipt>> {
        Ok(self.journal.remote_replace_receipts(&self.space_id)?)
    }
    pub fn apply_signed_remote_replace_from_file(
        &mut self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
        source: &std::path::Path,
    ) -> Result<RemoteReplaceResult> {
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote Replace original signature invalid"))?;
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote Replace requires exact stored approval",
            ));
        }
        let Change::Put { entry } = &signed.operation.payload.change else {
            return Err(ReconcileError::Invariant("remote Replace original action"));
        };
        // Terminal/restart replay does not depend on a sender file remaining online.
        let id = remote_replace_transaction(&signed.operation.op_id)?;
        if self
            .journal
            .remote_replace_receipts(&self.space_id)?
            .iter()
            .any(|r| r.transaction_id == id)
        {
            return self.apply_signed_remote_replace(peer, signed);
        }
        let content = self.import_source(source)?;
        if entry.content.as_ref() != Some(&content) {
            return Err(ReconcileError::Invariant(
                "remote Replace source differs from original signed content",
            ));
        }
        self.apply_signed_remote_replace(peer, signed)
    }
    pub fn apply_signed_remote_replace(
        &mut self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
    ) -> Result<RemoteReplaceResult> {
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote Replace original signature invalid"))?;
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote Replace requires exact stored approval",
            ));
        }
        let proof = RemotePublicationProof {
            public_key: peer.public_key,
            operation: signed.operation.clone(),
            signature: signed.signature.clone(),
        };
        self.replace_approval(&proof)?;
        let id = remote_replace_transaction(&signed.operation.op_id)?;
        let receipts = self.journal.remote_replace_receipts(&self.space_id)?;
        if let Some(receipt) = receipts.iter().find(|r| r.transaction_id == id) {
            if self.journal.remote_replace_original(&id)? != proof {
                return Err(ReconcileError::Invariant(
                    "remote Replace original transaction collision",
                ));
            }
            if receipt.native_cleanup_complete {
                return self.replace_result(&id, None);
            }
            return self.recover_remote_replace(&id);
        }
        self.recover()?;
        self.scan_without_recovery()?;
        let replay = self.replay_signed_remote_operation(peer, signed)?;
        if replay.disposition
            != sync_extend_journal::RemoteReplayDisposition::NativeMutationUnavailable
            || !matches!(&signed.operation.payload.change, Change::Put { .. })
        {
            return Err(ReconcileError::Invariant(
                "remote Replace conflict, ancestry or unsupported action",
            ));
        }
        self.verify_root()?;
        // Receiving is independent; admission never advances an already received cursor.
        self.journal.receive(&signed.operation)?;
        let source = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("remote Replace baseline missing"))?;
        let Change::Put { entry } = &signed.operation.payload.change else {
            return Err(ReconcileError::Invariant(
                "remote Replace requires original Put",
            ));
        };
        let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
            "remote Replace incoming content missing",
        ))?;
        let original = source
            .entries
            .get(&entry.entry_id)
            .and_then(|e| e.content.as_ref())
            .ok_or(ReconcileError::Invariant(
                "remote Replace original content missing",
            ))?;
        self.check_publication_limits(original)?;
        self.check_publication_limits(content)?;
        self.reserve_internal_worktree(original.length.checked_add(content.length).ok_or(
            ReconcileError::ResourceLimit("remote Replace peak overflow"),
        )?)?;
        self.cas.verify(original)?;
        self.cas.verify(content)?;
        checkpoint("before_remote_replace_admission");
        let held = self.journal.begin_remote_replace(&proof)?;
        checkpoint("after_remote_replace_selected");
        self.replace_approval(&proof)?;
        self.verify_root()?;
        let outcome = (|| {
            let held = self.journal.create_remote_replace_directories(held)?;
            checkpoint("after_remote_replace_creators");
            self.replace_approval(&proof)?;
            self.verify_root()?;
            self.reserve_native_internal_worktree(&held.file_view())?;
            let mut creation = self.journal.create_remote_replace_payload(held)?;
            self.reserve_native_internal_worktree(&creation.file_view())?;
            checkpoint("after_remote_replace_payload_creator");
            self.cas.write_file(content, creation.payload_writer())?;
            checkpoint("after_remote_replace_payload_written");
            self.replace_approval(&proof)?;
            self.verify_root()?;
            self.reserve_native_internal_worktree(&creation.file_view())?;
            let ready = self.journal.seal_remote_replace_payload(creation)?;
            checkpoint("after_remote_replace_seal");
            let ready = self.journal.record_remote_replace_ready(ready)?;
            checkpoint("after_remote_replace_ready");
            self.reserve_native_internal_worktree(&ready.file_view())?;
            let held = self.journal.start_remote_replace(ready)?;
            checkpoint("after_remote_replace_executing");
            self.replace_approval(&proof)?;
            self.verify_root()?;
            self.reserve_native_internal_worktree(&held.file_view())?;
            let held = self.journal.quarantine_remote_replace(held)?;
            checkpoint("after_remote_replace_quarantined");
            self.replace_approval(&proof)?;
            self.verify_root()?;
            let held = self.journal.start_remote_replace_publication(held)?;
            checkpoint("after_remote_replace_publishing");
            self.replace_approval(&proof)?;
            self.verify_root()?;
            self.reserve_native_internal_worktree(&held.file_view())?;
            let observation = self.journal.publish_remote_replace(held)?;
            checkpoint("after_remote_replace_observed");
            self.complete_remote_replace(observation)
        })();
        self.replace_result(&id, outcome.err().map(|e| e.to_string()))
    }
    fn complete_remote_replace(&mut self, observation: RemoteReplaceObservation) -> Result<()> {
        let id = observation.transaction_id().clone();
        let proof = self.journal.remote_replace_original(&id)?;
        self.replace_approval(&proof)?;
        self.verify_root()?;
        self.reserve_native_internal_worktree(&observation.file_view())?;
        let scan = crate::scan::scan_native(
            &self.worktree,
            &self.cas,
            &self.limits,
            &observation.file_view(),
        )?;
        if scan.len() != observation.manifest().entries.len()
            || observation.manifest().entries.values().any(|entry| {
                scan.get(&entry.path)
                    .is_none_or(|seen| seen.kind != entry.kind || seen.content != entry.content)
            })
        {
            return Err(ReconcileError::Unstable);
        }
        for content in observation
            .manifest()
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
        {
            self.cas.verify(content)?;
        }
        checkpoint("before_remote_replace_final");
        self.reserve_native_internal_worktree(&observation.file_view())?;
        let last = crate::scan::scan_native(
            &self.worktree,
            &self.cas,
            &self.limits,
            &observation.file_view(),
        )?;
        if last != scan {
            return Err(ReconcileError::Unstable);
        }
        observation.verify_content()?;
        self.replace_approval(&proof)?;
        self.verify_root()?;
        self.journal.finalize_remote_replace(observation)?;
        checkpoint("after_remote_replace_final");
        self.replace_approval(&proof)?;
        self.reserve_internal_worktree(0)?;
        self.journal.cleanup_remote_replace(&id)?;
        checkpoint("after_remote_replace_cleanup");
        Ok(())
    }
    pub fn recover_remote_replace(&mut self, id: &EntryId) -> Result<RemoteReplaceResult> {
        self.verify_root()?;
        let proof = self.journal.remote_replace_original(id)?;
        self.replace_approval(&proof)?;
        let current = self.replace_result(id, None)?;
        if current.receipt.native_cleanup_complete {
            return Ok(current);
        }
        if current.receipt.local_committed {
            if let Err(error) = self.reserve_internal_worktree(0) {
                return self.replace_result(id, Some(error.to_string()));
            }
            let error = self
                .journal
                .cleanup_remote_replace(id)
                .err()
                .map(|e| e.to_string());
            return self.replace_result(id, error);
        }
        let baseline = self.manifest()?.ok_or(ReconcileError::Invariant(
            "remote Replace recovery baseline missing",
        ))?;
        let Change::Put { entry } = &proof.operation.payload.change else {
            return Err(ReconcileError::Invariant(
                "remote Replace recovery original action",
            ));
        };
        let original = baseline
            .entries
            .get(&entry.entry_id)
            .and_then(|e| e.content.as_ref())
            .ok_or(ReconcileError::Invariant(
                "remote Replace recovery original missing",
            ))?;
        let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
            "remote Replace recovery incoming missing",
        ))?;
        self.check_publication_limits(original)?;
        self.check_publication_limits(content)?;
        self.cas.verify(original)?;
        self.cas.verify(content)?;

        let outcome = (|| {
            let held = self.journal.reopen_remote_replace_source(id)?;
            self.reserve_native_internal_worktree(&held.file_view())?;
            self.replace_approval(&proof)?;
            self.verify_root()?;
            let observation = self.journal.resume_remote_replace(held)?;
            self.complete_remote_replace(observation)
        })();
        self.replace_result(id, outcome.err().map(|e| e.to_string()))
    }
}
