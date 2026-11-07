//! Explicit original signed Delete with exact durable forward recovery.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::*;
use sync_extend_journal::{
    remote_delete_transaction, RemoteDeleteObservation, RemoteDeleteReceipt, RemotePublicationProof,
};
use sync_extend_transport::{PeerIdentity, SignedOperation};

#[derive(Serialize)]
pub struct RemoteDeleteResult {
    pub receipt: RemoteDeleteReceipt,
    pub pending_reason: Option<String>,
    pub automatic_sync: bool,
    pub remote_backup_complete: bool,
}
impl LocalSpace {
    fn delete_approval(&self, proof: &RemotePublicationProof) -> Result<()> {
        proof.verify()?;
        let peer = self.read_transport_peer(&proof.operation.payload.origin_device_id)?;
        if peer.public_key != proof.public_key
            || peer.space_id != self.space_id
            || peer.device_id == self.device_id
        {
            return Err(ReconcileError::Invariant(
                "remote Delete original approval differs",
            ));
        }
        Ok(())
    }
    fn delete_result(&self, id: &EntryId, error: Option<String>) -> Result<RemoteDeleteResult> {
        let receipt = self
            .journal
            .remote_delete_receipts(&self.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == *id)
            .ok_or(ReconcileError::Invariant(
                "remote Delete durable receipt missing",
            ))?;
        Ok(RemoteDeleteResult {
            receipt,
            pending_reason: error,
            automatic_sync: false,
            remote_backup_complete: false,
        })
    }
    pub fn remote_delete_receipts(&self) -> Result<Vec<RemoteDeleteReceipt>> {
        Ok(self.journal.remote_delete_receipts(&self.space_id)?)
    }
    pub fn apply_signed_remote_delete(
        &mut self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
    ) -> Result<RemoteDeleteResult> {
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote Delete original signature invalid"))?;
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote Delete requires exact stored approval",
            ));
        }
        let proof = RemotePublicationProof {
            public_key: peer.public_key,
            operation: signed.operation.clone(),
            signature: signed.signature.clone(),
        };
        self.delete_approval(&proof)?;
        let id = remote_delete_transaction(&signed.operation.op_id)?;
        let receipts = self.journal.remote_delete_receipts(&self.space_id)?;
        if let Some(receipt) = receipts.iter().find(|r| r.transaction_id == id) {
            if self.journal.remote_delete_original(&id)? != proof {
                return Err(ReconcileError::Invariant(
                    "remote Delete original transaction collision",
                ));
            }
            if receipt.native_cleanup_complete {
                return self.delete_result(&id, None);
            }
            return self.recover_remote_delete(&id);
        }
        self.recover()?;
        self.scan_without_recovery()?;
        let replay = self.replay_signed_remote_operation(peer, signed)?;
        if replay.disposition
            != sync_extend_journal::RemoteReplayDisposition::NativeMutationUnavailable
            || !matches!(&signed.operation.payload.change, Change::Delete { .. })
        {
            return Err(ReconcileError::Invariant(
                "remote Delete conflict, ancestry or unsupported action",
            ));
        }
        self.verify_root()?;
        // Receiving is independent; admission never advances an already received cursor.
        self.journal.receive(&signed.operation)?;
        let source = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("remote Delete baseline missing"))?;
        let Change::Delete { entry_id } = &signed.operation.payload.change else {
            return Err(ReconcileError::Invariant("remote Delete action"));
        };
        let content = source
            .entries
            .get(entry_id)
            .and_then(|e| e.content.as_ref())
            .ok_or(ReconcileError::Invariant(
                "remote Delete original file missing",
            ))?;
        self.check_publication_limits(content)?;
        self.reserve_internal_worktree(content.length)?;
        self.cas.verify(content)?;
        checkpoint("before_remote_delete_admission");
        let held = self.journal.begin_remote_delete(&proof)?;
        checkpoint("after_remote_delete_selected");
        self.delete_approval(&proof)?;
        self.verify_root()?;
        let outcome = (|| {
            let held = self.journal.create_remote_delete_directories(held)?;
            checkpoint("after_remote_delete_creators");
            self.delete_approval(&proof)?;
            self.verify_root()?;
            let held = self.journal.start_remote_delete(held)?;
            checkpoint("after_remote_delete_executing");
            self.delete_approval(&proof)?;
            self.verify_root()?;
            let observation = self.journal.publish_remote_delete(held)?;
            checkpoint("after_remote_delete_observed");
            self.complete_remote_delete(observation)
        })();
        self.delete_result(&id, outcome.err().map(|e| e.to_string()))
    }
    fn complete_remote_delete(&mut self, observation: RemoteDeleteObservation) -> Result<()> {
        let id = observation.transaction_id().clone();
        let proof = self.journal.remote_delete_original(&id)?;
        self.delete_approval(&proof)?;
        self.verify_root()?;
        let scan = self.stable_scan()?;
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
        checkpoint("before_remote_delete_final");
        let last = self.stable_scan()?;
        if last != scan {
            return Err(ReconcileError::Unstable);
        }
        observation.verify_content()?;
        self.delete_approval(&proof)?;
        self.verify_root()?;
        self.journal.finalize_remote_delete(observation)?;
        checkpoint("after_remote_delete_final");
        self.delete_approval(&proof)?;
        self.journal.cleanup_remote_delete(&id)?;
        checkpoint("after_remote_delete_cleanup");
        Ok(())
    }
    pub fn recover_remote_delete(&mut self, id: &EntryId) -> Result<RemoteDeleteResult> {
        self.verify_root()?;
        let proof = self.journal.remote_delete_original(id)?;
        self.delete_approval(&proof)?;
        let current = self.delete_result(id, None)?;
        if current.receipt.native_cleanup_complete {
            return Ok(current);
        }
        if current.receipt.local_committed {
            let error = self
                .journal
                .cleanup_remote_delete(id)
                .err()
                .map(|e| e.to_string());
            return self.delete_result(id, error);
        }
        let baseline = self.manifest()?.ok_or(ReconcileError::Invariant(
            "remote Delete recovery baseline missing",
        ))?;
        let Change::Delete { entry_id } = &proof.operation.payload.change else {
            return Err(ReconcileError::Invariant("remote Delete recovery action"));
        };
        let content = baseline
            .entries
            .get(entry_id)
            .and_then(|entry| entry.content.as_ref())
            .ok_or(ReconcileError::Invariant(
                "remote Delete recovery source missing",
            ))?;
        self.check_publication_limits(content)?;
        self.cas.verify(content)?;
        self.reserve_internal_worktree(
            if self
                .worktree
                .join(current.receipt.source_path.as_str())
                .try_exists()?
            {
                content.length
            } else {
                0
            },
        )?;
        let outcome = (|| {
            let held = self.journal.reopen_remote_delete_source(id)?;
            self.delete_approval(&proof)?;
            self.verify_root()?;
            let observation = self.journal.resume_remote_delete(held)?;
            self.complete_remote_delete(observation)
        })();
        self.delete_result(id, outcome.err().map(|e| e.to_string()))
    }
}
