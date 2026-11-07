//! Explicit original signed Rename with exact durable forward recovery.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::*;
use sync_extend_journal::{
    remote_rename_transaction, RemotePublicationProof, RemoteRenameObservation, RemoteRenameReceipt,
};
use sync_extend_transport::{PeerIdentity, SignedOperation};

#[derive(Serialize)]
pub struct RemoteRenameResult {
    pub receipt: RemoteRenameReceipt,
    pub pending_reason: Option<String>,
    pub automatic_sync: bool,
    pub remote_backup_complete: bool,
}
impl LocalSpace {
    fn rename_approval(&self, proof: &RemotePublicationProof) -> Result<()> {
        proof.verify()?;
        let peer = self.read_transport_peer(&proof.operation.payload.origin_device_id)?;
        if peer.public_key != proof.public_key
            || peer.space_id != self.space_id
            || peer.device_id == self.device_id
        {
            return Err(ReconcileError::Invariant(
                "remote Rename original approval differs",
            ));
        }
        Ok(())
    }
    fn rename_result(&self, id: &EntryId, error: Option<String>) -> Result<RemoteRenameResult> {
        let receipt = self
            .journal
            .remote_rename_receipts(&self.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == *id)
            .ok_or(ReconcileError::Invariant(
                "remote Rename durable receipt missing",
            ))?;
        Ok(RemoteRenameResult {
            receipt,
            pending_reason: error,
            automatic_sync: false,
            remote_backup_complete: false,
        })
    }
    pub fn remote_rename_receipts(&self) -> Result<Vec<RemoteRenameReceipt>> {
        Ok(self.journal.remote_rename_receipts(&self.space_id)?)
    }
    pub fn apply_signed_remote_rename(
        &mut self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
    ) -> Result<RemoteRenameResult> {
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote Rename original signature invalid"))?;
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote Rename requires exact stored approval",
            ));
        }
        let proof = RemotePublicationProof {
            public_key: peer.public_key,
            operation: signed.operation.clone(),
            signature: signed.signature.clone(),
        };
        self.rename_approval(&proof)?;
        let id = remote_rename_transaction(&signed.operation.op_id)?;
        let receipts = self.journal.remote_rename_receipts(&self.space_id)?;
        if let Some(receipt) = receipts.iter().find(|r| r.transaction_id == id) {
            if self.journal.remote_rename_original(&id)? != proof {
                return Err(ReconcileError::Invariant(
                    "remote Rename original transaction collision",
                ));
            }
            if receipt.local_committed {
                return self.rename_result(&id, None);
            }
            return self.recover_remote_rename(&id);
        }
        self.recover()?;
        self.scan_without_recovery()?;
        let replay = self.replay_signed_remote_operation(peer, signed)?;
        if replay.disposition
            != sync_extend_journal::RemoteReplayDisposition::NativeMutationUnavailable
            || !matches!(&signed.operation.payload.change, Change::Rename { .. })
        {
            return Err(ReconcileError::Invariant(
                "remote Rename conflict, ancestry or unsupported action",
            ));
        }
        self.verify_root()?;
        // Receiving is independent; admission never advances an already received cursor.
        self.journal.receive(&signed.operation)?;
        checkpoint("before_remote_rename_admission");
        let held = self.journal.begin_remote_rename(&proof)?;
        checkpoint("after_remote_rename_selected");
        self.rename_approval(&proof)?;
        self.verify_root()?;
        let outcome = (|| {
            let held = self.journal.start_remote_rename(held)?;
            checkpoint("after_remote_rename_executing");
            self.rename_approval(&proof)?;
            self.verify_root()?;
            let observation = self.journal.publish_remote_rename(held)?;
            checkpoint("after_remote_rename_observed");
            self.complete_remote_rename(observation)
        })();
        self.rename_result(&id, outcome.err().map(|e| e.to_string()))
    }
    fn complete_remote_rename(&mut self, observation: RemoteRenameObservation) -> Result<()> {
        let id = observation.transaction_id().clone();
        let proof = self.journal.remote_rename_original(&id)?;
        self.rename_approval(&proof)?;
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
        checkpoint("before_remote_rename_final");
        let last = self.stable_scan()?;
        if last != scan {
            return Err(ReconcileError::Unstable);
        }
        observation.verify_content()?;
        self.rename_approval(&proof)?;
        self.verify_root()?;
        self.journal.finalize_remote_rename(observation)?;
        checkpoint("after_remote_rename_final");
        Ok(())
    }
    pub fn recover_remote_rename(&mut self, id: &EntryId) -> Result<RemoteRenameResult> {
        self.verify_root()?;
        let proof = self.journal.remote_rename_original(id)?;
        self.rename_approval(&proof)?;
        let current = self.rename_result(id, None)?;
        if current.receipt.local_committed {
            return Ok(current);
        }
        let outcome = (|| {
            let held = self.journal.reopen_remote_rename_source(id)?;
            self.rename_approval(&proof)?;
            self.verify_root()?;
            let observation = self.journal.resume_remote_rename(held)?;
            self.complete_remote_rename(observation)
        })();
        self.rename_result(id, outcome.err().map(|e| e.to_string()))
    }
}
