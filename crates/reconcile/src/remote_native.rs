//! Explicit original signed new-file Put apply, never a second local Put.
use crate::{
    filesystem::physical_identity, LocalSpace, NativePublishResult, ReconcileError, Result,
};
use sync_extend_core_model::*;
use sync_extend_journal::{PublicationCompletion, PublicationIntent, RemotePublicationProof};
use sync_extend_transport::{PeerIdentity, SignedOperation};

impl LocalSpace {
    pub fn apply_signed_remote_put_from_file(
        &mut self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
        source: &std::path::Path,
    ) -> Result<NativePublishResult> {
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote apply signature invalid"))?;
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote content requires exact stored approval",
            ));
        }
        let Change::Put { entry } = &signed.operation.payload.change else {
            return Err(ReconcileError::Invariant(
                "remote native supports file Put only",
            ));
        };
        let content = self.import_source(source)?;
        if entry.content.as_ref() != Some(&content) {
            return Err(ReconcileError::Invariant(
                "remote source differs from original signed content",
            ));
        }
        self.apply_signed_remote_put(peer, signed)
    }

    /// Explicit caller-authorized peer; original signature is persisted for restart.
    /// Content must already be present in verified CAS; no download or auto worker.
    pub fn apply_signed_remote_put(
        &mut self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
    ) -> Result<NativePublishResult> {
        peer.validate()
            .map_err(|_| ReconcileError::Invariant("remote apply peer invalid"))?;
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote apply signature invalid"))?;
        if peer.space_id != self.space_id || peer.device_id == self.device_id {
            return Err(ReconcileError::Invariant(
                "remote apply authorization scope differs",
            ));
        }
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote apply requires exact stored peer approval",
            ));
        }
        self.verify_root()?;
        let proof = RemotePublicationProof {
            public_key: peer.public_key,
            operation: signed.operation.clone(),
            signature: signed.signature.clone(),
        };
        let transaction_id: EntryId =
            ContentId::hash(format!("remote-native-v1:{}", signed.operation.op_id).as_bytes())
                .as_str()[..32]
                .parse()?;
        if let Some(publication) = self.journal.find_publication(&transaction_id)? {
            if publication.intent.remote.as_ref() != Some(&proof) {
                return Err(ReconcileError::Invariant(
                    "remote original transaction identity collision",
                ));
            }
            if self
                .journal
                .audit_native_publication_stage(&transaction_id)?
                == sync_extend_journal::NativePublicationStage::Cleanup
            {
                return self.native_publish_result(&transaction_id, None);
            }
            let result = self.recover_native_publications()?;
            return result
                .into_iter()
                .find(|result| result.transaction_id == transaction_id)
                .ok_or(ReconcileError::Invariant("remote recovery result missing"));
        }
        self.recover()?;
        // Capture local edits once, before selecting immutable remote history.
        self.scan_without_recovery()?;
        let baseline = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("remote applied baseline missing"))?;
        let completion = PublicationCompletion::from_remote(&baseline, &proof)?;
        let Change::Put { entry } = &signed.operation.payload.change else {
            unreachable!()
        };
        if self.occupied(&entry.path)? {
            return Err(ReconcileError::Invariant(
                "remote occupied path preserved; conflict apply unsupported",
            ));
        }
        let content = entry
            .content
            .as_ref()
            .ok_or(ReconcileError::Invariant("remote file content missing"))?;
        self.check_publication_limits(content)?;
        self.cas.verify(content)?;
        let peak = content
            .length
            .checked_mul(17)
            .and_then(|n| n.checked_add(32))
            .ok_or(ReconcileError::ResourceLimit("remote native peak overflow"))?;
        self.reserve_internal_worktree(peak)?;
        // Receiving remains distinct from application; exact existing receive is idempotent.
        self.journal.receive(&signed.operation)?;
        let intent = PublicationIntent {
            format_version: FORMAT_VERSION,
            transaction_id: transaction_id.clone(),
            space_id: self.space_id.clone(),
            entry_id: entry.entry_id.clone(),
            requested_path: entry.path.clone(),
            target_path: entry.path.clone(),
            content: content.clone(),
            baseline_root: baseline.root()?,
            requested_baseline: None,
            source_snapshot: None,
            created_at_ms: signed.operation.payload.created_at_ms,
            attempt: 0,
            root_identity: Some(physical_identity(&self.worktree)?),
            parent_identity: Some(physical_identity(&self.parent_for(&entry.path)?)?),
            completion: Some(completion),
            native_only: true,
            remote: Some(proof),
        };
        self.journal.begin_remote_native_publication(&intent)?;
        crate::fault::checkpoint("after_remote_native_selection");
        let outcome = self.create_native_pipeline(&transaction_id, peak);
        self.native_publish_result(
            &transaction_id,
            outcome.err().map(|error| error.to_string()),
        )
    }
}

impl LocalSpace {
    pub(crate) fn check_native_remote_approval(&self, id: &EntryId) -> Result<()> {
        if let Some(proof) = &self.journal.publication(id)?.intent.remote {
            proof.verify()?;
            let peer = self.read_transport_peer(&proof.operation.payload.origin_device_id)?;
            if peer.public_key != proof.public_key {
                return Err(ReconcileError::Invariant(
                    "native remote original approval changed",
                ));
            }
        }
        Ok(())
    }
}
