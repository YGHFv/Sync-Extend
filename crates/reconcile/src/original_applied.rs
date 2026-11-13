//! Fresh complete native observation before a target-only applied page receipt.
#[cfg(windows)]
use crate::{fault::checkpoint, scan, LocalSpace, ReconcileError, Result};
#[cfg(windows)]
use sync_extend_core_model::{ContentId, EntryKind, PROTOCOL_VERSION};
#[cfg(windows)]
use sync_extend_transport::{OriginalPageAppliedReceipt, SignedOriginalPageAppliedReceipt};

#[cfg(windows)]
impl LocalSpace {
    pub fn original_applied_receipt(
        &self,
        request: &ContentId,
    ) -> Result<SignedOriginalPageAppliedReceipt> {
        let envelope = self
            .original_content_inbox(self.limits.max_storage_entries)?
            .into_iter()
            .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(request))
            .ok_or(ReconcileError::Invariant("original applied inbox absent"))?;
        let manifest = self.observe_original_native_applied(
            &envelope.source,
            &envelope.signed_page.page.operations,
        )?;
        let root = manifest.root()?;
        let identity = self.transport_identity()?;
        let page = &envelope.signed_page.page;
        let receipt = SignedOriginalPageAppliedReceipt::sign(
            &identity,
            OriginalPageAppliedReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                device_id: self.device_id.clone(),
                origin_device: page.origin_device.clone(),
                channel_binding: page.channel_binding.clone(),
                request_id: request.clone(),
                last_offered_sequence: page
                    .operations
                    .last()
                    .ok_or(ReconcileError::Invariant("original applied empty page"))?
                    .operation
                    .payload
                    .origin_seq,
                applied_snapshot: root,
                applied_vector: manifest.version_vector,
            },
        )
        .map_err(|_| ReconcileError::Invariant("original actual target applied signing"))?;
        receipt
            .verify(identity.peer_identity(), page)
            .map_err(|_| ReconcileError::Invariant("original applied target post-sign verify"))?;
        Ok(receipt)
    }

    pub(crate) fn observe_original_native_applied(
        &self,
        source: &sync_extend_transport::PeerIdentity,
        operations: &[sync_extend_transport::SignedOperation],
    ) -> Result<sync_extend_core_model::Manifest> {
        self.verify_root()?;
        if operations.is_empty() || self.read_transport_peer(&source.device_id)? != *source {
            return Err(ReconcileError::Invariant(
                "actual applied current original approval",
            ));
        }
        self.require_no_mutation()?;
        if !self
            .journal
            .outstanding_publications(&self.space_id)?
            .is_empty()
        {
            return Err(ReconcileError::Invariant(
                "original applied pending native lineage",
            ));
        }
        let manifest = self.manifest()?.ok_or(ReconcileError::Invariant(
            "original applied snapshot absent",
        ))?;
        for signed in operations {
            if self
                .replay_signed_remote_operation(source, signed)?
                .disposition
                != sync_extend_journal::RemoteReplayDisposition::AlreadyApplied
            {
                return Err(ReconcileError::Invariant("original page not fully applied"));
            }
        }
        let observed = self.stable_scan()?;
        if observed.len() != manifest.entries.len() {
            return Err(ReconcileError::Invariant(
                "original applied whole native membership differs",
            ));
        }
        for entry in manifest.entries.values() {
            let actual = observed.get(&entry.path).ok_or(ReconcileError::Invariant(
                "original applied native entry absent",
            ))?;
            if actual.kind != entry.kind
                || actual.content != entry.content
                || (entry.kind == EntryKind::File && !actual.single_link)
            {
                return Err(ReconcileError::Invariant(
                    "original applied native content or alias differs",
                ));
            }
            if let Some(file) = &entry.content {
                self.cas.verify(file)?;
            }
        }
        checkpoint("before_original_applied_receipt");
        let last = scan::scan(&self.worktree, &self.cas, &self.limits)?;
        if last != observed
            || self.manifest()?.as_ref() != Some(&manifest)
            || self.read_transport_peer(&source.device_id)? != *source
        {
            return Err(ReconcileError::Unstable);
        }
        self.verify_root()?;
        Ok(manifest)
    }

    pub fn forwarded_applied_receipt(
        &self,
        request: &ContentId,
    ) -> Result<SignedOriginalPageAppliedReceipt> {
        let envelope = self
            .forwarded_content_inbox(self.limits.max_storage_entries)?
            .into_iter()
            .find(|e| e.signed_page.page.request_id().ok().as_ref() == Some(request))
            .ok_or(ReconcileError::Invariant(
                "forwarded applied exact inbox absent",
            ))?;
        let page = &envelope.signed_page.page;
        let manifest = self.observe_original_native_applied(&envelope.origin, &page.operations)?;
        if self.read_transport_peer(&envelope.forwarder.device_id)? != envelope.forwarder {
            return Err(ReconcileError::Invariant(
                "forwarded applied current channel peer revoked",
            ));
        }
        self.verify_root()?;
        let identity = self.transport_identity()?;
        let receipt = SignedOriginalPageAppliedReceipt::sign(
            &identity,
            OriginalPageAppliedReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                device_id: self.device_id.clone(),
                origin_device: page.origin_device.clone(),
                channel_binding: page.channel_binding.clone(),
                request_id: request.clone(),
                last_offered_sequence: page
                    .operations
                    .last()
                    .ok_or(ReconcileError::Invariant("forwarded applied empty page"))?
                    .operation
                    .payload
                    .origin_seq,
                applied_snapshot: manifest.root()?,
                applied_vector: manifest.version_vector,
            },
        )
        .map_err(|_| ReconcileError::Invariant("forwarded actual target applied signing"))?;
        receipt
            .verify_forwarded(identity.peer_identity(), page)
            .map_err(|_| ReconcileError::Invariant("forwarded applied target post-sign verify"))?;
        Ok(receipt)
    }
}
