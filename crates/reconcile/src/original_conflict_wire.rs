//! Explicit complete original conflict exchange over one pinned live connection.
use crate::{LocalSpace, ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{
    conflict_resolution::ResolutionLimits, ContentId, EntryId, EntryKind, PROTOCOL_VERSION,
};
use sync_extend_transport::{
    Connection, OriginalConflictTargetReceipt, PeerIdentity, SignedFileResolution,
    SignedOriginalConflictOffer, SignedOriginalConflictTargetReceipt, SignedOriginalContentRequest,
    VerifiedOriginalContentOffer, MAX_RESOLUTION_WIRE_BYTES,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Chunks {
        request: SignedOriginalContentRequest,
    },
    Finish {
        request_id: ContentId,
    },
}

fn wire_limits() -> ResolutionLimits {
    ResolutionLimits {
        max_bytes: MAX_RESOLUTION_WIRE_BYTES,
        ..Default::default()
    }
}

impl LocalSpace {
    fn original_conflict_wire_peers(
        &self,
        signed: &SignedFileResolution,
    ) -> Result<Vec<PeerIdentity>> {
        signed
            .payload
            .originals
            .iter()
            .map(|s| s.operation.payload.origin_device_id.clone())
            .chain(std::iter::once(signed.payload.resolver_device.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|id| {
                if id == self.device_id {
                    Ok(self.transport_identity()?.peer_identity().clone())
                } else {
                    self.read_transport_peer(&id)
                }
            })
            .collect()
    }

    fn original_conflict_wire_approval(&self, connection: &Connection) -> Result<()> {
        self.verify_root()?;
        if self.read_transport_peer(&connection.peer_identity().device_id)?
            != *connection.peer_identity()
        {
            return Err(ReconcileError::Invariant(
                "conflict wire current transport approval",
            ));
        }
        Ok(())
    }

    fn original_conflict_wire_content(
        &self,
        connection: &Connection,
        signed: &SignedOriginalConflictOffer,
        source: &PeerIdentity,
        target: &PeerIdentity,
    ) -> Result<VerifiedOriginalContentOffer> {
        self.original_conflict_wire_approval(connection)?;
        let peers = self.original_conflict_wire_peers(&signed.offer.resolution)?;
        Ok(VerifiedOriginalContentOffer::from_original_conflict(
            signed,
            source,
            target,
            connection.channel_binding(),
            &peers,
            &self.limits,
        )?)
    }

    fn original_conflict_wire_native_root(&self) -> Result<sync_extend_core_model::Manifest> {
        self.require_no_mutation()?;
        self.journal.require_no_conflict_resolution()?;
        if self.original_worker_has_pending_native()? {
            return Err(ReconcileError::Invariant(
                "conflict wire pending native owners",
            ));
        }
        let manifest = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("conflict wire native baseline"))?;
        let observed = self.stable_scan()?;
        if observed.len() != manifest.entries.len() {
            return Err(ReconcileError::Invariant(
                "conflict wire whole native membership",
            ));
        }
        for entry in manifest.entries.values() {
            let actual = observed.get(&entry.path).ok_or(ReconcileError::Invariant(
                "conflict wire native entry absent",
            ))?;
            if actual.kind != entry.kind
                || actual.content != entry.content
                || (entry.kind == EntryKind::File && !actual.single_link)
            {
                return Err(ReconcileError::Invariant(
                    "conflict wire native content or alias",
                ));
            }
            if let Some(file) = &entry.content {
                self.cas.verify(file)?;
            }
        }
        if crate::scan::scan(&self.worktree, &self.cas, &self.limits)? != observed
            || self.manifest()?.as_ref() != Some(&manifest)
        {
            return Err(ReconcileError::Unstable);
        }
        self.verify_root()?;
        Ok(manifest)
    }

    /// Only an exact already-complete own resolver admission can be exported.
    pub async fn serve_original_conflict_resolution(
        &self,
        connection: &mut Connection,
        transaction: &EntryId,
    ) -> Result<SignedOriginalConflictTargetReceipt> {
        self.original_conflict_wire_native_root()?;
        let resolution: SignedFileResolution = serde_json::from_value(serde_json::to_value(
            self.journal.conflict_resolution_proof(transaction)?,
        )?)?;
        let identity = self.transport_identity()?;
        let signed = SignedOriginalConflictOffer::sign(
            &identity,
            connection.peer_identity(),
            connection.channel_binding(),
            resolution,
        )?;
        let offer = self.original_conflict_wire_content(
            connection,
            &signed,
            identity.peer_identity(),
            connection.peer_identity(),
        )?;
        let _session = self.cas.acquire_session()?;
        for file in offer.files() {
            self.cas.verify(file)?;
        }
        connection.send_json(&signed).await?;
        let mut requested = BTreeSet::new();
        for _ in 0..2 {
            match connection.receive_json::<Control>().await? {
                Control::Chunks { request } => {
                    request.verify(connection.peer_identity(), &offer)?;
                    for chunk in &request.request.chunks {
                        self.original_conflict_wire_content(
                            connection,
                            &signed,
                            identity.peer_identity(),
                            connection.peer_identity(),
                        )?;
                        if !requested.insert(chunk.content_id.clone()) {
                            return Err(ReconcileError::Invariant(
                                "conflict wire duplicate request",
                            ));
                        }
                        connection
                            .send_block(&chunk.content_id, &self.cas.read(chunk)?)
                            .await?;
                    }
                }
                Control::Finish { request_id } if request_id == signed.request_id()? => {
                    connection.send_json(&request_id).await?;
                    let receipt: SignedOriginalConflictTargetReceipt =
                        connection.receive_json_after_application().await?;
                    self.original_conflict_wire_approval(connection)?;
                    receipt.verify(connection.peer_identity(), &signed)?;
                    connection.send_json(&request_id).await?;
                    return Ok(receipt);
                }
                _ => {
                    return Err(ReconcileError::Invariant(
                        "conflict wire finish request differs",
                    ))
                }
            }
        }
        Err(ReconcileError::ResourceLimit(
            "conflict wire control attempts",
        ))
    }

    /// Foreign signatures are admitted unchanged. Metadata never independently
    /// applies resolver operations; the existing whole conflict Final does so.
    pub async fn pull_original_conflict_resolution(
        &mut self,
        connection: &mut Connection,
    ) -> Result<SignedOriginalConflictTargetReceipt> {
        let signed: SignedOriginalConflictOffer = connection.receive_json().await?;
        let identity = self.transport_identity()?;
        let source = connection.peer_identity().clone();
        let offer = self.original_conflict_wire_content(
            connection,
            &signed,
            &source,
            identity.peer_identity(),
        )?;
        let resolution = &signed.offer.resolution;
        let mut matching = None;
        let mut equivalent = None;
        for admission in self.conflict_resolution_admissions()? {
            let stored: SignedFileResolution = serde_json::from_value(serde_json::to_value(
                self.journal
                    .conflict_resolution_proof(&admission.transaction_id)?,
            )?)?;
            if stored == *resolution {
                matching = Some(admission.transaction_id);
            } else if admission.resolution_applied
                && stored.payload.originals == resolution.payload.originals
                && stored.payload.plan_fingerprint == resolution.payload.plan_fingerprint
            {
                let peers = self.original_conflict_wire_peers(resolution)?;
                sync_extend_transport::verify_equivalent_file_resolutions(
                    &[stored, resolution.clone()],
                    &peers,
                    wire_limits(),
                )?;
                equivalent = Some(admission.transaction_id);
            }
        }
        if matching.is_some() {
            equivalent = None;
        }
        if matching.is_none() && equivalent.is_none() {
            let originals = self.retained_original_conflict_bundle(wire_limits())?;
            if originals != resolution.payload.originals {
                return Err(ReconcileError::Invariant(
                    "conflict wire complete retained original bundle differs",
                ));
            }
        }
        let restart = matching.is_some();
        let id = if let Some(id) = matching {
            id
        } else if let Some(id) = equivalent.as_ref() {
            id.clone()
        } else {
            self.admit_foreign_signed_file_resolution(resolution, wire_limits())?
                .admission
                .transaction_id
        };
        let prepared = self.prepare_signed_conflict_branches(resolution, wire_limits())?;
        if !prepared.missing_chunks.is_empty() {
            let request = SignedOriginalContentRequest::sign(
                &identity,
                &offer,
                offer.request(prepared.missing_chunks.clone())?,
            )?;
            connection
                .send_json(&Control::Chunks {
                    request: request.clone(),
                })
                .await?;
            for chunk in &request.request.chunks {
                let bytes = connection
                    .receive_block(&chunk.content_id, chunk.length)
                    .await?;
                self.original_conflict_wire_content(
                    connection,
                    &signed,
                    &source,
                    identity.peer_identity(),
                )?;
                request.verify_block(
                    identity.peer_identity(),
                    &offer,
                    &chunk.content_id,
                    &bytes,
                )?;
                let current = self.prepare_signed_conflict_branches(resolution, wire_limits())?;
                let (guard, ()) = self.journal.with_reserved_chunk(
                    &self.space_id,
                    &current.reservation.intent.owner_id,
                    &chunk.content_id,
                    self.limits.max_storage_entries,
                    |expected| -> Result<()> {
                        if expected != chunk {
                            return Err(ReconcileError::Invariant(
                                "conflict wire reserved block differs",
                            ));
                        }
                        if self.cas.put(&bytes)? != *chunk {
                            return Err(ReconcileError::Invariant(
                                "conflict wire CAS block differs",
                            ));
                        }
                        self.cas.read(chunk)?;
                        Ok(())
                    },
                )?;
                drop(guard);
            }
        }
        if !self
            .prepare_signed_conflict_branches(resolution, wire_limits())?
            .content_closed
        {
            return Err(ReconcileError::Invariant(
                "conflict wire whole content remains missing",
            ));
        }
        let request_id = signed.request_id()?;
        connection
            .send_json(&Control::Finish {
                request_id: request_id.clone(),
            })
            .await?;
        if connection.receive_json::<ContentId>().await? != request_id {
            return Err(ReconcileError::Invariant(
                "conflict wire content finish differs",
            ));
        }
        self.original_conflict_wire_content(
            connection,
            &signed,
            &source,
            identity.peer_identity(),
        )?;
        if let Some(base) = equivalent {
            self.accept_equivalent_conflict_history(&base, resolution, wire_limits())?;
        } else {
            let admission = self
                .conflict_resolution_admissions()?
                .into_iter()
                .find(|r| r.transaction_id == id)
                .ok_or(ReconcileError::Invariant(
                    "conflict wire admitted receipt absent",
                ))?;
            if restart || admission.resolution_applied {
                self.recover_admitted_conflict_native(&id)?;
            } else {
                self.apply_admitted_conflict_native(&id)?;
            }
        }
        let manifest = self.original_conflict_wire_native_root()?;
        let mut received = manifest.version_vector.clone();
        for original in resolution
            .payload
            .originals
            .iter()
            .chain(&resolution.payload.resolving)
        {
            let payload = &original.operation.payload;
            let cursor = self
                .journal
                .cursor(&self.space_id, &payload.origin_device_id)?;
            if cursor < payload.origin_seq || cursor < received.get(&payload.origin_device_id) {
                return Err(ReconcileError::Invariant(
                    "conflict wire actual received frontier differs",
                ));
            }
            received.observe(payload.origin_device_id.clone(), cursor);
        }
        let receipt = SignedOriginalConflictTargetReceipt::sign(
            &identity,
            OriginalConflictTargetReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.space_id.clone(),
                device_id: self.device_id.clone(),
                source_device: source.device_id.clone(),
                channel_binding: connection.channel_binding().clone(),
                request_id: request_id.clone(),
                resolution_fingerprint: resolution.payload.plan_fingerprint.clone(),
                received_vector: received,
                applied_snapshot: manifest.root()?,
                applied_vector: manifest.version_vector,
            },
        )?;
        receipt.verify(identity.peer_identity(), &signed)?;
        self.original_conflict_wire_approval(connection)?;
        connection.send_json(&receipt).await?;
        if connection.receive_json::<ContentId>().await? != request_id {
            return Err(ReconcileError::Invariant(
                "conflict wire receipt acknowledgement differs",
            ));
        }
        Ok(receipt)
    }
}
