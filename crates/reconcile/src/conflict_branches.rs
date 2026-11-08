//! Durable expected conflict content only; no resolution/native or release grant.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    conflict_resolution::ResolutionLimits,
    reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope},
    ChunkRef, ContentId, EntryId, FORMAT_VERSION,
};
use sync_extend_journal::{ReferenceReservation, ReferenceReservationIntent};
use sync_extend_transport::{PeerIdentity, SignedFileResolution};

#[derive(Serialize)]
pub struct ConflictBranchPreparation {
    pub plan_fingerprint: ContentId,
    pub reservation: ReferenceReservation,
    pub protected_files: usize,
    pub missing_chunks: Vec<ChunkRef>,
    pub content_closed: bool,
    pub signed_sequence_reserved: bool,
    pub resolution_applied: bool,
    pub worktree_materialized: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    fn conflict_branch_peer(
        &self,
        device: &sync_extend_core_model::DeviceId,
    ) -> Result<PeerIdentity> {
        if *device == self.device_id {
            Ok(self.transport_identity()?.peer_identity().clone())
        } else {
            self.read_transport_peer(device)
        }
    }

    /// All keys are taken from exact local approvals. Missing content remains
    /// pinned; retries and independent resolvers reuse the same canonical owner.
    /// This neither stores signed history nor reserves the resolver's sequence.
    pub fn prepare_signed_conflict_branches(
        &mut self,
        signed: &SignedFileResolution,
        limits: ResolutionLimits,
    ) -> Result<ConflictBranchPreparation> {
        self.verify_root()?;
        if signed.payload.space_id != self.space_id
            || signed.payload.originals.len() > limits.max_operations
            || signed.payload.originals.len() > 10_000
            || serde_json::to_vec(signed)?.len()
                > limits
                    .max_bytes
                    .min(sync_extend_core_model::conflict_resolution::MAX_RESOLUTION_BYTES)
        {
            return Err(ReconcileError::Invariant(
                "conflict branch local scope or budget",
            ));
        }
        let resolver = self.conflict_branch_peer(&signed.payload.resolver_device)?;
        let origins: BTreeSet<_> = signed
            .payload
            .originals
            .iter()
            .map(|s| s.operation.payload.origin_device_id.clone())
            .collect();
        let approved = origins
            .iter()
            .map(|device| self.conflict_branch_peer(device))
            .collect::<Result<Vec<_>>>()?;
        let plan = signed
            .verify(&resolver, &approved, limits)
            .map_err(|_| ReconcileError::Invariant("conflict branch signed proposal invalid"))?;
        let fingerprint = plan.fingerprint()?;
        let owner: EntryId = ContentId::hash(
            format!("SyncExtend canonical conflict branch owner v1:{fingerprint}").as_bytes(),
        )
        .as_str()[..32]
            .parse()?;
        let mut files = BTreeMap::new();
        let mut chunks = BTreeMap::new();
        for selected in &plan.files {
            let file = selected
                .entry
                .content
                .as_ref()
                .ok_or(ReconcileError::Invariant(
                    "conflict branch file content absent",
                ))?;
            files
                .entry(serde_json::to_vec(file)?)
                .or_insert_with(|| file.clone());
            for chunk in &file.chunks {
                if chunks
                    .insert(chunk.content_id.clone(), chunk.clone())
                    .is_some_and(|old| old != *chunk)
                {
                    return Err(ReconcileError::Invariant(
                        "conflict branch chunk description differs",
                    ));
                }
            }
        }
        let intent = ReferenceReservationIntent {
            owner_id: owner,
            scope: ReferenceOwnerScope {
                format_version: FORMAT_VERSION,
                space_id: self.space_id.clone(),
                kind: ReferenceOwnerKind::Conflict,
                target_device: None,
                files: files.into_values().collect(),
            },
            // Metadata time is not resolver authority. Stable zero prevents an
            // independently issued proposal changing an exact existing owner.
            created_at_ms: 0,
        };
        checkpoint("before_conflict_branch_reservation");
        let reservation = self.reserve_content(&intent)?;
        checkpoint("after_conflict_branch_reservation");
        let _session = self.cas.acquire_session()?;
        let missing_chunks = chunks
            .into_values()
            .filter(|chunk| self.cas.read(chunk).is_err())
            .collect::<Vec<_>>();
        let content_closed = missing_chunks.is_empty();
        if content_closed {
            for file in &intent.scope.files {
                self.cas.verify(file)?;
            }
        }
        self.verify_root()?;
        Ok(ConflictBranchPreparation {
            plan_fingerprint: fingerprint,
            protected_files: intent.scope.files.len(),
            reservation,
            missing_chunks,
            content_closed,
            signed_sequence_reserved: false,
            resolution_applied: false,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }
}
