//! Durable expected conflict content only; no resolution/native or release grant.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    conflict_resolution::ResolutionLimits,
    reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope},
    Change, ChunkRef, ContentId, EntryId, FORMAT_VERSION,
};
use sync_extend_journal::{
    ConflictResolutionProof, ReferenceReservation, ReferenceReservationIntent,
};
use sync_extend_transport::{PeerIdentity, SignedFileResolution};

#[derive(Serialize)]
pub struct ConflictBranchPreparation {
    pub plan_fingerprint: ContentId,
    pub reservation: Option<ReferenceReservation>,
    pub native_transaction_id: Option<EntryId>,
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

    /// All keys are taken from exact local approvals. Missing original and
    /// resolving content stays pinned under one canonical owner across retries.
    /// This neither stores signed history nor reserves the resolver's sequence.
    pub fn prepare_signed_conflict_branches(
        &mut self,
        signed: &SignedFileResolution,
        limits: ResolutionLimits,
    ) -> Result<ConflictBranchPreparation> {
        self.prepare_signed_conflict_branches_for_native(signed, limits, None)
    }

    pub(crate) fn prepare_signed_conflict_branches_for_native(
        &mut self,
        signed: &SignedFileResolution,
        limits: ResolutionLimits,
        native_transaction: Option<&EntryId>,
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
        // v1 protected only projected branch files. A separate owner preserves
        // any persisted v1 intent; verified retries reuse the exact v2 scope.
        let owner: EntryId = ContentId::hash(
            format!("SyncExtend canonical conflict branch owner v2:{fingerprint}").as_bytes(),
        )
        .as_str()[..32]
            .parse()?;
        let mut files = BTreeMap::new();
        let mut chunks = BTreeMap::new();
        // Native Final checks every admitted original, including content that
        // the projection superseded. Request and reserve that complete set.
        for original in signed
            .payload
            .originals
            .iter()
            .chain(&signed.payload.resolving)
        {
            let Change::Put { entry } = &original.operation.payload.change else {
                continue;
            };
            let Some(file) = &entry.content else {
                continue;
            };
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
        intent.scope.validate()?;
        let mut file_bytes = 0u64;
        let mut file_chunks = 0usize;
        for file in &intent.scope.files {
            file_bytes = file_bytes
                .checked_add(file.length)
                .filter(|bytes| *bytes <= self.limits.max_scan_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "conflict branch complete content logical bytes",
                ))?;
            file_chunks = file_chunks
                .checked_add(file.chunks.len())
                .filter(|count| *count <= self.limits.max_scan_chunks)
                .ok_or(ReconcileError::ResourceLimit(
                    "conflict branch complete content chunk inventory",
                ))?;
            if file.length > self.limits.max_file_bytes {
                return Err(ReconcileError::ResourceLimit(
                    "conflict branch complete content file size",
                ));
            }
        }
        if intent.scope.files.len() > self.limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit(
                "conflict branch complete content file inventory",
            ));
        }
        let proof: ConflictResolutionProof = serde_json::from_slice(&serde_json::to_vec(signed)?)?;
        let native_transaction = if let Some(transaction) = native_transaction {
            Some(transaction.clone())
        } else {
            let mut matching = None;
            let mut equivalent = None;
            for admission in self.conflict_resolution_admissions()? {
                if admission.plan_fingerprint != fingerprint {
                    continue;
                }
                let stored = self
                    .journal
                    .conflict_resolution_proof(&admission.transaction_id)?;
                if stored == proof {
                    matching = Some(admission.transaction_id);
                } else if stored.payload.originals == proof.payload.originals {
                    equivalent = Some(admission.transaction_id);
                }
            }
            matching.or(equivalent)
        };
        let (_native_guard, frozen) = if let Some(transaction) = &native_transaction {
            let (guard, frozen) = self.journal.conflict_native_branch_preparation(
                &self.space_id,
                transaction,
                &proof,
                self.limits.max_storage_entries,
            )?;
            (Some(guard), frozen)
        } else {
            (None, None)
        };
        let _session = self.cas.acquire_session()?;
        if let Some((admission, _)) = &frozen {
            // A sealed header cannot gain another future handoff. Check the
            // original complete scope before creating any supplementary owner.
            if admission
                .protected_chunks
                .iter()
                .chain(chunks.values())
                .any(|chunk| self.cas.read(chunk).is_err())
            {
                return Err(ReconcileError::Invariant(
                    "conflict branch immutable Native scope original content incomplete",
                ));
            }
        }
        checkpoint("before_conflict_branch_reservation");
        let (reservation, native_transaction_id) = if let Some((admission, reservation)) = frozen {
            (reservation, Some(admission.transaction_id))
        } else {
            (Some(self.reserve_content(&intent)?), None)
        };
        checkpoint("after_conflict_branch_reservation");
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
            native_transaction_id,
            missing_chunks,
            content_closed,
            signed_sequence_reserved: false,
            resolution_applied: false,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }
}
