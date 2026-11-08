//! Exact signed local prospective owner only; no native application or release.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{conflict_resolution::ResolutionLimits, ChunkRef, DeviceId};
use sync_extend_journal::{
    ConflictResolutionAdmission, ConflictResolutionAdmissionIntent, ConflictResolutionKey,
    ConflictResolutionProof,
};
use sync_extend_transport::{PeerIdentity, SignedFileResolution, SignedOperation};

#[derive(Serialize)]
pub struct LocalConflictAdmission {
    pub admission: ConflictResolutionAdmission,
    pub missing_chunks: Vec<ChunkRef>,
    pub content_closed: bool,
    pub resolution_applied: bool,
    pub worktree_materialized: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    fn conflict_admission_peer(&self, device: &DeviceId) -> Result<PeerIdentity> {
        if *device == self.device_id {
            Ok(self.transport_identity()?.peer_identity().clone())
        } else {
            self.read_transport_peer(device)
        }
    }

    /// Sign without consuming sequence. Admission must immediately bind the
    /// complete original bundle; the resulting proposal alone is not a writer.
    pub fn sign_local_file_resolution(
        &self,
        originals: Vec<SignedOperation>,
        created_at_ms: u64,
        limits: ResolutionLimits,
    ) -> Result<SignedFileResolution> {
        self.verify_root()?;
        let origins: BTreeSet<_> = originals
            .iter()
            .map(|s| s.operation.payload.origin_device_id.clone())
            .collect();
        let approved = origins
            .iter()
            .map(|d| self.conflict_admission_peer(d))
            .collect::<Result<Vec<_>>>()?;
        SignedFileResolution::sign(
            &self.transport_identity()?,
            originals,
            &approved,
            created_at_ms,
            limits,
        )
        .map_err(|_| ReconcileError::Invariant("local conflict proposal cannot be signed"))
    }

    pub fn conflict_resolution_admissions(&self) -> Result<Vec<ConflictResolutionAdmission>> {
        self.verify_root()?;
        let admissions = self
            .journal
            .conflict_resolution_admissions(&self.space_id)?;
        self.verify_root()?;
        Ok(admissions)
    }

    /// Local-origin only, all original signatures retained exactly. Missing
    /// historical bytes remain pinned and are not falsely marked verified.
    pub fn admit_signed_file_resolution(
        &mut self,
        signed: &SignedFileResolution,
        limits: ResolutionLimits,
    ) -> Result<LocalConflictAdmission> {
        self.verify_root()?;
        if signed.payload.space_id != self.space_id
            || signed.payload.resolver_device != self.device_id
            || serde_json::to_vec(signed)?.len() > limits.max_bytes.min(16 * 1024 * 1024)
        {
            return Err(ReconcileError::Invariant(
                "conflict admission local resolver/scope/budget",
            ));
        }
        let origins: BTreeSet<_> = signed
            .payload
            .originals
            .iter()
            .map(|s| s.operation.payload.origin_device_id.clone())
            .collect();
        let approved = origins
            .iter()
            .map(|d| self.conflict_admission_peer(d))
            .collect::<Result<Vec<_>>>()?;
        let resolver = self.transport_identity()?.peer_identity().clone();
        signed
            .verify(&resolver, &approved, limits)
            .map_err(|_| ReconcileError::Invariant("conflict admission signed proposal invalid"))?;
        let mut keys = BTreeMap::new();
        for peer in approved.iter().chain(std::iter::once(&resolver)) {
            keys.insert(
                peer.device_id.clone(),
                ConflictResolutionKey {
                    device_id: peer.device_id.clone(),
                    public_key: peer.public_key,
                },
            );
        }
        // Journal avoids a transport dependency while retaining the exact same
        // signed payload/domain. Its independent verifier recomputes the plan.
        let proof: ConflictResolutionProof = serde_json::from_slice(&serde_json::to_vec(signed)?)?;
        let baseline = self
            .journal
            .current(&self.space_id)?
            .ok_or(ReconcileError::Invariant(
                "conflict admission requires applied baseline",
            ))?;
        let mut chunk_count = 0usize;
        for signed in signed
            .payload
            .originals
            .iter()
            .chain(&signed.payload.resolving)
        {
            if let sync_extend_core_model::Change::Put { entry } = &signed.operation.payload.change
            {
                if let Some(file) = &entry.content {
                    chunk_count = chunk_count
                        .checked_add(file.chunks.len())
                        .ok_or(ReconcileError::ResourceLimit("conflict admission chunks"))?;
                    if file.length > self.limits.max_file_bytes
                        || chunk_count > self.limits.max_scan_chunks
                    {
                        return Err(ReconcileError::ResourceLimit(
                            "conflict admission content inventory",
                        ));
                    }
                }
            }
        }
        if signed.payload.resolving.len() > self.limits.max_scan_entries {
            return Err(ReconcileError::ResourceLimit(
                "conflict admission projected files",
            ));
        }
        let intent = ConflictResolutionAdmissionIntent {
            proof,
            approved_keys: keys.into_values().collect(),
            baseline,
            worktree: self
                .worktree
                .to_str()
                .ok_or(ReconcileError::Invariant("conflict worktree UTF8"))?
                .to_string(),
            root_identity: self.root_identity.physical.clone(),
        };
        checkpoint("before_conflict_resolution_admission");
        let (_guard, missing, admission) = self.journal.with_conflict_resolution_admission(
            &intent,
            |receipt| -> Result<Vec<ChunkRef>> {
                self.verify_root()?;
                checkpoint("inside_conflict_resolution_admission");
                let missing: Vec<_> = receipt
                    .protected_chunks
                    .iter()
                    .filter(|chunk| self.cas.read(chunk).is_err())
                    .cloned()
                    .collect();
                if missing.is_empty() {
                    let files = signed
                        .payload
                        .originals
                        .iter()
                        .filter_map(|s| match &s.operation.payload.change {
                            sync_extend_core_model::Change::Put { entry } => entry.content.as_ref(),
                            _ => None,
                        })
                        .chain(signed.payload.resolving.iter().filter_map(|s| {
                            match &s.operation.payload.change {
                                sync_extend_core_model::Change::Put { entry } => {
                                    entry.content.as_ref()
                                }
                                _ => None,
                            }
                        }));
                    for file in files {
                        self.cas.verify(file)?;
                    }
                }
                self.verify_root()?;
                Ok(missing)
            },
        )?;
        checkpoint("after_conflict_resolution_admission");
        self.verify_root()?;
        Ok(LocalConflictAdmission {
            content_closed: missing.is_empty(),
            admission,
            missing_chunks: missing,
            resolution_applied: false,
            worktree_materialized: false,
            remote_backup_complete: false,
        })
    }
}
