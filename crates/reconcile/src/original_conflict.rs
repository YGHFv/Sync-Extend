//! Complete ordinary original history, never signatures reconstructed for foreign origins.
use crate::{LocalSpace, ReconcileError, Result};
use sync_extend_core_model::conflict_resolution::ResolutionLimits;
use sync_extend_transport::{SignedFileResolution, SignedOperation};

impl LocalSpace {
    /// Sign only our exact original operations. Every foreign row requires its
    /// individually retained signature and independent current local approval.
    pub fn retained_original_conflict_bundle(
        &self,
        limits: ResolutionLimits,
    ) -> Result<Vec<SignedOperation>> {
        self.verify_root()?;
        if !self.conflict_resolution_admissions()?.is_empty() {
            return Err(ReconcileError::Invariant(
                "original conflict history already includes resolver admission",
            ));
        }
        let own = self.transport_identity()?;
        let operations = self.journal.original_conflict_operations(
            &self.space_id,
            limits.max_operations,
            limits.max_bytes,
        )?;
        let mut originals = Vec::new();
        let mut bytes = 0usize;
        for operation in operations {
            let signed = if operation.payload.origin_device_id == self.device_id {
                SignedOperation::sign(&own, operation)?
            } else {
                let peer = self.read_transport_peer(&operation.payload.origin_device_id)?;
                let proof = self
                    .journal
                    .original_provenance(
                        &self.space_id,
                        &operation.payload.origin_device_id,
                        operation.payload.origin_seq,
                    )?
                    .ok_or(ReconcileError::Invariant(
                        "original conflict foreign row lacks retained individual signature",
                    ))?;
                if proof.operation != operation || proof.public_key != peer.public_key {
                    return Err(ReconcileError::Invariant(
                        "original conflict retained proof differs",
                    ));
                }
                let signed = SignedOperation {
                    operation: proof.operation,
                    signature: proof.signature,
                };
                signed.verify(&peer)?;
                signed
            };
            bytes = bytes
                .checked_add(serde_json::to_vec(&signed)?.len())
                .filter(|n| *n <= limits.max_bytes)
                .ok_or(ReconcileError::ResourceLimit(
                    "original conflict signed bundle bytes",
                ))?;
            originals.push(signed);
        }
        originals.sort_by(|a, b| a.operation.op_id.cmp(&b.operation.op_id));
        self.verify_root()?;
        Ok(originals)
    }

    /// Pure proposal only. Exact sequence admission, protected content and whole
    /// native Final remain separate and cannot be substituted by this signature.
    pub fn sign_retained_original_file_resolution(
        &self,
        created_at_ms: u64,
        limits: ResolutionLimits,
    ) -> Result<SignedFileResolution> {
        let originals = self.retained_original_conflict_bundle(limits)?;
        self.sign_local_file_resolution(originals, created_at_ms, limits)
    }

    #[cfg(windows)]
    pub fn apply_retained_original_file_conflict(
        &mut self,
        created_at_ms: u64,
        limits: ResolutionLimits,
    ) -> Result<crate::ConflictNativeResult> {
        self.require_no_mutation()?;
        if self.original_worker_has_pending_native()? {
            return Err(ReconcileError::Invariant(
                "original conflict pending native lineage",
            ));
        }
        let signed = self.sign_retained_original_file_resolution(created_at_ms, limits)?;
        let prepared = self.prepare_signed_conflict_branches(&signed, limits)?;
        if !prepared.content_closed {
            return Err(ReconcileError::Invariant(
                "original conflict protected historical content remains missing",
            ));
        }
        let admission = self.admit_signed_file_resolution(&signed, limits)?;
        if !admission.content_closed {
            return Err(ReconcileError::Invariant(
                "original conflict admitted content remains missing",
            ));
        }
        self.apply_admitted_conflict_native(&admission.admission.transaction_id)
    }
}
