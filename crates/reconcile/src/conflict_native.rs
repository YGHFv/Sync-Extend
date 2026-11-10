//! Explicit bounded whole conflict apply; no background synchronization.
use crate::{fault::checkpoint, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use sync_extend_core_model::{conflict_resolution::ResolutionLimits, EntryId, SnapshotId};
use sync_extend_transport::SignedFileResolution;

#[derive(Serialize)]
pub struct ConflictNativeResult {
    pub transaction_id: EntryId,
    pub snapshot_id: SnapshotId,
    pub equivalent_history: bool,
    pub native_cleanup_complete: bool,
    pub receiver_sequence_reserved: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    /// Complete an explicitly admitted original conflict using private native tokens.
    pub fn apply_admitted_conflict_native(&mut self, id: &EntryId) -> Result<ConflictNativeResult> {
        self.verify_admitted_conflict_policy(id)?;
        let source: SignedFileResolution = serde_json::from_slice(&serde_json::to_vec(
            &self.journal.conflict_resolution_proof(id)?,
        )?)?;
        let peers = self.conflict_approved_peers(&source)?;
        let resolver = peers
            .iter()
            .find(|p| p.device_id == source.payload.resolver_device)
            .ok_or(ReconcileError::Invariant(
                "conflict resolver approval absent",
            ))?;
        let plan = source
            .verify(resolver, &peers, ResolutionLimits::default())
            .map_err(|_| ReconcileError::Invariant("conflict immutable native plan invalid"))?;
        let initial = crate::storage::inventory_bytes(
            &self.storage_inventory(crate::storage::Region::Worktree)?,
        )?;
        let available = self
            .limits
            .max_internal_worktree_bytes
            .checked_sub(initial)
            .filter(|n| *n != 0)
            .ok_or(ReconcileError::ResourceLimit(
                "conflict original native capacity unavailable",
            ))?;
        let admission_limits = sync_extend_journal::ConflictNativeAdmissionLimits {
            max_internal_bytes: available,
            ..Default::default()
        };
        let payload_bytes = plan
            .projected
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .try_fold(0u64, |n, file| {
                n.checked_add(file.length)
                    .ok_or(ReconcileError::ResourceLimit(
                        "conflict prebinding payload bytes",
                    ))
            })?;
        if available
            < payload_bytes
                .checked_add(32)
                .ok_or(ReconcileError::ResourceLimit(
                    "conflict prebinding marker bytes",
                ))?
        {
            return Err(ReconcileError::ResourceLimit(
                "conflict prebinding native capacity unavailable",
            ));
        }
        let baseline = self
            .journal
            .hold_conflict_native_baseline(id, Default::default())?;
        let bound = self.journal.bind_conflict_native_baseline(baseline)?;
        let admission = self
            .journal
            .admit_conflict_native_baseline(bound, admission_limits)?;
        let report = admission.report()?;
        let target_length = plan
            .projected
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .try_fold(0u64, |n, file| {
                n.checked_add(file.length)
                    .ok_or(ReconcileError::ResourceLimit(
                        "conflict target aggregate bytes",
                    ))
            })?;
        if plan.projected.entries.len() > self.limits.max_scan_entries
            || target_length > self.limits.max_scan_bytes
            || report.native_peak_bytes > available
        {
            return Err(ReconcileError::ResourceLimit(
                "conflict exact preeffect native aggregate limits",
            ));
        }
        let mut creation = self.journal.create_conflict_native_payloads(admission)?;
        checkpoint("after_conflict_native_creators");
        // The authenticated plan remains bound by the immutable original admission.
        let admissions = self
            .journal
            .conflict_resolution_admissions(&self.space_id)?;
        let receipt = admissions.iter().find(|r| &r.transaction_id == id).ok_or(
            ReconcileError::Invariant("conflict admitted receipt absent"),
        )?;
        let entries = creation.payload_entries();
        for entry in entries {
            self.cas.write_file(
                plan.projected.entries[&entry]
                    .content
                    .as_ref()
                    .ok_or(ReconcileError::Invariant("conflict payload content absent"))?,
                creation.payload_writer(&entry)?,
            )?;
        }
        let reserved = receipt.signed_sequence_reserved;
        checkpoint("after_conflict_native_payloads");
        let ready = self.journal.seal_conflict_native_payloads(creation)?;
        checkpoint("after_conflict_native_ready");
        let execution = self.journal.start_conflict_native_execution(ready)?;
        let observed = self.journal.execute_conflict_native(execution)?;
        let snapshot = self.journal.finalize_conflict_native(observed)?;
        checkpoint("after_conflict_native_final");
        self.finish_admitted_conflict_cleanup(id)?;
        self.reserve_internal_worktree(0)?;
        Ok(ConflictNativeResult {
            transaction_id: id.clone(),
            snapshot_id: snapshot,
            equivalent_history: false,
            native_cleanup_complete: true,
            receiver_sequence_reserved: reserved,
            remote_backup_complete: false,
        })
    }

    fn finish_admitted_conflict_cleanup(&mut self, id: &EntryId) -> Result<()> {
        let execution = self.journal.reopen_conflict_native_execution(id)?;
        let observed = self.journal.execute_conflict_native(execution)?;
        let observed = self.journal.handoff_conflict_native_history(observed)?;
        drop(self.journal.dispose_conflict_native_originals(observed)?);
        let execution = self.journal.reopen_conflict_native_execution(id)?;
        drop(
            self.journal
                .cleanup_conflict_native_directories(execution)?,
        );
        self.verify_root()
    }

    fn verify_admitted_conflict_policy(&self, id: &EntryId) -> Result<()> {
        self.verify_root()?;
        self.reserve_internal_worktree(0)?;
        let source: SignedFileResolution = serde_json::from_slice(&serde_json::to_vec(
            &self.journal.conflict_resolution_proof(id)?,
        )?)?;
        let approved = self.conflict_approved_peers(&source)?;
        let resolver = approved
            .iter()
            .find(|peer| peer.device_id == source.payload.resolver_device)
            .ok_or(ReconcileError::Invariant(
                "conflict recovery resolver approval absent",
            ))?;
        let plan = source
            .verify(resolver, &approved, ResolutionLimits::default())
            .map_err(|_| ReconcileError::Invariant("conflict recovery immutable approved proof"))?;
        let mut chunks = 0usize;
        let mut bytes = 0u64;
        for entry in plan.projected.entries.values() {
            let file = entry.content.as_ref().ok_or(ReconcileError::Invariant(
                "conflict recovery target file content absent",
            ))?;
            chunks = chunks
                .checked_add(file.chunks.len())
                .ok_or(ReconcileError::ResourceLimit(
                    "conflict recovery target chunk overflow",
                ))?;
            bytes = bytes
                .checked_add(file.length)
                .ok_or(ReconcileError::ResourceLimit(
                    "conflict recovery target byte overflow",
                ))?;
            if file.length > self.limits.max_file_bytes {
                return Err(ReconcileError::ResourceLimit(
                    "conflict recovery file bytes",
                ));
            }
            self.cas.verify(file)?;
        }
        if plan.projected.entries.len() > self.limits.max_scan_entries
            || chunks > self.limits.max_scan_chunks
            || bytes > self.limits.max_scan_bytes
        {
            return Err(ReconcileError::ResourceLimit(
                "conflict recovery target aggregate",
            ));
        }
        Ok(())
    }

    /// Resume only original durable Ready/forward lineage; incomplete creates are not adopted.
    pub fn recover_admitted_conflict_native(
        &mut self,
        id: &EntryId,
    ) -> Result<ConflictNativeResult> {
        self.verify_admitted_conflict_policy(id)?;
        let execution = self.journal.reopen_conflict_native_execution(id)?;
        let observed = self.journal.execute_conflict_native(execution)?;
        let snapshot = self.journal.finalize_conflict_native(observed)?;
        self.finish_admitted_conflict_cleanup(id)?;
        let receipt = self
            .journal
            .conflict_resolution_admissions(&self.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == *id)
            .ok_or(ReconcileError::Invariant(
                "conflict recovery receipt absent",
            ))?;
        self.reserve_internal_worktree(0)?;
        Ok(ConflictNativeResult {
            transaction_id: id.clone(),
            snapshot_id: snapshot,
            equivalent_history: false,
            native_cleanup_complete: true,
            receiver_sequence_reserved: receipt.signed_sequence_reserved,
            remote_backup_complete: false,
        })
    }

    pub fn accept_equivalent_conflict_history(
        &mut self,
        base: &EntryId,
        signed: &SignedFileResolution,
        limits: ResolutionLimits,
    ) -> Result<ConflictNativeResult> {
        self.verify_admitted_conflict_policy(base)?;
        if signed.payload.space_id != self.space_id
            || signed.payload.resolver_device == self.device_id
        {
            return Err(ReconcileError::Invariant(
                "equivalent conflict foreign scope",
            ));
        }
        let peers = self.conflict_approved_peers(signed)?;
        let resolver = peers
            .iter()
            .find(|p| p.device_id == signed.payload.resolver_device)
            .ok_or(ReconcileError::Invariant(
                "equivalent resolver approval absent",
            ))?;
        signed
            .verify(resolver, &peers, limits)
            .map_err(|_| ReconcileError::Invariant("equivalent signed proposal invalid"))?;
        let mut keys = peers
            .into_iter()
            .map(|p| sync_extend_journal::ConflictResolutionKey {
                device_id: p.device_id,
                public_key: p.public_key,
            })
            .collect::<Vec<_>>();
        keys.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let proof = serde_json::from_slice(&serde_json::to_vec(signed)?)?;
        let execution = self.journal.reopen_conflict_native_execution(base)?;
        let observed = self.journal.execute_conflict_native(execution)?;
        let result = self
            .journal
            .finalize_equivalent_conflict_history(observed, &proof, &keys)?;
        self.verify_root()?;
        Ok(ConflictNativeResult {
            transaction_id: result.transaction_id,
            snapshot_id: result.target_root,
            equivalent_history: true,
            native_cleanup_complete: true,
            receiver_sequence_reserved: false,
            remote_backup_complete: false,
        })
    }

    fn conflict_approved_peers(
        &self,
        signed: &SignedFileResolution,
    ) -> Result<Vec<sync_extend_transport::PeerIdentity>> {
        let devices = signed
            .payload
            .originals
            .iter()
            .map(|s| s.operation.payload.origin_device_id.clone())
            .chain(std::iter::once(signed.payload.resolver_device.clone()))
            .collect::<std::collections::BTreeSet<_>>();
        devices
            .into_iter()
            .map(|d| {
                if d == self.device_id {
                    Ok(self.transport_identity()?.peer_identity().clone())
                } else {
                    self.read_transport_peer(&d)
                }
            })
            .collect()
    }
}
