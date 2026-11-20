//! Exact pre-effect local history plan; native ownership must be supplied separately.
use crate::{LocalSpace, ReconcileError, Result, ScanResult};
use sync_extend_core_model::{
    ContentId, EntryKind, FileManifest, Manifest, Operation, PortablePath, SnapshotId,
};
use sync_extend_journal::OriginalReservedHistoryCommitReceipt;

/// One live LocalSpace attempt. No Clone, Deserialize or public constructor.
pub struct PlannedLocalCreateHistory<'a> {
    local: &'a mut LocalSpace,
    prior: Manifest,
    planned: Manifest,
    operations: Vec<Operation>,
    path: PortablePath,
    content: FileManifest,
    timestamp: u64,
    reservation: sync_extend_journal::OriginalLocalHistoryReservation,
}

impl LocalSpace {
    /// Import source into outside CAS and compute the original full planner
    /// result before creating any target object. This grants no native rights.
    pub fn plan_local_file_create_history<'a>(
        &'a mut self,
        source: &std::path::Path,
        path: PortablePath,
    ) -> Result<PlannedLocalCreateHistory<'a>> {
        self.plan_local_file_native_history_impl(source, path, false)
    }

    #[cfg(target_os = "linux")]
    pub fn plan_local_file_native_history<'a>(
        &'a mut self,
        source: &std::path::Path,
        path: PortablePath,
    ) -> Result<PlannedLocalCreateHistory<'a>> {
        self.plan_local_file_native_history_impl(source, path, true)
    }

    fn plan_local_file_native_history_impl<'a>(
        &'a mut self,
        source: &std::path::Path,
        path: PortablePath,
        allow_replacement: bool,
    ) -> Result<PlannedLocalCreateHistory<'a>> {
        #[cfg(target_os = "linux")]
        let acquired_native = allow_replacement && self.linux_namespace.is_some();
        #[cfg(not(target_os = "linux"))]
        let acquired_native = false;
        if acquired_native {
            // Preparing the acquired native attempt may not run legacy worktree
            // recovery while no original helper has started. Refuse that work.
            self.require_no_mutation()?;
            if !self.journal.outstanding_publications(&self.space_id)?.is_empty() {
                return Err(ReconcileError::Invariant("native planning requires explicit legacy publication recovery first"));
            }
        } else {
            self.recover()?;
        }
        self.require_no_mutation()?;
        self.verify_root()?;
        let prior = self.manifest()?.ok_or(ReconcileError::Invariant(
            "pre-effect original baseline required",
        ))?;
        let first = self.stable_scan()?;
        let existing = crate::build_manifest(&prior, &first, &Default::default())?;
        let replaced = prior.entries.values().find(|entry| entry.path == path);
        let replacement = allow_replacement && replaced.is_some();
        if existing != prior
            || first.keys().any(|present| {
                present.collision_key() == path.collision_key()
                    && (!replacement || present != &path)
            })
            || (!replacement && self.occupied(&path)?)
            || replaced.is_some_and(|entry| entry.kind != EntryKind::File)
            || path
                .as_str()
                .split('/')
                .any(|component| component.starts_with('.'))
        {
            return Err(ReconcileError::Invariant(
                "pre-effect baseline or exact absent path differs",
            ));
        }
        let parent = self.parent_for(&path)?;
        if std::fs::symlink_metadata(&parent)?.file_type().is_symlink() {
            return Err(ReconcileError::Invariant(
                "pre-effect original parent required",
            ));
        }
        let content = self.import_source(source)?;
        self.check_publication_limits(&content)?;
        if let Some(original) = replaced.and_then(|entry| entry.content.as_ref()) {
            if !replacement || original == &content {
                return Err(ReconcileError::Invariant(
                    "native replacement must change one original file",
                ));
            }
            self.cas.verify(original)?;
            if original
                .length
                .checked_add(content.length)
                .is_none_or(|bytes| bytes > self.limits.max_staging_bytes)
            {
                return Err(ReconcileError::ResourceLimit(
                    "native replacement retained and staged bytes",
                ));
            }
        }
        let timestamp = crate::now_ms()?;
        let mut projected = first;
        projected.insert(
            path.clone(),
            crate::scan::ScannedEntry {
                kind: EntryKind::File,
                content: Some(content.clone()),
                // The planner does not mint native identity for a future file.
                // Actual physical identity is acquired from the held CREATE later.
                physical_identity: ContentId::hash(b"planned-entry-no-native-identity"),
                single_link: true,
            },
        );
        let mut planned = crate::build_manifest(&prior, &projected, &Default::default())?;
        let operations = self.original_local_history_operations(&prior, &mut planned, timestamp)?;
        if operations.len() != 1 {
            return Err(ReconcileError::Invariant(
                "explicit single CREATE changed another original planner entry",
            ));
        }
        #[cfg(target_os = "linux")]
        if acquired_native {
            // Reject a plan that cannot fit before persisting an active
            // reservation. SQLite's own capacity is checked separately.
            let footprint = sync_extend_journal::OriginalNativeCreateFootprint::plan_linux(
                &prior,
                &planned,
                &path,
                replacement,
            )?;
            self.reserve_internal_worktree(footprint.native_peak_bytes)?;
        }
        let prospective_observations = self.scan_observations(&planned, &projected)?;
        self.journal.preflight_local_history_capacity(
            Some(&prior.root()?),
            &planned,
            &operations,
            timestamp,
            &prospective_observations,
            self.limits.max_storage_entries,
        )?;
        let reserve = if replacement {
            sync_extend_journal::Journal::reserve_original_local_history_replacement
        } else if allow_replacement {
            sync_extend_journal::Journal::reserve_original_local_history_native_create
        } else {
            sync_extend_journal::Journal::reserve_original_local_history
        };
        let reservation = reserve(
            &mut self.journal,
            &prior,
            &planned,
            &operations,
            timestamp,
            &prospective_observations,
            &path,
            self.limits.max_storage_entries,
        )?;
        Ok(PlannedLocalCreateHistory {
            local: self,
            prior,
            planned,
            operations,
            path,
            content,
            timestamp,
            reservation,
        })
    }
}

impl PlannedLocalCreateHistory<'_> {
    pub fn prior_manifest(&self) -> &Manifest {
        &self.prior
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn write_original_planned_payload(
        &self,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.local.cas.write_file(&self.content, output)?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn write_original_prior_payload(
        &self,
        content: &FileManifest,
        output: &mut impl std::io::Write,
    ) -> Result<()> {
        self.local.cas.verify(content)?;
        self.local.cas.write_file(content, output)?;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub fn verify_original_live_phase_prefix(&self) -> Result<()> {
        Ok(self
            .local
            .journal
            .verify_original_live_native_phase_prefix(&self.reservation)?)
    }

    #[cfg(target_os = "linux")]
    pub fn observe_original_create_request(
        &mut self,
        intent: &sync_extend_platform_fs::OriginalOutsideIntent,
        volume: &sync_extend_platform_fs::HeldPrivateVolume,
    ) -> Result<sync_extend_journal::OriginalNativePhaseObservationReceipt> {
        if intent.exact_bytes() != self.intent_evidence_bytes()? {
            return Err(ReconcileError::Invariant(
                "original CREATE request full intent differs",
            ));
        }
        Ok(self.local.journal.observe_original_native_create_request(
            &self.reservation,
            intent,
            volume,
            self.local.limits.max_storage_entries,
        )?)
    }
    #[cfg(target_os = "linux")]
    pub fn observe_original_empty_create(
        &mut self,
        intent: &sync_extend_platform_fs::OriginalOutsideIntent,
        volume: &sync_extend_platform_fs::HeldPrivateVolume,
        creator: &sync_extend_platform_fs::OriginalPrivateVolumeFile<'_, '_>,
    ) -> Result<sync_extend_journal::OriginalNativePhaseObservationReceipt> {
        if intent.exact_bytes() != self.intent_evidence_bytes()? {
            return Err(ReconcileError::Invariant(
                "original empty CREATE full intent differs",
            ));
        }
        Ok(self.local.journal.observe_original_native_created(
            &self.reservation,
            intent,
            volume,
            creator,
            self.local.limits.max_storage_entries,
        )?)
    }

    #[cfg(target_os = "linux")]
    pub fn observe_original_outside_intent(
        &mut self,
        intent: &sync_extend_platform_fs::OriginalOutsideIntent,
        volume: &sync_extend_platform_fs::HeldPrivateVolume,
    ) -> Result<sync_extend_journal::OriginalNativePhaseObservationReceipt> {
        if intent.exact_bytes() != self.intent_evidence_bytes()? {
            return Err(ReconcileError::Invariant(
                "phase original intent differs from exact full plan",
            ));
        }
        Ok(self.local.journal.observe_original_native_intent(
            &self.reservation,
            intent,
            volume,
            self.local.limits.max_storage_entries,
        )?)
    }
    #[cfg(target_os = "linux")]
    pub fn observe_original_published_create(
        &mut self,
        intent: &sync_extend_platform_fs::OriginalOutsideIntent,
        volume: &sync_extend_platform_fs::HeldPrivateVolume,
        creator: &sync_extend_platform_fs::OriginalPrivateVolumeFile<'_, '_>,
    ) -> Result<sync_extend_journal::OriginalNativePhaseObservationReceipt> {
        if intent.exact_bytes() != self.intent_evidence_bytes()? {
            return Err(ReconcileError::Invariant(
                "phase published original intent differs",
            ));
        }
        creator.verify_original_slot(&self.local.worktree.join(self.path.as_str()))?;
        Ok(self.local.journal.observe_original_native_published(
            &self.reservation,
            intent,
            volume,
            creator,
            self.local.limits.max_storage_entries,
        )?)
    }
    /// Close only this pending ordinary history attempt after full original
    /// double scan confirms unchanged tree. This removes no native object.
    pub fn cancel_after_unchanged_original_tree(
        self,
    ) -> Result<sync_extend_journal::OriginalHistoryCancellationReceipt> {
        self.local.verify_root()?;
        self.local.require_no_mutation()?;
        if self.local.manifest()?.as_ref() != Some(&self.prior) {
            return Err(ReconcileError::Invariant(
                "cancel original baseline changed",
            ));
        }
        let scanned = self.local.stable_scan()?;
        let built = crate::build_manifest(&self.prior, &scanned, &Default::default())?;
        if built != self.prior
            || scanned
                .keys()
                .any(|path| path.collision_key() == self.path.collision_key())
            || self.local.occupied(&self.path)?
        {
            return Err(ReconcileError::Invariant(
                "cancel original target effects or foreign slot present",
            ));
        }
        let actual = self.local.scan_observations(&self.prior, &scanned)?;
        let stored: serde_json::Value = serde_json::from_str(self.reservation.exact_json())?;
        let planned: sync_extend_core_model::persisted_rename::RenameObservationMap =
            serde_json::from_value(stored["observations"].clone())?;
        if actual.scope.local_root_identity != planned.scope.local_root_identity
            || actual.scope.platform_epoch != planned.scope.platform_epoch
            || actual.scope.format_version != planned.scope.format_version
            || actual.scope.space_id != planned.scope.space_id
            || actual.scope.prior_snapshot != self.prior.root()?
            || planned.scope.prior_snapshot != self.planned.root()?
            || actual.entries.len().checked_add(1) != Some(planned.entries.len())
            || actual
                .entries
                .iter()
                .any(|entry| !planned.entries.contains(entry))
        {
            return Err(ReconcileError::Invariant(
                "cancel original identity or observation changed",
            ));
        }
        crate::fault::checkpoint("before_original_history_cancellation");
        let result = self.local.journal.cancel_original_history_reservation(
            self.reservation,
            &self.prior,
            self.local.limits.max_storage_entries,
        )?;
        crate::fault::checkpoint("after_original_history_cancellation");
        Ok(result)
    }
    pub fn original_native_create_footprint(
        &self,
    ) -> Result<sync_extend_journal::OriginalNativeCreateFootprint> {
        Ok(self.reservation.original_native_create_footprint()?)
    }
    pub fn original_reservation(&self) -> &sync_extend_journal::OriginalLocalHistoryReservation {
        &self.reservation
    }
    pub fn baseline(&self) -> Result<SnapshotId> {
        Ok(self.prior.root()?)
    }

    pub fn planned_manifest(&self) -> &Manifest {
        &self.planned
    }

    pub fn planned_operations(&self) -> &[Operation] {
        &self.operations
    }

    pub fn path(&self) -> &PortablePath {
        &self.path
    }

    pub fn content(&self) -> &FileManifest {
        &self.content
    }

    /// Exact description written by the caller's outside original intent owner.
    /// This does not adopt a prior receipt or grant native effects.
    pub fn intent_evidence_bytes(&self) -> Result<Vec<u8>> {
        let footprint = self.reservation.original_native_create_footprint()?;
        let bytes = serde_json::to_vec(&(
            1u32,
            &self.local.space_id,
            &self.local.device_id,
            &self.path,
            &self.prior,
            &self.planned,
            &self.operations,
            self.timestamp,
            self.local
                .worktree
                .to_str()
                .ok_or(ReconcileError::Invariant("original intent UTF8 root"))?,
            crate::filesystem::physical_identity(&self.local.worktree)?,
            self.reservation.exact_json(),
        ))?;
        if bytes.len() as u64 > footprint.max_intent_bytes {
            return Err(ReconcileError::ResourceLimit(
                "pre-effect original intent byte budget",
            ));
        }
        Ok(bytes)
    }

    /// Requires the caller's separate native/frozen boundary. Original double
    /// scans and full original builder remain mandatory before Journal effects.
    pub fn commit_after_original_native_observation(
        self,
    ) -> Result<(ScanResult, OriginalReservedHistoryCommitReceipt)> {
        self.local.verify_root()?;
        self.local.require_no_mutation()?;
        if self.local.manifest()?.as_ref() != Some(&self.prior) {
            return Err(ReconcileError::Invariant(
                "planned original baseline changed",
            ));
        }
        let scanned = self.local.stable_scan()?;
        let observed = scanned.get(&self.path).ok_or(ReconcileError::Unstable)?;
        if observed.kind != EntryKind::File
            || observed.content.as_ref() != Some(&self.content)
            || !observed.single_link
        {
            return Err(ReconcileError::Unstable);
        }
        let built = crate::build_manifest(&self.prior, &scanned, &Default::default())?;
        if built.entries.len() != self.planned.entries.len()
            || built.entries.values().any(|entry| {
                !self.planned.entries.values().any(|planned| {
                    planned.path == entry.path
                        && planned.kind == entry.kind
                        && planned.content == entry.content
                })
            })
        {
            return Err(ReconcileError::Invariant(
                "original planner actual tree differs",
            ));
        }
        let mut expected = self.planned.clone();
        // Replay the exact shared planner operation builder against the same
        // prior version vector. IDs and timestamp remain the pre-effect choices.
        expected.version_vector = self.prior.version_vector.clone();
        let operations = self.local.original_local_history_operations(
            &self.prior,
            &mut expected,
            self.timestamp,
        )?;
        if expected != self.planned || operations != self.operations {
            return Err(ReconcileError::Invariant(
                "pre-effect original full operation list differs",
            ));
        }
        for entry in self.planned.entries.values() {
            if let Some(content) = &entry.content {
                self.local.cas.verify(content)?;
            }
        }
        let observations = self.local.scan_observations(&self.planned, &scanned)?;
        crate::fault::checkpoint("before_planned_local_history_commit");
        let receipt = self.local.journal.commit_original_reserved_history(
            self.reservation,
            Some(&self.prior.root()?),
            &self.planned,
            &self.operations,
            self.timestamp,
            &observations,
            self.local.limits.max_storage_entries,
        )?;
        crate::fault::checkpoint("after_planned_local_history_commit");
        let result = ScanResult {
            space_id: self.planned.space_id.clone(),
            snapshot_id: receipt.snapshot().clone(),
            entries: self.planned.entries.len(),
            operations: self.operations.len(),
            files: self
                .planned
                .entries
                .values()
                .filter(|entry| entry.kind == EntryKind::File)
                .count(),
            logical_bytes: self
                .planned
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .map(|content| content.length)
                .sum(),
            network_enabled: false,
        };
        Ok((result, receipt))
    }
}
