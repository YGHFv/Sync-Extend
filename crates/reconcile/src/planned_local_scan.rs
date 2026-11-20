//! Exact pre-effect local history plan; native ownership must be supplied separately.
use crate::{scan, LocalSpace, ReconcileError, Result, ScanResult};
#[cfg(target_os = "linux")]
use std::fs::File;
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
            if !self
                .journal
                .outstanding_publications(&self.space_id)?
                .is_empty()
            {
                return Err(ReconcileError::Invariant(
                    "native planning requires explicit legacy publication recovery first",
                ));
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
        self.plan_local_native_content_history(
            prior,
            first,
            path,
            allow_replacement,
            content,
            acquired_native,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn plan_local_native_upload_history<'a>(
        &'a mut self,
        baseline: &Manifest,
        path: PortablePath,
        source: &File,
    ) -> Result<PlannedLocalCreateHistory<'a>> {
        self.require_no_mutation()?;
        if self.linux_namespace.is_none()
            || !self
                .journal
                .outstanding_publications(&self.space_id)?
                .is_empty()
        {
            return Err(ReconcileError::Invariant(
                "Linux upload plan requires its original idle namespace owner",
            ));
        }
        self.verify_root()?;
        let prior = self.manifest()?.ok_or(ReconcileError::Invariant(
            "pre-effect original baseline required",
        ))?;
        if &prior != baseline {
            return Err(ReconcileError::Unstable);
        }
        let first = self.stable_scan()?;
        if crate::build_manifest(&prior, &first, &Default::default())? != prior {
            return Err(ReconcileError::Unstable);
        }
        self.validate_native_upload_slot(&prior, &first, &path)?;
        let content = self.import_original_anonymous_upload(source)?;
        self.plan_local_native_content_history(prior, first, path, true, content, true)
    }

    #[cfg(target_os = "linux")]
    fn validate_native_upload_slot(
        &self,
        prior: &Manifest,
        first: &scan::Scan,
        path: &PortablePath,
    ) -> Result<()> {
        let replaced = prior.entries.values().find(|entry| entry.path == *path);
        let replacement = replaced.is_some();
        if first.keys().any(|present| {
            present.collision_key() == path.collision_key() && (!replacement || present != path)
        }) || (!replacement && self.occupied(path)?)
            || replaced.is_some_and(|entry| entry.kind != EntryKind::File)
            || path
                .as_str()
                .split('/')
                .any(|component| component.starts_with('.'))
        {
            return Err(ReconcileError::Invariant(
                "pre-effect baseline or exact visible file slot differs",
            ));
        }
        let parent = self.parent_for(path)?;
        if std::fs::symlink_metadata(&parent)?.file_type().is_symlink() {
            return Err(ReconcileError::Invariant(
                "pre-effect original parent required",
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn import_original_anonymous_upload(&self, source: &File) -> Result<FileManifest> {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;

        let before = source.metadata()?;
        if !before.is_file() {
            return Err(ReconcileError::Invariant(
                "Linux DAV upload requires an anonymous regular file",
            ));
        }
        if before.nlink() != 0 {
            return Err(ReconcileError::Invariant(
                "Linux DAV upload descriptor is not anonymous",
            ));
        }
        if before.len() > self.limits.max_file_bytes || before.len() > self.limits.max_staging_bytes
        {
            return Err(ReconcileError::ResourceLimit("DAV upload bytes"));
        }
        let identity = (before.dev(), before.ino(), before.len());
        let times = (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        );
        let mut reader = source.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let content = self.cas.import_bounded(
            reader.take(before.len().saturating_add(1)),
            before.len(),
            self.limits.max_scan_chunks,
        )?;
        let after = source.metadata()?;
        if content.length != before.len()
            || (after.dev(), after.ino(), after.len()) != identity
            || (
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ) != times
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(content)
    }

    fn plan_local_native_content_history<'a>(
        &'a mut self,
        prior: Manifest,
        first: scan::Scan,
        path: PortablePath,
        allow_replacement: bool,
        content: FileManifest,
        acquired_native: bool,
    ) -> Result<PlannedLocalCreateHistory<'a>> {
        #[cfg(not(target_os = "linux"))]
        let _ = acquired_native;
        self.verify_root()?;
        let existing = crate::build_manifest(&prior, &first, &Default::default())?;
        self.check_publication_limits(&content)?;
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

impl<'a> PlannedLocalCreateHistory<'a> {
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
    ) -> Result<(
        ScanResult,
        OriginalReservedHistoryCommitReceipt,
        &'a mut LocalSpace,
    )> {
        let PlannedLocalCreateHistory {
            local,
            prior,
            planned,
            operations,
            path,
            content,
            timestamp,
            reservation,
        } = self;
        local.verify_root()?;
        local.require_no_mutation()?;
        if local.manifest()?.as_ref() != Some(&prior) {
            return Err(ReconcileError::Invariant(
                "planned original baseline changed",
            ));
        }
        let scanned = local.stable_scan()?;
        let observed = scanned.get(&path).ok_or(ReconcileError::Unstable)?;
        if observed.kind != EntryKind::File
            || observed.content.as_ref() != Some(&content)
            || !observed.single_link
        {
            return Err(ReconcileError::Unstable);
        }
        let built = crate::build_manifest(&prior, &scanned, &Default::default())?;
        if built.entries.len() != planned.entries.len()
            || built.entries.values().any(|entry| {
                !planned.entries.values().any(|planned| {
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
        let mut expected = planned.clone();
        // Replay the exact shared planner operation builder against the same
        // prior version vector. IDs and timestamp remain the pre-effect choices.
        expected.version_vector = prior.version_vector.clone();
        let replayed_operations =
            local.original_local_history_operations(&prior, &mut expected, timestamp)?;
        if expected != planned || replayed_operations != operations {
            return Err(ReconcileError::Invariant(
                "pre-effect original full operation list differs",
            ));
        }
        for entry in planned.entries.values() {
            if let Some(content) = &entry.content {
                local.cas.verify(content)?;
            }
        }
        let observations = local.scan_observations(&planned, &scanned)?;
        crate::fault::checkpoint("before_planned_local_history_commit");
        let receipt = local.journal.commit_original_reserved_history(
            reservation,
            Some(&prior.root()?),
            &planned,
            &operations,
            timestamp,
            &observations,
            local.limits.max_storage_entries,
        )?;
        crate::fault::checkpoint("after_planned_local_history_commit");
        let result = ScanResult {
            space_id: planned.space_id.clone(),
            snapshot_id: receipt.snapshot().clone(),
            entries: planned.entries.len(),
            operations: operations.len(),
            files: planned
                .entries
                .values()
                .filter(|entry| entry.kind == EntryKind::File)
                .count(),
            logical_bytes: planned
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .map(|content| content.length)
                .sum(),
            network_enabled: false,
        };
        Ok((result, receipt, local))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_original_linux_native(
        mut self,
        owner: &sync_extend_platform_fs::LinuxNamespaceCapability,
        budget: &sync_extend_platform_fs::LinuxMetadataBudget,
        helpers: &mut Option<sync_extend_platform_fs::OutsideHelperSession>,
        prepare_helpers: impl FnOnce() -> Result<sync_extend_platform_fs::OutsideHelperSession>,
    ) -> Result<(
        crate::PublishResult,
        sync_extend_platform_fs::OriginalPairTerminalRelease,
    )> {
        use std::os::unix::fs::DirBuilderExt;

        let path = self.path.clone();
        let worktree = self.local.worktree.clone();
        let intent_parent = self.local.data_dir.join("native-intents");
        if !intent_parent.try_exists()? {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&intent_parent)?;
            std::fs::File::open(&self.local.data_dir)?.sync_all()?;
        }
        let volume = owner.volume();
        let outside =
            sync_extend_platform_fs::OutsidePrivateIntentOwner::open(&intent_parent, volume)?;
        let attempt_id = self.original_reservation().attempt().clone();
        let prior_content = self
            .prior_manifest()
            .entries
            .values()
            .find(|entry| entry.path == path)
            .and_then(|entry| entry.content.clone());
        let content = self.content().clone();
        let mut payload = Vec::new();
        self.write_original_planned_payload(&mut payload)?;
        if payload.len() as u64 != content.length || ContentId::hash(&payload) != content.content_id
        {
            return Err(ReconcileError::Invariant(
                "native planned payload differs from original CAS",
            ));
        }
        let prior_payload = if let Some(prior) = &prior_content {
            let mut bytes = Vec::new();
            self.write_original_prior_payload(prior, &mut bytes)?;
            if bytes.len() as u64 != prior.length || ContentId::hash(&bytes) != prior.content_id {
                return Err(ReconcileError::Invariant(
                    "native retained prior payload differs from original CAS",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        let intent_bytes = self.intent_evidence_bytes()?;
        let intent =
            outside.create_intent(&format!("intent-{attempt_id}"), &intent_bytes, volume)?;
        self.observe_original_outside_intent(&intent, volume)?;
        self.observe_original_create_request(&intent, volume)?;
        let relative_parent = worktree.join(
            path.parent()
                .map_or(String::new(), |parent| parent.to_string()),
        );
        let relative_parent = relative_parent
            .strip_prefix(owner.mount_path())
            .map_err(|_| ReconcileError::Invariant("native parent escaped acquired mount"))?;
        let parent = volume.directory(relative_parent)?;
        let component = path
            .as_str()
            .rsplit('/')
            .next()
            .ok_or(ReconcileError::Invariant("native target component absent"))?;
        let old = if prior_content.is_some() {
            Some(parent.writer_excluded_original(component)?)
        } else {
            None
        };
        let freeze = volume.prepare_original_pair_freeze()?;
        *helpers = Some(prepare_helpers()?);
        let session = helpers.as_mut().ok_or(ReconcileError::Invariant(
            "original late prepared helper session absent",
        ))?;
        owner.verify_prepared_helpers(session)?;
        session.arm(attempt_id.as_str())?;
        let native = owner.admit_native_attempt(session.pair())?;
        budget.validate_native_attempt(&native)?;
        native.verify()?;
        let mut created =
            parent.create_original_file(&format!("stage-{attempt_id}"), content.length.max(1))?;
        native.verify()?;
        self.observe_original_empty_create(&intent, volume, &created)?;
        native.verify()?;
        if !payload.is_empty() {
            created.observe_preallocated_original_payload(payload.len() as u64)?;
            native.verify()?;
        }
        created.write_all_bounded(&payload)?;
        native.verify()?;
        created.sync_original_and_parents()?;
        native.verify()?;
        let transaction = if old.is_some() {
            Some(parent.create_original_transaction_directory(attempt_id.as_str())?)
        } else {
            None
        };
        native.verify()?;
        let retained = match (old, transaction.as_ref(), prior_payload.as_ref()) {
            (Some(original), Some(transaction), Some(prior_payload)) => Some(
                original.retain_in_original_transaction(transaction, "original", prior_payload)?,
            ),
            (None, None, None) => None,
            _ => {
                return Err(ReconcileError::Invariant(
                    "native replacement original transaction incomplete",
                ))
            }
        };
        native.verify()?;
        created.rename_in_same_parent_no_replace(component)?;
        native.verify()?;
        self.observe_original_published_create(&intent, volume, &created)?;
        native.verify()?;
        let frozen = freeze.freeze_for_original_pair_diagnostic(session.pair())?;
        native.verify()?;
        let expected_manifest = self.planned.clone();
        let (result, history, local) = self.commit_after_original_native_observation()?;
        native.verify()?;
        let final_observation = crate::observe_original_linux_native_final(
            &created,
            &intent,
            volume,
            &frozen,
            session.pair(),
            &result,
            history,
        )?;
        local.journal.record_original_linux_native_final(
            &native,
            budget,
            &intent,
            &intent_parent,
            &worktree,
            &created,
            retained.as_ref(),
            &frozen,
            session.pair(),
            final_observation.original_history_receipt(),
            local.limits.max_storage_entries,
        )?;
        native.verify()?;
        drop(final_observation);
        drop(native);
        drop(frozen);
        let session = helpers.take().ok_or(ReconcileError::Invariant(
            "original armed session escaped owner",
        ))?;
        let terminal = session.finish_committed()?;
        local.journal.record_original_linux_committed_thaw(
            owner,
            &terminal,
            &attempt_id,
            local.limits.max_storage_entries,
        )?;
        budget.verify()?;
        let reopened_manifest = local
            .manifest()?
            .ok_or(ReconcileError::Invariant("committed DAV manifest absent"))?;
        let reopened_scan = local.stable_scan()?;
        let reopened_tree =
            crate::build_manifest(&reopened_manifest, &reopened_scan, &Default::default())?;
        if result.snapshot_id != expected_manifest.root()?
            || reopened_manifest != expected_manifest
            || reopened_tree != expected_manifest
        {
            return Err(ReconcileError::Unstable);
        }
        Ok((
            crate::PublishResult {
                transaction_id: attempt_id,
                requested_path: path.clone(),
                published_path: path,
                conflict_copy: false,
                snapshot_id: result.snapshot_id,
                local_committed: true,
                remote_backup_complete: false,
            },
            terminal,
        ))
    }
}
