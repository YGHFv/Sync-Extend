//! Storage role shares managed CAS/Journal but never constructs a local worktree.
use crate::{identity, managed_cas, now_ms, ReconcileError, Result};
use fs2::FileExt;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::PathBuf,
};
use sync_extend_cas::Cas;
use sync_extend_core_model::{
    reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope},
    storage_node::StorageNodeConfig,
    Change, ChunkRef, ContentId, DeviceId, EntryId, SpaceId, FORMAT_VERSION, PROTOCOL_VERSION,
};
use sync_extend_journal::{Journal, ReferenceReservationIntent, RemotePublicationProof};
use sync_extend_transport::{
    ForwardStoreReceipt, ForwardStoreState, ForwardedSnapshotEnvelope, PeerIdentity,
    SignedForwardStoreReceipt, SignedForwardedOperationPage, SignedOperation,
    SignedStorageSnapshotReceipt, StorageSnapshotReceipt, TransportIdentity, VerifiedForwardedPage,
};

pub struct StorageNode {
    pub(super) config: StorageNodeConfig,
    pub(super) device: DeviceId,
    pub(super) journal: Journal,
    pub(super) cas: Cas,
    pub(super) traffic: sync_extend_journal::StorageTrafficLedger,
    data_identity: crate::filesystem::PathIdentity,
    file_identities: Vec<(PathBuf, crate::filesystem::PathIdentity)>,
    #[cfg(windows)]
    _parents: Vec<sync_extend_platform_fs::LockedDirectory>,
    _lock: File,
}

pub struct StorageReceivedPage {
    verified: VerifiedForwardedPage,
    owner: Option<EntryId>,
}

pub struct StorageReceivedSnapshot {
    envelope: ForwardedSnapshotEnvelope,
    owner: Option<EntryId>,
}

#[derive(serde::Serialize)]
pub struct StorageSnapshotStatus {
    pub origin_device: DeviceId,
    pub snapshot_id: sync_extend_core_model::SnapshotId,
    pub reported_at_ms: u64,
    pub last_reported: bool,
    pub state: ForwardStoreState,
    pub missing_chunks: usize,
    pub native_applied: bool,
}

#[derive(serde::Serialize)]
pub struct StorageNodeStatus {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub state: ForwardStoreState,
    pub worktree: Option<PathBuf>,
    pub native_applied: bool,
    pub backup_complete: bool,
    pub protected_bytes: u64,
    pub physical_cas_bytes: u64,
    pub expired: bool,
    pub charged_logical_delivery_bytes: u64,
    pub snapshots: Vec<StorageSnapshotStatus>,
    pub role: sync_extend_core_model::storage_node::StorageRole,
    pub full_last_reported_content_complete: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageProvision {
    format_version: u32,
    provisioning_id: EntryId,
    peer: PeerIdentity,
}

impl crate::LocalSpace {
    /// Sign this device's current locally audited report before handing it to a forwarder.
    pub fn signed_storage_snapshot_report(
        &mut self,
    ) -> Result<sync_extend_transport::SignedStorageSnapshotReport> {
        self.scan()?;
        self.verify_root()?;
        self.require_no_mutation()?;
        self.snapshot_audit()?;
        let manifest = self.manifest()?.ok_or(ReconcileError::Invariant(
            "storage snapshot current manifest absent",
        ))?;
        let identity = self.transport_identity()?;
        sync_extend_transport::SignedStorageSnapshotReport::sign(
            &identity,
            sync_extend_transport::StorageSnapshotReport {
                protocol_version: PROTOCOL_VERSION,
                source_device: self.device_id.clone(),
                snapshot_id: manifest.root()?,
                manifest,
                reported_at_ms: now_ms()?,
            },
        )
        .map_err(|_| ReconcileError::Invariant("original storage snapshot report signing"))
    }
}

impl StorageNode {
    /// Replace only this exact snapshot owner after all explicit storage targets
    /// signed complete durable content receipts. Physical CAS disposition is separate.
    pub fn handoff_retained_snapshot_storage(
        &self,
        policy: &sync_extend_transport::SnapshotStorageHandoffPolicy,
        evidence: &[sync_extend_transport::SnapshotStorageHandoffEvidence],
    ) -> Result<bool> {
        self.verify_storage()?;
        policy.validate()?;
        if policy.space_id != self.config.space_id
            || policy.storage_device != self.device
            || evidence.len() > 1024
        {
            return Err(ReconcileError::Invariant(
                "snapshot handoff exact local policy scope",
            ));
        }
        let retained = self
            .traffic
            .snapshots(&self.config, &self.device)?
            .into_iter()
            .find(|retained| {
                retained.storage_id().ok().as_ref() == Some(&policy.storage_id)
                    && evidence
                        .first()
                        .is_some_and(|item| item.envelope.signed_report == retained.signed_report)
            })
            .ok_or(ReconcileError::Invariant(
                "snapshot handoff exact retained original report absent",
            ))?;
        let verified = sync_extend_transport::SnapshotStorageHandoffRecord {
            policy: policy.clone(),
            retained,
            evidence: evidence.to_vec(),
            handed_off_at_ms: now_ms()?,
        }
        .verify_current(&self.config, self.transport_identity()?.peer_identity())?;
        self.journal
            .handoff_storage_snapshot(&verified)
            .map_err(ReconcileError::from)
    }

    /// Explicit operator policy and all native target receipts allow only this
    /// retained original page's owner to hand off. Physical CAS bytes stay intact.
    pub fn handoff_retained_page_delivery(
        &self,
        policy: &sync_extend_core_model::storage_retention::StorageRetentionPolicy,
        evidence: &[sync_extend_transport::ForwardedAppliedEvidence],
    ) -> Result<bool> {
        let assessment = self.assess_retained_page_delivery(policy, evidence)?;
        if assessment.state != sync_extend_core_model::storage_retention::StorageRetentionState::EligibleForExplicitOwnerHandoff {
            return Err(ReconcileError::Invariant("storage delivery lacks required applied targets/deadline"));
        }
        let retained = self
            .traffic
            .pages(&self.config, &self.device)?
            .into_iter()
            .find(|envelope| {
                envelope.signed_page.page.storage_id().ok().as_ref() == Some(&policy.storage_id)
            })
            .ok_or(ReconcileError::Invariant(
                "storage delivery original page absent",
            ))?;
        let verified = sync_extend_transport::StoragePageDeliveryRecord {
            policy: policy.clone(),
            retained,
            evidence: evidence.to_vec(),
            handed_off_at_ms: now_ms()?,
        }
        .verify_current(&self.config, self.transport_identity()?.peer_identity())?;
        self.journal
            .handoff_storage_page(&verified)
            .map_err(ReconcileError::from)
    }

    /// Every target key is independently pinned in local policy. Even an eligible
    /// assessment keeps all pins until the exact durable handoff adapter commits.
    pub fn assess_retained_page_delivery(
        &self,
        policy: &sync_extend_core_model::storage_retention::StorageRetentionPolicy,
        evidence: &[sync_extend_transport::ForwardedAppliedEvidence],
    ) -> Result<sync_extend_core_model::storage_retention::StorageRetentionAssessment> {
        self.verify_storage()?;
        policy.validate()?;
        if policy.space_id != self.config.space_id
            || policy.storage_device != self.device
            || evidence.len() > 1024
        {
            return Err(ReconcileError::Invariant(
                "storage retention exact policy scope/bound",
            ));
        }
        let retained = self
            .traffic
            .pages(&self.config, &self.device)?
            .into_iter()
            .find(|envelope| {
                envelope.signed_page.page.storage_id().ok().as_ref() == Some(&policy.storage_id)
            })
            .ok_or(ReconcileError::Invariant(
                "storage retention exact retained page absent",
            ))?;
        self.verify_approved_key(&retained.origin, false)?;
        let storage = self.transport_identity()?;
        let mut targets = std::collections::BTreeSet::new();
        for item in evidence {
            let target = &item.envelope.receiver;
            if !policy.required_applied_targets.contains(&target.device_id)
                || !targets.insert(target.device_id.clone())
            {
                return Err(ReconcileError::Invariant(
                    "storage retention target duplicate/outside policy",
                ));
            }
            self.verify_approved_key(target, true)?;
            item.verify(&retained.origin, storage.peer_identity(), target)
                .map_err(|_| {
                    ReconcileError::Invariant("storage retention actual target signature")
                })?;
            item.matches_retained_page(&retained).map_err(|_| {
                ReconcileError::Invariant("storage retention exact retained original page")
            })?;
        }
        for target in &policy.required_applied_targets {
            if !self.config.approved_forwarders.contains_key(target) {
                return Err(ReconcileError::Invariant(
                    "storage retention target not independently approved",
                ));
            }
        }
        sync_extend_transport::assess_storage_retention(policy, &targets, now_ms()?)
            .map_err(ReconcileError::from)
    }

    /// Provision a fresh private storage identity before exchanging public approvals.
    /// This creates no journal, traffic policy, CAS, or worktree.
    pub fn provision_identity(data_dir: &std::path::Path, space: SpaceId) -> Result<PeerIdentity> {
        if !data_dir.is_absolute() || data_dir.try_exists()? {
            return Err(ReconcileError::Invariant(
                "fresh absolute storage identity directory required",
            ));
        }
        crate::check_ancestors(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(data_dir)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(data_dir)?;
        #[cfg(windows)]
        let _parents = {
            let mut result = Vec::new();
            for ancestor in data_dir.ancestors().collect::<Vec<_>>().into_iter().rev() {
                let held = sync_extend_platform_fs::LockedDirectory::open(ancestor)?;
                if !held.matches_path(ancestor)? {
                    return Err(ReconcileError::Invariant(
                        "storage provision ancestor changed",
                    ));
                }
                result.push(held);
            }
            result
                .last()
                .ok_or(ReconcileError::Invariant("storage provision parent absent"))?
                .require_local_ntfs(data_dir)?;
            result
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(3).custom_flags(0x00200000);
        }
        let lock = options.open(data_dir.join("storage.lock"))?;
        lock.try_lock_exclusive()?;
        let key = identity::load_signing_key(&data_dir.join("device.secret"), true)?;
        let transport = TransportIdentity::from_signing_key(space, key)
            .map_err(|_| ReconcileError::Invariant("storage provision identity"))?;
        let provision = StorageProvision {
            format_version: FORMAT_VERSION,
            provisioning_id: EntryId::random()?,
            peer: transport.peer_identity().clone(),
        };
        let mut marker = options.open(data_dir.join("storage-provision.json"))?;
        use std::io::Write;
        marker.write_all(&serde_json::to_vec(&provision)?)?;
        marker.sync_all()?;
        lock.sync_all()?;
        sync_extend_cas::sync_directory(data_dir)?;
        Ok(provision.peer)
    }

    /// Bind the provisioned identity to an explicit immutable policy exactly once.
    /// A partial initialization with additional files is refused, never adopted.
    pub fn initialize_provisioned(
        config: StorageNodeConfig,
        expected: &PeerIdentity,
    ) -> Result<Self> {
        config.validate()?;
        expected
            .validate()
            .map_err(|_| ReconcileError::Invariant("storage expected public identity"))?;
        if expected.space_id != config.space_id {
            return Err(ReconcileError::Invariant("storage provision space differs"));
        }
        crate::check_ancestors(&config.data_dir)?;
        let actual: std::collections::BTreeSet<_> = fs::read_dir(&config.data_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<_>>()?;
        let required: std::collections::BTreeSet<_> =
            ["storage.lock", "device.secret", "storage-provision.json"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect();
        if actual != required {
            return Err(ReconcileError::Invariant(
                "storage provision incomplete or already initialized",
            ));
        }
        let path = config.data_dir.join("storage-provision.json");
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || sync_extend_cas::is_reparse(&metadata)
            || metadata.len() > 4096
        {
            return Err(ReconcileError::Invariant(
                "storage provision marker differs",
            ));
        }
        let provision: StorageProvision = serde_json::from_slice(&fs::read(&path)?)?;
        if provision.format_version != FORMAT_VERSION || provision.peer != *expected {
            return Err(ReconcileError::Invariant(
                "storage provision expected identity differs",
            ));
        }
        let node = Self::open_inner(config, true, Some(expected))?;
        if node.transport_identity()?.peer_identity() != expected {
            return Err(ReconcileError::Invariant(
                "storage provision private identity differs",
            ));
        }
        Ok(node)
    }

    pub fn initialize(config: StorageNodeConfig) -> Result<Self> {
        config.validate()?;
        crate::check_ancestors(&config.data_dir)?;
        if config.data_dir.try_exists()? {
            return Err(ReconcileError::Invariant(
                "new storage data directory required",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(&config.data_dir)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(&config.data_dir)?;
        Self::open_inner(config, true, None)
    }

    pub fn open(config: StorageNodeConfig) -> Result<Self> {
        config.validate()?;
        Self::open_inner(config, false, None)
    }

    fn open_inner(
        config: StorageNodeConfig,
        create: bool,
        provisioned: Option<&PeerIdentity>,
    ) -> Result<Self> {
        crate::check_ancestors(&config.data_dir)?;
        let metadata = fs::symlink_metadata(&config.data_dir)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || sync_extend_cas::is_reparse(&metadata)
        {
            return Err(ReconcileError::Invariant(
                "storage data must be a real private directory",
            ));
        }
        #[cfg(windows)]
        let parents = {
            let mut result = Vec::new();
            for ancestor in config
                .data_dir
                .ancestors()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                let held = sync_extend_platform_fs::LockedDirectory::open(ancestor)?;
                if !held.matches_path(ancestor)? {
                    return Err(ReconcileError::Invariant("storage ancestor changed"));
                }
                result.push(held);
            }
            result
                .last()
                .ok_or(ReconcileError::Invariant("storage parent absent"))?
                .require_local_ntfs(&config.data_dir)?;
            result
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if create && provisioned.is_none() {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(3).custom_flags(0x00200000);
        }
        let lock = options.open(config.data_dir.join("storage.lock"))?;
        lock.try_lock_exclusive()?;
        if let Some(expected) = provisioned {
            let entries: std::collections::BTreeSet<_> = fs::read_dir(&config.data_dir)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<std::io::Result<_>>()?;
            let names: std::collections::BTreeSet<_> =
                ["storage.lock", "device.secret", "storage-provision.json"]
                    .into_iter()
                    .map(std::ffi::OsString::from)
                    .collect();
            if entries != names {
                return Err(ReconcileError::Invariant(
                    "storage provision changed while locking",
                ));
            }
            let marker = config.data_dir.join("storage-provision.json");
            let metadata = fs::symlink_metadata(&marker)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || sync_extend_cas::is_reparse(&metadata)
                || metadata.len() > 4096
            {
                return Err(ReconcileError::Invariant(
                    "storage provision changed while locking",
                ));
            }
            let provision: StorageProvision = serde_json::from_slice(&fs::read(marker)?)?;
            if provision.format_version != FORMAT_VERSION || provision.peer != *expected {
                return Err(ReconcileError::Invariant(
                    "storage provision identity changed while locking",
                ));
            }
        }
        let key = identity::load_signing_key(
            &config.data_dir.join("device.secret"),
            create && provisioned.is_none(),
        )?;
        let device = DeviceId::from_public_key(key.verifying_key().as_bytes());
        if provisioned.is_some_and(|expected| {
            expected.device_id != device || expected.public_key != *key.verifying_key().as_bytes()
        }) {
            return Err(ReconcileError::Invariant(
                "storage provision private key differs",
            ));
        }
        if create {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(config.data_dir.join("journal.sqlite"))?
                .sync_all()?;
        }
        let mut journal = Journal::open_with_storage_limit(
            &config.data_dir.join("journal.sqlite"),
            config.max_metadata_entries,
        )?;
        if create {
            journal.initialize_storage(&config.space_id, &device)?;
        }
        if journal.state("space_id")?.as_deref() != Some(config.space_id.as_str())
            || journal.state("device_id")?.as_deref() != Some(device.as_str())
            || journal.state("worktree")?.is_some()
            || journal.state("storage_role")?.as_deref() != Some("storage-v1")
        {
            return Err(ReconcileError::Invariant(
                "storage identity must have no worktree",
            ));
        }
        let cas = managed_cas(&config.data_dir)?;
        let traffic = sync_extend_journal::StorageTrafficLedger::open(
            &config.data_dir.join("storage-traffic.sqlite"),
            &config,
            &device,
            create,
        )?;
        let data_identity = crate::filesystem::PathIdentity::capture(&config.data_dir)?;
        let mut file_identities = Vec::new();
        for name in [
            "storage.lock",
            "device.secret",
            "journal.sqlite",
            "storage-traffic.sqlite",
        ] {
            let path = config.data_dir.join(name);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || sync_extend_cas::is_reparse(&metadata)
            {
                return Err(ReconcileError::Invariant("storage owned file differs"));
            }
            file_identities.push((
                path.clone(),
                crate::filesystem::PathIdentity::capture(&path)?,
            ));
        }
        Ok(Self {
            config,
            device,
            journal,
            cas,
            traffic,
            data_identity,
            file_identities,
            #[cfg(windows)]
            _parents: parents,
            _lock: lock,
        })
    }

    pub fn transport_identity(&self) -> Result<TransportIdentity> {
        self.verify_storage()?;
        let key = identity::load_signing_key(&self.config.data_dir.join("device.secret"), false)?;
        if DeviceId::from_public_key(key.verifying_key().as_bytes()) != self.device {
            return Err(ReconcileError::Invariant("storage identity changed"));
        }
        TransportIdentity::from_signing_key(self.config.space_id.clone(), key)
            .map_err(|_| ReconcileError::Invariant("storage transport identity"))
    }

    /// Approval is independently supplied by local configuration, never copied from wire keys.
    pub fn receive_forwarded_page(
        &mut self,
        signed: &SignedForwardedOperationPage,
        origin: &PeerIdentity,
        authenticated_forwarder: &PeerIdentity,
        binding: &ContentId,
    ) -> Result<StorageReceivedPage> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        self.verify_approved_key(authenticated_forwarder, true)?;
        self.config.admits(
            &origin.device_id,
            &authenticated_forwarder.device_id,
            now_ms()?,
        )?;
        let identity = self.transport_identity()?;
        let cursor = self
            .journal
            .cursor(&self.config.space_id, &origin.device_id)?;
        let after = signed.page.after_sequence;
        if after > cursor {
            return Err(ReconcileError::Invariant(
                "storage forwarded page skips durable prefix",
            ));
        }
        let verified = signed
            .verify(
                origin,
                authenticated_forwarder,
                identity.peer_identity(),
                binding,
                after,
            )
            .map_err(|_| ReconcileError::Invariant("storage verified original forwarded page"))?;
        self.traffic
            .retain_page(&self.config, &self.device, &verified.envelope(), now_ms()?)?;
        let files = verified
            .page()
            .operations
            .iter()
            .filter_map(|signed| match &signed.operation.payload.change {
                Change::Put { entry } => entry.content.clone(),
                _ => None,
            })
            .collect::<Vec<_>>();
        let owner = if files.is_empty() {
            None
        } else {
            let request = verified
                .storage_id()
                .map_err(|_| ReconcileError::Invariant("storage request"))?;
            let owner: EntryId = request.as_str()[..32].parse()?;
            let intent = ReferenceReservationIntent {
                owner_id: owner.clone(),
                scope: ReferenceOwnerScope {
                    format_version: FORMAT_VERSION,
                    space_id: self.config.space_id.clone(),
                    kind: ReferenceOwnerKind::Download,
                    target_device: None,
                    files,
                },
                created_at_ms: verified
                    .page()
                    .operations
                    .first()
                    .map_or(0, |signed| signed.operation.payload.created_at_ms),
            };
            let chunks = Self::page_chunks(&verified)?;
            let mut reserved = self.reserved_chunks()?;
            for (id, chunk) in &chunks {
                if reserved
                    .insert(id.clone(), chunk.clone())
                    .is_some_and(|prior| prior != *chunk)
                {
                    return Err(ReconcileError::Invariant(
                        "storage prior reservation chunk length differs",
                    ));
                }
            }
            let missing = reserved.values().try_fold(0u64, |total, chunk| {
                let bytes = if self.cas.read(chunk).is_ok() {
                    0
                } else {
                    u64::from(chunk.length)
                };
                total
                    .checked_add(bytes)
                    .ok_or(ReconcileError::ResourceLimit("storage bytes overflow"))
            })?;
            if self
                .physical_bytes()?
                .checked_add(missing)
                .is_none_or(|total| total > self.config.max_stored_bytes)
            {
                return Err(ReconcileError::ResourceLimit("storage physical quota"));
            }
            let (guard, _) = self
                .journal
                .with_reference_reservation::<(), ReconcileError>(
                    &intent,
                    self.config.max_metadata_entries,
                    |_| Ok(()),
                )?;
            drop(guard);
            Some(owner)
        };
        for signed in &verified.page().operations {
            self.verify_approved_key(origin, false)?;
            self.verify_approved_key(authenticated_forwarder, true)?;
            self.config.admits(
                &origin.device_id,
                &authenticated_forwarder.device_id,
                now_ms()?,
            )?;
            self.journal.retain_original_provenance(
                &RemotePublicationProof {
                    public_key: origin.public_key,
                    operation: signed.operation.clone(),
                    signature: signed.signature.clone(),
                },
                &origin.public_key,
            )?;
            self.journal.receive_storage(&signed.operation)?;
        }
        let last = verified
            .page()
            .operations
            .last()
            .map_or(after, |signed| signed.operation.payload.origin_seq);
        if self
            .journal
            .cursor(&self.config.space_id, &origin.device_id)?
            < last
        {
            return Err(ReconcileError::Invariant(
                "storage page prefix remains pending",
            ));
        }
        Ok(StorageReceivedPage { verified, owner })
    }

    /// Historical pages are reverified against current independently configured keys.
    /// A restart resumes exact durable ownership before any additional chunk is accepted.
    pub fn recover_forwarded_pages(&mut self) -> Result<Vec<StorageReceivedPage>> {
        self.verify_storage()?;
        let envelopes = self.traffic.pages(&self.config, &self.device)?;
        let mut result = Vec::new();
        for envelope in envelopes {
            if now_ms()? >= self.config.expires_at_ms {
                self.config.permits_retained_delivery(
                    &envelope.origin.device_id,
                    &envelope.forwarder.device_id,
                )?;
                let verified = envelope.signed_page.verify(
                    &envelope.origin,
                    &envelope.forwarder,
                    self.transport_identity()?.peer_identity(),
                    &envelope.signed_page.page.channel_binding,
                    envelope.signed_page.page.after_sequence,
                )?;
                let id = verified.storage_id()?;
                let files = verified
                    .page()
                    .operations
                    .iter()
                    .filter_map(|signed| match &signed.operation.payload.change {
                        Change::Put { entry } => entry.content.clone(),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let owner = if files.is_empty() {
                    None
                } else {
                    let owner: EntryId = id.as_str()[..32].parse()?;
                    let old = self
                        .journal
                        .reference_reservations(
                            &self.config.space_id,
                            self.config.max_metadata_entries,
                        )?
                        .into_iter()
                        .find(|r| r.intent.owner_id == owner)
                        .ok_or(ReconcileError::Invariant(
                            "expired retained page owner not yet recovered",
                        ))?;
                    if old.intent.scope.files != files
                        || old.intent.scope.kind != ReferenceOwnerKind::Download
                        || old.intent.scope.space_id != self.config.space_id
                        || old.intent.scope.target_device.is_some()
                        || old.intent.created_at_ms
                            != verified
                                .page()
                                .operations
                                .first()
                                .map_or(0, |signed| signed.operation.payload.created_at_ms)
                    {
                        return Err(ReconcileError::Invariant(
                            "expired retained owner scope differs",
                        ));
                    }
                    Some(owner)
                };
                for signed in &verified.page().operations {
                    if self
                        .journal
                        .cursor(&self.config.space_id, &envelope.origin.device_id)?
                        < signed.operation.payload.origin_seq
                    {
                        return Err(ReconcileError::Invariant(
                            "expired retained original prefix incomplete",
                        ));
                    }
                    let proof = self
                        .journal
                        .original_provenance(
                            &self.config.space_id,
                            &envelope.origin.device_id,
                            signed.operation.payload.origin_seq,
                        )?
                        .ok_or(ReconcileError::Invariant(
                            "expired retained original incomplete",
                        ))?;
                    if proof.operation != signed.operation
                        || proof.signature != signed.signature
                        || proof.public_key != envelope.origin.public_key
                    {
                        return Err(ReconcileError::Invariant(
                            "expired retained original differs",
                        ));
                    }
                }
                result.push(StorageReceivedPage { verified, owner });
                continue;
            }
            let received = self.receive_forwarded_page(
                &envelope.signed_page,
                &envelope.origin,
                &envelope.forwarder,
                &envelope.signed_page.page.channel_binding,
            )?;
            result.push(received);
        }
        Ok(result)
    }

    pub fn receive_forwarded_snapshot(
        &mut self,
        envelope: &ForwardedSnapshotEnvelope,
        origin: &PeerIdentity,
        forwarder: &PeerIdentity,
        binding: &ContentId,
    ) -> Result<StorageReceivedSnapshot> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        self.verify_approved_key(forwarder, true)?;
        self.config
            .admits(&origin.device_id, &forwarder.device_id, now_ms()?)?;
        let identity = self.transport_identity()?;
        envelope
            .verify(origin, forwarder, identity.peer_identity(), binding)
            .map_err(|_| {
                ReconcileError::Invariant("storage forwarded snapshot scope/signatures")
            })?;
        let manifest = &envelope.signed_report.report.manifest;
        for (device, sequence) in &manifest.version_vector.0 {
            if self.journal.cursor(&self.config.space_id, device)? < *sequence {
                return Err(ReconcileError::Invariant(
                    "snapshot metadata prefix has missing original operations",
                ));
            }
        }
        // The independent signature authenticates a report; it does not prove the
        // source knows an offline device's current state or native application.
        self.traffic
            .retain_snapshot(&self.config, &self.device, envelope, now_ms()?)?;
        let files = manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.clone())
            .collect::<Vec<_>>();
        let owner = if files.is_empty() {
            None
        } else {
            let id = envelope
                .storage_id()
                .map_err(|_| ReconcileError::Invariant("storage snapshot request"))?;
            let owner: EntryId = id.as_str()[..32].parse()?;
            let intent = ReferenceReservationIntent {
                owner_id: owner.clone(),
                scope: ReferenceOwnerScope {
                    format_version: FORMAT_VERSION,
                    space_id: self.config.space_id.clone(),
                    kind: ReferenceOwnerKind::Restore,
                    target_device: None,
                    files,
                },
                // Ownership is immutable across equivalent report times and reconnects.
                created_at_ms: 0,
            };
            let mut reserved = self.reserved_chunks()?;
            for file in &intent.scope.files {
                for chunk in &file.chunks {
                    if reserved
                        .insert(chunk.content_id.clone(), chunk.clone())
                        .is_some_and(|old| old != *chunk)
                    {
                        return Err(ReconcileError::Invariant(
                            "snapshot conflicting chunk lengths",
                        ));
                    }
                }
            }
            let missing = reserved.values().try_fold(0u64, |sum, chunk| {
                sum.checked_add(if self.cas.read(chunk).is_ok() {
                    0
                } else {
                    u64::from(chunk.length)
                })
                .ok_or(ReconcileError::ResourceLimit("snapshot quota overflow"))
            })?;
            if self
                .physical_bytes()?
                .checked_add(missing)
                .is_none_or(|sum| sum > self.config.max_stored_bytes)
            {
                return Err(ReconcileError::ResourceLimit("storage snapshot quota"));
            }
            let (guard, _) = self
                .journal
                .with_reference_reservation::<(), ReconcileError>(
                    &intent,
                    self.config.max_metadata_entries,
                    |_| Ok(()),
                )?;
            drop(guard);
            Some(owner)
        };
        Ok(StorageReceivedSnapshot {
            envelope: envelope.clone(),
            owner,
        })
    }

    pub fn recover_forwarded_snapshots(&mut self) -> Result<Vec<StorageReceivedSnapshot>> {
        self.verify_storage()?;
        let envelopes = self.traffic.snapshots(&self.config, &self.device)?;
        let mut result = Vec::new();
        for envelope in envelopes {
            if now_ms()? >= self.config.expires_at_ms {
                self.config.permits_retained_delivery(
                    &envelope.origin.device_id,
                    &envelope.forwarder.device_id,
                )?;
                envelope.verify(
                    &envelope.origin,
                    &envelope.forwarder,
                    self.transport_identity()?.peer_identity(),
                    &envelope.channel_binding,
                )?;
                let files = envelope
                    .signed_report
                    .report
                    .manifest
                    .entries
                    .values()
                    .filter_map(|entry| entry.content.clone())
                    .collect::<Vec<_>>();
                let owner = if files.is_empty() {
                    None
                } else {
                    let id = envelope.storage_id()?;
                    let owner: EntryId = id.as_str()[..32].parse()?;
                    let old = self
                        .journal
                        .reference_reservations(
                            &self.config.space_id,
                            self.config.max_metadata_entries,
                        )?
                        .into_iter()
                        .find(|r| r.intent.owner_id == owner)
                        .ok_or(ReconcileError::Invariant(
                            "expired retained snapshot owner incomplete",
                        ))?;
                    if old.intent.scope.files != files
                        || old.intent.scope.kind != ReferenceOwnerKind::Restore
                        || old.intent.scope.space_id != self.config.space_id
                        || old.intent.scope.target_device.is_some()
                        || old.intent.created_at_ms != 0
                    {
                        return Err(ReconcileError::Invariant(
                            "expired retained snapshot owner differs",
                        ));
                    }
                    Some(owner)
                };
                for (device, sequence) in &envelope.signed_report.report.manifest.version_vector.0 {
                    if self.journal.cursor(&self.config.space_id, device)? < *sequence {
                        return Err(ReconcileError::Invariant(
                            "expired retained snapshot prefix incomplete",
                        ));
                    }
                }
                result.push(StorageReceivedSnapshot { envelope, owner });
                continue;
            }
            result.push(self.receive_forwarded_snapshot(
                &envelope,
                &envelope.origin,
                &envelope.forwarder,
                &envelope.channel_binding,
            )?);
        }
        Ok(result)
    }

    /// Admit and durably charge a snapshot chunk before reading its network body.
    pub fn admit_snapshot_chunk(
        &self,
        received: &StorageReceivedSnapshot,
        chunk: &ChunkRef,
    ) -> Result<()> {
        self.verify_storage()?;
        self.verify_approved_key(&received.envelope.origin, false)?;
        self.verify_approved_key(&received.envelope.forwarder, true)?;
        self.config.admits(
            &received.envelope.origin.device_id,
            &received.envelope.forwarder.device_id,
            now_ms()?,
        )?;
        let expected = received
            .envelope
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|file| &file.chunks)
            .any(|expected| expected == chunk);
        if !expected
            || u64::from(chunk.length) > self.config.max_request_bytes
            || received.owner.is_none()
        {
            return Err(ReconcileError::Invariant(
                "storage exact announced snapshot chunk",
            ));
        }
        if self.cas.read(chunk).is_err()
            && self
                .physical_bytes()?
                .checked_add(u64::from(chunk.length))
                .is_none_or(|sum| sum > self.config.max_stored_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "storage snapshot physical quota before block reception",
            ));
        }
        self.traffic.charge(
            &self.config,
            &self.device,
            &received
                .envelope
                .storage_id()
                .map_err(|_| ReconcileError::Invariant("snapshot charge request"))?,
            &chunk.content_id,
            "ingress",
            u64::from(chunk.length),
            now_ms()?,
        )?;
        Ok(())
    }

    pub fn ingest_snapshot_chunk(
        &mut self,
        received: &StorageReceivedSnapshot,
        chunk: &ChunkRef,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.len() != chunk.length as usize || ContentId::hash(bytes) != chunk.content_id {
            return Err(ReconcileError::Invariant("storage exact snapshot chunk"));
        }
        self.admit_snapshot_chunk(received, chunk)?;
        let owner = received
            .owner
            .as_ref()
            .ok_or(ReconcileError::Invariant("storage snapshot owner absent"))?;
        if self.cas.read(chunk).is_err()
            && self
                .physical_bytes()?
                .checked_add(bytes.len() as u64)
                .is_none_or(|sum| sum > self.config.max_stored_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "storage snapshot physical quota changed",
            ));
        }
        let (guard, ()) = self.journal.with_reserved_chunk::<(), ReconcileError>(
            &self.config.space_id,
            owner,
            &chunk.content_id,
            self.config.max_metadata_entries,
            |expected| {
                if expected != chunk || self.cas.put(bytes)? != *chunk {
                    return Err(ReconcileError::Invariant("storage snapshot reserved chunk"));
                }
                self.cas.read(chunk)?;
                Ok(())
            },
        )?;
        drop(guard);
        Ok(())
    }

    /// Authorize and charge the exact announced chunk before its block is read.
    /// Failed reads retain a logical charge; retries of this page/chunk are idempotent.
    pub fn admit_forwarded_chunk(
        &self,
        received: &StorageReceivedPage,
        chunk: &ChunkRef,
    ) -> Result<()> {
        self.verify_storage()?;
        let page = &received.verified;
        self.verify_approved_key(page.origin(), false)?;
        self.verify_approved_key(page.forwarder(), true)?;
        self.config.admits(
            &page.origin().device_id,
            &page.forwarder().device_id,
            now_ms()?,
        )?;
        if Self::page_chunks(page)?.get(&chunk.content_id) != Some(chunk)
            || u64::from(chunk.length) > self.config.max_request_bytes
            || received.owner.is_none()
        {
            return Err(ReconcileError::Invariant(
                "storage exact announced forwarded chunk",
            ));
        }
        if self.cas.read(chunk).is_err()
            && self
                .physical_bytes()?
                .checked_add(u64::from(chunk.length))
                .is_none_or(|total| total > self.config.max_stored_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "storage physical quota before block reception",
            ));
        }
        self.traffic
            .charge(
                &self.config,
                &self.device,
                &page
                    .storage_id()
                    .map_err(|_| ReconcileError::Invariant("storage request"))?,
                &chunk.content_id,
                "ingress",
                u64::from(chunk.length),
                now_ms()?,
            )
            .map_err(Into::into)
    }

    pub fn ingest_forwarded_chunk(
        &mut self,
        received: &StorageReceivedPage,
        chunk: &ChunkRef,
        bytes: &[u8],
    ) -> Result<()> {
        self.verify_storage()?;
        let page = &received.verified;
        self.verify_approved_key(page.origin(), false)?;
        self.verify_approved_key(page.forwarder(), true)?;
        self.config.admits(
            &page.origin().device_id,
            &page.forwarder().device_id,
            now_ms()?,
        )?;
        let expected = Self::page_chunks(page)?;
        if expected.get(&chunk.content_id) != Some(chunk)
            || bytes.len() != chunk.length as usize
            || ContentId::hash(bytes) != chunk.content_id
            || bytes.len() as u64 > self.config.max_request_bytes
        {
            return Err(ReconcileError::Invariant(
                "storage exact expected forwarded chunk",
            ));
        }
        self.admit_forwarded_chunk(received, chunk)?;
        let owner = received
            .owner
            .as_ref()
            .ok_or(ReconcileError::Invariant("storage content owner absent"))?;
        if self.cas.read(chunk).is_err()
            && self
                .physical_bytes()?
                .checked_add(bytes.len() as u64)
                .is_none_or(|total| total > self.config.max_stored_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "storage physical quota changed",
            ));
        }
        let (guard, ()) = self.journal.with_reserved_chunk::<(), ReconcileError>(
            &self.config.space_id,
            owner,
            &chunk.content_id,
            self.config.max_metadata_entries,
            |expected| {
                if expected != chunk || self.cas.put(bytes)? != *chunk {
                    return Err(ReconcileError::Invariant(
                        "storage reserved chunk publication",
                    ));
                }
                self.cas.read(chunk)?;
                Ok(())
            },
        )?;
        drop(guard);
        Ok(())
    }

    /// Report stored-only state from the exact retained report, owner and CAS audit.
    pub fn stored_snapshot_receipt(
        &self,
        received: &StorageReceivedSnapshot,
    ) -> Result<SignedStorageSnapshotReceipt> {
        self.verify_storage()?;
        let envelope = &received.envelope;
        self.verify_approved_key(&envelope.origin, false)?;
        self.verify_approved_key(&envelope.forwarder, true)?;
        self.config.admits(
            &envelope.origin.device_id,
            &envelope.forwarder.device_id,
            now_ms()?,
        )?;
        let identity = self.transport_identity()?;
        envelope.verify(
            &envelope.origin,
            &envelope.forwarder,
            identity.peer_identity(),
            &envelope.channel_binding,
        )?;
        if !self
            .traffic
            .snapshots(&self.config, &self.device)?
            .iter()
            .any(|retained| {
                retained.origin == envelope.origin
                    && retained.receiver == envelope.receiver
                    && retained.signed_report == envelope.signed_report
            })
        {
            return Err(ReconcileError::Invariant(
                "snapshot receipt exact retained report absent",
            ));
        }
        let files = envelope
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.clone())
            .collect::<Vec<_>>();
        if !files.is_empty() {
            let storage_id = envelope.storage_id()?;
            let expected: EntryId = storage_id.as_str()[..32].parse()?;
            if received.owner.as_ref() != Some(&expected) {
                return Err(ReconcileError::Invariant("snapshot receipt exact owner"));
            }
            let owner = self
                .journal
                .reference_reservations(&self.config.space_id, self.config.max_metadata_entries)?
                .into_iter()
                .find(|owner| owner.intent.owner_id == expected)
                .ok_or(ReconcileError::Invariant(
                    "snapshot receipt durable owner absent",
                ))?;
            if owner.state != "reserved"
                || owner.intent.scope.kind != ReferenceOwnerKind::Restore
                || owner.intent.scope.space_id != self.config.space_id
                || owner.intent.scope.target_device.is_some()
                || owner.intent.scope.files != files
                || owner.intent.created_at_ms != 0
            {
                return Err(ReconcileError::Invariant(
                    "snapshot receipt exact durable owner differs",
                ));
            }
        } else if received.owner.is_some() {
            return Err(ReconcileError::Invariant(
                "empty snapshot receipt unexpected owner",
            ));
        }
        let mut chunks = BTreeMap::new();
        for file in &files {
            for chunk in &file.chunks {
                if chunks
                    .insert(chunk.content_id.clone(), chunk.clone())
                    .is_some_and(|old| old != *chunk)
                {
                    return Err(ReconcileError::Invariant(
                        "snapshot receipt conflicting chunk lengths",
                    ));
                }
            }
        }
        let mut verified_chunks = 0u32;
        let mut verified_bytes = 0u64;
        let protected = self.journal.protected_objects()?;
        for chunk in chunks.values() {
            if !protected.contains(&chunk.content_id) {
                return Err(ReconcileError::Invariant(
                    "snapshot receipt exact content pin missing",
                ));
            }
            let guard = self.journal.acquire_cas_access(&chunk.content_id)?;
            if self.cas.read(chunk).is_ok() {
                verified_chunks =
                    verified_chunks
                        .checked_add(1)
                        .ok_or(ReconcileError::ResourceLimit(
                            "snapshot receipt chunk count",
                        ))?;
                verified_bytes = verified_bytes
                    .checked_add(u64::from(chunk.length))
                    .ok_or(ReconcileError::ResourceLimit("snapshot receipt byte count"))?;
            }
            drop(guard);
        }
        let complete = files.iter().all(|file| self.cas.verify(file).is_ok());
        let state = if complete {
            ForwardStoreState::ContentClosed
        } else if verified_chunks == 0 {
            ForwardStoreState::MetadataOnly
        } else {
            ForwardStoreState::PartialStaging
        };
        let signed = SignedStorageSnapshotReceipt::sign(
            &identity,
            StorageSnapshotReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.config.space_id.clone(),
                storage_device: self.device.clone(),
                origin_device: envelope.origin.device_id.clone(),
                storage_id: envelope.storage_id()?,
                report_id: envelope.report_id()?,
                channel_binding: envelope.channel_binding.clone(),
                state,
                verified_chunks,
                verified_bytes,
            },
        )?;
        signed.verify(identity.peer_identity(), envelope)?;
        Ok(signed)
    }

    pub fn stored_receipt(
        &self,
        received: &StorageReceivedPage,
    ) -> Result<SignedForwardStoreReceipt> {
        self.verify_storage()?;
        let page = &received.verified;
        self.verify_approved_key(page.origin(), false)?;
        self.verify_approved_key(page.forwarder(), true)?;
        self.config.admits(
            &page.origin().device_id,
            &page.forwarder().device_id,
            now_ms()?,
        )?;
        let chunks = Self::page_chunks(page)?;
        let mut bytes = 0u64;
        let mut verified = 0u32;
        for chunk in chunks.values() {
            if self.cas.read(chunk).is_ok() {
                bytes += u64::from(chunk.length);
                verified += 1;
            }
        }
        let complete =
            page.page()
                .operations
                .iter()
                .all(|signed| match &signed.operation.payload.change {
                    Change::Put { entry } => entry
                        .content
                        .as_ref()
                        .is_none_or(|file| self.cas.verify(file).is_ok()),
                    _ => true,
                });
        let state = if complete {
            ForwardStoreState::ContentClosed
        } else if verified == 0 {
            ForwardStoreState::MetadataOnly
        } else {
            ForwardStoreState::PartialStaging
        };
        let identity = self.transport_identity()?;
        let receipt = SignedForwardStoreReceipt::sign(
            &identity,
            ForwardStoreReceipt {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.config.space_id.clone(),
                storage_device: self.device.clone(),
                origin_device: page.origin().device_id.clone(),
                request_id: page
                    .request_id()
                    .map_err(|_| ReconcileError::Invariant("storage request"))?,
                channel_binding: page.page().channel_binding.clone(),
                after_sequence: page.page().after_sequence,
                received_sequence: page
                    .page()
                    .operations
                    .last()
                    .map_or(page.page().after_sequence, |signed| {
                        signed.operation.payload.origin_seq
                    }),
                state,
                verified_chunks: verified,
                verified_bytes: bytes,
            },
        )
        .map_err(|_| ReconcileError::Invariant("stored-only receipt signing"))?;
        receipt
            .verify(identity.peer_identity(), page.page())
            .map_err(|_| ReconcileError::Invariant("stored receipt post-sign verification"))?;
        Ok(receipt)
    }

    pub fn original_operations(
        &self,
        origin: &PeerIdentity,
        after: u64,
    ) -> Result<Vec<SignedOperation>> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        if !self.config.enabled
            || !self.config.approved_origins.contains_key(&origin.device_id)
            || origin.space_id != self.config.space_id
        {
            return Err(ReconcileError::Invariant(
                "forward original current approval",
            ));
        }
        let mut result = Vec::new();
        for operation in self.journal.operations(&self.config.space_id)? {
            if operation.payload.origin_device_id != origin.device_id
                || operation.payload.origin_seq <= after
            {
                continue;
            }
            if result.len() >= sync_extend_core_model::operation_batch::MAX_OPERATION_BATCH {
                break;
            }
            let proof = self
                .journal
                .original_provenance(
                    &self.config.space_id,
                    &origin.device_id,
                    operation.payload.origin_seq,
                )?
                .ok_or(ReconcileError::Invariant(
                    "stored original signature absent",
                ))?;
            if proof.public_key != origin.public_key || proof.operation != operation {
                return Err(ReconcileError::Invariant(
                    "stored original identity differs",
                ));
            }
            result.push(SignedOperation {
                operation,
                signature: proof.signature,
            });
        }
        result.sort_by_key(|signed| signed.operation.payload.origin_seq);
        Ok(result)
    }

    /// Prepare one original page from a client's retained independently signed log.
    /// The forwarding envelope grants no authority to rewrite origin operations.
    pub fn local_forwarding_page(
        local: &crate::LocalSpace,
        origin: &PeerIdentity,
        storage: &PeerIdentity,
        binding: ContentId,
        after: u64,
    ) -> Result<SignedForwardedOperationPage> {
        local.verify_root()?;
        if local.read_transport_peer(&origin.device_id)? != *origin
            || local.read_transport_peer(&storage.device_id)? != *storage
        {
            return Err(ReconcileError::Invariant(
                "client forwarding current independent pairing",
            ));
        }
        let identity = local.transport_identity()?;
        let mut operations = Vec::new();
        for operation in local.journal.operations(&local.space_id)? {
            if operation.payload.origin_device_id != origin.device_id
                || operation.payload.origin_seq <= after
            {
                continue;
            }
            if operations.len() >= sync_extend_core_model::operation_batch::MAX_OPERATION_BATCH {
                break;
            }
            let proof = local
                .journal
                .original_provenance(
                    &local.space_id,
                    &origin.device_id,
                    operation.payload.origin_seq,
                )?
                .ok_or(ReconcileError::Invariant(
                    "client forward original signature missing",
                ))?;
            if proof.operation != operation || proof.public_key != origin.public_key {
                return Err(ReconcileError::Invariant(
                    "client forward original signature differs",
                ));
            }
            operations.push(SignedOperation {
                operation,
                signature: proof.signature,
            });
        }
        operations.sort_by_key(|signed| signed.operation.payload.origin_seq);
        SignedForwardedOperationPage::sign(
            &identity,
            origin,
            sync_extend_transport::ForwardedOperationPage {
                protocol_version: PROTOCOL_VERSION,
                space_id: local.space_id.clone(),
                origin_device: origin.device_id.clone(),
                forwarding_device: identity.peer_identity().device_id.clone(),
                receiver_device: storage.device_id.clone(),
                channel_binding: binding,
                after_sequence: after,
                tip_sequence: local.journal.cursor(&local.space_id, &origin.device_id)?,
                operations,
            },
        )
        .map_err(|_| ReconcileError::Invariant("client authenticated forwarding page"))
    }

    pub fn local_forwarded_chunk(
        local: &crate::LocalSpace,
        origin: &PeerIdentity,
        storage: &PeerIdentity,
        signed: &SignedForwardedOperationPage,
        chunk: &ChunkRef,
    ) -> Result<Vec<u8>> {
        local.verify_root()?;
        if local.read_transport_peer(&origin.device_id)? != *origin
            || local.read_transport_peer(&storage.device_id)? != *storage
        {
            return Err(ReconcileError::Invariant(
                "client forwarding approval changed",
            ));
        }
        let identity = local.transport_identity()?;
        let verified = signed
            .verify(
                origin,
                identity.peer_identity(),
                storage,
                &signed.page.channel_binding,
                signed.page.after_sequence,
            )
            .map_err(|_| ReconcileError::Invariant("client forwarding signed chunk scope"))?;
        if Self::page_chunks(&verified)?.get(&chunk.content_id) != Some(chunk) {
            return Err(ReconcileError::Invariant(
                "client forward chunk not original page",
            ));
        }
        if u64::from(chunk.length) > local.limits.max_staging_bytes {
            return Err(ReconcileError::ResourceLimit("client forward chunk bytes"));
        }
        Ok(local.cas.read(chunk)?)
    }

    /// Forward a retained report with its original signature and fresh channel envelope.
    /// The paired forwarding client never signs a foreign report as its own.
    pub fn local_forwarding_snapshot(
        local: &crate::LocalSpace,
        origin: &PeerIdentity,
        storage: &PeerIdentity,
        binding: ContentId,
        report: sync_extend_transport::SignedStorageSnapshotReport,
    ) -> Result<ForwardedSnapshotEnvelope> {
        local.verify_root()?;
        if local.read_transport_peer(&origin.device_id)? != *origin
            || local.read_transport_peer(&storage.device_id)? != *storage
        {
            return Err(ReconcileError::Invariant(
                "client snapshot forwarding current independent pairing",
            ));
        }
        report
            .verify(origin)
            .map_err(|_| ReconcileError::Invariant("client original snapshot signature"))?;
        for (device, sequence) in &report.report.manifest.version_vector.0 {
            if local.journal.cursor(&local.space_id, device)? < *sequence {
                return Err(ReconcileError::Invariant(
                    "client snapshot original prefix missing",
                ));
            }
        }
        let identity = local.transport_identity()?;
        ForwardedSnapshotEnvelope::sign(&identity, origin, storage, binding, report)
            .map_err(|_| ReconcileError::Invariant("client original snapshot envelope"))
    }

    pub fn local_snapshot_chunk(
        local: &crate::LocalSpace,
        origin: &PeerIdentity,
        storage: &PeerIdentity,
        envelope: &ForwardedSnapshotEnvelope,
        chunk: &ChunkRef,
    ) -> Result<Vec<u8>> {
        local.verify_root()?;
        if local.read_transport_peer(&origin.device_id)? != *origin
            || local.read_transport_peer(&storage.device_id)? != *storage
        {
            return Err(ReconcileError::Invariant(
                "client snapshot forwarding approval changed",
            ));
        }
        let identity = local.transport_identity()?;
        envelope
            .verify(
                origin,
                identity.peer_identity(),
                storage,
                &envelope.channel_binding,
            )
            .map_err(|_| ReconcileError::Invariant("client snapshot signed chunk scope"))?;
        if !envelope
            .signed_report
            .report
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|file| &file.chunks)
            .any(|expected| expected == chunk)
            || u64::from(chunk.length) > local.limits.max_staging_bytes
        {
            return Err(ReconcileError::Invariant(
                "client chunk is outside original snapshot report",
            ));
        }
        let guard = local.journal.acquire_cas_access(&chunk.content_id)?;
        let bytes = local.cas.read(chunk)?;
        drop(guard);
        Ok(bytes)
    }

    pub fn forwarded_offer(
        &self,
        origin: &PeerIdentity,
        requester: &PeerIdentity,
        binding: ContentId,
        after: u64,
    ) -> Result<SignedForwardedOperationPage> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        self.verify_approved_key(requester, true)?;
        self.config
            .permits_retained_delivery(&origin.device_id, &requester.device_id)?;
        let identity = self.transport_identity()?;
        let operations = self.original_operations(origin, after)?;
        let tip = self
            .journal
            .cursor(&self.config.space_id, &origin.device_id)?;
        if after > tip {
            return Err(ReconcileError::Invariant(
                "storage egress cursor beyond retained prefix",
            ));
        }
        SignedForwardedOperationPage::sign(
            &identity,
            origin,
            sync_extend_transport::ForwardedOperationPage {
                protocol_version: PROTOCOL_VERSION,
                space_id: self.config.space_id.clone(),
                origin_device: origin.device_id.clone(),
                forwarding_device: self.device.clone(),
                receiver_device: requester.device_id.clone(),
                channel_binding: binding,
                after_sequence: after,
                tip_sequence: tip,
                operations,
            },
        )
        .map_err(|_| ReconcileError::Invariant("storage current egress signed page"))
    }

    pub fn verify_forwarding_peer(&self, peer: &PeerIdentity) -> Result<()> {
        self.verify_storage()?;
        self.verify_approved_key(peer, true)?;
        if !self.config.enabled {
            return Err(ReconcileError::Invariant(
                "storage forwarding policy disabled",
            ));
        }
        Ok(())
    }

    /// Rebind the latest retained original report to this authenticated requesting peer.
    pub fn forwarded_snapshot_offer(
        &self,
        origin: &PeerIdentity,
        requester: &PeerIdentity,
        binding: ContentId,
    ) -> Result<Option<ForwardedSnapshotEnvelope>> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        self.verify_approved_key(requester, true)?;
        self.config
            .permits_retained_delivery(&origin.device_id, &requester.device_id)?;
        let report = self
            .traffic
            .snapshots(&self.config, &self.device)?
            .into_iter()
            .filter(|envelope| envelope.origin == *origin)
            .max_by_key(|envelope| envelope.signed_report.report.reported_at_ms)
            .map(|envelope| envelope.signed_report);
        let Some(report) = report else {
            return Ok(None);
        };
        let identity = self.transport_identity()?;
        ForwardedSnapshotEnvelope::sign(&identity, origin, requester, binding, report)
            .map(Some)
            .map_err(|_| ReconcileError::Invariant("storage rebound original snapshot offer"))
    }

    pub fn read_snapshot_chunk(
        &self,
        origin: &PeerIdentity,
        requester: &PeerIdentity,
        offered: &ForwardedSnapshotEnvelope,
        binding: &ContentId,
        chunk: &ChunkRef,
    ) -> Result<Vec<u8>> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        self.verify_approved_key(requester, true)?;
        self.config
            .permits_retained_delivery(&origin.device_id, &requester.device_id)?;
        let identity = self.transport_identity()?;
        offered
            .verify(origin, identity.peer_identity(), requester, binding)
            .map_err(|_| ReconcileError::Invariant("storage snapshot egress offer scope"))?;
        if !self
            .traffic
            .snapshots(&self.config, &self.device)?
            .iter()
            .any(|retained| {
                retained.origin == *origin && retained.signed_report == offered.signed_report
            })
            || !offered
                .signed_report
                .report
                .manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
                .flat_map(|file| &file.chunks)
                .any(|expected| expected == chunk)
        {
            return Err(ReconcileError::Invariant(
                "storage snapshot egress must match exact retained original report",
            ));
        }
        if !self
            .journal
            .protected_objects()?
            .contains(&chunk.content_id)
        {
            return Err(ReconcileError::Invariant(
                "storage snapshot egress lacks retained owner",
            ));
        }
        self.traffic.charge(
            &self.config,
            &self.device,
            &offered
                .storage_id()
                .map_err(|_| ReconcileError::Invariant("snapshot egress request identity"))?,
            &chunk.content_id,
            "egress",
            u64::from(chunk.length),
            now_ms()?,
        )?;
        let guard = self.journal.acquire_cas_access(&chunk.content_id)?;
        let bytes = self.cas.read(chunk)?;
        drop(guard);
        Ok(bytes)
    }

    /// Only verified chunks from the offered original page may leave the storage node.
    /// The current requesting device is independently approved and charged before I/O.
    pub fn read_forwarded_chunk(
        &self,
        origin: &PeerIdentity,
        requester: &PeerIdentity,
        offered: &SignedForwardedOperationPage,
        binding: &ContentId,
        chunk: &ChunkRef,
    ) -> Result<Vec<u8>> {
        self.verify_storage()?;
        self.verify_approved_key(origin, false)?;
        self.verify_approved_key(requester, true)?;
        self.config
            .permits_retained_delivery(&origin.device_id, &requester.device_id)?;
        let identity = self.transport_identity()?;
        let page = offered
            .verify(
                origin,
                identity.peer_identity(),
                requester,
                binding,
                offered.page.after_sequence,
            )
            .map_err(|_| ReconcileError::Invariant("storage egress authenticated offer"))?;
        if Self::page_chunks(&page)?.get(&chunk.content_id) != Some(chunk) {
            return Err(ReconcileError::Invariant(
                "storage egress chunk outside original offer",
            ));
        }
        if !self
            .journal
            .protected_objects()?
            .contains(&chunk.content_id)
        {
            return Err(ReconcileError::Invariant(
                "storage egress content lacks retained owner",
            ));
        }
        for signed in &page.page().operations {
            let proof = self
                .journal
                .original_provenance(
                    &self.config.space_id,
                    &origin.device_id,
                    signed.operation.payload.origin_seq,
                )?
                .ok_or(ReconcileError::Invariant("storage egress original absent"))?;
            if proof.public_key != origin.public_key
                || proof.operation != signed.operation
                || proof.signature != signed.signature
            {
                return Err(ReconcileError::Invariant("storage egress original differs"));
            }
        }
        self.traffic.charge(
            &self.config,
            &self.device,
            &page
                .storage_id()
                .map_err(|_| ReconcileError::Invariant("storage egress request"))?,
            &chunk.content_id,
            "egress",
            u64::from(chunk.length),
            now_ms()?,
        )?;
        Ok(self.cas.read(chunk)?)
    }

    fn verify_approved_key(&self, peer: &PeerIdentity, forwarding: bool) -> Result<()> {
        peer.validate()
            .map_err(|_| ReconcileError::Invariant("storage peer key invalid"))?;
        let keys = if forwarding {
            &self.config.approved_forwarders
        } else {
            &self.config.approved_origins
        };
        let public = peer
            .public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if peer.space_id != self.config.space_id
            || keys.get(&peer.device_id).map(ContentId::as_str) != Some(public.as_str())
        {
            return Err(ReconcileError::Invariant(
                "storage independent approved key differs",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_storage(&self) -> Result<()> {
        self.data_identity.verify(&self.config.data_dir)?;
        for (path, identity) in &self.file_identities {
            identity.verify(path)?;
        }
        if self.journal.state("space_id")?.as_deref() != Some(self.config.space_id.as_str())
            || self.journal.state("device_id")?.as_deref() != Some(self.device.as_str())
            || self.journal.state("worktree")?.is_some()
            || self.journal.state("storage_role")?.as_deref() != Some("storage-v1")
        {
            return Err(ReconcileError::Invariant(
                "storage immutable role identity differs",
            ));
        }
        self.traffic.charged_bytes(&self.config, &self.device)?;
        Ok(())
    }

    fn page_chunks(page: &VerifiedForwardedPage) -> Result<BTreeMap<ContentId, ChunkRef>> {
        let mut chunks = BTreeMap::new();
        for original in &page.page().operations {
            if let Change::Put { entry } = &original.operation.payload.change {
                if let Some(file) = &entry.content {
                    for chunk in &file.chunks {
                        if chunks.len() >= sync_extend_core_model::limits::MAX_CHUNKS {
                            return Err(ReconcileError::ResourceLimit(
                                "storage page chunk inventory",
                            ));
                        }
                        if chunks
                            .insert(chunk.content_id.clone(), chunk.clone())
                            .is_some_and(|old| old != *chunk)
                        {
                            return Err(ReconcileError::Invariant(
                                "storage conflicting chunk length",
                            ));
                        }
                    }
                }
            }
        }
        Ok(chunks)
    }

    fn reserved_chunks(&self) -> Result<BTreeMap<ContentId, ChunkRef>> {
        let mut chunks = BTreeMap::new();
        for owner in self
            .journal
            .reference_reservations(&self.config.space_id, self.config.max_metadata_entries)?
        {
            if owner.state != "reserved" {
                continue;
            }
            for file in &owner.intent.scope.files {
                for chunk in &file.chunks {
                    if chunks
                        .insert(chunk.content_id.clone(), chunk.clone())
                        .is_some_and(|prior| prior != *chunk)
                    {
                        return Err(ReconcileError::Invariant(
                            "storage prior reservation conflicting hash length",
                        ));
                    }
                    if chunks.len() > self.config.max_metadata_entries {
                        return Err(ReconcileError::ResourceLimit(
                            "storage outstanding chunk inventory",
                        ));
                    }
                }
            }
        }
        Ok(chunks)
    }

    fn physical_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        let mut count = 0usize;
        let root = self.config.data_dir.join("cas");
        for directory in [&root, &root.join("objects"), &root.join("tmp")] {
            let metadata = fs::symlink_metadata(directory)?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || sync_extend_cas::is_reparse(&metadata)
            {
                return Err(ReconcileError::Invariant("storage CAS namespace differs"));
            }
        }
        for bucket in fs::read_dir(root.join("objects"))? {
            let bucket = bucket?;
            count += 1;
            if count > self.config.max_metadata_entries {
                return Err(ReconcileError::ResourceLimit("storage bucket inventory"));
            }
            let metadata = fs::symlink_metadata(bucket.path())?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || sync_extend_cas::is_reparse(&metadata)
            {
                return Err(ReconcileError::Invariant("storage CAS bucket differs"));
            }
            for entry in fs::read_dir(bucket.path())? {
                let entry = entry?;
                count += 1;
                if count > self.config.max_metadata_entries {
                    return Err(ReconcileError::ResourceLimit("storage inventory"));
                }
                let metadata = fs::symlink_metadata(entry.path())?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || sync_extend_cas::is_reparse(&metadata)
                {
                    return Err(ReconcileError::Invariant("storage CAS slot differs"));
                }
                total = total
                    .checked_add(metadata.len())
                    .ok_or(ReconcileError::ResourceLimit("storage byte inventory"))?;
            }
        }
        for entry in fs::read_dir(root.join("tmp"))? {
            let entry = entry?;
            count += 1;
            let metadata = fs::symlink_metadata(entry.path())?;
            if count > self.config.max_metadata_entries
                || !metadata.is_file()
                || metadata.file_type().is_symlink()
                || sync_extend_cas::is_reparse(&metadata)
            {
                return Err(ReconcileError::Invariant(
                    "storage temporary inventory differs",
                ));
            }
            total = total
                .checked_add(metadata.len())
                .ok_or(ReconcileError::ResourceLimit(
                    "storage temporary byte inventory",
                ))?;
        }
        if total > self.config.max_stored_bytes {
            return Err(ReconcileError::ResourceLimit(
                "storage physical quota exceeded",
            ));
        }
        Ok(total)
    }

    pub fn status(&self) -> Result<StorageNodeStatus> {
        self.verify_storage()?;
        self.journal.integrity_check()?;
        let owners = self
            .journal
            .reference_reservations(&self.config.space_id, self.config.max_metadata_entries)?;
        let mut chunks = BTreeMap::new();
        for owner in owners {
            if owner.state != "reserved" {
                continue;
            }
            for file in owner.intent.scope.files {
                for chunk in file.chunks {
                    chunks.insert(chunk.content_id, chunk.length);
                }
            }
        }
        let protected_bytes = chunks.values().try_fold(0u64, |sum, length| {
            sum.checked_add(u64::from(*length))
                .ok_or(ReconcileError::ResourceLimit("storage protected byte sum"))
        })?;
        let envelopes = self.traffic.snapshots(&self.config, &self.device)?;
        let mut latest = BTreeMap::<DeviceId, u64>::new();
        for envelope in &envelopes {
            latest
                .entry(envelope.origin.device_id.clone())
                .and_modify(|old| *old = (*old).max(envelope.signed_report.report.reported_at_ms))
                .or_insert(envelope.signed_report.report.reported_at_ms);
        }
        let mut snapshots = Vec::new();
        for envelope in envelopes {
            let report = envelope.signed_report.report;
            let mut missing = 0usize;
            let mut present = 0usize;
            let mut complete = true;
            for file in report
                .manifest
                .entries
                .values()
                .filter_map(|entry| entry.content.as_ref())
            {
                for chunk in &file.chunks {
                    if self.cas.read(chunk).is_ok() {
                        present += 1;
                    } else {
                        missing += 1;
                    }
                }
                complete &= self.cas.verify(file).is_ok();
            }
            snapshots.push(StorageSnapshotStatus {
                origin_device: report.source_device.clone(),
                snapshot_id: report.snapshot_id,
                reported_at_ms: report.reported_at_ms,
                last_reported: latest.get(&report.source_device) == Some(&report.reported_at_ms),
                state: if complete {
                    ForwardStoreState::ContentClosed
                } else if present == 0 {
                    ForwardStoreState::MetadataOnly
                } else {
                    ForwardStoreState::PartialStaging
                },
                missing_chunks: missing,
                native_applied: false,
            });
        }
        let full_last_reported_content_complete = self.config.role
            == sync_extend_core_model::storage_node::StorageRole::Full
            && self.config.approved_origins.keys().all(|origin| {
                let mut reported = false;
                let complete = snapshots
                    .iter()
                    .filter(|snapshot| &snapshot.origin_device == origin && snapshot.last_reported)
                    .all(|snapshot| {
                        reported = true;
                        snapshot.state == ForwardStoreState::ContentClosed
                    });
                reported && complete
            });
        let pages = self.traffic.pages(&self.config, &self.device)?;
        let files = pages
            .iter()
            .flat_map(|envelope| &envelope.signed_page.page.operations)
            .filter_map(|signed| match &signed.operation.payload.change {
                Change::Put { entry } => entry.content.as_ref(),
                _ => None,
            })
            .collect::<Vec<_>>();
        let state = if files.is_empty() && snapshots.is_empty() {
            ForwardStoreState::MetadataOnly
        } else if files.iter().all(|file| self.cas.verify(file).is_ok())
            && snapshots
                .iter()
                .all(|snapshot| snapshot.state == ForwardStoreState::ContentClosed)
        {
            ForwardStoreState::ContentClosed
        } else if self.physical_bytes()? == 0 {
            ForwardStoreState::MetadataOnly
        } else {
            ForwardStoreState::PartialStaging
        };
        Ok(StorageNodeStatus {
            space_id: self.config.space_id.clone(),
            device_id: self.device.clone(),
            state,
            worktree: None,
            native_applied: false,
            backup_complete: false,
            protected_bytes,
            physical_cas_bytes: self.physical_bytes()?,
            expired: now_ms()? >= self.config.expires_at_ms,
            charged_logical_delivery_bytes: self
                .traffic
                .charged_bytes(&self.config, &self.device)?,
            snapshots,
            role: self.config.role,
            full_last_reported_content_complete,
        })
    }
}
