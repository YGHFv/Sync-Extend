//! Exact retained handle observations are inputs, never physical deletion authority.
use crate::{ReconcileError, Result, StorageNode};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SpaceId};

#[derive(Debug, serde::Serialize)]
pub struct StorageRetirementObjectObservation {
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub storage_policy: ContentId,
    pub storage_id: ContentId,
    pub owner_id: EntryId,
    pub content_id: ContentId,
    pub original_metadata_hash: ContentId,
    pub physical_identity: ContentId,
    pub data_identity: ContentId,
    pub cas_identity: ContentId,
    pub objects_identity: ContentId,
    pub shard_identity: ContentId,
    pub length: u32,
    pub modified_at_ns: u64,
    pub exact_retired_metadata_verified: bool,
    pub current_other_owner_protection_absent: bool,
    pub content_hash_verified: bool,
    pub single_link_verified: bool,
    pub deletion_authorized: bool,
    pub remote_backup_complete: bool,
}

#[cfg(windows)]
pub struct StorageRetirementInspection<'a> {
    _storage: &'a StorageNode,
    _session: sync_extend_cas::CasSessionGuard,
    _directories: Vec<sync_extend_platform_fs::LockedDirectory>,
    _file: sync_extend_platform_fs::GuardedReadFile,
    observation: StorageRetirementObjectObservation,
}

#[cfg(windows)]
impl StorageRetirementInspection<'_> {
    pub fn observation(&self) -> &StorageRetirementObjectObservation {
        &self.observation
    }
}

impl StorageNode {
    #[cfg(not(windows))]
    pub fn inspect_retired_storage_object(
        &self,
        _: &ContentId,
        _: &ContentId,
    ) -> Result<StorageRetirementObjectObservation> {
        Err(ReconcileError::Invariant(
            "storage retirement exact handle inspection requires Windows fixed local NTFS",
        ))
    }

    /// Retain the storage instance, CAS reader guard, ancestors and exact file.
    /// A writer must perform fresh exclusive admission under its own durable protocol.
    #[cfg(windows)]
    pub fn inspect_retired_storage_object<'a>(
        &'a self,
        storage_id: &ContentId,
        content_id: &ContentId,
    ) -> Result<StorageRetirementInspection<'a>> {
        use crate::{filesystem::physical_identity, guarded_mutation::directory_chain};
        use std::io::Read;
        use sync_extend_platform_fs::GuardedReadFile;

        self.verify_storage()?;
        let session = self.cas.acquire_session()?;
        self.journal.with_gc_diagnostics(
            &self.config.space_id,
            self.config.max_metadata_entries,
            |_| {
                let (owner_id, chunks) = self.retired_storage_chunks(storage_id)?;
                let chunk = chunks.get(content_id).ok_or(ReconcileError::Invariant(
                    "retired storage exact chunk absent from original owner",
                ))?;
                if !(1..=4 * 1024 * 1024).contains(&chunk.length)
                    || self.journal.protected_objects()?.contains(content_id)
                {
                    return Err(ReconcileError::Invariant(
                        "retired storage object protected or exceeds chunk bounds",
                    ));
                }
                self.journal.require_cas_access(content_id)?;
                let path = self.cas.object_path(content_id);
                let shard = path.parent().ok_or(ReconcileError::Invariant(
                    "retired storage CAS shard absent",
                ))?;
                let directories = directory_chain(shard)?;
                for directory in &directories {
                    directory.require_case_insensitive()?;
                }
                let file = GuardedReadFile::open(&path)?;
                file.verify_single_link()?;
                let before = file.reader().metadata()?;
                let identity = ContentId::hash(file.key()?.to_string().as_bytes());
                if physical_identity(&path)? != identity || before.len() != u64::from(chunk.length)
                {
                    return Err(ReconcileError::Unstable);
                }
                let mut hash = blake3::Hasher::new();
                let mut bytes = 0u64;
                let mut buffer = [0u8; 65536];
                let mut reader = file.reader();
                loop {
                    let count = reader.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    bytes =
                        bytes
                            .checked_add(count as u64)
                            .ok_or(ReconcileError::ResourceLimit(
                                "retired storage object length",
                            ))?;
                    if bytes > u64::from(chunk.length) {
                        return Err(ReconcileError::Unstable);
                    }
                    hash.update(&buffer[..count]);
                }
                let modified_at_ns = u64::try_from(
                    before
                        .modified()?
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| ReconcileError::Invariant("retired storage object timestamp"))?
                        .as_nanos(),
                )
                .map_err(|_| {
                    ReconcileError::Invariant("retired storage object timestamp overflow")
                })?;
                file.verify_single_link()?;
                let after = file.reader().metadata()?;
                if bytes != u64::from(chunk.length)
                    || ContentId::from_hasher(&hash) != *content_id
                    || physical_identity(&path)? != identity
                    || before.len() != after.len()
                    || before.modified()? != after.modified()?
                {
                    return Err(ReconcileError::Invariant(
                        "retired storage object hash or identity changed",
                    ));
                }
                self.verify_storage()?;
                if self.journal.protected_objects()?.contains(content_id) {
                    return Err(ReconcileError::Invariant(
                        "retired storage object protection changed",
                    ));
                }
                let cas = self.config.data_dir.join("cas");
                let observation = StorageRetirementObjectObservation {
                    space_id: self.config.space_id.clone(),
                    storage_device: self.device.clone(),
                    storage_policy: self.config.fingerprint()?,
                    storage_id: storage_id.clone(),
                    owner_id,
                    content_id: content_id.clone(),
                    original_metadata_hash: self.retained_retirement_metadata_hash(storage_id)?,
                    physical_identity: identity,
                    data_identity: physical_identity(&self.config.data_dir)?,
                    cas_identity: physical_identity(&cas)?,
                    objects_identity: physical_identity(&cas.join("objects"))?,
                    shard_identity: physical_identity(shard)?,
                    length: chunk.length,
                    modified_at_ns,
                    exact_retired_metadata_verified: true,
                    current_other_owner_protection_absent: true,
                    content_hash_verified: true,
                    single_link_verified: true,
                    deletion_authorized: false,
                    remote_backup_complete: false,
                };
                Ok(StorageRetirementInspection {
                    _storage: self,
                    _session: session,
                    _directories: directories,
                    _file: file,
                    observation,
                })
            },
        )
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, serde::Serialize)]
pub struct UnixStorageRetirementObjectObservation {
    pub space_id: SpaceId,
    pub storage_device: DeviceId,
    pub storage_policy: ContentId,
    pub storage_id: ContentId,
    pub original_owner_id: EntryId,
    pub content_id: ContentId,
    pub original_metadata_hash: ContentId,
    pub binding: sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementBinding,
    pub expected_original:
        sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementExpectation,
    pub exact_retained_metadata_verified: bool,
    pub current_other_owner_protection_absent: bool,
    pub original_exclusive_coordination_verified: bool,
    pub content_hash_verified: bool,
    pub single_link_verified: bool,
    pub native_activation_authorized: bool,
    pub deletion_authorized: bool,
    pub backup_complete: bool,
    pub pending_resume_authorized: bool,
}

/// The storage instance outlives the original payload, same exclusive Journal
/// guard and namespace/directory loans. The observation cannot construct this.
#[cfg(target_os = "linux")]
pub struct LinuxStorageRetirementInspection<'a> {
    storage: &'a StorageNode,
    original: Option<sync_extend_platform_fs::LinuxStorageCasRetirementInspection>,
    coordination: Option<sync_extend_journal::CasAccessGuard>,
    reference: sync_extend_core_model::ChunkRef,
    observation: UnixStorageRetirementObjectObservation,
}

#[cfg(target_os = "linux")]
pub(super) fn combine_unix<T>(operation: Result<T>, closed: Result<()>) -> Result<T> {
    match (operation, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(closed)) => Err(std::io::Error::other(format!(
            "{error}; original Unix retirement closure also refused: {closed}"
        ))
        .into()),
    }
}

#[cfg(target_os = "linux")]
impl StorageNode {
    pub(super) fn unix_retirement_binding(
        &self,
        coordination: &sync_extend_journal::CasAccessGuard,
        original: &sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
    ) -> Result<sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementBinding> {
        use sync_extend_core_model::storage_retirement_unix::{
            UnixStorageRetirementBinding, UnixStorageRetirementKey, UNIX_STORAGE_RETIREMENT_VERSION,
        };
        let key = |value: sync_extend_platform_fs::UnixFileKey| UnixStorageRetirementKey {
            device: value.device,
            inode: value.inode,
        };
        let owner = self.cas.retirement_owner_observation()?;
        let inside = owner.inside_cas.as_ref().ok_or(ReconcileError::Invariant(
            "actual original v2 retirement owner lacks inside CAS",
        ))?;
        let expected = &inside.expected_layout;
        let exclusive = coordination.linux_storage_exclusive()?;
        let layout = original.layout_observation(&exclusive)?;
        let payload = original.payload_observation(&exclusive)?;
        if owner.format_version != 2
            || owner.policy_fingerprint != expected.owner_config_fingerprint
            || owner.backing_image != layout.expected_layout.backing_image.into()
            || owner.namespace != layout.namespace.into()
            || owner.runtime_mount_id != layout.runtime_mount_id
            || owner.mounted_root != layout.mounted_root.into()
            || inside.current_owner_generation != layout.owner_generation
            || expected.storage_policy != self.config.fingerprint()?
            || !payload.single_link
            || !payload.mandatory_original_write_lease
        {
            return Err(ReconcileError::Unstable);
        }
        let binding = UnixStorageRetirementBinding {
            format_version: UNIX_STORAGE_RETIREMENT_VERSION,
            owner_config_fingerprint: expected.owner_config_fingerprint.clone(),
            outside_data: key(exclusive.outside_data_key()?),
            coordination: key(exclusive.coordination_key()?),
            backing_image: key(layout.expected_layout.backing_image),
            image_filesystem_id: layout.expected_layout.image_filesystem_id,
            owner_uid: layout.expected_layout.owner_uid,
            owner_process_id: owner.process_id,
            owner_process_start_ticks: owner.process_start_ticks,
            owner_generation: layout.owner_generation,
            persistent_metadata_owner_generation: expected.persistent_metadata_owner_generation,
            namespace: key(layout.namespace),
            runtime_mount_id: layout.runtime_mount_id,
            mounted_root: key(layout.mounted_root),
            cas: key(layout.cas),
            objects: key(layout.objects),
            temporary: key(layout.temporary),
            realm: key(layout.realm),
            realm_fingerprint: expected.realm_fingerprint.clone(),
            shard: key(payload.parent),
            payload: key(payload.identity),
            length: u32::try_from(payload.length).map_err(|_| ReconcileError::Unstable)?,
            modified_seconds: payload.modified_seconds,
            modified_nanoseconds: u32::try_from(payload.modified_nanoseconds)
                .map_err(|_| ReconcileError::Unstable)?,
        };
        binding.validate()?;
        if binding.realm_fingerprint.as_str().as_bytes() != layout.expected_layout.realm_fingerprint
        {
            return Err(ReconcileError::Unstable);
        }
        original.verify(&exclusive)?;
        Ok(binding)
    }

    pub(super) fn close_unix_retirement_original(
        &self,
        coordination: sync_extend_journal::CasAccessGuard,
        original: sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
    ) -> Result<()> {
        let mut first = None;
        let directories = match original.close_file() {
            Ok(directories) => Some(directories),
            Err(error) => {
                first = Some(ReconcileError::from(error));
                None
            }
        };
        if let Err(error) = coordination.close_linux_storage_original() {
            first.get_or_insert(error.into());
        }
        if let Some(directories) = directories {
            if let Err(error) = directories.close() {
                first.get_or_insert(error.into());
            }
        }
        if let Err(error) = self.cas.retirement_owner_observation() {
            first.get_or_insert(error);
        }
        if let Some(error) = first {
            self.cas.retirement_failure(&error);
            return Err(error);
        }
        Ok(())
    }

    /// Inspect one exact retired original under the real exclusive sentinel.
    /// No shared read guard or duplicate payload lease is acquired.
    pub fn inspect_unix_retired_storage_object<'a>(
        &'a self,
        storage_id: &ContentId,
        content_id: &ContentId,
    ) -> Result<LinuxStorageRetirementInspection<'a>> {
        self.verify_storage()?;
        self.cas.retirement_owner_observation()?;
        let coordination = self
            .journal
            .acquire_linux_storage_retirement_exclusive(content_id)?;
        let observed = self.journal.with_gc_diagnostics(
            &self.config.space_id,
            self.config.max_metadata_entries,
            |_| -> Result<_> {
                let (original_owner_id, chunks) = self.retired_storage_chunks(storage_id)?;
                let reference = chunks
                    .get(content_id)
                    .ok_or(ReconcileError::Invariant(
                        "exact retired Unix chunk absent from original signed owner",
                    ))?
                    .clone();
                if !(1..=4 * 1024 * 1024).contains(&reference.length)
                    || self.journal.protected_objects()?.contains(content_id)
                {
                    return Err(ReconcileError::Invariant(
                        "retired Unix chunk protected or outside bounded original length",
                    ));
                }
                self.journal.require_cas_access(content_id)?;
                let exclusive = coordination.linux_storage_exclusive()?;
                let original = self
                    .cas
                    .inspect_retirement_original(&exclusive, &reference)?;
                let binding = self.unix_retirement_binding(&coordination, &original)?;
                let expected_original = sync_extend_core_model::storage_retirement_unix::
                    UnixStorageRetirementExpectation::from_binding(&binding)?;
                let bytes = original.read_bytes(&exclusive)?;
                if bytes.len() != reference.length as usize
                    || ContentId::hash(&bytes) != *content_id
                {
                    self.cas.retirement_failure(&ReconcileError::Unstable);
                    return Err(ReconcileError::Unstable);
                }
                let observation = UnixStorageRetirementObjectObservation {
                    space_id: self.config.space_id.clone(),
                    storage_device: self.device.clone(),
                    storage_policy: self.config.fingerprint()?,
                    storage_id: storage_id.clone(),
                    original_owner_id,
                    content_id: content_id.clone(),
                    original_metadata_hash: self.retained_retirement_metadata_hash(storage_id)?,
                    binding,
                    expected_original,
                    exact_retained_metadata_verified: true,
                    current_other_owner_protection_absent: true,
                    original_exclusive_coordination_verified: true,
                    content_hash_verified: true,
                    single_link_verified: true,
                    native_activation_authorized: false,
                    deletion_authorized: false,
                    backup_complete: false,
                    pending_resume_authorized: false,
                };
                Ok((original, reference, observation))
            },
        );
        let (original, reference, observation) = match observed {
            Ok(value) => value,
            Err(error) => {
                return combine_unix(
                    Err(error),
                    coordination
                        .close_linux_storage_original()
                        .map_err(ReconcileError::from),
                )
            }
        };
        let inspection = LinuxStorageRetirementInspection {
            storage: self,
            original: Some(original),
            coordination: Some(coordination),
            reference,
            observation,
        };
        if let Err(error) = inspection.verify() {
            return combine_unix(Err(error), inspection.close());
        }
        Ok(inspection)
    }
}

#[cfg(target_os = "linux")]
impl LinuxStorageRetirementInspection<'_> {
    pub fn verify(&self) -> Result<()> {
        let original = self.original.as_ref().ok_or(ReconcileError::Invariant(
            "original Unix retirement payload inspection closed",
        ))?;
        let coordination = self.coordination.as_ref().ok_or(ReconcileError::Invariant(
            "original Unix retirement coordination closed",
        ))?;
        let operation = (|| {
            self.storage.verify_storage()?;
            let exclusive = coordination.linux_storage_exclusive()?;
            let bytes = original.read_bytes(&exclusive)?;
            if self
                .storage
                .unix_retirement_binding(coordination, original)?
                != self.observation.binding
                || bytes.len() != self.reference.length as usize
                || ContentId::hash(&bytes) != self.reference.content_id
                || self
                    .storage
                    .journal
                    .protected_objects()?
                    .contains(&self.reference.content_id)
            {
                return Err(ReconcileError::Unstable);
            }
            self.storage
                .journal
                .require_cas_access(&self.reference.content_id)?;
            Ok(())
        })();
        if let Err(error) = &operation {
            self.storage.cas.retirement_failure(error);
        }
        operation
    }

    pub fn observation(&self) -> Result<&UnixStorageRetirementObjectObservation> {
        self.verify()?;
        Ok(&self.observation)
    }

    fn release(&mut self) -> Result<()> {
        match (self.coordination.take(), self.original.take()) {
            (Some(coordination), Some(original)) => self
                .storage
                .close_unix_retirement_original(coordination, original),
            (None, None) => Ok(()),
            (Some(coordination), None) => coordination
                .close_linux_storage_original()
                .map_err(ReconcileError::from),
            (None, Some(original)) => {
                let result = original
                    .close_file()
                    .and_then(|directories| directories.close())
                    .map_err(ReconcileError::from);
                self.storage
                    .cas
                    .retirement_failure(&ReconcileError::Invariant(
                        "original Unix retirement payload lost its coordination guard",
                    ));
                result.and(Err(ReconcileError::Invariant(
                    "original Unix retirement payload lost its coordination guard",
                )))
            }
        }
    }

    pub fn close(mut self) -> Result<()> {
        self.release()
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxStorageRetirementInspection<'_> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
