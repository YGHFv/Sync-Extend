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
