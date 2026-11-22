//! Versioned Unix provenance descriptions. Deserialization never acquires an FD.
use crate::{
    storage_node::StorageNodeConfig, ContentId, DeviceId, EntryId, ModelError, Result, SpaceId,
    FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};

pub const UNIX_STORAGE_RETIREMENT_VERSION: u32 = 1;
pub const UNIX_STORAGE_RETIREMENT_REQUEST_BYTES: usize = 16384;

// A tagged struct serializes its type without requiring it on deserialization.
// Use an internally tagged variant while defining the model fields only once.
macro_rules! strict_tagged_unix_description {
    (
        $(#[$meta:meta])*
        pub struct $name:ident, $tag:literal {
            $(pub $field:ident: $field_type:ty),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq, Serialize)]
        #[serde(tag = "type", rename = $tag, deny_unknown_fields)]
        pub struct $name {
            $(pub $field: $field_type),*
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(Deserialize)]
                #[serde(tag = "type", deny_unknown_fields)]
                enum Tagged {
                    #[serde(rename = $tag)]
                    Value {
                        $($field: $field_type),*
                    },
                }
                match Tagged::deserialize(deserializer)? {
                    Tagged::Value { $($field),* } => Ok(Self { $($field),* }),
                }
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixStorageRetirementKey {
    pub device: u64,
    pub inode: u64,
}

impl UnixStorageRetirementKey {
    pub fn validate(&self) -> Result<()> {
        if self.device == 0
            || self.inode == 0
            || self.device > i64::MAX as u64
            || self.inode > i64::MAX as u64
        {
            return Err(ModelError::InvalidData(
                "bounded Unix storage retirement key",
            ));
        }
        Ok(())
    }
}

/// Historical native facts are rejection expectations, never live authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixStorageRetirementBinding {
    pub format_version: u32,
    pub owner_config_fingerprint: ContentId,
    pub outside_data: UnixStorageRetirementKey,
    pub coordination: UnixStorageRetirementKey,
    pub backing_image: UnixStorageRetirementKey,
    pub image_filesystem_id: [u8; 8],
    pub owner_uid: u32,
    pub owner_process_id: u32,
    pub owner_process_start_ticks: u64,
    pub owner_generation: [u8; 16],
    pub persistent_metadata_owner_generation: [u8; 16],
    pub namespace: UnixStorageRetirementKey,
    pub runtime_mount_id: u64,
    pub mounted_root: UnixStorageRetirementKey,
    pub cas: UnixStorageRetirementKey,
    pub objects: UnixStorageRetirementKey,
    pub temporary: UnixStorageRetirementKey,
    pub realm: UnixStorageRetirementKey,
    pub realm_fingerprint: ContentId,
    pub shard: UnixStorageRetirementKey,
    pub payload: UnixStorageRetirementKey,
    pub length: u32,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u32,
}

impl UnixStorageRetirementBinding {
    pub fn validate(&self) -> Result<()> {
        let keys = [
            self.outside_data,
            self.coordination,
            self.backing_image,
            self.namespace,
            self.mounted_root,
            self.cas,
            self.objects,
            self.temporary,
            self.realm,
            self.shard,
            self.payload,
        ];
        for key in keys {
            key.validate()?;
        }
        let inside = [
            self.mounted_root,
            self.cas,
            self.objects,
            self.temporary,
            self.realm,
            self.shard,
            self.payload,
        ];
        if self.format_version != UNIX_STORAGE_RETIREMENT_VERSION
            || self.owner_process_id == 0
            || self.owner_process_start_ticks == 0
            || self.owner_process_start_ticks > i64::MAX as u64
            || self.owner_generation == [0; 16]
            || self.persistent_metadata_owner_generation == [0; 16]
            || self.runtime_mount_id == 0
            || self.runtime_mount_id > i64::MAX as u64
            || self.outside_data.device != self.coordination.device
            || self.outside_data == self.coordination
            || self.outside_data == self.backing_image
            || self.coordination == self.backing_image
            || self.image_filesystem_id == [0; 8]
            || !(1..=4 * 1024 * 1024).contains(&self.length)
            || self.modified_seconds < 0
            || self.modified_nanoseconds >= 1_000_000_000
        {
            return Err(ModelError::InvalidData(
                "complete versioned Unix storage binding",
            ));
        }
        for (index, key) in inside.iter().enumerate() {
            if key.device != self.mounted_root.device || inside[..index].contains(key) {
                return Err(ModelError::InvalidData("Unix storage original slot alias"));
            }
        }
        let durable_realm = ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-linux-storage-inside-cas-durable-realm-v1",
            &self.owner_config_fingerprint,
            self.persistent_metadata_owner_generation,
            self.outside_data,
            self.coordination,
            self.backing_image,
            1u32,
            self.image_filesystem_id,
            [
                self.mounted_root.inode,
                self.cas.inode,
                self.objects.inode,
                self.temporary.inode,
                self.realm.inode,
            ],
            self.owner_uid,
        ))?);
        if durable_realm != self.realm_fingerprint {
            return Err(ModelError::InvalidData(
                "Unix storage durable realm provenance",
            ));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend.unix-storage-retirement.binding.v1",
            self,
        ))?))
    }
}

strict_tagged_unix_description! {
    pub struct UnixStorageRetirementRequest, "unix_storage_retirement_request_v1" {
        pub format_version: u32,
        pub request_id: EntryId,
        pub space_id: SpaceId,
        pub storage_id: ContentId,
        pub original_owner_id: EntryId,
        pub content_id: ContentId,
        pub original_metadata_hash: ContentId,
        pub storage_device: DeviceId,
        pub storage_policy: ContentId,
        pub binding: UnixStorageRetirementBinding,
        pub requested_at_ms: u64,
        pub grace_until_ms: u64,
        pub expires_at_ms: u64,
    }
}

impl UnixStorageRetirementRequest {
    pub fn validate(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<()> {
        self.binding.validate()?;
        LogicalScope {
            format_version: self.format_version,
            request_id: &self.request_id,
            space_id: &self.space_id,
            storage_id: &self.storage_id,
            original_owner_id: &self.original_owner_id,
            storage_device: &self.storage_device,
            storage_policy: &self.storage_policy,
            length: self.binding.length,
            requested_at_ms: self.requested_at_ms,
            grace_until_ms: self.grace_until_ms,
            expires_at_ms: self.expires_at_ms,
        }
        .validate(config, device)?;
        if serde_json::to_vec(self)?.len() > UNIX_STORAGE_RETIREMENT_REQUEST_BYTES {
            return Err(ModelError::InvalidData(
                "Unix storage retirement request byte limit",
            ));
        }
        Ok(())
    }

    pub fn fingerprint(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<ContentId> {
        self.validate(config, device)?;
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend.unix-storage-retirement.request.v1",
            config,
            self,
        ))?))
    }
}

/// Stable rejection expectations. Runtime st_dev inside the image, namespace,
/// mount ID, process birth and live owner generation are deliberately absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixStorageRetirementExpectation {
    pub format_version: u32,
    pub owner_config_fingerprint: ContentId,
    pub persistent_metadata_owner_generation: [u8; 16],
    pub outside_data: UnixStorageRetirementKey,
    pub coordination: UnixStorageRetirementKey,
    pub backing_image: UnixStorageRetirementKey,
    pub image_filesystem_id: [u8; 8],
    pub owner_uid: u32,
    pub mounted_root_inode: u64,
    pub cas_inode: u64,
    pub objects_inode: u64,
    pub temporary_inode: u64,
    pub realm_inode: u64,
    pub realm_fingerprint: ContentId,
    pub shard_inode: u64,
    pub payload_inode: u64,
    pub length: u32,
    pub modified_seconds: i64,
    pub modified_nanoseconds: u32,
}

impl UnixStorageRetirementExpectation {
    pub fn validate(&self) -> Result<()> {
        for key in [self.outside_data, self.coordination, self.backing_image] {
            key.validate()?;
        }
        let inodes = [
            self.mounted_root_inode,
            self.cas_inode,
            self.objects_inode,
            self.temporary_inode,
            self.realm_inode,
            self.shard_inode,
            self.payload_inode,
        ];
        if self.format_version != UNIX_STORAGE_RETIREMENT_VERSION
            || self.persistent_metadata_owner_generation == [0; 16]
            || self.image_filesystem_id == [0; 8]
            || self.outside_data.device != self.coordination.device
            || self.outside_data == self.coordination
            || self.outside_data == self.backing_image
            || self.coordination == self.backing_image
            || !(1..=4 * 1024 * 1024).contains(&self.length)
            || self.modified_seconds < 0
            || self.modified_nanoseconds >= 1_000_000_000
            || inodes.iter().enumerate().any(|(index, inode)| {
                *inode == 0 || *inode > i64::MAX as u64 || inodes[..index].contains(inode)
            })
        {
            return Err(ModelError::InvalidData(
                "complete stable Unix retirement expectation",
            ));
        }
        let realm = ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-linux-storage-inside-cas-durable-realm-v1",
            &self.owner_config_fingerprint,
            self.persistent_metadata_owner_generation,
            self.outside_data,
            self.coordination,
            self.backing_image,
            1u32,
            self.image_filesystem_id,
            [
                self.mounted_root_inode,
                self.cas_inode,
                self.objects_inode,
                self.temporary_inode,
                self.realm_inode,
            ],
            self.owner_uid,
        ))?);
        if realm != self.realm_fingerprint {
            return Err(ModelError::InvalidData(
                "stable Unix retirement durable realm",
            ));
        }
        Ok(())
    }

    pub fn from_binding(binding: &UnixStorageRetirementBinding) -> Result<Self> {
        binding.validate()?;
        let expected = Self {
            format_version: UNIX_STORAGE_RETIREMENT_VERSION,
            owner_config_fingerprint: binding.owner_config_fingerprint.clone(),
            persistent_metadata_owner_generation: binding.persistent_metadata_owner_generation,
            outside_data: binding.outside_data,
            coordination: binding.coordination,
            backing_image: binding.backing_image,
            image_filesystem_id: binding.image_filesystem_id,
            owner_uid: binding.owner_uid,
            mounted_root_inode: binding.mounted_root.inode,
            cas_inode: binding.cas.inode,
            objects_inode: binding.objects.inode,
            temporary_inode: binding.temporary.inode,
            realm_inode: binding.realm.inode,
            realm_fingerprint: binding.realm_fingerprint.clone(),
            shard_inode: binding.shard.inode,
            payload_inode: binding.payload.inode,
            length: binding.length,
            modified_seconds: binding.modified_seconds,
            modified_nanoseconds: binding.modified_nanoseconds,
        };
        expected.validate()?;
        Ok(expected)
    }
}

strict_tagged_unix_description! {
    /// A versioned fresh intent is a plan and rejection expectation, never a live
    /// capability. Materializing a request still grants no SQL/native authority.
    pub struct UnixStorageRetirementIntent, "unix_storage_retirement_fresh_intent_v1" {
        pub format_version: u32,
        pub request_id: EntryId,
        pub space_id: SpaceId,
        pub storage_id: ContentId,
        pub original_owner_id: EntryId,
        pub content_id: ContentId,
        pub original_metadata_hash: ContentId,
        pub storage_device: DeviceId,
        pub storage_policy: ContentId,
        pub expected_original: UnixStorageRetirementExpectation,
        pub requested_at_ms: u64,
        pub grace_until_ms: u64,
        pub expires_at_ms: u64,
    }
}

impl UnixStorageRetirementIntent {
    pub fn validate(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<()> {
        self.expected_original.validate()?;
        LogicalScope {
            format_version: self.format_version,
            request_id: &self.request_id,
            space_id: &self.space_id,
            storage_id: &self.storage_id,
            original_owner_id: &self.original_owner_id,
            storage_device: &self.storage_device,
            storage_policy: &self.storage_policy,
            length: self.expected_original.length,
            requested_at_ms: self.requested_at_ms,
            grace_until_ms: self.grace_until_ms,
            expires_at_ms: self.expires_at_ms,
        }
        .validate(config, device)?;
        if serde_json::to_vec(self)?.len() > UNIX_STORAGE_RETIREMENT_REQUEST_BYTES {
            return Err(ModelError::InvalidData(
                "Unix storage retirement intent byte limit",
            ));
        }
        Ok(())
    }

    pub fn materialize(
        &self,
        binding: UnixStorageRetirementBinding,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<UnixStorageRetirementRequest> {
        self.validate(config, device)?;
        if self.expected_original != UnixStorageRetirementExpectation::from_binding(&binding)? {
            return Err(ModelError::InvalidData(
                "fresh Unix original differs from complete stable expectation",
            ));
        }
        let request = UnixStorageRetirementRequest {
            format_version: self.format_version,
            request_id: self.request_id.clone(),
            space_id: self.space_id.clone(),
            storage_id: self.storage_id.clone(),
            original_owner_id: self.original_owner_id.clone(),
            content_id: self.content_id.clone(),
            original_metadata_hash: self.original_metadata_hash.clone(),
            storage_device: self.storage_device.clone(),
            storage_policy: self.storage_policy.clone(),
            binding,
            requested_at_ms: self.requested_at_ms,
            grace_until_ms: self.grace_until_ms,
            expires_at_ms: self.expires_at_ms,
        };
        request.validate(config, device)?;
        Ok(request)
    }
}

struct LogicalScope<'a> {
    format_version: u32,
    request_id: &'a EntryId,
    space_id: &'a SpaceId,
    storage_id: &'a ContentId,
    original_owner_id: &'a EntryId,
    storage_device: &'a DeviceId,
    storage_policy: &'a ContentId,
    length: u32,
    requested_at_ms: u64,
    grace_until_ms: u64,
    expires_at_ms: u64,
}

impl LogicalScope<'_> {
    fn validate(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<()> {
        config.validate()?;
        let grace = self.grace_until_ms.checked_sub(self.requested_at_ms);
        if self.format_version != FORMAT_VERSION
            || self.space_id != &config.space_id
            || !config.enabled
            || self.storage_device != device
            || self.storage_policy != &config.fingerprint()?
            || self.request_id == self.original_owner_id
            || !self
                .storage_id
                .as_str()
                .starts_with(self.original_owner_id.as_str())
            || u64::from(self.length) > config.max_stored_bytes
            || self.requested_at_ms > i64::MAX as u64
            || self.grace_until_ms > i64::MAX as u64
            || self.expires_at_ms > i64::MAX as u64
            || self.expires_at_ms <= self.grace_until_ms
            || grace.is_none_or(|value| !(1000..=604800000).contains(&value) || value % 1000 != 0)
        {
            return Err(ModelError::InvalidData(
                "exact Unix retirement logical scope",
            ));
        }
        Ok(())
    }
}
