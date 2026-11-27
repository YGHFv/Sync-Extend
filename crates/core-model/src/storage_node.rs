//! Explicit worktree-free storage policy; a stored prefix is not a complete backup.
use crate::{ContentId, DeviceId, FORMAT_VERSION, ModelError, Result, SpaceId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageRole {
    Full,
    Staging,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageNodeConfig {
    pub format_version: u32,
    pub enabled: bool,
    pub space_id: SpaceId,
    pub data_dir: PathBuf,
    pub role: StorageRole,
    pub max_stored_bytes: u64,
    pub max_request_bytes: u64,
    pub max_metadata_entries: usize,
    pub max_traffic_bytes: u64,
    pub expires_at_ms: u64,
    pub bind: SocketAddr,
    pub approved_origins: BTreeMap<DeviceId, ContentId>,
    pub approved_forwarders: BTreeMap<DeviceId, ContentId>,
}

impl StorageNodeConfig {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_absolute_path(self.data_dir.is_absolute())
    }

    fn validate_with_absolute_path(&self, absolute: bool) -> Result<()> {
        if self.format_version != FORMAT_VERSION
            || !absolute
            || self.max_stored_bytes == 0
            || self.max_stored_bytes > i64::MAX as u64
            || self.max_request_bytes == 0
            || self.max_request_bytes > 16 * 1024 * 1024
            || self.max_request_bytes > self.max_stored_bytes
            || self.max_metadata_entries == 0
            || self.max_metadata_entries > crate::limits::MAX_ENTRIES
            || self.max_traffic_bytes == 0
            || self.max_traffic_bytes > i64::MAX as u64
            || self.expires_at_ms == 0
            || self.expires_at_ms > i64::MAX as u64
            || !self.bind.ip().is_loopback()
            || self.bind.port() == 0
            || self.approved_origins.is_empty()
            || self.approved_origins.len() > 1024
            || self.approved_forwarders.is_empty()
            || self.approved_forwarders.len() > 1024
        {
            return Err(ModelError::InvalidConfig(
                "explicit bounded storage-node policy required",
            ));
        }
        for (device, public) in self
            .approved_origins
            .iter()
            .chain(self.approved_forwarders.iter())
        {
            let mut bytes = [0u8; 32];
            for (index, pair) in public.as_str().as_bytes().chunks_exact(2).enumerate() {
                let hex = std::str::from_utf8(pair)
                    .map_err(|_| ModelError::InvalidConfig("storage public key encoding"))?;
                bytes[index] = u8::from_str_radix(hex, 16)
                    .map_err(|_| ModelError::InvalidConfig("storage public key encoding"))?;
            }
            if DeviceId::from_public_key(&bytes) != *device {
                return Err(ModelError::InvalidConfig(
                    "storage approval device/key differs",
                ));
            }
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<ContentId> {
        self.validate()?;
        self.validated_fingerprint()
    }

    fn validated_fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend-explicit-storage-policy-v1",
            self,
        ))?))
    }

    pub fn admits(&self, origin: &DeviceId, forwarder: &DeviceId, at_ms: u64) -> Result<()> {
        self.validate()?;
        if !self.enabled
            || at_ms >= self.expires_at_ms
            || !self.approved_origins.contains_key(origin)
            || !self.approved_forwarders.contains_key(forwarder)
        {
            return Err(ModelError::InvalidConfig(
                "storage policy disabled/expired/unapproved",
            ));
        }
        Ok(())
    }

    /// Expiry closes new storage admission. Existing protected content remains
    /// available to independently approved targets while this policy is enabled.
    pub fn permits_retained_delivery(&self, origin: &DeviceId, target: &DeviceId) -> Result<()> {
        self.validate()?;
        if !self.enabled
            || !self.approved_origins.contains_key(origin)
            || !self.approved_forwarders.contains_key(target)
        {
            return Err(ModelError::InvalidConfig(
                "retained delivery disabled/unapproved",
            ));
        }
        Ok(())
    }
}

/// An immutable historical Unix policy description. This does not authorize
/// opening its data directory, delivery, admission, or any native effect.
/// Only a versioned Unix archive family may select this path grammar.
pub struct ArchivedUnixStoragePolicy<'a> {
    config: &'a StorageNodeConfig,
}

impl<'a> ArchivedUnixStoragePolicy<'a> {
    pub fn validate(config: &'a StorageNodeConfig) -> Result<Self> {
        let path = config.data_dir.to_str().ok_or(ModelError::InvalidConfig(
            "archived Unix storage path encoding",
        ))?;
        // Match Unix Path::is_absolute without normalizing the original bytes.
        // Unix permits //, dot components, colons and backslashes within an
        // absolute path; drive-letter paths and backslash UNC are not absolute.
        // NUL cannot name a Unix filesystem path. No filesystem access occurs.
        let absolute = path.starts_with('/') && !path.contains('\0');
        config.validate_with_absolute_path(absolute)?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &'a StorageNodeConfig {
        self.config
    }

    pub fn fingerprint(&self) -> Result<ContentId> {
        self.config.validated_fingerprint()
    }
}
