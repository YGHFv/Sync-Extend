//! Explicit offline configuration mapping; no credentials, ACL adoption or listener activation.
use super::{ArchiveRole, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::path::{Component, Path};
use sync_extend_core_model::{config::Config, ContentId};

/// No Debug/Serialize for configuration payloads. Only evidence digests and
/// caller-owned bytes escape; this type grants no permission to install them.
pub struct ExplicitOriginalConfigMapping {
    original: Vec<u8>,
    mapped: Vec<u8>,
    original_digest: ContentId,
    mapped_digest: ContentId,
    archive_digest: ContentId,
}

fn root(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().len() > 32_768
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(ReconcileError::Invariant(
            "explicit normalized config root required",
        ));
    }
    Ok(())
}

impl VerifiedNodeStateArchive {
    /// Only an explicitly captured config with no external credentials/TLS
    /// references is accepted here. Secret and ACL mappings require separate
    /// actual protected-object contracts and remain refused by this API.
    pub fn map_explicit_original_config(
        &self,
        name: &str,
        original_data: &Path,
        new_data: &Path,
        new_worktree: &Path,
        max_combined_bytes: usize,
    ) -> Result<ExplicitOriginalConfigMapping> {
        root(original_data)?;
        root(new_data)?;
        root(new_worktree)?;
        if new_data.starts_with(new_worktree)
            || new_worktree.starts_with(new_data)
            || max_combined_bytes == 0
            || max_combined_bytes > 2 * 1024 * 1024
            || self.original_config_data() != Some(original_data)
        {
            return Err(ReconcileError::Invariant(
                "explicit original config scope and aggregate budget",
            ));
        }
        let role = ArchiveRole::ExplicitConfig { name: name.into() };
        let source = self
            .archive
            .section(&role)
            .ok_or(ReconcileError::Invariant(
                "explicit original config role absent",
            ))?;
        if source
            .len()
            .checked_mul(2)
            .is_none_or(|bytes| bytes > max_combined_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "original and mapped config aggregate bytes",
            ));
        }
        let mut config: Config = serde_json::from_slice(source)
            .map_err(|_| ReconcileError::Invariant("original config encoding"))?;
        config.validate()?;
        if config.data_dir != original_data
            || config.worktree.as_deref() != Some(self.original_worktree())
            || config.webdav.credential_ref.is_some()
            || config.webdav.tls_certificate.is_some()
            || config.webdav.tls_key.is_some()
        {
            return Err(ReconcileError::Invariant(
                "config mapping requires separate protected references",
            ));
        }
        let before = serde_json::to_value(&config)
            .map_err(|_| ReconcileError::Invariant("original config canonical encoding"))?;
        config.data_dir = new_data.into();
        config.worktree = Some(new_worktree.into());
        config.validate()?;
        let mut expected = before;
        let object = expected
            .as_object_mut()
            .ok_or(ReconcileError::Invariant("original config object"))?;
        object.insert(
            "data_dir".into(),
            serde_json::to_value(new_data)
                .map_err(|_| ReconcileError::Invariant("mapped config data encoding"))?,
        );
        object.insert(
            "worktree".into(),
            serde_json::to_value(new_worktree)
                .map_err(|_| ReconcileError::Invariant("mapped config worktree encoding"))?,
        );
        if serde_json::to_value(&config)
            .map_err(|_| ReconcileError::Invariant("mapped config canonical encoding"))?
            != expected
        {
            return Err(ReconcileError::Invariant(
                "config mapping changed another setting",
            ));
        }
        let mapped = serde_json::to_vec(&config)
            .map_err(|_| ReconcileError::Invariant("mapped config bounded encoding"))?;
        if source
            .len()
            .checked_add(mapped.len())
            .is_none_or(|bytes| bytes > max_combined_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "mapped config aggregate bytes",
            ));
        }
        Ok(ExplicitOriginalConfigMapping {
            original: source.to_vec(),
            original_digest: ContentId::hash(source),
            mapped_digest: ContentId::hash(&mapped),
            mapped,
            archive_digest: self.digest().clone(),
        })
    }
}

impl ExplicitOriginalConfigMapping {
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }
    pub fn mapped_bytes(&self) -> &[u8] {
        &self.mapped
    }
    pub fn original_digest(&self) -> &ContentId {
        &self.original_digest
    }
    pub fn mapped_digest(&self) -> &ContentId {
        &self.mapped_digest
    }
    pub fn archive_digest(&self) -> &ContentId {
        &self.archive_digest
    }
}
