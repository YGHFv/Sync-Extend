//! Same-user management credential migration matches the existing daemon payload.
use crate::explicit_credential_mapping::{
    install_private_bytes, InstalledExplicitWebDavCredential,
};
use crate::{ReconcileError, Result};
use std::{io::Read, path::Path};
use sync_extend_core_model::{
    management::{ManagementConfig, TokenProtection},
    ContentId,
};
use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory};

const ENTROPY: &[u8] = b"SyncExtend management token v1";
const MAX: usize = 4096;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedToken {
    format_version: u32,
    address: std::net::SocketAddr,
    token_file: std::path::PathBuf,
    token: String,
}
pub struct ExplicitManagementCredentialMapping {
    protected: Vec<u8>,
    source_digest: ContentId,
    target_digest: ContentId,
    target: ManagementConfig,
}
fn valid(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
impl ExplicitManagementCredentialMapping {
    /// Only token_file is explicitly rebound. Address, policy and protection
    /// remain unchanged. Plain and cross-user credentials are refused here.
    pub fn from_original_current_user_file(
        original: &ManagementConfig,
        target: &ManagementConfig,
        max_aggregate_bytes: usize,
    ) -> Result<Self> {
        original.validate()?;
        target.validate()?;
        let mut expected = original.clone();
        expected.token_file = target.token_file.clone();
        if expected != *target
            || original.token_protection != TokenProtection::WindowsUser
            || original.token_file == target.token_file
            || max_aggregate_bytes == 0
            || max_aggregate_bytes > 4 * MAX
        {
            return Err(ReconcileError::Invariant(
                "explicit management protected path-only mapping",
            ));
        }
        let _parents = original
            .token_file
            .parent()
            .ok_or(ReconcileError::Invariant(
                "original management credential parent",
            ))?
            .ancestors()
            .filter(|path| path.is_absolute())
            .map(LockedDirectory::open)
            .collect::<std::io::Result<Vec<_>>>()?;
        let file = GuardedReadFile::open(&original.token_file)?;
        sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
        let size = usize::try_from(file.reader().metadata()?.len())
            .map_err(|_| ReconcileError::ResourceLimit("management credential bytes"))?;
        if size > MAX
            || size
                .checked_mul(4)
                .is_none_or(|sum| sum > max_aggregate_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "management credential aggregate bound",
            ));
        }
        let mut encrypted = Vec::with_capacity(size);
        file.reader()
            .take(MAX as u64 + 1)
            .read_to_end(&mut encrypted)?;
        if encrypted.len() != size {
            return Err(ReconcileError::Invariant(
                "original management stable bytes",
            ));
        }
        let clear =
            windows_dpapi::decrypt_data(&encrypted, windows_dpapi::Scope::User, Some(ENTROPY))
                .map_err(|_| {
                    ReconcileError::Invariant("original management current user protection")
                })?;
        if clear.len() > MAX {
            return Err(ReconcileError::ResourceLimit("management clear bound"));
        }
        let mut token: ProtectedToken = serde_json::from_slice(&clear)
            .map_err(|_| ReconcileError::Invariant("original management credential encoding"))?;
        if token.format_version != 1
            || token.address != original.address
            || token.token_file != original.token_file
            || !valid(&token.token)
        {
            return Err(ReconcileError::Invariant(
                "original management address path token binding",
            ));
        }
        token.token_file = target.token_file.clone();
        let mapped_clear = serde_json::to_vec(&token)
            .map_err(|_| ReconcileError::Invariant("mapped management credential encoding"))?;
        let protected = windows_dpapi::encrypt_data(
            &mapped_clear,
            windows_dpapi::Scope::User,
            Some(ENTROPY),
        )
        .map_err(|_| ReconcileError::Invariant("mapped management current user protection"))?;
        if protected.len() > MAX
            || [
                encrypted.len(),
                clear.len(),
                mapped_clear.len(),
                protected.len(),
            ]
            .into_iter()
            .try_fold(0usize, |sum, n| sum.checked_add(n))
            .is_none_or(|sum| sum > max_aggregate_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "mapped management aggregate bound",
            ));
        }
        Ok(Self {
            source_digest: ContentId::hash(&encrypted),
            target_digest: ContentId::hash(&protected),
            protected,
            target: target.clone(),
        })
    }
    pub fn original_ciphertext_digest(&self) -> &ContentId {
        &self.source_digest
    }
    pub fn mapped_ciphertext_digest(&self) -> &ContentId {
        &self.target_digest
    }
    pub fn install_current_user_file(
        self,
        parent: &LockedDirectory,
        component: &str,
        target: &ManagementConfig,
    ) -> Result<InstalledExplicitWebDavCredential> {
        if self.target != *target
            || target.token_file.file_name().and_then(|name| name.to_str()) != Some(component)
            || !parent.matches_path(
                target
                    .token_file
                    .parent()
                    .ok_or(ReconcileError::Invariant("management target parent"))?,
            )?
        {
            return Err(ReconcileError::Invariant(
                "exact management mapped target slot",
            ));
        }
        install_private_bytes(&self.protected, &self.target_digest, parent, component)
    }
    pub fn target_path(&self) -> &Path {
        &self.target.token_file
    }
}
