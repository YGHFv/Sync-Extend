//! Explicit local re-protection of the existing daemon WebDAV credential format.
//! No plaintext payload, Debug or Serialize leaves this mapping.
use crate::{ReconcileError, Result};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Component, Path},
};
use sync_extend_core_model::{webdav::WebDavListener, ContentId, EntryId};
use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory, SealedOriginalFile};

const ENTROPY: &[u8] = b"SyncExtend WebDAV credentials v1";
const MAX_BYTES: usize = 65536;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format_version: u32,
    listener_id: EntryId,
    passwords: BTreeMap<String, String>,
}

pub struct ExplicitWebDavCredentialMapping {
    protected: Vec<u8>,
    original_ciphertext: ContentId,
    mapped_ciphertext: ContentId,
    original_listener: ContentId,
    mapped_listener: ContentId,
}
pub struct InstalledExplicitWebDavCredential {
    file: SealedOriginalFile,
    protected_digest: ContentId,
}

fn listener_digest(listener: &WebDavListener) -> Result<ContentId> {
    listener.validate()?;
    let bytes = serde_json::to_vec(listener)
        .map_err(|_| ReconcileError::Invariant("explicit credential listener encoding"))?;
    Ok(ContentId::hash(&bytes))
}
fn validate(stored: &Stored, listener: &WebDavListener) -> Result<()> {
    if stored.format_version != 1
        || stored.listener_id != listener.listener_id
        || stored
            .passwords
            .keys()
            .collect::<std::collections::BTreeSet<_>>()
            != listener.accounts.iter().map(|row| &row.username).collect()
        || stored.passwords.values().any(|password| {
            password.len() != 64
                || !password
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(ReconcileError::Invariant(
            "original credential listener account scope",
        ));
    }
    Ok(())
}
fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 32768
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

impl ExplicitWebDavCredentialMapping {
    /// Both exact listener descriptors are explicit local input. Export and
    /// account grants must be identical; a new listener ID is bound separately.
    pub fn from_original_current_user_file(
        source: &Path,
        original: &WebDavListener,
        mapped: &WebDavListener,
        max_aggregate_bytes: usize,
    ) -> Result<Self> {
        listener_digest(original)?;
        listener_digest(mapped)?;
        if !normalized(source) || max_aggregate_bytes == 0 || max_aggregate_bytes > 4 * MAX_BYTES {
            return Err(ReconcileError::Invariant(
                "explicit credential path aggregate bounds",
            ));
        }
        let mut expected = original.clone();
        expected.listener_id = mapped.listener_id.clone();
        if &expected != mapped {
            return Err(ReconcileError::Invariant(
                "credential mapping changes listener grants or policy",
            ));
        }
        let parent = source
            .parent()
            .ok_or(ReconcileError::Invariant("credential parent"))?;
        let _parents = parent
            .ancestors()
            .filter(|path| path.is_absolute())
            .map(LockedDirectory::open)
            .collect::<std::io::Result<Vec<_>>>()?;
        let file = GuardedReadFile::open(source)?;
        // Impersonated and foreign-user objects fail before decryption.
        sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
        let size = usize::try_from(file.reader().metadata()?.len())
            .map_err(|_| ReconcileError::ResourceLimit("original credential file bytes"))?;
        if size > MAX_BYTES
            || size
                .checked_mul(4)
                .is_none_or(|sum| sum > max_aggregate_bytes)
        {
            return Err(ReconcileError::ResourceLimit(
                "original credential aggregate bytes",
            ));
        }
        let mut encrypted = Vec::with_capacity(size);
        file.reader()
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut encrypted)?;
        if encrypted.len() != size {
            return Err(ReconcileError::Invariant(
                "original credential stable bounded bytes",
            ));
        }
        file.verify_single_link()?;
        sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
        if !file.matches_path(source)? {
            return Err(ReconcileError::Unstable);
        }
        let result =
            Self::from_bound_ciphertext(&encrypted, original, mapped, max_aggregate_bytes)?;
        file.verify_single_link()?;
        sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
        if !file.matches_path(source)? {
            return Err(ReconcileError::Unstable);
        }
        Ok(result)
    }

    /// Verified v2 protection supplies the original DPAPI ciphertext directly.
    pub fn from_verified_protected_artifact(
        source: &crate::VerifiedProtectedArtifact,
        original: &WebDavListener,
        mapped: &WebDavListener,
        max_aggregate_bytes: usize,
    ) -> Result<Self> {
        if source.protection_scope().provider
            != crate::ProtectionProviderKind::WindowsCurrentUserDpapi
        {
            return Err(ReconcileError::Invariant(
                "WebDAV original DPAPI provider scope",
            ));
        }
        let encrypted = source.checked_original_bytes(
            crate::ProtectedArtifactRole::WebdavCredential,
            &listener_digest(original)?,
        )?;
        Self::from_bound_ciphertext(encrypted, original, mapped, max_aggregate_bytes)
    }

    fn from_bound_ciphertext(
        encrypted: &[u8],
        original: &WebDavListener,
        mapped: &WebDavListener,
        max_aggregate_bytes: usize,
    ) -> Result<Self> {
        let original_listener = listener_digest(original)?;
        let mapped_listener = listener_digest(mapped)?;
        let mut expected = original.clone();
        expected.listener_id = mapped.listener_id.clone();
        if expected != *mapped
            || encrypted.is_empty()
            || encrypted.len() > MAX_BYTES
            || max_aggregate_bytes == 0
            || max_aggregate_bytes > 4 * MAX_BYTES
        {
            return Err(ReconcileError::Invariant(
                "protected WebDAV exact listener and aggregate scope",
            ));
        }
        let clear =
            windows_dpapi::decrypt_data(encrypted, windows_dpapi::Scope::User, Some(ENTROPY))
                .map_err(|_| {
                    ReconcileError::Invariant("original current user credential protection")
                })?;
        if clear.len() > MAX_BYTES {
            return Err(ReconcileError::ResourceLimit(
                "original clear credential bytes",
            ));
        }
        let mut stored: Stored =
            sync_extend_core_model::deployment::decode_deployment_document(&clear, MAX_BYTES)
                .map_err(|_| ReconcileError::Invariant("original credential encoding"))?;
        validate(&stored, original)?;
        stored.listener_id = mapped.listener_id.clone();
        let mapped_clear = serde_json::to_vec(&stored)
            .map_err(|_| ReconcileError::Invariant("mapped credential encoding"))?;
        validate(&stored, mapped)?;
        let protected = windows_dpapi::encrypt_data(
            &mapped_clear,
            windows_dpapi::Scope::User,
            Some(ENTROPY),
        )
        .map_err(|_| ReconcileError::Invariant("mapped current user credential protection"))?;
        if protected.len() > MAX_BYTES
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
                "mapped credential aggregate bytes",
            ));
        }
        Ok(Self {
            original_ciphertext: ContentId::hash(encrypted),
            mapped_ciphertext: ContentId::hash(&protected),
            protected,
            original_listener,
            mapped_listener,
        })
    }
    pub fn original_ciphertext_digest(&self) -> &ContentId {
        &self.original_ciphertext
    }
    pub fn mapped_ciphertext_digest(&self) -> &ContentId {
        &self.mapped_ciphertext
    }
    pub fn original_listener_digest(&self) -> &ContentId {
        &self.original_listener
    }
    pub fn mapped_listener_digest(&self) -> &ContentId {
        &self.mapped_listener
    }
    pub(crate) fn protected_bytes_for_deployment(&self) -> &[u8] {
        &self.protected
    }

    /// Exact retained parent and CREATE_NEW establish ownership. Foreign files
    /// are preserved. Partial native failures retain the created orphan; no
    /// pathname deletion, replacement or inferred durable recovery authority.
    pub fn install_current_user_file(
        self,
        parent: &LockedDirectory,
        component: &str,
        mapped: &WebDavListener,
    ) -> Result<InstalledExplicitWebDavCredential> {
        if listener_digest(mapped)? != self.mapped_listener {
            return Err(ReconcileError::Invariant(
                "mapped credential exact target listener",
            ));
        }
        install_private_bytes(&self.protected, &self.mapped_ciphertext, parent, component)
    }
}
impl InstalledExplicitWebDavCredential {
    pub fn verify_current_user_acl(&self) -> Result<()> {
        self.file.verify_original()?;
        sync_extend_platform_fs::verify_current_user_private_file(self.file.reader())?;
        Ok(())
    }
    pub fn protected_digest(&self) -> &ContentId {
        &self.protected_digest
    }
}

/// One actual original CREATE installer shared by credential and config roles.
/// Plaintext secrets are never supplied by the credential mapping callers.
pub(crate) fn install_private_bytes(
    bytes: &[u8],
    digest: &ContentId,
    parent: &LockedDirectory,
    component: &str,
) -> Result<InstalledExplicitWebDavCredential> {
    if bytes.len() > 1024 * 1024 || ContentId::hash(bytes) != *digest {
        return Err(ReconcileError::Invariant("explicit local file size digest"));
    }
    let mut file = parent.create_new_current_user_file(component)?;
    file.original_creation()?.verify()?;
    sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
    file.writer().write_all(bytes)?;
    file.writer().sync_all()?;
    let mut readback = Vec::new();
    // Reduced reader remains the original CREATE; seek is separate from writer cursor.
    use std::io::{Seek, SeekFrom};
    file.writer().seek(SeekFrom::Start(0))?;
    file.reader()
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut readback)?;
    if readback.as_slice() != bytes {
        return Err(ReconcileError::Invariant(
            "mapped credential original CREATE readback",
        ));
    }
    sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
    let file = file.seal_original()?;
    file.verify_original()?;
    sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
    Ok(InstalledExplicitWebDavCredential {
        file,
        protected_digest: digest.clone(),
    })
}
