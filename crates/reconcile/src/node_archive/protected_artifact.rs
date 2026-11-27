//! Retained original sources and an authenticated, same-user secret envelope.
//! Source permissions and cryptographic protection are separate observations.
//! No secret type implements Debug, Serialize, a public byte view, or a
//! pathname-only provider verification constructor.
use crate::{ReconcileError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use sync_extend_core_model::{deployment::DeploymentPlatform, ContentId};

// The v1 node image already has a one-GiB ceiling. The caller's independent
// bundle/plaintext/memory budgets must be checked before selecting this limit;
// ordinary configuration and credential roles keep their smaller role limits.
const MAX_SOURCE: usize = 1024 * 1024 * 1024;
const MAX_ENVELOPE: usize = MAX_SOURCE + 65_536;
const MAGIC: &[u8; 8] = b"SEDPAv02";

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedArtifactRole {
    WebdavCredential,
    ManagementCredential,
    TlsPrivateKey,
    DeviceIdentity,
    NodeState,
    EasyTierConfig,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionProviderKind {
    WindowsCurrentUserDpapi,
    UnixSameUidAead,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionScope {
    pub provider: ProtectionProviderKind,
    pub principal_digest: ContentId,
    pub independent_key_digest: Option<ContentId>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedArtifactBinding {
    pub format_version: u32,
    pub artifact_id: u32,
    pub role: ProtectedArtifactRole,
    pub source_path: PathBuf,
    pub source_bytes: u64,
    pub source_digest: ContentId,
    pub graph_digest: ContentId,
    /// Exact source listener, management endpoint, TLS consumer or node scope.
    pub consumer_digest: ContentId,
    pub platform: DeploymentPlatform,
}

impl ProtectedArtifactBinding {
    fn validate(&self) -> Result<()> {
        if self.format_version != 2
            || !normalized(&self.source_path)
            || self.source_bytes == 0
            || self.source_bytes > maximum_protected_role(self.role) as u64
        {
            return Err(ReconcileError::Invariant(
                "bounded exact protected deployment artifact binding",
            ));
        }
        Ok(())
    }
}

fn maximum_protected_role(role: ProtectedArtifactRole) -> usize {
    match role {
        ProtectedArtifactRole::NodeState => MAX_SOURCE,
        ProtectedArtifactRole::WebdavCredential => 65_536,
        ProtectedArtifactRole::ManagementCredential => 4096,
        ProtectedArtifactRole::DeviceIdentity => 4096,
        ProtectedArtifactRole::TlsPrivateKey | ProtectedArtifactRole::EasyTierConfig => 1024 * 1024,
    }
}

pub(crate) fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path.as_os_str().len() <= 32_768
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

struct SecretBytes(Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Best-effort lifetime minimization; no guarantee about allocator,
        // provider internals or the operating system's own secret buffers.
        self.0.fill(0);
    }
}

#[cfg(windows)]
struct WindowsSource {
    path: PathBuf,
    ancestors: Vec<(
        PathBuf,
        sync_extend_platform_fs::LockedDirectory,
        sync_extend_platform_fs::FileKey,
    )>,
    original: sync_extend_platform_fs::GuardedReadFile,
    key: sync_extend_platform_fs::FileKey,
    bytes: u64,
    modified: std::time::SystemTime,
    private_owner_acl: Option<(ContentId, ContentId)>,
}

/// Capture remains backed by the original read exclusion and all ancestors
/// until explicit close. A digest or a JSON description cannot create it.
pub struct OriginalProtectedArtifact {
    path: PathBuf,
    bytes: SecretBytes,
    digest: ContentId,
    private: bool,
    #[cfg(windows)]
    source: WindowsSource,
    #[cfg(target_os = "linux")]
    source: sync_extend_platform_fs::UnixProtectedArtifactSource,
}

#[cfg(windows)]
pub struct OriginalProtectedArtifactOpenFailure {
    pub error: ReconcileError,
    pub original_resources: Option<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
}

#[cfg(windows)]
impl OriginalProtectedArtifactOpenFailure {
    pub fn retain_and_report(self) -> ReconcileError {
        if let Some(original) = self.original_resources {
            original.retain_until_process_exit();
        }
        self.error
    }
}

impl OriginalProtectedArtifact {
    pub fn capture(path: &Path, maximum: usize, private: bool) -> Result<Self> {
        #[cfg(windows)]
        {
            return Self::capture_retaining(path, maximum, private)
                .map_err(OriginalProtectedArtifactOpenFailure::retain_and_report);
        }
        #[cfg(not(windows))]
        {
        if !normalized(path) || maximum == 0 || maximum > MAX_SOURCE {
            return Err(ReconcileError::Invariant(
                "bounded original deployment artifact path",
            ));
        }
        #[cfg(target_os = "linux")]
        let source = sync_extend_platform_fs::UnixProtectedArtifactSource::open_original(
            path, maximum, private,
        )?;
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err(ReconcileError::Invariant(
            "protected deployment source platform unsupported",
        ));
        #[cfg(any(windows, target_os = "linux"))]
        {
            let observed = read_original(&source, maximum).and_then(|bytes| {
                if bytes.is_empty() || bytes.len() > maximum {
                    Err(ReconcileError::ResourceLimit("original deployment artifact bytes"))
                } else {
                    Ok(bytes)
                }
            });
            let bytes = match observed {
                Ok(bytes) => bytes,
                Err(error) => {
                    retain_failed_unix_close(source.close_retaining());
                    return Err(error);
                }
            };
            let digest = ContentId::hash(&bytes);
            let result = Self {
                path: path.to_path_buf(),
                bytes: SecretBytes(bytes),
                digest,
                private,
                source,
            };
            if let Err(error) = result.verify_original() {
                retain_failed_unix_close(result.close_retaining());
                return Err(error);
            }
            Ok(result)
        }
        }
    }

    #[cfg(windows)]
    pub fn capture_retaining(
        path: &Path,
        maximum: usize,
        private: bool,
    ) -> std::result::Result<Self, OriginalProtectedArtifactOpenFailure> {
        let mut ancestors = Vec::<(
            PathBuf,
            sync_extend_platform_fs::LockedDirectory,
            Option<sync_extend_platform_fs::FileKey>,
        )>::new();
        let mut original = None;
        let mut failed_opens = Vec::new();
        let observed = (|| -> Result<_> {
            if !normalized(path) || maximum == 0 || maximum > MAX_SOURCE {
                return Err(ReconcileError::Invariant(
                    "bounded original deployment artifact path",
                ));
            }
            for parent in path.parent().ok_or(ReconcileError::Invariant(
                "original deployment artifact parent",
            ))?.ancestors().filter(|parent| parent.is_absolute()) {
                let directory = sync_extend_platform_fs::LockedDirectory::open_retaining(parent)
                    .map_err(|failure| {
                        if let Some(resources) = failure.original_resources {
                            failed_opens.push(resources);
                        }
                        ReconcileError::Io(failure.error)
                    })?;
                // Own the acquired prefix before the first fallible check.
                ancestors.push((parent.to_path_buf(), directory, None));
                let (_, directory, key) = ancestors.last_mut().ok_or(ReconcileError::Unstable)?;
                directory.require_local_ntfs(parent)?;
                directory.require_case_insensitive()?;
                if !directory.matches_path(parent)? {
                    return Err(ReconcileError::Unstable);
                }
                *key = Some(directory.key()?);
            }
            if private {
                ancestors.first().ok_or(ReconcileError::Invariant(
                    "private deployment source parent absent",
                ))?.1.require_current_user_private()?;
            }
            original = Some(sync_extend_platform_fs::GuardedReadFile::open_retaining(path)
                .map_err(|failure| {
                    if let Some(resources) = failure.original_resources {
                        failed_opens.push(resources);
                    }
                    ReconcileError::Io(failure.error)
                })?);
            let file = original.as_ref().ok_or(ReconcileError::Unstable)?;
            let metadata = file.reader().metadata()?;
            if metadata.len() == 0 || metadata.len() > maximum as u64 {
                return Err(ReconcileError::ResourceLimit("original deployment artifact bytes"));
            }
            let private_owner_acl = if private {
                let (owner, acl) =
                    sync_extend_platform_fs::capture_current_user_private_acl(file.reader())?;
                Some((ContentId::hash(&owner), ContentId::hash(&acl)))
            } else {
                None
            };
            Ok((file.key()?, metadata.len(), metadata.modified()?, private_owner_acl))
        })();
        let (key, bytes, modified, private_owner_acl) = match observed {
            Ok(observed) => observed,
            Err(error) => {
                let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
                if let Some(file) = original {
                    file.close_into_attempt(&mut close);
                }
                for (_, directory, _) in ancestors {
                    close.close_directory(directory);
                }
                for resources in failed_opens {
                    close.append_failure(resources);
                }
                return Err(OriginalProtectedArtifactOpenFailure {
                    error,
                    original_resources: close.finish().err(),
                });
            }
        };
        let source = WindowsSource {
            path: path.to_path_buf(),
            ancestors: ancestors.into_iter().map(|(path, directory, key)| {
                (path, directory, key.expect("successful original ancestor key"))
            }).collect(),
            original: original.expect("successful original artifact acquisition"),
            key, bytes, modified, private_owner_acl,
        };
        let observed = read_original(&source, maximum);
        let captured_bytes = match observed {
            Ok(bytes) => bytes,
            Err(error) => {
                let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
                source.original.close_into_attempt(&mut close);
                for (_, directory, _) in source.ancestors {
                    close.close_directory(directory);
                }
                return Err(OriginalProtectedArtifactOpenFailure {
                    error,
                    original_resources: close.finish().err(),
                });
            }
        };
        let result = Self {
            path: path.to_path_buf(),
            digest: ContentId::hash(&captured_bytes),
            bytes: SecretBytes(captured_bytes),
            private,
            source,
        };
        if let Err(error) = result.verify_original() {
            return Err(OriginalProtectedArtifactOpenFailure {
                error,
                original_resources: result.close_retaining().err(),
            });
        }
        Ok(result)
    }

    pub fn source_digest(&self) -> &ContentId {
        &self.digest
    }

    pub fn source_bytes(&self) -> usize {
        self.bytes.0.len()
    }

    /// Only artifacts explicitly opened as public documents have a byte view.
    /// Secret/provider artifacts keep their separate protected interface.
    pub fn public_document_bytes(&self) -> Result<&[u8]> {
        if self.private {
            return Err(ReconcileError::Invariant("private artifact has no public document view"));
        }
        self.verify_original()?;
        Ok(&self.bytes.0)
    }

    pub fn verify_original(&self) -> Result<()> {
        #[cfg(any(windows, target_os = "linux"))]
        if read_original(&self.source, self.bytes.0.len())? != self.bytes.0 {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }

    pub(crate) fn original_bytes(&self) -> &[u8] {
        &self.bytes.0
    }

    pub(crate) fn source_path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn native_identity(&self) -> Result<String> {
        self.verify_original()?;
        #[cfg(windows)]
        return Ok(self.source.key.to_string());
        #[cfg(target_os = "linux")]
        {
            let key = self.source.key();
            return Ok(format!("unix:{}:{}:{}", key.device, key.inode, key.uid));
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        Err(ReconcileError::Invariant(
            "deployment native identity unavailable",
        ))
    }

    pub fn close(self) -> Result<()> {
        #[cfg(windows)]
        {
            return self.close_retaining()
                .map(|_| ())
                .map_err(|failure| failure.retain_and_report().into());
        }
        #[cfg(target_os = "linux")]
        {
            self.close_retaining().map(|_| ())
                .map_err(|failure| failure.retain_and_report().into())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        Err(ReconcileError::Invariant("original deployment close unavailable"))
    }

    #[cfg(windows)]
    pub fn close_retaining(
        self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        let mut attempt = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
        if let Err(error) = self.verify_original() {
            attempt.note_error(std::io::Error::other(error.to_string()));
        }
        self.source.original.close_into_attempt(&mut attempt);
        for (_, directory, _) in self.source.ancestors {
            attempt.close_directory(directory);
        }
        attempt.finish()
    }

    #[cfg(target_os = "linux")]
    pub fn close_retaining(
        self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedUnixOriginalResources,
        sync_extend_platform_fs::UnixOriginalResourceCloseFailure,
    > {
        let mut attempt = sync_extend_platform_fs::UnixOriginalCloseAttempt::new();
        if let Err(error) = self.verify_original() {
            attempt.note_error(std::io::Error::other(error.to_string()));
        }
        attempt.append_result(self.source.close_retaining());
        attempt.finish()
    }
}

#[cfg(windows)]
fn read_original(source: &WindowsSource, maximum: usize) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    for (path, original, key) in &source.ancestors {
        if original.key()? != *key || !original.matches_path(path)? {
            return Err(ReconcileError::Unstable);
        }
    }
    source.original.verify_single_link()?;
    if source.original.key()? != source.key || !source.original.matches_path(&source.path)? {
        return Err(ReconcileError::Unstable);
    }
    if let Some((owner_digest, acl_digest)) = &source.private_owner_acl {
        source
            .ancestors
            .first()
            .ok_or(ReconcileError::Invariant(
                "original private source parent absent",
            ))?
            .1
            .require_current_user_private()?;
        let (owner, acl) =
            sync_extend_platform_fs::capture_current_user_private_acl(source.original.reader())?;
        if ContentId::hash(&owner) != *owner_digest || ContentId::hash(&acl) != *acl_digest {
            return Err(ReconcileError::Unstable);
        }
    }
    let before = source.original.reader().metadata()?;
    if before.len() != source.bytes
        || before.len() > maximum as u64
        || before.modified()? != source.modified
    {
        return Err(ReconcileError::Unstable);
    }
    let mut reader = source.original.reader();
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    reader.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    let after = source.original.reader().metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || !source.original.matches_path(&source.path)?
    {
        return Err(ReconcileError::Unstable);
    }
    source.original.verify_single_link()?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn retain_failed_unix_close(
    closed: std::result::Result<
        sync_extend_platform_fs::ClosedUnixOriginalResources,
        sync_extend_platform_fs::UnixOriginalResourceCloseFailure,
    >,
) {
    // Preserve the acquisition error at the call site. Any uncertain original
    // close remains retained; a failed acquisition never issues a close witness.
    if let Err(failure) = closed {
        failure.retain_until_process_exit();
    }
}

#[cfg(target_os = "linux")]
fn read_original(
    source: &sync_extend_platform_fs::UnixProtectedArtifactSource,
    maximum: usize,
) -> Result<Vec<u8>> {
    source.verify_original()?;
    if source.bytes() > maximum as u64 {
        return Err(ReconcileError::ResourceLimit(
            "original Unix artifact bytes",
        ));
    }
    Ok(source.read_bounded()?)
}

/// The operator supplies one existing private anchor. On Windows this proves
/// the current process SID; on Linux it is an independent exact 32-byte
/// wrapping key, held through all envelope operations and never bundled.
pub struct DeploymentProtectionProvider {
    original_anchor: OriginalProtectedArtifact,
    scope: ProtectionScope,
    #[cfg(target_os = "linux")]
    key: ring::aead::LessSafeKey,
}

impl DeploymentProtectionProvider {
    pub fn open_original(private_anchor: &Path) -> Result<Self> {
        #[cfg(windows)]
        {
            return Self::open_original_retaining(private_anchor)
                .map_err(OriginalProtectedArtifactOpenFailure::retain_and_report);
        }
        #[cfg(not(windows))]
        {
        let original_anchor = OriginalProtectedArtifact::capture(private_anchor, 65_536, true)?;
        #[cfg(target_os = "linux")]
        let observed = (|| -> Result<_> {
            if original_anchor.original_bytes().len() != 32 {
                return Err(ReconcileError::Invariant(
                    "independent Unix deployment wrapping key must be exactly 32 bytes",
                ));
            }
            let uid = original_anchor.source.key().uid;
            let scope = ProtectionScope {
                provider: ProtectionProviderKind::UnixSameUidAead,
                principal_digest: ContentId::hash(&serde_json::to_vec(&(
                    "sync-extend-deployment-unix-principal-v2",
                    uid,
                ))?),
                independent_key_digest: Some(original_anchor.source_digest().clone()),
            };
            let key = ring::aead::UnboundKey::new(
                &ring::aead::CHACHA20_POLY1305,
                original_anchor.original_bytes(),
            )
            .map_err(|_| ReconcileError::Invariant("Unix deployment AEAD key refused"))?;
            Ok((scope, ring::aead::LessSafeKey::new(key)))
        })();
        #[cfg(target_os = "linux")]
        let (scope, key) = match observed {
            Ok(observed) => observed,
            Err(error) => {
                retain_failed_unix_close(original_anchor.close_retaining());
                return Err(error);
            }
        };
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err(ReconcileError::Invariant(
            "deployment cryptographic provider unavailable",
        ));
        #[cfg(any(windows, target_os = "linux"))]
        {
            let provider = Self {
                original_anchor,
                scope,
                #[cfg(target_os = "linux")]
                key,
            };
            if let Err(error) = provider.verify_original() {
                retain_failed_unix_close(provider.close_retaining());
                return Err(error);
            }
            Ok(provider)
        }
        }
    }

    #[cfg(windows)]
    pub fn open_original_retaining(
        private_anchor: &Path,
    ) -> std::result::Result<Self, OriginalProtectedArtifactOpenFailure> {
        let original_anchor = OriginalProtectedArtifact::capture_retaining(
            private_anchor, 65_536, true,
        )?;
        let scope = match original_anchor.source.private_owner_acl.as_ref() {
            Some((principal_digest, _)) => ProtectionScope {
                provider: ProtectionProviderKind::WindowsCurrentUserDpapi,
                principal_digest: principal_digest.clone(),
                independent_key_digest: None,
            },
            None => {
                return Err(OriginalProtectedArtifactOpenFailure {
                    error: ReconcileError::Invariant("actual private Windows provider anchor"),
                    original_resources: original_anchor.close_retaining().err(),
                });
            }
        };
        let provider = Self { original_anchor, scope };
        if let Err(error) = provider.verify_original() {
            return Err(OriginalProtectedArtifactOpenFailure {
                error,
                original_resources: provider.close_retaining().err(),
            });
        }
        Ok(provider)
    }

    pub fn scope(&self) -> &ProtectionScope {
        &self.scope
    }

    pub fn verify_original(&self) -> Result<()> {
        if !self.original_anchor.private {
            return Err(ReconcileError::Invariant(
                "native private provider scope absent",
            ));
        }
        self.original_anchor.verify_original()
    }

    pub(crate) fn protect_original(
        &self,
        source: &OriginalProtectedArtifact,
        binding: &ProtectedArtifactBinding,
    ) -> Result<Vec<u8>> {
        if !source.private || source.source_path() != binding.source_path {
            return Err(ReconcileError::Invariant(
                "protected artifact original private source",
            ));
        }
        source.verify_original()?;
        let result = self.protect_bytes(source.original_bytes(), binding)?;
        source.verify_original()?;
        Ok(result)
    }

    /// Actual node capture and a restricted mapping of a verified original
    /// supply bytes here. This crate-private operation is never a CLI bypass.
    pub(crate) fn protect_bytes(
        &self,
        source: &[u8],
        binding: &ProtectedArtifactBinding,
    ) -> Result<Vec<u8>> {
        self.verify_original()?;
        binding.validate()?;
        if source.len() as u64 != binding.source_bytes
            || ContentId::hash(source) != binding.source_digest
            || !self.platform_matches(binding.platform)
        {
            return Err(ReconcileError::Invariant(
                "protected original byte/platform binding",
            ));
        }
        let entropy = authenticated_context(binding, &self.scope)?;
        #[cfg(windows)]
        let (nonce, ciphertext) = (
            Vec::new(),
            windows_dpapi::encrypt_data(source, windows_dpapi::Scope::User, Some(&entropy))
                .map_err(|_| ReconcileError::Invariant("deployment current-user DPAPI refused"))?,
        );
        #[cfg(target_os = "linux")]
        let (nonce, ciphertext) = {
            use ring::rand::SecureRandom;
            let mut nonce = [0u8; 12];
            ring::rand::SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| {
                    ReconcileError::Invariant("deployment cryptographic nonce unavailable")
                })?;
            let mut ciphertext = source.to_vec();
            self.key
                .seal_in_place_append_tag(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(&entropy),
                    &mut ciphertext,
                )
                .map_err(|_| ReconcileError::Invariant("Unix deployment AEAD sealing refused"))?;
            (nonce.to_vec(), ciphertext)
        };
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err(ReconcileError::Invariant(
            "deployment protection unavailable",
        ));
        #[cfg(any(windows, target_os = "linux"))]
        {
            let header = serde_json::to_vec(&EnvelopeHeader {
                format_version: 2,
                scope: self.scope.clone(),
                binding_digest: ContentId::hash(&entropy),
                nonce,
                ciphertext_bytes: ciphertext.len() as u64,
            })?;
            if header.len() > 4096 || ciphertext.is_empty() || ciphertext.len() > MAX_ENVELOPE {
                return Err(ReconcileError::ResourceLimit(
                    "protected envelope allocation",
                ));
            }
            let mut bytes = Vec::with_capacity(12 + header.len() + ciphertext.len());
            bytes.extend_from_slice(MAGIC);
            bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&ciphertext);
            self.verify_original()?;
            Ok(bytes)
        }
    }

    pub(crate) fn verify_provider(
        &self,
        envelope: &[u8],
        binding: &ProtectedArtifactBinding,
    ) -> Result<VerifiedProtectedArtifact> {
        self.verify_original()?;
        binding.validate()?;
        if envelope.len() < 13
            || envelope.len() > MAX_ENVELOPE + 4108
            || envelope.get(..8) != Some(MAGIC.as_slice())
            || !self.platform_matches(binding.platform)
        {
            return Err(ReconcileError::Invariant(
                "protected deployment envelope framing",
            ));
        }
        let length = u32::from_le_bytes(
            envelope[8..12]
                .try_into()
                .map_err(|_| ReconcileError::Invariant("protected header length"))?,
        ) as usize;
        let end = 12usize
            .checked_add(length)
            .filter(|end| length > 0 && length <= 4096 && *end < envelope.len())
            .ok_or(ReconcileError::ResourceLimit(
                "protected envelope header bytes",
            ))?;
        let header: EnvelopeHeader = serde_json::from_slice(&envelope[12..end])?;
        let entropy = authenticated_context(binding, &self.scope)?;
        if header.format_version != 2
            || header.scope != self.scope
            || header.binding_digest != ContentId::hash(&entropy)
            || header.ciphertext_bytes != (envelope.len() - end) as u64
        {
            return Err(ReconcileError::Invariant(
                "protected deployment role/graph/provider/user/key binding",
            ));
        }
        #[cfg(windows)]
        let clear = {
            if !header.nonce.is_empty() {
                return Err(ReconcileError::Invariant(
                    "DPAPI envelope has foreign nonce",
                ));
            }
            windows_dpapi::decrypt_data(
                &envelope[end..],
                windows_dpapi::Scope::User,
                Some(&entropy),
            )
            .map_err(|_| ReconcileError::Invariant("deployment current-user DPAPI verification"))?
        };
        #[cfg(target_os = "linux")]
        let clear = {
            let nonce: [u8; 12] = header
                .nonce
                .as_slice()
                .try_into()
                .map_err(|_| ReconcileError::Invariant("Unix deployment AEAD nonce length"))?;
            let mut bytes = envelope[end..].to_vec();
            let clear = self
                .key
                .open_in_place(
                    ring::aead::Nonce::assume_unique_for_key(nonce),
                    ring::aead::Aad::from(&entropy),
                    &mut bytes,
                )
                .map_err(|_| {
                    ReconcileError::Invariant("Unix deployment AEAD verification refused")
                })?;
            let length = clear.len();
            bytes.truncate(length);
            bytes
        };
        #[cfg(not(any(windows, target_os = "linux")))]
        return Err(ReconcileError::Invariant("deployment provider unavailable"));
        #[cfg(any(windows, target_os = "linux"))]
        {
            let clear = SecretBytes(clear);
            if clear.0.len() as u64 != binding.source_bytes
                || ContentId::hash(&clear.0) != binding.source_digest
            {
                return Err(ReconcileError::Invariant(
                    "verified protected original length/digest",
                ));
            }
            self.verify_original()?;
            Ok(VerifiedProtectedArtifact {
                original: clear,
                binding: binding.clone(),
                scope: self.scope.clone(),
            })
        }
    }

    fn platform_matches(&self, platform: DeploymentPlatform) -> bool {
        matches!(
            (self.scope.provider, platform),
            (
                ProtectionProviderKind::WindowsCurrentUserDpapi,
                DeploymentPlatform::Windows
            ) | (
                ProtectionProviderKind::UnixSameUidAead,
                DeploymentPlatform::Linux
            )
        )
    }

    pub fn close(self) -> Result<()> {
        self.original_anchor.close()
    }

    #[cfg(windows)]
    pub fn close_retaining(
        self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedWindowsOriginalResources,
        sync_extend_platform_fs::WindowsOriginalResourceCloseFailure,
    > {
        self.original_anchor.close_retaining()
    }

    #[cfg(target_os = "linux")]
    pub fn close_retaining(
        self,
    ) -> std::result::Result<
        sync_extend_platform_fs::ClosedUnixOriginalResources,
        sync_extend_platform_fs::UnixOriginalResourceCloseFailure,
    > {
        self.original_anchor.close_retaining()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeHeader {
    format_version: u32,
    scope: ProtectionScope,
    binding_digest: ContentId,
    nonce: Vec<u8>,
    ciphertext_bytes: u64,
}

fn authenticated_context(
    binding: &ProtectedArtifactBinding,
    scope: &ProtectionScope,
) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&(
        "sync-extend-protected-deployment-original-v2",
        scope,
        binding,
    ))?;
    if bytes.len() > 65_536 {
        return Err(ReconcileError::ResourceLimit(
            "protected authentication context",
        ));
    }
    Ok(bytes)
}

/// Issued only after actual provider verification against the complete
/// re-derived graph. Existing payload mappers receive this live value rather
/// than a reconstructed temporary secret file or caller-supplied raw bytes.
pub struct VerifiedProtectedArtifact {
    original: SecretBytes,
    binding: ProtectedArtifactBinding,
    scope: ProtectionScope,
}

impl VerifiedProtectedArtifact {
    pub fn binding(&self) -> &ProtectedArtifactBinding {
        &self.binding
    }

    pub fn protection_scope(&self) -> &ProtectionScope {
        &self.scope
    }

    pub(crate) fn checked_original_bytes(
        &self,
        role: ProtectedArtifactRole,
        consumer: &ContentId,
    ) -> Result<&[u8]> {
        if self.binding.role != role
            || self.binding.consumer_digest != *consumer
            || self.original.0.len() as u64 != self.binding.source_bytes
            || ContentId::hash(&self.original.0) != self.binding.source_digest
        {
            return Err(ReconcileError::Invariant(
                "sealed protected consumer role/bytes",
            ));
        }
        Ok(&self.original.0)
    }

    pub(crate) fn original_bytes(&self) -> &[u8] {
        &self.original.0
    }
}
