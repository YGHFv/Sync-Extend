use crate::{ReconcileError, Result};
use ed25519_dalek::SigningKey;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use sync_extend_core_model::DeviceId;

pub fn load_or_create(path: &Path, create: bool) -> Result<DeviceId> {
    let key = load_signing_key(path, create)?;
    Ok(DeviceId::from_public_key(key.verifying_key().as_bytes()))
}

pub(crate) fn load_signing_key(path: &Path, create: bool) -> Result<SigningKey> {
    let secret = if path.try_exists()? {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || sync_extend_cas::is_reparse(&metadata)
            || metadata.len() > 4096
        {
            return Err(ReconcileError::Invariant("unsafe identity file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ReconcileError::Invariant(
                    "identity permissions must be private",
                ));
            }
        }
        let mut stored = Vec::new();
        fs::File::open(path)?.take(4097).read_to_end(&mut stored)?;
        unprotect(&stored)?
    } else {
        if !create {
            return Err(ReconcileError::Invariant(
                "identity is missing; refusing a replacement identity",
            ));
        }
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| ReconcileError::Invariant("system RNG failed"))?;
        let protected = protect(&secret)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&protected)?;
        file.sync_all()?;
        sync_extend_cas::sync_directory(
            path.parent()
                .ok_or(ReconcileError::Invariant("missing identity directory"))?,
        )?;
        secret
    };
    Ok(SigningKey::from_bytes(&secret))
}

#[cfg(windows)]
fn protect(secret: &[u8; 32]) -> Result<Vec<u8>> {
    windows_dpapi::encrypt_data(
        secret,
        windows_dpapi::Scope::User,
        Some(b"SyncExtend device secret v1"),
    )
    .map_err(|_| ReconcileError::Invariant("DPAPI protection failed"))
}

#[cfg(windows)]
fn unprotect(stored: &[u8]) -> Result<[u8; 32]> {
    windows_dpapi::decrypt_data(
        stored,
        windows_dpapi::Scope::User,
        Some(b"SyncExtend device secret v1"),
    )
    .map_err(|_| ReconcileError::Invariant("DPAPI unprotect failed"))?
    .try_into()
    .map_err(|_| ReconcileError::Invariant("invalid device secret"))
}

#[cfg(not(windows))]
fn protect(secret: &[u8; 32]) -> Result<Vec<u8>> {
    Ok(secret.to_vec())
}

#[cfg(not(windows))]
fn unprotect(stored: &[u8]) -> Result<[u8; 32]> {
    stored
        .try_into()
        .map_err(|_| ReconcileError::Invariant("invalid device secret"))
}
