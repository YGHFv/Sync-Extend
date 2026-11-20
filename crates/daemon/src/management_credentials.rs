//! Explicit listener-local credentials with optional Windows current-user protection.
#[cfg(not(windows))]
use std::fs;
#[cfg(windows)]
use std::io::{Read, Seek, SeekFrom};
use std::{io::Write, path::Path};
use sync_extend_core_model::{
    management::{ManagementConfig, TokenProtection},
    EntryId,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn valid(bytes: &[u8]) -> bool {
    bytes.len() == 64
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(windows)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedToken {
    format_version: u32,
    address: std::net::SocketAddr,
    token_file: std::path::PathBuf,
    token: String,
}

#[cfg(windows)]
fn protect(config: &ManagementConfig, token: &[u8]) -> Result<Vec<u8>> {
    let value = ProtectedToken {
        format_version: 1,
        address: config.address,
        token_file: config.token_file.clone(),
        token: std::str::from_utf8(token)?.to_owned(),
    };
    windows_dpapi::encrypt_data(
        &serde_json::to_vec(&value)?,
        windows_dpapi::Scope::User,
        Some(b"SyncExtend management token v1"),
    )
    .map_err(|_| "management current-user protection failed".into())
}

#[cfg(windows)]
fn unprotect(config: &ManagementConfig, bytes: &[u8]) -> Result<Vec<u8>> {
    let clear = windows_dpapi::decrypt_data(
        bytes,
        windows_dpapi::Scope::User,
        Some(b"SyncExtend management token v1"),
    )
    .map_err(|_| "management current-user credential cannot be decrypted")?;
    let value: ProtectedToken = serde_json::from_slice(&clear)?;
    if value.format_version != 1
        || value.address != config.address
        || value.token_file != config.token_file
        || !valid(value.token.as_bytes())
    {
        return Err("management credential listener or file binding differs".into());
    }
    Ok(value.token.into_bytes())
}

#[cfg(not(windows))]
fn protect(_: &ManagementConfig, _: &[u8]) -> Result<Vec<u8>> {
    Err("windows_user management protection requires Windows".into())
}

#[cfg(not(windows))]
fn unprotect(_: &ManagementConfig, _: &[u8]) -> Result<Vec<u8>> {
    Err("windows_user management protection requires Windows".into())
}

#[cfg(windows)]
fn parents(path: &Path) -> std::io::Result<Vec<sync_extend_platform_fs::LockedDirectory>> {
    path.parent()
        .ok_or_else(|| std::io::Error::other("management credential parent required"))?
        .ancestors()
        .filter(|ancestor| ancestor.is_absolute())
        .map(sync_extend_platform_fs::LockedDirectory::open)
        .collect()
}

#[cfg(not(windows))]
fn parents(path: &Path) -> std::io::Result<()> {
    for ancestor in path
        .parent()
        .ok_or_else(|| std::io::Error::other("management credential parent required"))?
        .ancestors()
    {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err(std::io::Error::other(
                "management credential symlink refused",
            ));
        }
    }
    Ok(())
}

pub fn generate(config: &ManagementConfig) -> Result<()> {
    config.validate()?;
    let token = format!("{}{}", EntryId::random()?, EntryId::random()?);
    if !valid(token.as_bytes()) {
        return Err("management random token format differs".into());
    }
    let bytes = match config.token_protection {
        TokenProtection::Plain => token.into_bytes(),
        TokenProtection::WindowsUser => protect(config, token.as_bytes())?,
    };
    if bytes.len() > 4096 {
        return Err("protected management credential exceeds bound".into());
    }
    #[cfg(windows)]
    let locked_parents = parents(&config.token_file)?;
    #[cfg(not(windows))]
    parents(&config.token_file)?;
    #[cfg(windows)]
    {
        // The token is created through the retained native parent handle so
        // the kernel installs the current-user owner and protected DACL in
        // the CREATE itself.  A pathname OpenOptions CREATE would inherit
        // the directory DACL and leave a race before the security audit.
        let parent = locked_parents
            .first()
            .ok_or("management credential parent required")?;
        let component = config
            .token_file
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("management credential filename required")?;
        let mut file = parent.create_new_current_user_file(component)?;
        file.original_creation()?.verify()?;
        sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
        file.writer().write_all(&bytes)?;
        file.writer().sync_all()?;
        file.writer().seek(SeekFrom::Start(0))?;
        let mut readback = Vec::with_capacity(bytes.len());
        file.reader()
            .take(bytes.len() as u64 + 1)
            .read_to_end(&mut readback)?;
        if readback != bytes {
            return Err("management credential CREATE readback differs".into());
        }
        sync_extend_platform_fs::verify_current_user_private_file(file.reader())?;
        let sealed = file.seal_original()?;
        sealed.verify_original()?;
        sync_extend_platform_fs::verify_current_user_private_file(sealed.reader())?;
    }
    #[cfg(not(windows))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&config.token_file)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    #[cfg(unix)]
    fs::File::open(
        config
            .token_file
            .parent()
            .ok_or("credential parent required")?,
    )?
    .sync_all()?;
    Ok(())
}

pub fn load(config: &ManagementConfig) -> Result<Vec<u8>> {
    config.validate()?;
    let maximum = match config.token_protection {
        TokenProtection::Plain => 64,
        TokenProtection::WindowsUser => 4096,
    };
    #[cfg(not(windows))]
    let bytes = super::config_file::read(&config.token_file, maximum)?;
    #[cfg(windows)]
    let bytes = {
        let _parents = parents(&config.token_file)?;
        let held = sync_extend_platform_fs::GuardedReadFile::open(&config.token_file)?;
        sync_extend_platform_fs::verify_current_user_private_file(held.reader())?;
        let mut bytes = Vec::new();
        held.reader()
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > maximum {
            return Err("management credential exceeds bound".into());
        }
        held.verify_single_link()?;
        sync_extend_platform_fs::verify_current_user_private_file(held.reader())?;
        bytes
    };
    let token = match config.token_protection {
        TokenProtection::Plain => bytes,
        TokenProtection::WindowsUser => unprotect(config, &bytes)?,
    };
    if !valid(&token) {
        return Err("management token requires exactly 64 lowercase hexadecimal bytes".into());
    }
    Ok(token)
}
