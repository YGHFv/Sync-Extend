//! Listener-specific credentials never become synchronized space data.
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::Path,
};
use sync_extend_core_model::{webdav::WebDavListener, ContentId, EntryId};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format_version: u32,
    listener_id: EntryId,
    passwords: BTreeMap<String, String>,
}

pub struct Credentials {
    passwords: BTreeMap<String, String>,
}

pub fn generate(path: &Path, listener: &WebDavListener) -> Result<(), Box<dyn std::error::Error>> {
    listener.validate()?;
    let passwords = listener
        .accounts
        .iter()
        .map(|account| {
            let a = EntryId::random()?;
            let b = EntryId::random()?;
            Ok((account.username.clone(), format!("{a}{b}")))
        })
        .collect::<sync_extend_core_model::Result<BTreeMap<_, _>>>()?;
    let stored = Stored {
        format_version: 1,
        listener_id: listener.listener_id.clone(),
        passwords,
    };
    let bytes = serde_json::to_vec(&stored)?;
    let bytes = protect(&bytes)?;
    #[cfg(windows)]
    let _parents = parents(path)?;
    #[cfg(not(windows))]
    parents(path)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let mut file = options.open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

impl Credentials {
    pub fn password(&self, username: &str) -> Option<&str> {
        self.passwords.get(username).map(String::as_str)
    }

    pub fn load(
        path: &Path,
        listener: &WebDavListener,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        #[cfg(windows)]
        let _parents = parents(path)?;
        #[cfg(not(windows))]
        parents(path)?;
        #[cfg(windows)]
        let held = sync_extend_platform_fs::GuardedReadFile::open(path)?;
        #[cfg(windows)]
        let file = held.reader();
        #[cfg(not(windows))]
        let held = fs::File::open(path)?;
        #[cfg(not(windows))]
        let file = &held;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 {
            return Err("invalid local credential file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("credential permissions require owner only".into());
            }
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 {
            return Err("credential file limit".into());
        }
        let stored: Stored = serde_json::from_slice(&unprotect(&bytes)?)?;
        if stored.format_version != 1
            || stored.listener_id != listener.listener_id
            || stored
                .passwords
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
                != listener
                    .accounts
                    .iter()
                    .map(|account| &account.username)
                    .collect()
            || stored.passwords.values().any(|password| {
                password.len() != 64
                    || !password
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err("credential listener/account scope differs".into());
        }
        Ok(Self {
            passwords: stored.passwords,
        })
    }

    pub fn authenticate(&self, authorization: &str) -> Option<&str> {
        let encoded = authorization.strip_prefix("Basic ")?;
        let bytes = base64(encoded)?;
        let clear = std::str::from_utf8(&bytes).ok()?;
        let (username, password) = clear.split_once(':')?;
        let expected = self.passwords.get_key_value(username)?;
        let actual_hash = ContentId::hash(password.as_bytes());
        let expected_hash = ContentId::hash(expected.1.as_bytes());
        let different = actual_hash
            .as_str()
            .bytes()
            .zip(expected_hash.as_str().bytes())
            .fold(0u8, |different, (a, b)| different | (a ^ b));
        if different == 0 {
            Some(expected.0.as_str())
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn parents(path: &Path) -> std::io::Result<Vec<sync_extend_platform_fs::LockedDirectory>> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("credential parent required"))?;
    if !path.is_absolute() {
        return Err(std::io::Error::other("absolute credential path required"));
    }
    parent
        .ancestors()
        .filter(|path| path.is_absolute())
        .map(sync_extend_platform_fs::LockedDirectory::open)
        .collect()
}

#[cfg(not(windows))]
fn parents(path: &Path) -> std::io::Result<()> {
    if !path.is_absolute() {
        return Err(std::io::Error::other("absolute credential path required"));
    }
    for parent in path
        .parent()
        .ok_or_else(|| std::io::Error::other("credential parent required"))?
        .ancestors()
    {
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() {
            return Err(std::io::Error::other("credential symlink refused"));
        }
    }
    Ok(())
}

fn base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() > 512 || !value.len().is_multiple_of(4) {
        return None;
    }
    let mut output = Vec::new();
    let decode = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let chunks = value.as_bytes().chunks_exact(4);
    let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let a = decode(chunk[0])?;
        let b = decode(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            decode(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            decode(chunk[3])?
        };
        let padding = usize::from(chunk[2] == b'=') + usize::from(chunk[3] == b'=');
        if padding > 0 && index + 1 != count
            || chunk[2] == b'=' && chunk[3] != b'='
            || padding == 2 && b & 15 != 0
            || padding == 1 && c & 3 != 0
        {
            return None;
        }
        output.push(a << 2 | b >> 4);
        if padding < 2 {
            output.push(b << 4 | c >> 2);
        }
        if padding < 1 {
            output.push(c << 6 | d);
        }
    }
    Some(output)
}

#[cfg(windows)]
fn protect(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    windows_dpapi::encrypt_data(
        bytes,
        windows_dpapi::Scope::User,
        Some(b"SyncExtend WebDAV credentials v1"),
    )
    .map_err(|_| "credential DPAPI encryption failed".into())
}
#[cfg(windows)]
fn unprotect(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    windows_dpapi::decrypt_data(
        bytes,
        windows_dpapi::Scope::User,
        Some(b"SyncExtend WebDAV credentials v1"),
    )
    .map_err(|_| "credential DPAPI decryption failed".into())
}
#[cfg(not(windows))]
fn protect(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(bytes.to_vec())
}
#[cfg(not(windows))]
fn unprotect(bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(bytes.to_vec())
}
