//! Listener-local export authorization and bounded HTTP conditions.
use crate::{ContentId, ModelError, PortablePath, Result, SpaceId};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavExport {
    pub name: String,
    pub space_id: SpaceId,
    pub subtree: Option<PortablePath>,
    pub writable: bool,
    pub max_upload_bytes: u64,
    pub allow_native_windows_writes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavAccount {
    pub username: String,
    pub exports: BTreeSet<String>,
    pub writable_exports: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavListener {
    pub format_version: u32,
    pub enabled: bool,
    pub listener_id: crate::EntryId,
    pub address: SocketAddr,
    pub exports: Vec<WebDavExport>,
    pub accounts: Vec<WebDavAccount>,
    pub request_timeout_secs: u64,
    pub max_header_bytes: usize,
    pub max_requests: u64,
}

impl WebDavListener {
    pub fn validate(&self) -> Result<()> {
        if self.format_version != 1
            || !self.address.ip().is_loopback()
            || self.address.port() == 0
            || self.exports.len() > 64
            || self.accounts.len() > 64
            || !(1..=300).contains(&self.request_timeout_secs)
            || !(1024..=65536).contains(&self.max_header_bytes)
            || !(1..=1_000_000).contains(&self.max_requests)
        {
            return Err(ModelError::InvalidConfig(
                "bounded loopback authenticated WebDAV listener required",
            ));
        }
        let mut names = BTreeSet::new();
        for export in &self.exports {
            if !name(&export.name)
                || !names.insert(&export.name)
                || export.max_upload_bytes == 0
                || export.max_upload_bytes > 64 * 1024 * 1024 * 1024
                || export.allow_native_windows_writes && !export.writable
            {
                return Err(ModelError::InvalidConfig("invalid WebDAV export"));
            }
        }
        let mut accounts = BTreeSet::new();
        for account in &self.accounts {
            if !name(&account.username)
                || !accounts.insert(&account.username)
                || account.exports.is_empty()
                || !account.writable_exports.is_subset(&account.exports)
                || !account.exports.iter().all(|name| names.contains(name))
            {
                return Err(ModelError::InvalidConfig(
                    "invalid WebDAV account export grants",
                ));
            }
        }
        if self.enabled && (names.is_empty() || accounts.is_empty()) {
            return Err(ModelError::InvalidConfig(
                "enabled WebDAV requires explicit exports and accounts",
            ));
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        username: &str,
        target: &str,
        write: bool,
    ) -> Result<AuthorizedWebDavPath> {
        self.validate()?;
        if !self.enabled {
            return Err(ModelError::InvalidConfig("WebDAV disabled"));
        }
        let decoded = decode_path(target)?;
        let relative = decoded
            .strip_prefix('/')
            .ok_or(ModelError::InvalidPath("absolute DAV path required"))?;
        let (export_name, tail) = relative.split_once('/').unwrap_or((relative, ""));
        let export = self
            .exports
            .iter()
            .find(|export| export.name == export_name)
            .ok_or(ModelError::InvalidPath("unknown DAV export"))?;
        let account = self
            .accounts
            .iter()
            .find(|account| account.username == username)
            .ok_or(ModelError::InvalidData("unknown DAV account"))?;
        if !account.exports.contains(export_name)
            || (write && (!export.writable || !account.writable_exports.contains(export_name)))
        {
            return Err(ModelError::InvalidData("DAV export access denied"));
        }
        let tail = tail.strip_suffix('/').unwrap_or(tail);
        if tail.starts_with('/') || tail.ends_with('/') {
            return Err(ModelError::InvalidPath("DAV repeated separators"));
        }
        let path = match (&export.subtree, tail.is_empty()) {
            (None, true) => None,
            (Some(prefix), true) => Some(prefix.clone()),
            (None, false) => Some(PortablePath::new(tail)?),
            (Some(prefix), false) => Some(PortablePath::new(format!("{prefix}/{tail}"))?),
        };
        Ok(AuthorizedWebDavPath {
            listener_id: self.listener_id.clone(),
            export_name: export.name.clone(),
            space_id: export.space_id.clone(),
            path,
            export_root: tail.is_empty(),
            max_upload_bytes: export.max_upload_bytes,
            allow_native_windows_writes: export.allow_native_windows_writes,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedWebDavPath {
    pub listener_id: crate::EntryId,
    pub export_name: String,
    pub space_id: SpaceId,
    pub path: Option<PortablePath>,
    pub export_root: bool,
    pub max_upload_bytes: u64,
    pub allow_native_windows_writes: bool,
}

fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}

pub fn decode_path(target: &str) -> Result<String> {
    if target.len() > 12288 || !target.starts_with('/') || target.contains(['?', '#', '\\']) {
        return Err(ModelError::InvalidPath("invalid DAV request target"));
    }
    let mut result = Vec::new();
    let mut bytes = target.bytes();
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let high = bytes.next().and_then(|byte| (byte as char).to_digit(16));
            let low = bytes.next().and_then(|byte| (byte as char).to_digit(16));
            let value = high
                .zip(low)
                .map(|(high, low)| (high * 16 + low) as u8)
                .ok_or(ModelError::InvalidPath("invalid DAV percent encoding"))?;
            if b"/\\%".contains(&value) {
                return Err(ModelError::InvalidPath(
                    "encoded DAV separator or nested escape",
                ));
            }
            value
        } else {
            byte
        };
        if byte.is_ascii_control() {
            return Err(ModelError::InvalidPath("DAV control character"));
        }
        result.push(byte);
    }
    String::from_utf8(result).map_err(|_| ModelError::InvalidPath("DAV UTF8 encoding"))
}

pub fn etag(content: &ContentId) -> String {
    format!("\"{content}\"")
}

pub fn resource_etag(entry: &crate::Entry) -> Result<String> {
    // Entry identity makes COPY/recreate distinguishable even with equal bytes.
    // Directory ETags describe the directory entry, not its descendants.
    Ok(etag(&ContentId::hash(&serde_json::to_vec(entry)?)))
}

pub fn if_match(header: Option<&str>, current: Option<&str>) -> Result<bool> {
    let Some(header) = header else {
        return Ok(true);
    };
    if header.len() > 8192 {
        return Err(ModelError::InvalidData("DAV condition limit"));
    }
    if header == "*" {
        return Ok(current.is_some());
    }
    let values = etag_list(header)?;
    let mut matched = false;
    for value in values {
        matched |= !value.starts_with("W/") && current == Some(value);
    }
    Ok(matched)
}

pub fn valid_etag(value: &str) -> bool {
    let value = value.strip_prefix("W/").unwrap_or(value);
    value.len() >= 2
        && value.starts_with('"')
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte) || *byte >= 0x80)
}

pub fn if_none_match(header: Option<&str>, current: Option<&str>) -> Result<bool> {
    let Some(header) = header else {
        return Ok(true);
    };
    if header == "*" {
        return Ok(current.is_none());
    }
    if header.len() > 8192 {
        return Err(ModelError::InvalidData("DAV condition limit"));
    }
    for value in etag_list(header)? {
        let normalized = value.strip_prefix("W/").unwrap_or(value);
        if current.map(|current| current.strip_prefix("W/").unwrap_or(current)) == Some(normalized)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn etag_list(header: &str) -> Result<Vec<&str>> {
    let mut remainder = header.trim();
    let mut values = Vec::new();
    while !remainder.is_empty() {
        if values.len() >= 32 {
            return Err(ModelError::InvalidData("DAV condition count"));
        }
        let tag = remainder.strip_prefix("W/").unwrap_or(remainder);
        if !tag.starts_with('"') {
            return Err(ModelError::InvalidData("DAV quoted ETag required"));
        }
        let end = tag[1..]
            .find('"')
            .map(|index| index + 2)
            .ok_or(ModelError::InvalidData("DAV unclosed ETag"))?;
        let length = remainder.len() - tag.len() + end;
        let value = &remainder[..length];
        if !valid_etag(value) {
            return Err(ModelError::InvalidData("invalid DAV ETag"));
        }
        values.push(value);
        remainder = remainder[length..].trim_start();
        if !remainder.is_empty() {
            remainder = remainder
                .strip_prefix(',')
                .ok_or(ModelError::InvalidData("DAV ETag list separator"))?
                .trim_start();
            if remainder.is_empty() {
                return Err(ModelError::InvalidData("DAV trailing ETag separator"));
            }
        }
    }
    if values.is_empty() {
        return Err(ModelError::InvalidData("empty DAV ETag list"));
    }
    Ok(values)
}

pub fn byte_range(header: Option<&str>, length: u64) -> Result<Option<(u64, u64)>> {
    let Some(header) = header else {
        return Ok(None);
    };
    if header.len() > 80 || length == 0 {
        return Err(ModelError::InvalidData("unsatisfiable DAV range"));
    }
    let (start, end) = header
        .strip_prefix("bytes=")
        .and_then(|value| value.split_once('-'))
        .ok_or(ModelError::InvalidData("invalid DAV range"))?;
    if start.is_empty() {
        let suffix = decimal(end)?;
        if suffix == 0 {
            return Err(ModelError::InvalidData("unsatisfiable DAV suffix"));
        }
        return Ok(Some((length.saturating_sub(suffix), length - 1)));
    }
    let start = decimal(start)?;
    let end = if end.is_empty() {
        length - 1
    } else {
        decimal(end)?.min(length - 1)
    };
    if start > end || start >= length {
        return Err(ModelError::InvalidData("unsatisfiable DAV range"));
    }
    Ok(Some((start, end)))
}

fn decimal(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ModelError::InvalidData("invalid DAV decimal"));
    }
    value
        .parse()
        .map_err(|_| ModelError::InvalidData("DAV decimal overflow"))
}
