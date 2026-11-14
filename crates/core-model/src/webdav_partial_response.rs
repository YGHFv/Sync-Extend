//! Exact bounded collection failure descriptions. Rendering grants no native effect receipt.
use crate::{limits, EntryId, ModelError, PortablePath, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebDavCollectionFailure {
    Forbidden,
    NotFound,
    Conflict,
    PreconditionFailed,
    Locked,
    FailedDependency,
    InsufficientStorage,
    InternalError,
}
impl WebDavCollectionFailure {
    pub fn status(self) -> u16 {
        match self {
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::Locked => 423,
            Self::FailedDependency => 424,
            Self::InsufficientStorage => 507,
            Self::InternalError => 500,
        }
    }
    fn reason(self) -> &'static str {
        match self {
            Self::Forbidden => "Forbidden",
            Self::NotFound => "Not Found",
            Self::Conflict => "Conflict",
            Self::PreconditionFailed => "Precondition Failed",
            Self::Locked => "Locked",
            Self::FailedDependency => "Failed Dependency",
            Self::InsufficientStorage => "Insufficient Storage",
            Self::InternalError => "Internal Server Error",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavCollectionPathFailure {
    /// Canonical full path within one export, before URI percent encoding.
    pub path: PortablePath,
    pub failure: WebDavCollectionFailure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebDavCollectionPartialResponse {
    transaction_id: EntryId,
    failures: Vec<WebDavCollectionPathFailure>,
    body: String,
}
impl WebDavCollectionPartialResponse {
    pub fn status(&self) -> u16 {
        207
    }
    pub fn transaction_id(&self) -> &EntryId {
        &self.transaction_id
    }
    pub fn failures(&self) -> &[WebDavCollectionPathFailure] {
        &self.failures
    }
    pub fn content_type(&self) -> &'static str {
        "application/xml; charset=utf-8"
    }
    pub fn body(&self) -> &str {
        &self.body
    }
    pub fn native_execution_admitted(&self) -> bool {
        false
    }
    pub fn causal_final_committed(&self) -> bool {
        false
    }
    pub fn collection_atomic(&self) -> bool {
        false
    }
}

fn invalid() -> ModelError {
    ModelError::InvalidData("bounded exact DAV collection failure")
}
fn export_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}
fn inside(path: &PortablePath, subtree: Option<&PortablePath>) -> bool {
    subtree.is_none_or(|root| {
        path == root
            || path
                .as_str()
                .strip_prefix(root.as_str())
                .is_some_and(|tail| tail.starts_with('/'))
    })
}
fn append(output: &mut String, value: &str, maximum: usize) -> Result<()> {
    if output
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > maximum)
    {
        return Err(invalid());
    }
    output.push_str(value);
    Ok(())
}
fn encode_href(export: &str, tail: &str, maximum: usize) -> Result<String> {
    let mut href = String::new();
    append(&mut href, "/", maximum)?;
    append(&mut href, export, maximum)?;
    append(&mut href, "/", maximum)?;
    for byte in tail.bytes() {
        if byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte) {
            append(&mut href, &(byte as char).to_string(), maximum)?;
        } else {
            append(&mut href, &format!("%{byte:02X}"), maximum)?;
        }
    }
    Ok(href)
}

/// Describe only failed paths already identified by a later retained native
/// adapter. Caller booleans cannot certify partial effects or create retry rights.
pub fn describe_webdav_collection_failures(
    transaction: &EntryId,
    export: &str,
    subtree: Option<&PortablePath>,
    selected_paths: &BTreeSet<PortablePath>,
    failures: &[WebDavCollectionPathFailure],
    max_failures: usize,
    max_body_bytes: usize,
) -> Result<WebDavCollectionPartialResponse> {
    if !export_name(export)
        || selected_paths.is_empty()
        || selected_paths.len() > limits::MAX_ENTRIES
        || max_failures == 0
        || max_failures > limits::MAX_ENTRIES
        || failures.is_empty()
        || failures.len() > max_failures
        || max_body_bytes == 0
        || max_body_bytes > 4 * 1024 * 1024
        || selected_paths.iter().any(|path| !inside(path, subtree))
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for item in failures {
        if !selected_paths.contains(&item.path)
            || !inside(&item.path, subtree)
            || !seen.insert(item.path.clone())
        {
            return Err(invalid());
        }
    }
    let mut failures = failures.to_vec();
    failures.sort_by(|left, right| left.path.cmp(&right.path));
    let mut body = String::new();
    append(
        &mut body,
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><D:multistatus xmlns:D=\"DAV:\">",
        max_body_bytes,
    )?;
    for item in &failures {
        let tail = if let Some(root) = subtree {
            if &item.path == root {
                ""
            } else {
                item.path
                    .as_str()
                    .strip_prefix(root.as_str())
                    .and_then(|tail| tail.strip_prefix('/'))
                    .ok_or_else(invalid)?
            }
        } else {
            item.path.as_str()
        };
        let href = encode_href(export, tail, max_body_bytes)?;
        append(&mut body, "<D:response><D:href>", max_body_bytes)?;
        append(&mut body, &href, max_body_bytes)?;
        append(&mut body, "</D:href><D:status>HTTP/1.1 ", max_body_bytes)?;
        append(
            &mut body,
            &item.failure.status().to_string(),
            max_body_bytes,
        )?;
        append(&mut body, " ", max_body_bytes)?;
        append(&mut body, item.failure.reason(), max_body_bytes)?;
        append(&mut body, "</D:status></D:response>", max_body_bytes)?;
    }
    append(&mut body, "</D:multistatus>", max_body_bytes)?;
    Ok(WebDavCollectionPartialResponse {
        transaction_id: transaction.clone(),
        failures,
        body,
    })
}
