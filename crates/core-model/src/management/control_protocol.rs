//! Explicit local control grants with owner generation and bounded replay refusal.
//! Credentials authorize only the configured local role, never synchronization data.
use crate::{EntryId, ModelError, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlPolicy {
    pub status: bool,
    #[serde(default)]
    pub dashboard: bool,
    pub stop: bool,
    pub max_control_requests: u32,
}

impl ControlPolicy {
    pub fn validate(&self) -> Result<()> {
        if (!self.status && !self.stop && !self.dashboard)
            || !(1..=4096).contains(&self.max_control_requests)
        {
            return Err(ModelError::InvalidConfig(
                "explicit bounded local control policy",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlOperation {
    Status,
    Stop,
}

pub struct ControlRequest {
    operation: ControlOperation,
    owner_generation: Option<EntryId>,
    request_id: Option<EntryId>,
}

/// Parse a complete, bodyless request. Reject duplicate framing, pipeline bytes,
/// unsupported routes/headers, noncanonical IDs and unrelated authority.
pub fn authenticated_control_request(
    bytes: &[u8],
    address: SocketAddr,
    secret: &[u8],
) -> Result<ControlRequest> {
    if bytes.len() > 4096
        || secret.len() != 64
        || !secret
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || !bytes.ends_with(b"\r\n\r\n")
    {
        return Err(ModelError::InvalidData("bounded local control request"));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ModelError::InvalidData("local control request encoding"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let operation = match lines.next() {
        Some("GET /v1/status HTTP/1.1") => ControlOperation::Status,
        Some("POST /v1/control/stop HTTP/1.1") => ControlOperation::Stop,
        _ => return Err(ModelError::InvalidData("local control route")),
    };
    let mut authority = None;
    let mut authorization = None;
    let mut generation = None;
    let mut request = None;
    let mut content_length = None;
    let mut connection = None;
    for line in lines {
        let (name, value) = line
            .split_once(": ")
            .ok_or(ModelError::InvalidData("local control header"))?;
        let slot = if name.eq_ignore_ascii_case("host") {
            &mut authority
        } else if name.eq_ignore_ascii_case("authorization") {
            &mut authorization
        } else if name.eq_ignore_ascii_case("x-sync-owner") {
            &mut generation
        } else if name.eq_ignore_ascii_case("x-sync-request") {
            &mut request
        } else if name.eq_ignore_ascii_case("content-length") {
            &mut content_length
        } else if name.eq_ignore_ascii_case("connection") {
            &mut connection
        } else {
            return Err(ModelError::InvalidData("unsupported local control header"));
        };
        if slot.replace(value).is_some() {
            return Err(ModelError::InvalidData("duplicate local control header"));
        }
    }
    if authority != Some(address.to_string().as_str())
        || content_length.is_some_and(|value| value != "0")
        || connection.is_some_and(|value| !value.eq_ignore_ascii_case("close"))
    {
        return Err(ModelError::InvalidData(
            "local control authority or framing",
        ));
    }
    let supplied = authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ModelError::InvalidData("local control authorization"))?
        .as_bytes();
    let mut mismatch = supplied.len() ^ secret.len();
    for (actual, expected) in supplied.iter().zip(secret) {
        mismatch |= usize::from(actual ^ expected);
    }
    if mismatch != 0 {
        return Err(ModelError::InvalidData("local control authorization"));
    }
    let parse_id =
        |value: Option<&str>| -> Result<Option<EntryId>> { value.map(str::parse).transpose() };
    let owner_generation = parse_id(generation)?;
    let request_id = parse_id(request)?;
    match operation {
        ControlOperation::Status if owner_generation.is_some() || request_id.is_some() => {
            return Err(ModelError::InvalidData("unexpected local status fields"));
        }
        ControlOperation::Stop if owner_generation.is_none() || request_id.is_none() => {
            return Err(ModelError::InvalidData(
                "local control generation and request required",
            ));
        }
        _ => {}
    }
    Ok(ControlRequest {
        operation,
        owner_generation,
        request_id,
    })
}

pub struct ControlSession {
    generation: EntryId,
    policy: ControlPolicy,
    accepted: BTreeSet<EntryId>,
    stop_requested: bool,
}

impl ControlSession {
    pub fn new(generation: EntryId, policy: ControlPolicy) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            generation,
            policy,
            accepted: BTreeSet::new(),
            stop_requested: false,
        })
    }

    pub fn generation(&self) -> &EntryId {
        &self.generation
    }

    pub fn stop_requested(&self) -> bool {
        self.stop_requested
    }

    /// The caller dispatches the granted operation while holding this session's
    /// exclusive borrow. No replay entry is evicted during the owner's lifetime.
    pub fn accept(&mut self, request: ControlRequest) -> Result<ControlOperation> {
        let allowed = match request.operation {
            ControlOperation::Status => self.policy.status,
            ControlOperation::Stop => self.policy.stop,
        };
        if !allowed {
            return Err(ModelError::InvalidData("local control permission absent"));
        }
        if request.operation == ControlOperation::Status {
            return Ok(request.operation);
        }
        let generation = request
            .owner_generation
            .ok_or(ModelError::InvalidData("local control generation absent"))?;
        let request_id = request
            .request_id
            .ok_or(ModelError::InvalidData("local control request absent"))?;
        if generation != self.generation
            || self.accepted.contains(&request_id)
            || self.accepted.len() >= self.policy.max_control_requests as usize
            || self.stop_requested
        {
            return Err(ModelError::InvalidData(
                "local control stale replay or exhausted",
            ));
        }
        self.accepted.insert(request_id);
        if request.operation == ControlOperation::Stop {
            self.stop_requested = true;
        }
        Ok(request.operation)
    }
}
