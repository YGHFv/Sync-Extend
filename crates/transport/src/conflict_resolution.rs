//! Signed resolution descriptions. No Journal, CAS handoff or native execution.
use crate::{PeerIdentity, Result, SignedOperation, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    conflict_resolution::{
        plan_file_resolution, resolving_file_operations, verify_file_resolution_projection,
        FileResolutionPlan, ResolutionLimits,
    },
    ContentId, DeviceId, Operation, SpaceId,
};

const DOMAIN: &str = "SyncExtend signed canonical file resolution v1";

fn validate_limits(space: &SpaceId, limits: ResolutionLimits) -> Result<()> {
    plan_file_resolution(space, &[], limits)?;
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileResolutionPayload {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub resolver_device: DeviceId,
    pub plan_fingerprint: ContentId,
    pub originals: Vec<SignedOperation>,
    pub resolving: Vec<SignedOperation>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFileResolution {
    pub payload: FileResolutionPayload,
    pub signature: Vec<u8>,
}

fn refused(message: &'static str) -> TransportError {
    TransportError::Authorization(message)
}

fn authenticated_originals(
    payload: &FileResolutionPayload,
    approved: &[PeerIdentity],
    limits: ResolutionLimits,
) -> Result<Vec<Operation>> {
    if approved.len() > 1024
        || payload.originals.len() > limits.max_operations
        || payload
            .originals
            .windows(2)
            .any(|pair| pair[0].operation.op_id >= pair[1].operation.op_id)
    {
        return Err(refused(
            "resolution original order, approval or operation budget",
        ));
    }
    let mut peers = BTreeMap::new();
    for peer in approved {
        peer.validate()?;
        if peer.space_id != payload.space_id || peers.insert(&peer.device_id, peer).is_some() {
            return Err(refused("resolution approval scope or duplicate"));
        }
    }
    let mut originals = Vec::new();
    for signed in &payload.originals {
        let peer = peers
            .get(&signed.operation.payload.origin_device_id)
            .ok_or(refused("resolution original origin not approved"))?;
        signed.verify(peer)?;
        originals.push(signed.operation.clone());
    }
    Ok(originals)
}

impl SignedFileResolution {
    /// Parse only a bounded envelope. This does not authenticate or authorize it.
    pub fn from_slice(bytes: &[u8], limits: ResolutionLimits) -> Result<Self> {
        if limits.max_bytes == 0
            || limits.max_bytes > sync_extend_core_model::conflict_resolution::MAX_RESOLUTION_BYTES
            || bytes.len() > limits.max_bytes
        {
            return Err(TransportError::Limit("resolution encoded byte budget"));
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Sign a pure proposal from exact approved originals. The caller still needs
    /// durable sequence admission, all branch pins and whole-plan native proof.
    pub fn sign(
        identity: &TransportIdentity,
        mut originals: Vec<SignedOperation>,
        approved: &[PeerIdentity],
        created_at_ms: u64,
        limits: ResolutionLimits,
    ) -> Result<Self> {
        validate_limits(&identity.peer.space_id, limits)?;
        if originals.len() > limits.max_operations {
            return Err(TransportError::Limit("resolution original count"));
        }
        originals.sort_by(|a, b| a.operation.op_id.cmp(&b.operation.op_id));
        let mut payload = FileResolutionPayload {
            format_version: 1,
            space_id: identity.peer.space_id.clone(),
            resolver_device: identity.peer.device_id.clone(),
            plan_fingerprint: ContentId::hash(&[]),
            originals,
            resolving: Vec::new(),
            created_at_ms,
        };
        if serde_json::to_vec(&payload)?.len() > limits.max_bytes {
            return Err(TransportError::Limit("resolution original byte budget"));
        }
        let operations = authenticated_originals(&payload, approved, limits)?;
        let plan = plan_file_resolution(&payload.space_id, &operations, limits)?;
        payload.plan_fingerprint = plan.fingerprint()?;
        let resolving =
            resolving_file_operations(&plan, &payload.resolver_device, created_at_ms, limits)?;
        verify_file_resolution_projection(&plan, &operations, &resolving, limits)?;
        payload.resolving = resolving
            .into_iter()
            .map(|operation| SignedOperation::sign(identity, operation))
            .collect::<Result<_>>()?;
        let bytes = serde_json::to_vec(&payload)?;
        if bytes.len().saturating_add(512) > limits.max_bytes {
            return Err(TransportError::Limit("resolution aggregate byte budget"));
        }
        let digest = blake3::derive_key(DOMAIN, &bytes);
        Ok(Self {
            payload,
            signature: identity.signing_key.sign(&digest).to_bytes().to_vec(),
        })
    }

    /// Resolver and original approvals come from the caller, never wire keys.
    /// Returned projection has execution_authorized/worktree_materialized=false.
    pub fn verify(
        &self,
        resolver: &PeerIdentity,
        approved: &[PeerIdentity],
        limits: ResolutionLimits,
    ) -> Result<FileResolutionPlan> {
        validate_limits(&resolver.space_id, limits)?;
        resolver.validate()?;
        let payload = &self.payload;
        if payload.format_version != 1
            || payload.space_id != resolver.space_id
            || payload.resolver_device != resolver.device_id
            || payload
                .originals
                .len()
                .saturating_add(payload.resolving.len())
                > limits.max_operations
            || serde_json::to_vec(self)?.len() > limits.max_bytes
        {
            return Err(refused("resolution envelope scope or budget"));
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| refused("resolution envelope signature length"))?;
        let key = VerifyingKey::from_bytes(&resolver.public_key)
            .map_err(|_| refused("resolution resolver public key"))?;
        let digest = blake3::derive_key(DOMAIN, &serde_json::to_vec(payload)?);
        key.verify_strict(&digest, &signature)
            .map_err(|_| refused("resolution envelope signature mismatch"))?;
        let originals = authenticated_originals(payload, approved, limits)?;
        let plan = plan_file_resolution(&payload.space_id, &originals, limits)?;
        if plan.fingerprint()? != payload.plan_fingerprint {
            return Err(refused("resolution canonical fingerprint differs"));
        }
        let expected = resolving_file_operations(
            &plan,
            &payload.resolver_device,
            payload.created_at_ms,
            limits,
        )?;
        if expected.len() != payload.resolving.len() {
            return Err(refused("resolution resolving prefix length differs"));
        }
        for (signed, expected) in payload.resolving.iter().zip(&expected) {
            signed.verify(resolver)?;
            if signed.operation != *expected {
                return Err(refused("resolution canonical resolving operation differs"));
            }
        }
        verify_file_resolution_projection(&plan, &originals, &expected, limits)?;
        Ok(plan)
    }
}
