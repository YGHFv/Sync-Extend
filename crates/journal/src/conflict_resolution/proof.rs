use crate::{JournalError, RemotePublicationProof, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    conflict_resolution::{
        plan_file_resolution, resolving_file_operations, verify_file_resolution_projection,
        FileResolutionPlan, ResolutionLimits,
    },
    ContentId, DeviceId, Operation, SpaceId,
};

/// Exact transport signed-operation representation, with no wire-supplied keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictSignedOperation {
    pub operation: Operation,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionPayload {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub resolver_device: DeviceId,
    pub plan_fingerprint: ContentId,
    pub originals: Vec<ConflictSignedOperation>,
    pub resolving: Vec<ConflictSignedOperation>,
    pub created_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionProof {
    pub payload: ConflictResolutionPayload,
    pub signature: Vec<u8>,
}

/// Separately supplied, locally approved key; not part of the signed envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionKey {
    pub device_id: DeviceId,
    pub public_key: [u8; 32],
}

impl ConflictResolutionProof {
    pub fn verify(
        &self,
        approved: &[ConflictResolutionKey],
        limits: ResolutionLimits,
    ) -> Result<FileResolutionPlan> {
        let p = &self.payload;
        if p.format_version != 1
            || p.originals.len().saturating_add(p.resolving.len()) > limits.max_operations
            || serde_json::to_vec(self)?.len() > limits.max_bytes.min(crate::MAX_OPERATION_BYTES)
            || approved.len() > 1024
            || p.originals
                .windows(2)
                .any(|s| s[0].operation.op_id >= s[1].operation.op_id)
        {
            return Err(JournalError::Invariant(
                "conflict signed scope/order/budget",
            ));
        }
        let mut keys = BTreeMap::new();
        for key in approved {
            if DeviceId::from_public_key(&key.public_key) != key.device_id
                || keys.insert(key.device_id.clone(), key.public_key).is_some()
            {
                return Err(JournalError::Invariant("conflict approved key differs"));
            }
        }
        let resolver = keys
            .get(&p.resolver_device)
            .ok_or(JournalError::Invariant("conflict resolver not approved"))?;
        let key = VerifyingKey::from_bytes(resolver)
            .map_err(|_| JournalError::Invariant("conflict resolver key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| JournalError::Invariant("conflict envelope signature length"))?;
        let digest = blake3::derive_key(
            "SyncExtend signed canonical file resolution v1",
            &serde_json::to_vec(p)?,
        );
        key.verify_strict(&digest, &signature)
            .map_err(|_| JournalError::Invariant("conflict envelope signature invalid"))?;
        for signed in p.originals.iter().chain(&p.resolving) {
            let public_key = keys
                .get(&signed.operation.payload.origin_device_id)
                .ok_or(JournalError::Invariant("conflict original not approved"))?;
            if signed.operation.payload.space_id != p.space_id {
                return Err(JournalError::Invariant("conflict original space differs"));
            }
            RemotePublicationProof {
                public_key: *public_key,
                operation: signed.operation.clone(),
                signature: signed.signature.clone(),
            }
            .verify()?;
        }
        let originals: Vec<_> = p.originals.iter().map(|s| s.operation.clone()).collect();
        let plan = plan_file_resolution(&p.space_id, &originals, limits)?;
        let resolving =
            resolving_file_operations(&plan, &p.resolver_device, p.created_at_ms, limits)?;
        if plan.fingerprint()? != p.plan_fingerprint
            || resolving
                != p.resolving
                    .iter()
                    .map(|s| s.operation.clone())
                    .collect::<Vec<_>>()
        {
            return Err(JournalError::Invariant(
                "conflict canonical signed prefix differs",
            ));
        }
        verify_file_resolution_projection(&plan, &originals, &resolving, limits)?;
        Ok(plan)
    }
}
