//! Authenticated equivalent histories only; no receipt, native grant or sequence reservation.
use super::*;
use sync_extend_core_model::VersionVector;

pub const MAX_EQUIVALENT_RESOLVERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EquivalentFileResolutions {
    pub original_plan: FileResolutionPlan,
    pub combined_vector: VersionVector,
    pub distinct_resolving_operations: usize,
    pub distinct_resolvers: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedResolutionPrefix {
    pub original_plan: FileResolutionPlan,
    pub received_resolving_operations: usize,
    pub missing_resolving_operations: usize,
    pub received_vector: VersionVector,
    pub complete_vector: VersionVector,
}

/// Describe exact receipt of originals and a contiguous signed resolver prefix.
/// Received rows are not applied rows, and this result reserves no local sequence.
pub fn verify_received_resolution_prefix(
    envelope: &SignedFileResolution,
    approved: &[PeerIdentity],
    received: &[Operation],
    cursor: &VersionVector,
    limits: ResolutionLimits,
) -> Result<ReceivedResolutionPrefix> {
    if approved.len() > 1024 || received.len() > limits.max_operations {
        return Err(TransportError::Limit("resolution received prefix bounds"));
    }
    let resolver = approved
        .iter()
        .find(|peer| peer.device_id == envelope.payload.resolver_device)
        .ok_or(refused("received resolution resolver not approved"))?;
    let plan = envelope.verify(resolver, approved, limits)?;
    let mut rows = BTreeMap::new();
    let mut bytes = 0usize;
    for operation in received {
        bytes = bytes
            .checked_add(serde_json::to_vec(operation)?.len())
            .filter(|bytes| *bytes <= limits.max_bytes)
            .ok_or(TransportError::Limit("resolution received prefix bytes"))?;
        operation.validate()?;
        if rows.insert(operation.op_id.clone(), operation).is_some() {
            return Err(refused("resolution received duplicate row"));
        }
    }
    for original in &envelope.payload.originals {
        if rows.remove(&original.operation.op_id) != Some(&original.operation) {
            return Err(refused("resolution received original bundle differs"));
        }
    }
    let mut prefix = 0usize;
    let mut missing = false;
    let mut complete = plan.received_vector.clone();
    for signed in &envelope.payload.resolving {
        let operation = &signed.operation;
        complete.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        match rows.remove(&operation.op_id) {
            Some(actual) if actual == operation && !missing => prefix += 1,
            None => missing = true,
            _ => {
                return Err(refused(
                    "resolution received resolver prefix differs or skips",
                ))
            }
        }
    }
    if !rows.is_empty() {
        return Err(refused("resolution received unrelated history row"));
    }
    let reduction = sync_extend_core_model::causal::reduce_operations(
        &envelope.payload.space_id,
        received,
        limits.max_operations,
    )?;
    if &reduction.received_vector != cursor {
        return Err(refused("resolution received exact complete cursor differs"));
    }
    Ok(ReceivedResolutionPrefix {
        original_plan: plan,
        received_resolving_operations: prefix,
        missing_resolving_operations: envelope.payload.resolving.len() - prefix,
        received_vector: cursor.clone(),
        complete_vector: complete,
    })
}

/// Validate complete signed prefixes independently, then their actual combined
/// causal projection. Later resolver acknowledgements never enter copy-ID input.
pub fn verify_equivalent_file_resolutions(
    envelopes: &[SignedFileResolution],
    approved: &[PeerIdentity],
    limits: ResolutionLimits,
) -> Result<EquivalentFileResolutions> {
    if envelopes.is_empty() || envelopes.len() > MAX_EQUIVALENT_RESOLVERS || approved.len() > 1024 {
        return Err(refused("equivalent resolution envelope or approval count"));
    }
    let mut peers = BTreeMap::new();
    for peer in approved {
        peer.validate()?;
        if peers.insert(peer.device_id.clone(), peer).is_some() {
            return Err(refused("equivalent resolution duplicate approval"));
        }
    }
    let first = &envelopes[0];
    let resolver = peers
        .get(&first.payload.resolver_device)
        .ok_or(refused("equivalent resolution resolver not approved"))?;
    let plan = first.verify(resolver, approved, limits)?;
    let mut bytes = 0usize;
    let mut resolving = BTreeMap::new();
    let mut resolvers = std::collections::BTreeSet::new();
    for envelope in envelopes {
        bytes = bytes
            .checked_add(serde_json::to_vec(envelope)?.len())
            .filter(|bytes| *bytes <= limits.max_bytes)
            .ok_or(TransportError::Limit(
                "equivalent resolution aggregate bytes",
            ))?;
        if envelope.payload.originals != first.payload.originals {
            return Err(refused(
                "equivalent resolution original signed bundle differs",
            ));
        }
        let resolver = peers
            .get(&envelope.payload.resolver_device)
            .ok_or(refused("equivalent resolution resolver not approved"))?;
        if envelope.verify(resolver, approved, limits)? != plan {
            return Err(refused(
                "equivalent resolution canonical original plan differs",
            ));
        }
        resolvers.insert(envelope.payload.resolver_device.clone());
        for signed in &envelope.payload.resolving {
            if let Some(old) = resolving.insert(signed.operation.op_id.clone(), signed) {
                if old != signed {
                    return Err(refused("equivalent resolution signed operation differs"));
                }
            }
            if plan.input_operations.len().saturating_add(resolving.len()) > limits.max_operations {
                return Err(TransportError::Limit(
                    "equivalent resolution combined operation count",
                ));
            }
        }
    }
    let originals = first
        .payload
        .originals
        .iter()
        .map(|signed| signed.operation.clone())
        .collect::<Vec<_>>();
    let operations = resolving
        .into_values()
        .map(|signed| signed.operation.clone())
        .collect::<Vec<_>>();
    verify_file_resolution_projection(&plan, &originals, &operations, limits)?;
    let mut vector = plan.received_vector.clone();
    for operation in &operations {
        vector.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
    }
    Ok(EquivalentFileResolutions {
        original_plan: plan,
        combined_vector: vector,
        distinct_resolving_operations: operations.len(),
        distinct_resolvers: resolvers.len(),
    })
}
