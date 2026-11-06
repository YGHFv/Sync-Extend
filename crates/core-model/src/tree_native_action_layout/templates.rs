//! Private maximum-width action serialization, never a durable observation issuer.
use super::{
    initial_state, intent, observe, phases, plan_tree_native_action_layout, TreeNativeActionIntent,
    TreeNativeActionLayoutLimits, TreeNativeActionLayoutPlan, TreeNativeActionLayoutRecord,
    TreeNativeActionObservation, TreeNativeActionPayload,
};
use crate::{
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_native_protocol::TreeNativeProtocolPlan,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::TreeNativeIdentity,
    ContentId, ModelError, Result,
};

fn hash(record: &TreeNativeActionLayoutRecord, max: u64) -> Result<ContentId> {
    Ok(ContentId::hash(&encode_history_record(record, max)?))
}

fn next_identity(state: &super::State, next: &mut u128) -> Result<TreeNativeIdentity> {
    loop {
        let identity = TreeNativeIdentity {
            volume_serial: state.volume,
            file_id: format!("{:032x}", *next),
        };
        *next = next.checked_add(1).ok_or(ModelError::InvalidData(
            "native capacity identity template exhausted",
        ))?;
        if !state.identities.contains(&identity) {
            return Ok(identity);
        }
    }
}

fn observation(
    expected: &TreeNativeActionIntent,
    state: &super::State,
    next: &mut u128,
) -> Result<TreeNativeActionObservation> {
    use TreeNativeActionIntent as I;
    use TreeNativeActionObservation as O;
    Ok(match expected {
        I::CreateOwnerDirectory { .. } | I::CreateOwnerMarker { .. } | I::CreateEntry { .. } => {
            O::Created {
                identity: next_identity(state, next)?,
            }
        }
        I::PublishOwnerDirectory { directory, .. } => O::Moved {
            identity: directory.clone(),
        },
        I::MoveOriginal { original, .. } => O::Moved {
            identity: original.clone(),
        },
        I::PublishEntry { creator, .. } => O::Moved {
            identity: creator.clone(),
        },
        I::MaterializeOwnerMarker {
            marker,
            payload_hash,
            payload_length,
            ..
        } => O::Materialized {
            identity: marker.clone(),
            content_hash: payload_hash.clone(),
            length: *payload_length,
        },
        I::MaterializeEntry {
            creator, content, ..
        } => O::Materialized {
            identity: creator.clone(),
            content_hash: content.content_id.clone(),
            length: content.length,
        },
        I::ReadyOwner {
            directory, marker, ..
        } => O::OwnerReady {
            directory: directory.clone(),
            marker: marker.clone(),
        },
        I::DisposeEmptyDirectory { original, .. } => O::EmptyDirectoryAbsent {
            original: original.clone(),
        },
        I::CompleteStep {
            original,
            published,
            ..
        } => O::StepComplete {
            original: original.clone(),
            published: published.clone(),
        },
    })
}

pub(crate) fn records(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    initial: &TreeNativeActionLayoutRecord,
    bounds: TreeNativeActionLayoutLimits,
) -> Result<(
    Vec<TreeNativeActionLayoutRecord>,
    TreeNativeActionLayoutPlan,
)> {
    if bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("native capacity template bounds"));
    }
    let start =
        plan_tree_native_action_layout(context, protocol, std::slice::from_ref(initial), bounds)?;
    let count = start
        .action_count()
        .checked_mul(2)
        .filter(|n| *n <= bounds.max_records)
        .ok_or(ModelError::InvalidData(
            "native capacity template record inventory",
        ))?;
    if initial.record_index != 0 || !start.awaiting_observation() {
        return Err(ModelError::InvalidData(
            "native capacity exact initial intention",
        ));
    }
    let mut state = initial_state(context);
    let mut next = 0;
    let mut records = Vec::new();
    let mut previous = None;
    let mut encoded_bytes = 2u64;
    for (ordinal, phase) in phases(context)?.into_iter().enumerate() {
        let intended = if ordinal == 0 {
            initial.clone()
        } else {
            TreeNativeActionLayoutRecord {
                scope: start.scope().clone(),
                record_index: ordinal * 2,
                action_ordinal: ordinal,
                previous_hash: previous.take().ok_or(ModelError::InvalidData(
                    "native capacity preceding template hash",
                ))?,
                recorded_at_ms: i64::MAX as u64,
                payload: TreeNativeActionPayload::Intended {
                    intent: Box::new(intent(context, &state, phase)?),
                },
            }
        };
        let TreeNativeActionPayload::Intended { intent: expected } = &intended.payload else {
            return Err(ModelError::InvalidData("native capacity initial payload"));
        };
        let intended_hash = hash(&intended, bounds.max_encoded_bytes)?;
        let proposed = observation(expected, &state, &mut next)?;
        observe(&mut state, expected, &proposed)?;
        let observed = TreeNativeActionLayoutRecord {
            scope: start.scope().clone(),
            record_index: ordinal * 2 + 1,
            action_ordinal: ordinal,
            previous_hash: intended_hash.clone(),
            recorded_at_ms: i64::MAX as u64,
            payload: TreeNativeActionPayload::Observed {
                intended_record_hash: intended_hash,
                observation: proposed,
            },
        };
        previous = Some(hash(&observed, bounds.max_encoded_bytes)?);
        for record in [intended, observed] {
            let n = encode_history_record(&record, bounds.max_encoded_bytes)?.len() as u64;
            encoded_bytes = encoded_bytes
                .checked_add(n + u64::from(!records.is_empty()))
                .filter(|n| *n <= bounds.max_encoded_bytes)
                .ok_or(ModelError::InvalidData(
                    "native capacity aggregate template bytes",
                ))?;
            records.push(record);
        }
    }
    // One complete grammar audit, not a quadratic per-prefix reconstruction.
    let complete = plan_tree_native_action_layout(context, protocol, &records, bounds)?;
    if !complete.complete_layout() || records.len() != count {
        return Err(ModelError::InvalidData(
            "native capacity incomplete template",
        ));
    }
    Ok((records, complete))
}
