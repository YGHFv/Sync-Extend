//! Bounded prospective native DAV history. Serialized observations grant no native authority.
use crate::{
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::TreeNativeIdentity,
    webdav_mutation::WebDavMutationRequest,
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
    ContentId, EntryId, ModelError, Result, SnapshotId, FORMAT_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavExecutionScope {
    pub format_version: u32,
    pub transaction_id: EntryId,
    pub request_hash: ContentId,
    pub plan_hash: ContentId,
    pub description_hash: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "observed", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebDavExecutionObservation {
    QuarantinedOriginal {
        identity: TreeNativeIdentity,
    },
    CreatedDirectory {
        identity: TreeNativeIdentity,
    },
    PublishedFile {
        identity: TreeNativeIdentity,
        content_id: ContentId,
        length: u64,
    },
    HistoryCommitted {
        final_snapshot: SnapshotId,
        operation_count: usize,
    },
    OriginalAbsent {
        quarantine_action: usize,
        original: TreeNativeIdentity,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebDavExecutionPhase {
    Activated,
    Observed {
        activation_hash: ContentId,
        observation: WebDavExecutionObservation,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavExecutionRecord {
    pub scope: WebDavExecutionScope,
    pub record_index: usize,
    pub action_index: usize,
    pub attempt_id: EntryId,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub phase: WebDavExecutionPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebDavExecutionLimits {
    pub max_records: usize,
    pub max_record_bytes: u64,
    pub max_total_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebDavExecutionState {
    NextAction { action_index: usize },
    UnresolvedActivation { action_index: usize },
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebDavExecutionAudit {
    state: WebDavExecutionState,
    completed_actions: usize,
    history_observed: bool,
    encoded_bytes: u64,
    last_hash: ContentId,
    last_recorded_at_ms: u64,
}

impl WebDavExecutionAudit {
    pub fn state(&self) -> WebDavExecutionState {
        self.state
    }
    pub fn completed_actions(&self) -> usize {
        self.completed_actions
    }
    pub fn history_observed(&self) -> bool {
        self.history_observed
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn last_hash(&self) -> &ContentId {
        &self.last_hash
    }
    pub fn last_recorded_at_ms(&self) -> u64 {
        self.last_recorded_at_ms
    }
    pub fn metadata_cancellation_allowed(&self) -> bool {
        self.completed_actions == 0
            && matches!(
                self.state,
                WebDavExecutionState::NextAction { action_index: 0 }
            )
    }
    pub fn native_execution_admitted(&self) -> bool {
        false
    }
    pub fn native_cleanup_authorized(&self) -> bool {
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
    ModelError::InvalidData("exact prospective DAV execution prefix")
}

fn observe(
    plan: &WebDavNativePlan,
    action: usize,
    observation: &WebDavExecutionObservation,
    identities: &mut BTreeSet<TreeNativeIdentity>,
    history: &mut bool,
) -> Result<()> {
    match (&plan.steps()[action].action, observation) {
        (
            WebDavNativeAction::QuarantineOriginal { identity, .. },
            WebDavExecutionObservation::QuarantinedOriginal { identity: observed },
        ) if identity == observed => {}
        (
            WebDavNativeAction::CreateDirectory { .. },
            WebDavExecutionObservation::CreatedDirectory { identity },
        ) => {
            identity.validate()?;
            if identity.volume_serial != plan.inventory().root.volume_serial
                || !identities.insert(identity.clone())
            {
                return Err(invalid());
            }
        }
        (
            WebDavNativeAction::PublishFile { entry },
            WebDavExecutionObservation::PublishedFile {
                identity,
                content_id,
                length,
            },
        ) if entry.content.as_ref().is_some_and(|content| {
            &content.content_id == content_id && content.length == *length
        }) =>
        {
            identity.validate()?;
            if identity.volume_serial != plan.inventory().root.volume_serial
                || !identities.insert(identity.clone())
            {
                return Err(invalid());
            }
        }
        (
            WebDavNativeAction::CommitHistory {
                final_snapshot,
                operation_count,
            },
            WebDavExecutionObservation::HistoryCommitted {
                final_snapshot: snapshot,
                operation_count: count,
            },
        ) if !*history && final_snapshot == snapshot && operation_count == count => {
            *history = true;
        }
        (
            WebDavNativeAction::CleanupOriginal {
                quarantine_action, ..
            },
            WebDavExecutionObservation::OriginalAbsent {
                quarantine_action: original_action,
                original,
            },
        ) if *history && quarantine_action == original_action => {
            match &plan.steps()[*quarantine_action].action {
                WebDavNativeAction::QuarantineOriginal { identity, .. } if identity == original => {
                }
                _ => return Err(invalid()),
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

/// Audit proposed bytes only. A later private Journal/platform issuer must
/// independently persist activations, retain real handles and establish effects.
pub fn audit_webdav_execution_prefix(
    request: &WebDavMutationRequest,
    plan: &WebDavNativePlan,
    description_hash: &ContentId,
    records: &[WebDavExecutionRecord],
    limits: WebDavExecutionLimits,
) -> Result<WebDavExecutionAudit> {
    if limits.max_records == 0
        || limits.max_records > crate::limits::MAX_ENTRIES
        || limits.max_record_bytes == 0
        || limits.max_record_bytes > MAX_TREE_HISTORY_BYTES
        || limits.max_total_bytes == 0
        || limits.max_total_bytes > MAX_TREE_HISTORY_BYTES
        || records.len() > limits.max_records
        || records.len() > plan.steps().len().checked_mul(2).ok_or_else(invalid)?
        || request.created_at_ms > i64::MAX as u64
    {
        return Err(invalid());
    }
    // Bind the actual request encoding, including baseline, fresh IDs and limits.
    let request_hash =
        ContentId::hash(&encode_history_record(request, request.max_metadata_bytes)?);
    if &request_hash != plan.request_hash() || plan.inventory().request_hash != request_hash {
        return Err(invalid());
    }
    let scope = WebDavExecutionScope {
        format_version: FORMAT_VERSION,
        transaction_id: request.transaction_id.clone(),
        request_hash,
        plan_hash: plan.fingerprint().clone(),
        description_hash: description_hash.clone(),
    };
    let mut identities: BTreeSet<_> = plan
        .inventory()
        .entries
        .values()
        .map(|entry| entry.identity.clone())
        .collect();
    identities.extend([
        plan.inventory().root.clone(),
        plan.inventory().marker_directory.clone(),
        plan.inventory().marker_file.clone(),
    ]);
    let mut attempts = BTreeSet::new();
    let mut total = 0u64;
    let mut last_hash = description_hash.clone();
    let mut time = request.created_at_ms;
    let mut activation: Option<(EntryId, ContentId)> = None;
    let mut history = false;
    let mut completed = 0;
    for (index, record) in records.iter().enumerate() {
        let action = index / 2;
        if record.scope != scope
            || record.record_index != index
            || record.action_index != action
            || record.previous_hash != last_hash
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
            || record.attempt_id == request.transaction_id
            || request.fresh_ids.contains_key(&record.attempt_id)
            || request
                .fresh_ids
                .values()
                .any(|id| id == &record.attempt_id)
            || plan
                .inventory()
                .entries
                .values()
                .any(|entry| entry.entry_id == record.attempt_id)
            || plan
                .final_manifest()
                .entries
                .contains_key(&record.attempt_id)
            || plan.steps()[action].index != action
            || plan.steps()[action]
                .dependencies
                .iter()
                .any(|prior| *prior >= completed)
        {
            return Err(invalid());
        }
        let bytes = encode_history_record(record, limits.max_record_bytes)?;
        total = total
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= limits.max_total_bytes)
            .ok_or_else(invalid)?;
        let hash = ContentId::hash(&bytes);
        match (&record.phase, index % 2) {
            (WebDavExecutionPhase::Activated, 0) => {
                if activation.is_some() || !attempts.insert(record.attempt_id.clone()) {
                    return Err(invalid());
                }
                activation = Some((record.attempt_id.clone(), hash.clone()));
            }
            (
                WebDavExecutionPhase::Observed {
                    activation_hash,
                    observation,
                },
                1,
            ) => {
                if activation.as_ref()
                    != Some(&(record.attempt_id.clone(), activation_hash.clone()))
                {
                    return Err(invalid());
                }
                observe(plan, action, observation, &mut identities, &mut history)?;
                activation = None;
                completed += 1;
            }
            _ => return Err(invalid()),
        }
        last_hash = hash;
        time = record.recorded_at_ms;
    }
    let state = if activation.is_some() {
        WebDavExecutionState::UnresolvedActivation {
            action_index: completed,
        }
    } else if completed == plan.steps().len() {
        WebDavExecutionState::Terminal
    } else {
        WebDavExecutionState::NextAction {
            action_index: completed,
        }
    };
    Ok(WebDavExecutionAudit {
        state,
        completed_actions: completed,
        history_observed: history,
        encoded_bytes: total,
        last_hash,
        last_recorded_at_ms: time,
    })
}
