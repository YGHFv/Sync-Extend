//! Distinct intent/observation wire layouts. Shape is never durable effect proof.
use crate::{
    limits,
    tree_coordinator_lifecycle::TreeCoordinatorContext,
    tree_native_protocol::{
        plan_tree_native_protocol, TreeNativeProtocolLimits, TreeNativeProtocolPlan,
    },
    tree_restore::TreeRestoreAction,
    tree_restore_history::{encode_history_record, MAX_TREE_HISTORY_BYTES},
    tree_restore_identity::{TreeNativeEntry, TreeNativeIdentity, TreeParentBinding},
    ContentId, EntryId, EntryKind, FileManifest, ModelError, PortablePath, Result, SpaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeActionLayoutLimits {
    pub max_records: usize,
    pub max_input_bytes: u64,
    pub max_encoded_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeActionScope {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub transaction_id: EntryId,
    pub coordinator_execution_id: EntryId,
    pub admission_id: EntryId,
    pub admission_hash: ContentId,
    pub protocol_hash: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeNativeActionIntent {
    CreateOwnerDirectory {
        parent: TreeNativeIdentity,
        component: String,
    },
    PublishOwnerDirectory {
        directory: TreeNativeIdentity,
        parent: TreeNativeIdentity,
        source_component: String,
        destination_component: String,
    },
    CreateOwnerMarker {
        directory: TreeNativeIdentity,
        component: String,
    },
    MaterializeOwnerMarker {
        directory: TreeNativeIdentity,
        marker: TreeNativeIdentity,
        payload_hash: ContentId,
        payload_length: u64,
    },
    ReadyOwner {
        directory: TreeNativeIdentity,
        marker: TreeNativeIdentity,
        payload_hash: ContentId,
        payload_length: u64,
    },
    MoveOriginal {
        step_index: usize,
        step_execution_id: EntryId,
        parent: TreeNativeIdentity,
        path: PortablePath,
        original: TreeNativeIdentity,
        owner_directory: TreeNativeIdentity,
        component: String,
        content: FileManifest,
    },
    CreateEntry {
        step_index: usize,
        step_execution_id: EntryId,
        owner_directory: TreeNativeIdentity,
        component: String,
        kind: EntryKind,
    },
    MaterializeEntry {
        step_index: usize,
        step_execution_id: EntryId,
        owner_directory: TreeNativeIdentity,
        component: String,
        creator: TreeNativeIdentity,
        content: FileManifest,
    },
    PublishEntry {
        step_index: usize,
        step_execution_id: EntryId,
        owner_directory: TreeNativeIdentity,
        component: String,
        creator: TreeNativeIdentity,
        parent: TreeNativeIdentity,
        path: PortablePath,
        kind: EntryKind,
    },
    DisposeEmptyDirectory {
        step_index: usize,
        step_execution_id: EntryId,
        parent: TreeNativeIdentity,
        path: PortablePath,
        original: TreeNativeIdentity,
    },
    CompleteStep {
        step_index: usize,
        step_execution_id: EntryId,
        action_kind: TreeRestoreAction,
        parent: TreeNativeIdentity,
        path: PortablePath,
        original: Option<TreeNativeIdentity>,
        published: Option<TreeNativeIdentity>,
    },
}

/// These caller-serializable values are proposed observations, NOT proof tokens.
/// Only a future private platform/Journal issuer can establish their provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "observation", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeNativeActionObservation {
    Created {
        identity: TreeNativeIdentity,
    },
    Moved {
        identity: TreeNativeIdentity,
    },
    Materialized {
        identity: TreeNativeIdentity,
        content_hash: ContentId,
        length: u64,
    },
    OwnerReady {
        directory: TreeNativeIdentity,
        marker: TreeNativeIdentity,
    },
    EmptyDirectoryAbsent {
        original: TreeNativeIdentity,
    },
    StepComplete {
        original: Option<TreeNativeIdentity>,
        published: Option<TreeNativeIdentity>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeNativeActionPayload {
    Intended {
        intent: Box<TreeNativeActionIntent>,
    },
    Observed {
        intended_record_hash: ContentId,
        observation: TreeNativeActionObservation,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeActionLayoutRecord {
    pub scope: TreeNativeActionScope,
    pub record_index: usize,
    pub action_ordinal: usize,
    pub previous_hash: ContentId,
    pub recorded_at_ms: u64,
    pub payload: TreeNativeActionPayload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeNativeActionLayoutPlan {
    scope: TreeNativeActionScope,
    layout_hash: ContentId,
    fingerprint: ContentId,
    encoded_bytes: u64,
    peak_encoded_bytes: u64,
    record_count: usize,
    action_count: usize,
    next_intent: Option<TreeNativeActionIntent>,
    awaiting_observation: bool,
    completed_native_layout: Option<TreeNativeActionCompletedLayout>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeActionCompletedLayout {
    pub owner_directory: TreeNativeIdentity,
    pub owner_marker: TreeNativeIdentity,
    pub entries: BTreeMap<PortablePath, TreeNativeEntry>,
    pub retained_originals: BTreeMap<usize, TreeNativeIdentity>,
    pub last_record_hash: ContentId,
    pub last_recorded_at_ms: u64,
}
impl TreeNativeActionLayoutPlan {
    pub fn scope(&self) -> &TreeNativeActionScope {
        &self.scope
    }
    pub fn layout_hash(&self) -> &ContentId {
        &self.layout_hash
    }
    pub fn fingerprint(&self) -> &ContentId {
        &self.fingerprint
    }
    pub fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }
    pub fn peak_encoded_bytes(&self) -> u64 {
        self.peak_encoded_bytes
    }
    pub fn record_count(&self) -> usize {
        self.record_count
    }
    pub fn action_count(&self) -> usize {
        self.action_count
    }
    pub fn next_intent(&self) -> Option<&TreeNativeActionIntent> {
        self.next_intent.as_ref()
    }
    pub fn awaiting_observation(&self) -> bool {
        self.awaiting_observation
    }
    pub fn complete_layout(&self) -> bool {
        self.next_intent.is_none()
    }
    pub fn completed_native_layout(&self) -> Option<&TreeNativeActionCompletedLayout> {
        self.completed_native_layout.as_ref()
    }
    pub fn durable_native_action_evidence(&self) -> bool {
        false
    }
    pub fn native_execution_available(&self) -> bool {
        false
    }
    pub fn history_commit_available(&self) -> bool {
        false
    }
    pub fn input_reference_release_available(&self) -> bool {
        false
    }
    pub fn original_reference_release_available(&self) -> bool {
        false
    }
    pub fn final_handoff_capacity_verified(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy)]
enum Phase {
    OwnerCreate,
    OwnerPublish,
    MarkerCreate,
    MarkerWrite,
    Ready,
    Move(usize),
    Create(usize),
    Write(usize),
    Publish(usize),
    Dispose(usize),
    Complete(usize),
}
struct State {
    directory: Option<TreeNativeIdentity>,
    marker: Option<TreeNativeIdentity>,
    creators: BTreeMap<usize, TreeNativeIdentity>,
    identities: BTreeSet<TreeNativeIdentity>,
    volume: u64,
}
fn known(id: &Option<TreeNativeIdentity>) -> Result<TreeNativeIdentity> {
    id.clone().ok_or(ModelError::InvalidData(
        "native action preceding observation missing",
    ))
}
fn intent(
    context: &TreeCoordinatorContext<'_>,
    state: &State,
    phase: Phase,
) -> Result<TreeNativeActionIntent> {
    use TreeNativeActionIntent as I;
    let owner = context.owner.intent();
    let directory = || known(&state.directory);
    let marker = || known(&state.marker);
    let marker_values = || -> Result<_> {
        Ok((
            directory()?,
            marker()?,
            context.owner.marker_hash().clone(),
            context.owner.marker_bytes().len() as u64,
        ))
    };
    match phase {
        Phase::OwnerCreate => Ok(I::CreateOwnerDirectory {
            parent: owner.parent.clone(),
            component: owner.stage_component.clone(),
        }),
        Phase::OwnerPublish => Ok(I::PublishOwnerDirectory {
            directory: directory()?,
            parent: owner.parent.clone(),
            source_component: owner.stage_component.clone(),
            destination_component: owner.published_component.clone(),
        }),
        Phase::MarkerCreate => Ok(I::CreateOwnerMarker {
            directory: directory()?,
            component: owner.marker_component.clone(),
        }),
        Phase::MarkerWrite => {
            let (directory, marker, payload_hash, payload_length) = marker_values()?;
            Ok(I::MaterializeOwnerMarker {
                directory,
                marker,
                payload_hash,
                payload_length,
            })
        }
        Phase::Ready => {
            let (directory, marker, payload_hash, payload_length) = marker_values()?;
            Ok(I::ReadyOwner {
                directory,
                marker,
                payload_hash,
                payload_length,
            })
        }
        Phase::Move(index)
        | Phase::Create(index)
        | Phase::Write(index)
        | Phase::Publish(index)
        | Phase::Dispose(index)
        | Phase::Complete(index) => {
            let step = &context.execution.intent().steps[index];
            let slots = &owner.steps[&index];
            let parent = match &step.identity_binding.parent {
                TreeParentBinding::Root => context.identity.inventory().root.clone(),
                TreeParentBinding::Existing { identity, .. } => identity.clone(),
                TreeParentBinding::CreatedBy { step_index, .. } => state
                    .creators
                    .get(step_index)
                    .cloned()
                    .ok_or(ModelError::InvalidData(
                        "native action created parent missing",
                    ))?,
            };
            let original = context
                .identity
                .inventory()
                .entries
                .get(&step.step.path)
                .map(|e| e.identity.clone());
            let creator = || {
                state
                    .creators
                    .get(&index)
                    .cloned()
                    .ok_or(ModelError::InvalidData("native action creator missing"))
            };
            let component = || {
                slots.new_component.clone().ok_or(ModelError::InvalidData(
                    "native action creator slot missing",
                ))
            };
            let content = || {
                step.step
                    .historical_target_entry
                    .as_ref()
                    .and_then(|e| e.content.as_ref())
                    .cloned()
                    .ok_or(ModelError::InvalidData(
                        "native action target content missing",
                    ))
            };
            let path = step.step.path.clone();
            let step_execution_id = step.step_execution_id.clone();
            let kind = if step.step.action == TreeRestoreAction::CreateDirectory {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            match phase {
                Phase::Move(_) => {
                    Ok(I::MoveOriginal {
                        step_index: index,
                        step_execution_id,
                        parent,
                        path,
                        original: known(&original)?,
                        owner_directory: directory()?,
                        component: slots.original_component.clone().ok_or(
                            ModelError::InvalidData("native action original slot missing"),
                        )?,
                        content: context.originals.intents()[&index].original_content.clone(),
                    })
                }
                Phase::Create(_) => Ok(I::CreateEntry {
                    step_index: index,
                    step_execution_id,
                    owner_directory: directory()?,
                    component: component()?,
                    kind,
                }),
                Phase::Write(_) => Ok(I::MaterializeEntry {
                    step_index: index,
                    step_execution_id,
                    owner_directory: directory()?,
                    component: component()?,
                    creator: creator()?,
                    content: content()?,
                }),
                Phase::Publish(_) => Ok(I::PublishEntry {
                    step_index: index,
                    step_execution_id,
                    owner_directory: directory()?,
                    component: component()?,
                    creator: creator()?,
                    parent,
                    path,
                    kind,
                }),
                Phase::Dispose(_) => Ok(I::DisposeEmptyDirectory {
                    step_index: index,
                    step_execution_id,
                    parent,
                    path,
                    original: known(&original)?,
                }),
                _ => Ok(I::CompleteStep {
                    step_index: index,
                    step_execution_id,
                    action_kind: step.step.action,
                    parent,
                    path,
                    original: if matches!(
                        step.step.action,
                        TreeRestoreAction::DeleteFile
                            | TreeRestoreAction::ReplaceFile
                            | TreeRestoreAction::RemoveEmptyDirectory
                    ) {
                        original
                    } else {
                        None
                    },
                    published: state.creators.get(&index).cloned(),
                }),
            }
        }
    }
}
fn observe(
    state: &mut State,
    expected: &TreeNativeActionIntent,
    proposed: &TreeNativeActionObservation,
) -> Result<()> {
    use TreeNativeActionIntent as I;
    use TreeNativeActionObservation as O;
    match (expected, proposed) {
        (
            I::CreateOwnerDirectory { .. } | I::CreateOwnerMarker { .. } | I::CreateEntry { .. },
            O::Created { identity },
        ) => {
            identity.validate()?;
            if identity.volume_serial != state.volume || !state.identities.insert(identity.clone())
            {
                return Err(ModelError::InvalidData(
                    "native action creator identity alias or volume",
                ));
            }
            match expected {
                I::CreateOwnerDirectory { .. } => state.directory = Some(identity.clone()),
                I::CreateOwnerMarker { .. } => state.marker = Some(identity.clone()),
                I::CreateEntry { step_index, .. } => {
                    state.creators.insert(*step_index, identity.clone());
                }
                _ => unreachable!(),
            }
        }
        (
            I::PublishOwnerDirectory { directory: id, .. }
            | I::MoveOriginal { original: id, .. }
            | I::PublishEntry { creator: id, .. },
            O::Moved { identity },
        ) if id == identity => {}
        (
            I::MaterializeOwnerMarker {
                marker,
                payload_hash,
                payload_length,
                ..
            },
            O::Materialized {
                identity,
                content_hash,
                length,
            },
        ) if marker == identity && payload_hash == content_hash && payload_length == length => {}
        (
            I::MaterializeEntry {
                creator, content, ..
            },
            O::Materialized {
                identity,
                content_hash,
                length,
            },
        ) if creator == identity
            && &content.content_id == content_hash
            && content.length == *length => {}
        (
            I::ReadyOwner {
                directory: d,
                marker: m,
                ..
            },
            O::OwnerReady { directory, marker },
        ) if d == directory && m == marker => {}
        (I::DisposeEmptyDirectory { original: id, .. }, O::EmptyDirectoryAbsent { original })
            if id == original => {}
        (
            I::CompleteStep {
                original: o,
                published: p,
                ..
            },
            O::StepComplete {
                original,
                published,
            },
        ) if o == original && p == published => {}
        _ => {
            return Err(ModelError::InvalidData(
                "native action observation does not match preceding intent",
            ))
        }
    }
    Ok(())
}

/// Independently projects a distinct deterministic action layout and all prefixes.
/// Even a complete caller transcript is NOT real admission or native provenance.
pub fn plan_tree_native_action_layout(
    context: &TreeCoordinatorContext<'_>,
    protocol: &TreeNativeProtocolPlan,
    records: &[TreeNativeActionLayoutRecord],
    bounds: TreeNativeActionLayoutLimits,
) -> Result<TreeNativeActionLayoutPlan> {
    if bounds.max_records > limits::MAX_ENTRIES
        || records.len() > bounds.max_records
        || bounds.max_input_bytes > MAX_TREE_HISTORY_BYTES
        || bounds.max_encoded_bytes > MAX_TREE_HISTORY_BYTES
    {
        return Err(ModelError::InvalidData("native action layout bounds"));
    }
    // Bound borrowed caller records before the context reprojection copies data.
    encode_history_record(&(protocol.input(), records), bounds.max_input_bytes)?;
    let protocol_bounds = TreeNativeProtocolLimits {
        max_records: bounds.max_records,
        max_input_bytes: bounds.max_input_bytes,
        max_encoded_bytes: bounds.max_encoded_bytes,
    };
    if plan_tree_native_protocol(context, protocol.input(), protocol_bounds)? != *protocol {
        return Err(ModelError::InvalidData(
            "native action layout private protocol projection",
        ));
    }
    let a = &protocol.input().admission;
    let scope = TreeNativeActionScope {
        format_version: 1,
        space_id: context.baseline.space_id.clone(),
        transaction_id: a.input.transaction_id.clone(),
        coordinator_execution_id: a.input.coordinator_execution_id.clone(),
        admission_id: a.input.admission_id.clone(),
        admission_hash: a.intent_hash.clone(),
        protocol_hash: protocol.intent_hash().clone(),
    };
    encode_history_record(&(&scope, records), bounds.max_encoded_bytes)?;
    let layout_bytes = encode_history_record(
        &("sync-extend-tree-native-action-layout-v1", &scope),
        bounds.max_encoded_bytes,
    )?;
    let layout_hash = ContentId::hash(&layout_bytes);
    let phase_count = context
        .execution
        .intent()
        .steps
        .iter()
        .try_fold(5usize, |n, step| {
            let extra = match step.step.action {
                TreeRestoreAction::CreateDirectory => 3,
                TreeRestoreAction::PublishNewFile => 4,
                TreeRestoreAction::ReplaceFile => 5,
                TreeRestoreAction::DeleteFile | TreeRestoreAction::RemoveEmptyDirectory => 2,
            };
            n.checked_add(extra)
                .filter(|n| *n <= limits::MAX_ENTRIES / 2)
                .ok_or(ModelError::InvalidData(
                    "native action complete phase inventory",
                ))
        })?;
    let mut phases = Vec::with_capacity(phase_count);
    phases.extend([
        Phase::OwnerCreate,
        Phase::OwnerPublish,
        Phase::MarkerCreate,
        Phase::MarkerWrite,
        Phase::Ready,
    ]);
    for step in &context.execution.intent().steps {
        let i = step.step.index;
        if matches!(
            step.step.action,
            TreeRestoreAction::DeleteFile | TreeRestoreAction::ReplaceFile
        ) {
            phases.push(Phase::Move(i));
        }
        if matches!(
            step.step.action,
            TreeRestoreAction::CreateDirectory
                | TreeRestoreAction::PublishNewFile
                | TreeRestoreAction::ReplaceFile
        ) {
            phases.push(Phase::Create(i));
            if step.step.action != TreeRestoreAction::CreateDirectory {
                phases.push(Phase::Write(i));
            }
            phases.push(Phase::Publish(i));
        }
        if step.step.action == TreeRestoreAction::RemoveEmptyDirectory {
            phases.push(Phase::Dispose(i));
        }
        phases.push(Phase::Complete(i));
    }
    let inventory = context.identity.inventory();
    let mut state = State {
        directory: None,
        marker: None,
        creators: BTreeMap::new(),
        identities: [
            inventory.root.clone(),
            inventory.marker_directory.clone(),
            inventory.marker_file.clone(),
        ]
        .into_iter()
        .chain(inventory.entries.values().map(|e| e.identity.clone()))
        .collect(),
        volume: inventory.root.volume_serial,
    };
    let mut previous = layout_hash.clone();
    let mut time = a.input.admitted_at_ms;
    let mut intended_hash = None;
    for (index, record) in records.iter().enumerate() {
        let phase = phases
            .get(index / 2)
            .ok_or(ModelError::InvalidData("native action excess record"))?;
        let expected = intent(context, &state, *phase)?;
        if record.scope != scope
            || record.record_index != index
            || record.action_ordinal != index / 2
            || record.previous_hash != previous
            || record.recorded_at_ms < time
            || record.recorded_at_ms > i64::MAX as u64
        {
            return Err(ModelError::InvalidData("native action exact scope chain"));
        }
        match &record.payload {
            TreeNativeActionPayload::Intended { intent }
                if index % 2 == 0 && **intent == expected =>
            {
                intended_hash = Some(ContentId::hash(&encode_history_record(
                    record,
                    bounds.max_encoded_bytes,
                )?));
            }
            TreeNativeActionPayload::Observed {
                intended_record_hash,
                observation,
            } if index % 2 == 1 && intended_hash.as_ref() == Some(intended_record_hash) => {
                observe(&mut state, &expected, observation)?;
            }
            _ => {
                return Err(ModelError::InvalidData(
                    "native action intent must precede exact observation",
                ))
            }
        }
        previous = ContentId::hash(&encode_history_record(record, bounds.max_encoded_bytes)?);
        time = record.recorded_at_ms;
    }
    let next_intent = phases
        .get(records.len() / 2)
        .map(|p| intent(context, &state, *p))
        .transpose()?;
    let completed_native_layout = if next_intent.is_none() {
        let mut entries = inventory.entries.clone();
        let mut retained_originals = BTreeMap::new();
        for step in &context.execution.intent().steps {
            let path = &step.step.path;
            match step.step.action {
                TreeRestoreAction::DeleteFile | TreeRestoreAction::ReplaceFile => {
                    retained_originals.insert(
                        step.step.index,
                        context.originals.intents()[&step.step.index]
                            .original_identity
                            .clone(),
                    );
                    entries.remove(path);
                }
                TreeRestoreAction::RemoveEmptyDirectory => {
                    entries.remove(path);
                }
                _ => {}
            }
            if let Some(identity) = state.creators.get(&step.step.index) {
                let logical = context
                    .history
                    .manifest()
                    .entries
                    .values()
                    .find(|e| &e.path == path)
                    .ok_or(ModelError::InvalidData(
                        "native action final logical entry missing",
                    ))?;
                entries.insert(
                    path.clone(),
                    TreeNativeEntry {
                        entry_id: logical.entry_id.clone(),
                        kind: logical.kind,
                        identity: identity.clone(),
                    },
                );
            }
        }
        Some(TreeNativeActionCompletedLayout {
            owner_directory: known(&state.directory)?,
            owner_marker: known(&state.marker)?,
            entries,
            retained_originals,
            last_record_hash: previous,
            last_recorded_at_ms: time,
        })
    } else {
        None
    };
    let bytes = encode_history_record(
        &(&scope, records, &next_intent, &completed_native_layout),
        bounds.max_encoded_bytes,
    )?;
    Ok(TreeNativeActionLayoutPlan {
        scope,
        layout_hash,
        fingerprint: ContentId::hash(&bytes),
        encoded_bytes: bytes.len() as u64,
        peak_encoded_bytes: (bytes.len() as u64)
            .max(layout_bytes.len() as u64)
            .max(protocol.encoded_bytes()),
        record_count: records.len(),
        action_count: phases.len(),
        next_intent,
        awaiting_observation: records.len() % 2 == 1,
        completed_native_layout,
    })
}
