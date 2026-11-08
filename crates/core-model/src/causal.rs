//! Bounded logical frontiers only: no filesystem, snapshot or receipt authority.
use crate::{
    Change, EntryId, EntryKind, FileManifest, ModelError, Operation, OperationId, PortablePath,
    Result, SpaceId, VersionVector,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_CAUSAL_OPERATIONS: usize = 10_000;
pub const MAX_CAUSAL_FRONTIER: usize = 256;
const MAX_REDUCTION_WORK: usize = 2_000_000;
const MAX_REDUCTION_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentAlternative {
    pub operations: Vec<OperationId>,
    pub kind: EntryKind,
    pub content: Option<FileManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAlternative {
    pub operations: Vec<OperationId>,
    pub path: PortablePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryFrontier {
    pub entry_id: EntryId,
    pub deleted: bool,
    pub delete_conflict: bool,
    pub deletions: Vec<OperationId>,
    pub paths: Vec<PathAlternative>,
    pub contents: Vec<ContentAlternative>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathCollision {
    pub collision_key: String,
    pub entries: Vec<EntryId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalReduction {
    pub space_id: SpaceId,
    pub received_vector: VersionVector,
    pub entries: BTreeMap<EntryId, EntryFrontier>,
    pub path_collisions: Vec<PathCollision>,
    pub worktree_materialized: bool,
}

#[derive(Default)]
struct History {
    lifecycle: Vec<usize>,
    contents: Vec<usize>,
    paths: Vec<usize>,
}

fn invalid(message: &'static str) -> ModelError {
    ModelError::InvalidData(message)
}

fn before(left: &Operation, right: &Operation) -> bool {
    right.payload.causal.get(&left.payload.origin_device_id) >= left.payload.origin_seq
}

fn spend(work: &mut usize) -> Result<()> {
    *work = work
        .checked_add(1)
        .filter(|work| *work <= MAX_REDUCTION_WORK)
        .ok_or(invalid("causal reduction work budget"))?;
    Ok(())
}

fn frontier(
    candidates: &[usize],
    operations: &[&Operation],
    work: &mut usize,
) -> Result<Vec<usize>> {
    let mut result: Vec<usize> = Vec::new();
    for &index in candidates {
        let mut dominated = false;
        let mut retained = Vec::new();
        for &old in &result {
            spend(work)?;
            if before(operations[index], operations[old]) {
                dominated = true;
            }
            if !before(operations[old], operations[index]) {
                retained.push(old);
            }
        }
        if !dominated {
            retained.push(index);
        }
        if retained.len() > MAX_CAUSAL_FRONTIER {
            return Err(invalid("causal frontier budget"));
        }
        result = retained;
    }
    result.sort_by_key(|&index| &operations[index].op_id);
    Ok(result)
}

fn entry_id(change: &Change) -> &EntryId {
    match change {
        Change::Put { entry } => &entry.entry_id,
        Change::Rename { entry_id, .. } | Change::Delete { entry_id } => entry_id,
    }
}

fn path(operation: &Operation) -> Result<&PortablePath> {
    match &operation.payload.change {
        Change::Put { entry } => Ok(&entry.path),
        Change::Rename { path, .. } => Ok(path),
        Change::Delete { .. } => Err(invalid("delete has no path register")),
    }
}

/// Reduce a complete log from genesis into deterministic alternatives.
/// Input order and wall clocks have no effect. Missing dependencies, excessive
/// work and ambiguous names fail or remain explicit, never implicit overwrites.
pub fn reduce_operations(
    space: &SpaceId,
    input: &[Operation],
    maximum: usize,
) -> Result<CausalReduction> {
    if maximum == 0 || maximum > MAX_CAUSAL_OPERATIONS || input.len() > maximum {
        return Err(invalid("causal operation count"));
    }
    let mut by_id = BTreeMap::new();
    let mut by_origin = BTreeMap::new();
    let mut encoded_bytes = 0usize;
    for operation in input {
        operation.validate()?;
        encoded_bytes = encoded_bytes
            .checked_add(serde_json::to_vec(operation)?.len())
            .filter(|bytes| *bytes <= MAX_REDUCTION_BYTES)
            .ok_or(invalid("causal operation byte budget"))?;
        if operation.payload.space_id != *space {
            return Err(invalid("causal operation space mismatch"));
        }
        if let Some(old) = by_id.insert(operation.op_id.clone(), operation) {
            if old != operation {
                return Err(invalid("causal operation identifier collision"));
            }
        }
        let origin = (
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        if let Some(old) = by_origin.insert(origin, operation) {
            if old != operation {
                return Err(invalid("causal origin sequence collision"));
            }
        }
    }
    let operations: Vec<_> = by_id.values().copied().collect();
    let indexes: BTreeMap<_, _> = operations
        .iter()
        .enumerate()
        .map(|(index, operation)| (operation.op_id.clone(), index))
        .collect();
    let mut dependencies = vec![BTreeSet::new(); operations.len()];
    let mut dependents = vec![Vec::new(); operations.len()];
    let mut vector = VersionVector::default();
    let mut work = 0;
    for (index, operation) in operations.iter().enumerate() {
        for (device, sequence) in &operation.payload.causal.0 {
            spend(&mut work)?;
            let dependency = by_origin
                .get(&(device.clone(), *sequence))
                .ok_or(invalid("causal dependency is missing"))?;
            for (ancestor, sequence) in &dependency.payload.causal.0 {
                spend(&mut work)?;
                if operation.payload.causal.get(ancestor) < *sequence {
                    return Err(invalid("causal context is not transitively closed"));
                }
            }
            let dependency = *indexes
                .get(&dependency.op_id)
                .ok_or(invalid("causal dependency index"))?;
            dependencies[index].insert(dependency);
        }
        vector.observe(
            operation.payload.origin_device_id.clone(),
            operation.payload.origin_seq,
        );
        if vector.0.len() > 1024 {
            return Err(invalid("causal device count"));
        }
    }
    for (index, dependencies) in dependencies.iter().enumerate() {
        for &dependency in dependencies {
            dependents[dependency].push(index);
        }
    }
    let mut ready: BTreeSet<usize> = dependencies
        .iter()
        .enumerate()
        .filter_map(|(index, dependencies)| dependencies.is_empty().then_some(index))
        .collect();
    let mut order = Vec::new();
    while let Some(index) = ready.pop_first() {
        order.push(index);
        for &dependent in &dependents[index] {
            dependencies[dependent].remove(&index);
            if dependencies[dependent].is_empty() {
                ready.insert(dependent);
            }
        }
    }
    if order.len() != operations.len() {
        return Err(invalid("causal dependency cycle"));
    }
    let mut histories: BTreeMap<EntryId, History> = BTreeMap::new();
    for index in order {
        let operation = operations[index];
        let history = histories
            .entry(entry_id(&operation.payload.change).clone())
            .or_default();
        let mut known = Vec::new();
        for &old in &history.lifecycle {
            spend(&mut work)?;
            if before(operations[old], operation) {
                known.push(old);
            }
        }
        let known = frontier(&known, &operations, &mut work)?;
        let known_live = known
            .iter()
            .any(|&old| !matches!(operations[old].payload.change, Change::Delete { .. }));
        match &operation.payload.change {
            Change::Put { entry } => {
                history.contents.push(index);
                let mut known_paths = Vec::new();
                for &old in &history.paths {
                    spend(&mut work)?;
                    if before(operations[old], operation) {
                        known_paths.push(old);
                    }
                }
                let known_paths = frontier(&known_paths, &operations, &mut work)?;
                // Ordinary edits carry the old path in Put. They must not undo
                // an independent Rename the editor had not yet observed.
                // Observing a Delete ends the old path incarnation, even when
                // a concurrent live branch remains in the known frontier.
                if !known_live
                    || known
                        .iter()
                        .any(|&old| matches!(operations[old].payload.change, Change::Delete { .. }))
                    || !known_paths
                        .iter()
                        .any(|&old| path(operations[old]).is_ok_and(|p| p == &entry.path))
                {
                    history.paths.push(index);
                }
            }
            Change::Rename { .. } => {
                if !known_live {
                    return Err(invalid("rename has no causal live entry"));
                }
                history.paths.push(index);
            }
            Change::Delete { .. } => {
                if !known_live {
                    return Err(invalid("delete has no causal live entry"));
                }
            }
        }
        history.lifecycle.push(index);
    }
    let mut entries = BTreeMap::new();
    let mut names: BTreeMap<String, BTreeSet<EntryId>> = BTreeMap::new();
    for (entry_id, history) in histories {
        let lifecycle = frontier(&history.lifecycle, &operations, &mut work)?;
        let deletions: Vec<_> = lifecycle
            .iter()
            .filter(|&&index| matches!(operations[index].payload.change, Change::Delete { .. }))
            .map(|&index| operations[index].op_id.clone())
            .collect();
        let deleted = deletions.len() == lifecycle.len();
        let mut paths: BTreeMap<PortablePath, Vec<OperationId>> = BTreeMap::new();
        let mut contents: BTreeMap<Vec<u8>, ContentAlternative> = BTreeMap::new();
        if !deleted {
            let mut eligible_paths = Vec::new();
            let mut eligible_contents = Vec::new();
            // An observed deletion ends the old incarnation's registers.
            // A later Put restores its own values, not pre-delete alternatives.
            for (candidates, eligible) in [
                (&history.paths, &mut eligible_paths),
                (&history.contents, &mut eligible_contents),
            ] {
                for &index in candidates {
                    let mut superseded = false;
                    for &deletion in &history.lifecycle {
                        spend(&mut work)?;
                        if matches!(operations[deletion].payload.change, Change::Delete { .. })
                            && before(operations[index], operations[deletion])
                        {
                            for &put in &history.contents {
                                spend(&mut work)?;
                                if before(operations[deletion], operations[put]) {
                                    superseded = true;
                                    break;
                                }
                            }
                            if superseded {
                                break;
                            }
                        }
                    }
                    if !superseded {
                        eligible.push(index);
                    }
                }
            }
            for index in frontier(&eligible_paths, &operations, &mut work)? {
                let path = path(operations[index])?.clone();
                names
                    .entry(path.collision_key())
                    .or_default()
                    .insert(entry_id.clone());
                paths
                    .entry(path)
                    .or_default()
                    .push(operations[index].op_id.clone());
            }
            for index in frontier(&eligible_contents, &operations, &mut work)? {
                let Change::Put { entry } = &operations[index].payload.change else {
                    return Err(invalid("content register has no put"));
                };
                let key = serde_json::to_vec(&(entry.kind, &entry.content))?;
                contents
                    .entry(key)
                    .or_insert_with(|| ContentAlternative {
                        operations: Vec::new(),
                        kind: entry.kind,
                        content: entry.content.clone(),
                    })
                    .operations
                    .push(operations[index].op_id.clone());
            }
            if paths.is_empty() || contents.is_empty() {
                return Err(invalid("live entry has incomplete registers"));
            }
        }
        entries.insert(
            entry_id.clone(),
            EntryFrontier {
                entry_id,
                deleted,
                delete_conflict: !deleted && !deletions.is_empty(),
                deletions,
                paths: paths
                    .into_iter()
                    .map(|(path, operations)| PathAlternative { operations, path })
                    .collect(),
                contents: contents.into_values().collect(),
            },
        );
    }
    Ok(CausalReduction {
        space_id: space.clone(),
        received_vector: vector,
        entries,
        path_collisions: names
            .into_iter()
            .filter(|(_, entries)| entries.len() > 1)
            .map(|(collision_key, entries)| PathCollision {
                collision_key,
                entries: entries.into_iter().collect(),
            })
            .collect(),
        worktree_materialized: false,
    })
}
