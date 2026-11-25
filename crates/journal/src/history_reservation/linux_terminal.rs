//! Immutable native Final/THAWED evidence and append-only cleanup progress.
//! Deserialized diagnostics cannot construct a live cleanup permit.
use super::{Stored, phase_evidence};
use crate::{JournalError, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    ContentId, EntryId, FileManifest, Manifest, Operation, PortablePath, SnapshotId,
};

const FINAL: &str = "original.linux-native.final.v1.";
const THAWED: &str = "original.linux-native.thawed.v1.";
const PREPARED: &str = "original.linux-native.cleanup-prepared.v1.";
const CLEANED: &str = "original.linux-native.cleaned.v1.";
type Key = (u64, u64);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retained {
    directory: std::path::PathBuf,
    directory_key: Key,
    container_key: Key,
    file_key: Key,
    source_parent_key: Key,
    content: FileManifest,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Final {
    version: u32,
    attempt: EntryId,
    owner_generation: [u8; 16],
    persistent_metadata_generation: [u8; 16],
    backing_image: Key,
    volume_root: Key,
    worktree_key: Key,
    worktree: std::path::PathBuf,
    target: PortablePath,
    target_key: Key,
    target_parent_key: Key,
    intent_parent: std::path::PathBuf,
    intent_parent_key: Key,
    intent_file_key: Key,
    intent_component: String,
    intent_json: String,
    reservation_json: String,
    snapshot_json: String,
    operation_json: Vec<String>,
    observation_json: String,
    history_digest: ContentId,
    phase_json: Vec<String>,
    retained: Option<Retained>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Thawed {
    version: u32,
    attempt: EntryId,
    final_digest: ContentId,
    owner_generation: [u8; 16],
    process_ids: (u32, u32),
    startup: (Vec<u8>, Vec<u8>),
    stdout: (Vec<u8>, Vec<u8>),
    stderr: (Vec<u8>, Vec<u8>),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    version: u32,
    attempt: EntryId,
    final_digest: ContentId,
    thawed_digest: ContentId,
    cleanup_owner_generation: [u8; 16],
    persistent_metadata_generation: [u8; 16],
    backing_image: Key,
    predecessor: Option<ContentId>,
    observed_absent_slots: Vec<(Key, Key, String)>,
}

#[derive(Serialize)]
pub struct OriginalLinuxNativeFinalDiagnostic {
    pub transaction_id: EntryId,
    pub target: PortablePath,
    pub snapshot_id: SnapshotId,
    pub native_action: &'static str,
    pub final_exact_digest: ContentId,
    pub helper_thawed: bool,
    pub cleanup_prepared: bool,
    pub cleanup_completed: bool,
    pub immutable_history_and_native_receipts_retained: bool,
}

/// A live Journal binding; deserialized history never constructs this value.
#[cfg(target_os = "linux")]
pub struct OriginalLinuxPublisherBinding {
    issuer: std::sync::Arc<()>,
}

/// Issued only after durable cleanup and all native absence postchecks.
#[cfg(target_os = "linux")]
pub struct OriginalLinuxCleanupCompletion {
    permit: OriginalLinuxCleanupPermit,
}

/// Live receipt for one append-only predecessor transition.
#[cfg(target_os = "linux")]
pub struct OriginalLinuxSuccessorReceipt {
    issuer: std::sync::Arc<()>,
    row_key: String,
    exact_json: String,
    owner_generation: [u8; 16],
    next_sequence: u64,
}

pub struct OriginalLinuxCleanupPermit {
    final_record: Final,
    final_json: String,
    thawed_json: String,
    prepared_json: Option<String>,
    cleaned_json: Option<String>,
    issuer: std::sync::Arc<()>,
    cleanup_owner_generation: [u8; 16],
    current_volume_root: Key,
}

fn key(prefix: &str, attempt: &EntryId) -> String {
    format!("{prefix}{attempt}")
}
fn ordinary_key(value: Key) -> bool {
    value.0 != 0 && value.1 != 0
}
fn parse<T: for<'a> Deserialize<'a> + Serialize>(json: &str) -> Result<T> {
    if json.is_empty() || json.len() > 64 * 1024 * 1024 {
        return Err(JournalError::Invariant(
            "bounded native terminal record required",
        ));
    }
    let value: T = serde_json::from_str(json)?;
    if serde_json::to_string(&value)? != json {
        return Err(JournalError::Invariant(
            "native terminal canonical bytes differ",
        ));
    }
    Ok(value)
}

fn validate_final(json: &str) -> Result<(Final, Stored)> {
    let value: Final = parse(json)?;
    let stored: Stored = parse(&value.reservation_json)?;
    stored.validate(sync_extend_core_model::limits::MAX_ENTRIES)?;
    let snapshot: Manifest = parse(&value.snapshot_json)?;
    let operations: Vec<Operation> = value
        .operation_json
        .iter()
        .map(|json| parse(json))
        .collect::<Result<_>>()?;
    let observations: sync_extend_core_model::persisted_rename::RenameObservationMap =
        parse(&value.observation_json)?;
    observations.validate(&snapshot, sync_extend_core_model::limits::MAX_ENTRIES)?;
    let parts: serde_json::Value = serde_json::from_str(&value.intent_json)?;
    let parts = parts
        .as_array()
        .ok_or(JournalError::Invariant("native Final full intent required"))?;
    if value.version != 1
        || value.attempt != stored.attempt
        || value.owner_generation == [0; 16]
        || value.persistent_metadata_generation == [0; 16]
        || ![
            value.backing_image,
            value.volume_root,
            value.worktree_key,
            value.target_key,
            value.target_parent_key,
            value.intent_parent_key,
            value.intent_file_key,
        ]
        .into_iter()
        .all(ordinary_key)
        || value.target_key.0 != value.volume_root.0
        || value.worktree_key.0 != value.volume_root.0
        || value.target_parent_key.0 != value.volume_root.0
        || value.intent_parent_key.0 == value.volume_root.0
        || value.intent_file_key.0 != value.intent_parent_key.0
        || value.intent_component != format!("intent-{}", value.attempt)
        || !value.worktree.is_absolute()
        || !value.intent_parent.is_absolute()
        || value.target != stored.future_path
        || snapshot != stored.planned
        || operations != stored.operations
        || observations.scope.local_root_identity != stored.observations.scope.local_root_identity
        || observations.scope.platform_epoch != stored.observations.scope.platform_epoch
        || ContentId::hash(
            value
                .worktree
                .to_str()
                .ok_or(JournalError::Invariant("Final UTF8 worktree"))?
                .as_bytes(),
        ) != stored.original_worktree_digest
        || parts.len() != 11
        || parts[0] != 1u32
        || parts[1] != serde_json::to_value(&stored.planned.space_id)?
        || parts[2] != serde_json::to_value(&stored.original_device)?
        || parts[3] != serde_json::to_value(&stored.future_path)?
        || parts[4] != serde_json::to_value(&stored.baseline)?
        || parts[5] != serde_json::to_value(&stored.planned)?
        || parts[6] != serde_json::to_value(&stored.operations)?
        || parts[7].as_u64() != Some(stored.timestamp)
        || parts[8].as_str() != value.worktree.to_str()
        || parts[9].as_str() != Some(observations.scope.local_root_identity.as_str())
        || parts[10].as_str() != Some(value.reservation_json.as_str())
        || value.history_digest
            != ContentId::hash(&serde_json::to_vec(&(
                1u32,
                Some(stored.baseline.root()?),
                &value.snapshot_json,
                &value.operation_json,
                Some(value.observation_json.as_str()),
                stored.timestamp,
            ))?)
        || value.phase_json.len() != 4
    {
        return Err(JournalError::Invariant(
            "original Linux Final complete lineage differs",
        ));
    }
    let mut previous = None;
    let mut previous_json = None;
    for (sequence, phase_json) in value.phase_json.iter().enumerate() {
        let phase = phase_evidence::validate(
            &format!("{}{}.{sequence:04}", phase_evidence::PREFIX, value.attempt),
            phase_json,
            &stored,
            previous.as_ref(),
            previous_json,
        )?;
        previous = Some(phase);
        previous_json = Some(phase_json.as_str());
    }
    let last = previous.ok_or(JournalError::Invariant("Final native phase absent"))?;
    if last.original_file_key != Some(value.target_key)
        || last.original_parent_key != Some(value.target_parent_key)
        || last.intent_digest != ContentId::hash(value.intent_json.as_bytes())
    {
        return Err(JournalError::Invariant(
            "Final original inode differs from complete phase chain",
        ));
    }
    let target = observations
        .entries
        .iter()
        .find(|row| row.observed.path == value.target)
        .ok_or(JournalError::Invariant(
            "Final original target observation absent",
        ))?;
    if target.observed.physical_identity
        != ContentId::hash(
            format!("inode:{}:{}", value.target_key.0, value.target_key.1).as_bytes(),
        )
        || !target.observed.single_link
    {
        return Err(JournalError::Invariant(
            "Final original physical observation differs",
        ));
    }
    match (stored.version, &value.retained) {
        (1 | 3, None) => {}
        (2, Some(retained)) => {
            let prior = stored
                .baseline
                .entries
                .values()
                .find(|entry| entry.path == value.target)
                .and_then(|entry| entry.content.as_ref())
                .ok_or(JournalError::Invariant(
                    "replacement Final prior content absent",
                ))?;
            let expected = value
                .worktree
                .join(
                    value
                        .target
                        .parent()
                        .map_or(String::new(), |path| path.to_string()),
                )
                .join(".sync-tmp")
                .join(value.attempt.as_str());
            if retained.directory != expected
                || &retained.content != prior
                || ![
                    retained.directory_key,
                    retained.container_key,
                    retained.file_key,
                    retained.source_parent_key,
                ]
                .into_iter()
                .all(ordinary_key)
                || retained.directory_key.0 != value.volume_root.0
                || retained.file_key.0 != value.volume_root.0
                || retained.container_key.0 != value.volume_root.0
                || retained.source_parent_key != value.target_parent_key
                || retained.file_key == value.target_key
            {
                return Err(JournalError::Invariant(
                    "replacement retained original lineage differs",
                ));
            }
        }
        _ => {
            return Err(JournalError::Invariant(
                "CREATE/REPLACE Final retained contract differs",
            ));
        }
    }
    Ok((value, stored))
}

fn state(connection: &Connection, key: &str) -> Result<Option<String>> {
    Ok(connection.query_row(
        "SELECT CASE WHEN length(CAST(value AS BLOB)) BETWEEN 1 AND 67108864 THEN value ELSE '' END FROM local_state WHERE key=?1",
        [key], |row| row.get(0)).optional()?)
}

fn validate_context(connection: &Connection, value: &Final, stored: &Stored) -> Result<()> {
    if state(connection, "space_id")?.as_deref() != Some(stored.baseline.space_id.as_str())
        || state(connection, "device_id")?.as_deref() != Some(stored.original_device.as_str())
        || state(connection, "worktree")?.as_deref() != value.worktree.to_str()
    {
        return Err(JournalError::Invariant(
            "Final belongs to another local identity",
        ));
    }
    for manifest in [&stored.baseline, &stored.planned] {
        let actual: String = connection.query_row(
            "SELECT manifest FROM snapshots WHERE snapshot_id=?1 AND space_id=?2",
            params![manifest.root()?.as_str(), manifest.space_id.as_str()],
            |row| row.get(0),
        )?;
        if actual != serde_json::to_string(manifest)? {
            return Err(JournalError::Invariant("Final immutable snapshot differs"));
        }
    }
    for (operation, json) in stored.operations.iter().zip(&value.operation_json) {
        let actual: String = connection.query_row(
            "SELECT payload FROM operations WHERE op_id=?1 AND space_id=?2",
            params![
                operation.op_id.as_str(),
                operation.payload.space_id.as_str()
            ],
            |row| row.get(0),
        )?;
        if actual != *json {
            return Err(JournalError::Invariant("Final immutable operation differs"));
        }
    }
    super::liability::verify_pending_connection(connection, &value.reservation_json)?;
    for (sequence, json) in value.phase_json.iter().enumerate() {
        if state(
            connection,
            &format!("{}{}.{sequence:04}", phase_evidence::PREFIX, value.attempt),
        )?
        .as_deref()
            != Some(json.as_str())
        {
            return Err(JournalError::Invariant(
                "Final immutable native phase differs",
            ));
        }
    }
    Ok(())
}

fn validate_thawed(json: &str, final_json: &str, value: &Final) -> Result<()> {
    let thawed: Thawed = parse(json)?;
    let raw: serde_json::Value = serde_json::from_slice(&thawed.stdout.0)?;
    if thawed.version != 1
        || thawed.attempt != value.attempt
        || thawed.final_digest != ContentId::hash(final_json.as_bytes())
        || thawed.owner_generation != value.owner_generation
        || thawed.process_ids.0 <= 1
        || thawed.process_ids.1 <= 1
        || thawed.process_ids.0 == thawed.process_ids.1
        || thawed.startup.0 != b"{\"event\":\"GUARD_READY\",\"actual_Rust_guardian\":true}\n"
        || thawed.startup.1 != b"{\"event\":\"SUPERVISOR_READY\",\"actual_Rust_guardian\":true}\n"
        || thawed.stdout.1 != b"{\"event\":\"GUARDIAN_FINISHED\"}\n"
        || !thawed.stderr.0.is_empty()
        || !thawed.stderr.1.is_empty()
        || raw["event"] != "THAWED"
        || raw["reason"] != "committed"
        || raw["owner_exit_before_thaw"] != false
        || raw["guardian_exit_before_thaw"] != false
        || !raw["exit_verified_ns"].is_null()
        || !raw["guardian_exit_verified_ns"].is_null()
        || raw["actual_Rust_guardian"] != true
        || raw["thaw_finished_ns"]
            .as_u64()
            .is_none_or(|stamp| stamp == 0)
        || raw.as_object().is_none_or(|fields| fields.len() != 8)
    {
        return Err(JournalError::Invariant(
            "original committed helper terminal bytes differ",
        ));
    }
    Ok(())
}

fn validate_progress(
    json: &str,
    final_json: &str,
    thawed_json: &str,
    value: &Final,
    predecessor: Option<&str>,
) -> Result<Progress> {
    let progress: Progress = parse(json)?;
    if progress.version != 1
        || progress.attempt != value.attempt
        || progress.final_digest != ContentId::hash(final_json.as_bytes())
        || progress.thawed_digest != ContentId::hash(thawed_json.as_bytes())
        || progress.backing_image != value.backing_image
        || progress.persistent_metadata_generation != value.persistent_metadata_generation
        || progress.cleanup_owner_generation == [0; 16]
        || progress.predecessor != predecessor.map(|json| ContentId::hash(json.as_bytes()))
        || (predecessor.is_none() && !progress.observed_absent_slots.is_empty())
    {
        return Err(JournalError::Invariant(
            "original cleanup progress lineage differs",
        ));
    }
    if let Some(prior_json) = predecessor {
        let prepared: Progress = parse(prior_json)?;
        if progress.cleanup_owner_generation == [0; 16]
            || prepared.predecessor.is_some()
            || progress.observed_absent_slots.len() != if value.retained.is_some() { 3 } else { 1 }
            || progress
                .observed_absent_slots
                .iter()
                .any(|(parent, file, component)| {
                    !ordinary_key(*parent) || !ordinary_key(*file) || component.is_empty()
                })
        {
            return Err(JournalError::Invariant(
                "original cleanup absence inventory differs",
            ));
        }
        let intent = &progress.observed_absent_slots[0];
        if intent
            != &(
                value.intent_parent_key,
                value.intent_file_key,
                value.intent_component.clone(),
            )
        {
            return Err(JournalError::Invariant(
                "cleanup outside absence differs from original Final",
            ));
        }
        if let Some(retained) = &value.retained {
            let same_inode = |actual: &(Key, Key, String),
                              expected_parent: Key,
                              expected_file: Key,
                              component: &str| {
                actual.0.1 == expected_parent.1
                    && actual.1.1 == expected_file.1
                    && actual.0.0 == actual.1.0
                    && actual.2 == component
            };
            if !same_inode(
                &progress.observed_absent_slots[1],
                retained.directory_key,
                retained.file_key,
                "original",
            ) || !same_inode(
                &progress.observed_absent_slots[2],
                retained.container_key,
                retained.directory_key,
                value.attempt.as_str(),
            ) {
                return Err(JournalError::Invariant(
                    "cleanup retained absence differs from original Final",
                ));
            }
        }
    }
    Ok(progress)
}

pub(super) fn cleaned_connection(connection: &Connection, attempt: &EntryId) -> Result<bool> {
    let Some(cleaned) = state(connection, &key(CLEANED, attempt))? else {
        return Ok(false);
    };
    let final_json = state(connection, &key(FINAL, attempt))?
        .ok_or(JournalError::Invariant("cleaned original Final absent"))?;
    let (value, stored) = validate_final(&final_json)?;
    if value.attempt != *attempt {
        return Err(JournalError::Invariant("cleaned Final row key differs"));
    }
    validate_context(connection, &value, &stored)?;
    let thawed = state(connection, &key(THAWED, attempt))?
        .ok_or(JournalError::Invariant("cleaned original THAWED absent"))?;
    validate_thawed(&thawed, &final_json, &value)?;
    let prepared = state(connection, &key(PREPARED, attempt))?.ok_or(JournalError::Invariant(
        "cleaned original preparation absent",
    ))?;
    validate_progress(&prepared, &final_json, &thawed, &value, None)?;
    validate_progress(&cleaned, &final_json, &thawed, &value, Some(&prepared))?;
    Ok(true)
}

pub(super) fn cleaned_rows(rows: &[crate::JournalStoredRow], attempt: &EntryId) -> Result<bool> {
    let get = |key: &str| -> Result<Option<&str>> {
        rows.iter()
            .find(|row| row.table() == "local_state" && row.primary_key() == [key.to_owned()])
            .map(|row| {
                match row
                    .columns()
                    .iter()
                    .find(|column| column.name == "value")
                    .map(|column| &column.value)
                {
                    Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value.as_str()),
                    _ => Err(JournalError::Invariant(
                        "cleanup original state is not text",
                    )),
                }
            })
            .transpose()
    };
    let Some(cleaned) = get(&key(CLEANED, attempt))? else {
        return Ok(false);
    };
    let final_json = get(&key(FINAL, attempt))?
        .ok_or(JournalError::Invariant("cleaned original Final absent"))?;
    let (value, stored) = validate_final(final_json)?;
    if value.attempt != *attempt {
        return Err(JournalError::Invariant("cleaned Final row key differs"));
    }
    super::liability::verify_pending_rows(&value.reservation_json, rows)?;
    if get("space_id")? != Some(stored.baseline.space_id.as_str())
        || get("device_id")? != Some(stored.original_device.as_str())
        || get("worktree")? != value.worktree.to_str()
    {
        return Err(JournalError::Invariant(
            "cleaned rows local identity differs",
        ));
    }
    let field = |table: &str, primary: &str, column: &str| -> Result<&str> {
        let row = rows
            .iter()
            .find(|row| row.table() == table && row.primary_key() == [primary.to_owned()])
            .ok_or(JournalError::Invariant(
                "cleaned immutable original row absent",
            ))?;
        match row
            .columns()
            .iter()
            .find(|value| value.name == column)
            .map(|value| &value.value)
        {
            Some(crate::JournalStorageColumnValue::Text(value)) => Ok(value.as_str()),
            _ => Err(JournalError::Invariant(
                "cleaned immutable original text absent",
            )),
        }
    };
    for manifest in [&stored.baseline, &stored.planned] {
        if field("snapshots", manifest.root()?.as_str(), "manifest")?
            != serde_json::to_string(manifest)?
        {
            return Err(JournalError::Invariant(
                "cleaned immutable snapshot differs",
            ));
        }
    }
    for (operation, json) in stored.operations.iter().zip(&value.operation_json) {
        if field("operations", operation.op_id.as_str(), "payload")? != json {
            return Err(JournalError::Invariant(
                "cleaned immutable operation differs",
            ));
        }
    }
    for (sequence, json) in value.phase_json.iter().enumerate() {
        if get(&format!(
            "{}{}.{sequence:04}",
            phase_evidence::PREFIX,
            value.attempt
        ))? != Some(json.as_str())
        {
            return Err(JournalError::Invariant(
                "cleaned immutable native phase differs",
            ));
        }
    }
    let thawed = get(&key(THAWED, attempt))?
        .ok_or(JournalError::Invariant("cleaned original THAWED absent"))?;
    validate_thawed(thawed, final_json, &value)?;
    let prepared = get(&key(PREPARED, attempt))?.ok_or(JournalError::Invariant(
        "cleaned original preparation absent",
    ))?;
    validate_progress(prepared, final_json, thawed, &value, None)?;
    validate_progress(cleaned, final_json, thawed, &value, Some(prepared))?;
    Ok(true)
}

/// Complete immutable Final/THAWED/cleanup audit on the caller's same read view.
/// This performs SELECTs and validation only; no live Journal or permit is issued.
pub(crate) fn audit_source_native_terminals(
    connection: &Connection,
    max: usize,
) -> Result<Vec<OriginalLinuxNativeFinalDiagnostic>> {
    let mut query = connection.prepare(
        "SELECT key,value FROM local_state WHERE substr(key,1,?1)=?2 ORDER BY key LIMIT ?3",
    )?;
    let rows = query
        .query_map(params![FINAL.len() as i64, FINAL, max as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() > max {
        return Err(JournalError::Invariant("native Final inventory limit"));
    }
    let mut result = Vec::new();
    for (name, json) in rows {
        let (value, stored) = validate_final(&json)?;
        if name != key(FINAL, &value.attempt) {
            return Err(JournalError::Invariant("native Final row key differs"));
        }
        validate_context(connection, &value, &stored)?;
        let thawed = state(connection, &key(THAWED, &value.attempt))?;
        if let Some(thawed) = &thawed {
            validate_thawed(thawed, &json, &value)?;
        }
        let prepared = state(connection, &key(PREPARED, &value.attempt))?;
        if let Some(prepared) = &prepared {
            validate_progress(
                prepared,
                &json,
                thawed
                    .as_deref()
                    .ok_or(JournalError::Invariant("prepared cleanup THAWED absent"))?,
                &value,
                None,
            )?;
        }
        let cleaned = cleaned_connection(connection, &value.attempt)?;
        result.push(OriginalLinuxNativeFinalDiagnostic {
            transaction_id: value.attempt,
            target: value.target,
            snapshot_id: stored.planned.root()?,
            native_action: if stored.version == 2 {
                "REPLACE"
            } else {
                "CREATE"
            },
            final_exact_digest: ContentId::hash(json.as_bytes()),
            helper_thawed: thawed.is_some(),
            cleanup_prepared: prepared.is_some(),
            cleanup_completed: cleaned,
            immutable_history_and_native_receipts_retained: true,
        });
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
mod live;

#[cfg(target_os = "linux")]
mod successor;
