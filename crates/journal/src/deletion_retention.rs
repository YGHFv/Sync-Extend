//! Optional durable local observation, bounded lookup and shared age protection.
use crate::{
    Journal, JournalError, JournalReadView, MAX_OPERATION_BYTES, ReadOnlyJournal, Result,
    storage_inventory::reader::{invalid, preflight},
    storage_policy,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    config::HistoryPolicy,
    deletion_retention::{
        DELETION_CLOCK_REVISION, DeletionObservation, DeletionObservationBasis,
        DeletionRetentionSnapshot, ObservedDeletion, RetentionClockView,
        deletion_retention_protection, retention_milliseconds,
    },
    *,
};

mod capacity;
pub(crate) mod physical;
pub(crate) mod schema;
const MAX_LOOKUP_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClockRecord {
    pub(crate) format_version: u32,
    pub(crate) space_id: SpaceId,
    pub(crate) clock_revision: u64,
    pub(crate) watermark_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyRecord {
    format_version: u32,
    space_id: SpaceId,
    revision: u64,
    minimum_days: u32,
    observed_at_ms: u64,
    previous: Option<ContentId>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeletionRetentionPolicy {
    pub minimum_days: u32,
    pub revision: u64,
    pub policy_hash: Option<ContentId>,
    pub automatic_pruning_enabled: bool,
}

pub struct RetentionPreviewInputs {
    pub policy: HistoryPolicy,
    pub deletion_policy: DeletionRetentionPolicy,
    pub snapshots: Vec<crate::RetainedSnapshot>,
    pub current: Option<Manifest>,
    pub pruned_snapshots: usize,
    pub trees: Vec<crate::TreeRestorePreparation>,
    pub leases: Vec<crate::ReadLease>,
    pub mutations: Vec<crate::Mutation>,
    pub publications: Vec<crate::Publication>,
    pub deletion_protection: BTreeMap<SnapshotId, BTreeSet<&'static str>>,
}

pub(crate) fn local_now_ms() -> Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| JournalError::RetentionClockUncertain("local clock precedes epoch"))?;
    let now = i64::try_from(duration.as_millis())
        .map_err(|_| JournalError::RetentionClockUncertain("local clock exceeds integer range"))?;
    if now <= 0 {
        return Err(JournalError::RetentionClockUncertain("unknown local clock"));
    }
    Ok(now)
}

fn encode<T: Serialize>(record: &T) -> Result<(String, ContentId)> {
    let json = serde_json::to_string(record)?;
    if json.is_empty() || json.len() > schema::MAX_RECORD_BYTES {
        return Err(invalid("retention record byte limit"));
    }
    let hash = ContentId::hash(json.as_bytes());
    Ok((json, hash))
}

fn decode<T: serde::de::DeserializeOwned>(json: &str, hash: &str) -> Result<T> {
    if json.is_empty()
        || json.len() > schema::MAX_RECORD_BYTES
        || ContentId::hash(json.as_bytes()).as_str() != hash
    {
        return Err(invalid("retention record hash/byte limit"));
    }
    Ok(serde_json::from_str(json)?)
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    fn objects(connection: &Connection) -> Result<Vec<(String, String, Option<String>)>> {
        Ok(connection
            .prepare_cached(
                "SELECT type,name,sql FROM main.sqlite_schema
             WHERE name LIKE 'deletion_retention_%' OR tbl_name LIKE 'deletion_retention_%'
             ORDER BY type,name LIMIT 64",
            )?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(include_str!("migration-066.sql"))?;
    if objects(connection)? != objects(&expected)? {
        return Err(invalid("retention exact schema/immutable guards differ"));
    }
    Ok(())
}

fn preflight_records(connection: &Connection, max_entries: usize) -> Result<()> {
    storage_policy::validate(max_entries)?;
    validate_schema(connection)?;
    preflight(
        connection,
        schema::TABLES,
        max_entries,
        max_entries as u64 * 1024,
    )?;
    Ok(())
}

fn clock(connection: &Connection, space: &SpaceId) -> Result<Option<ClockRecord>> {
    let row: Option<(i64, i64, String, String, i64)> = connection
        .query_row(
            "SELECT clock_revision,watermark_ms,
         CASE WHEN length(CAST(record AS BLOB))<=?2 THEN record ELSE '' END,
         record_hash,length(CAST(record AS BLOB))
         FROM main.deletion_retention_clock WHERE space_id=?1",
            params![space.as_str(), schema::MAX_RECORD_BYTES as i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((revision, watermark, json, hash, length)) = row else {
        return Ok(None);
    };
    if !(1..=schema::MAX_RECORD_BYTES as i64).contains(&length) {
        return Err(invalid("retention clock metadata limit"));
    }
    let record: ClockRecord = decode(&json, &hash)?;
    if record.format_version != FORMAT_VERSION
        || record.space_id != *space
        || record.clock_revision != DELETION_CLOCK_REVISION
        || crate::sql_integer(record.clock_revision)? != revision
        || crate::sql_integer(record.watermark_ms)? != watermark
        || watermark <= 0
    {
        return Err(invalid("retention clock columns/identity differ"));
    }
    Ok(Some(record))
}

fn policy(
    connection: &Connection,
    space: &SpaceId,
    max_entries: usize,
) -> Result<DeletionRetentionPolicy> {
    let mut query = connection.prepare_cached(
        "SELECT revision,minimum_days,observed_at_ms,
         CASE WHEN length(CAST(record AS BLOB))<=?2 THEN record ELSE '' END,
         record_hash,length(CAST(record AS BLOB))
         FROM main.deletion_retention_policies WHERE space_id=?1 ORDER BY revision LIMIT ?3",
    )?;
    let mut rows = query.query(params![
        space.as_str(),
        schema::MAX_RECORD_BYTES as i64,
        max_entries as i64 + 1
    ])?;
    let mut count = 0usize;
    let mut previous = None;
    let mut prior_time = 0;
    let mut answer = DeletionRetentionPolicy {
        minimum_days: 0,
        revision: 0,
        policy_hash: None,
        automatic_pruning_enabled: false,
    };
    while let Some(row) = rows.next()? {
        count += 1;
        if count > max_entries {
            return Err(invalid("retention policy revision count limit"));
        }
        let length: i64 = row.get(5)?;
        if !(1..=schema::MAX_RECORD_BYTES as i64).contains(&length) {
            return Err(invalid("retention policy metadata limit"));
        }
        let json: String = row.get(3)?;
        let hash: String = row.get(4)?;
        let record: PolicyRecord = decode(&json, &hash)?;
        if record.format_version != FORMAT_VERSION
            || record.space_id != *space
            || record.revision != count as u64
            || record.previous != previous
            || record.observed_at_ms == 0
            || record.observed_at_ms < prior_time
            || crate::sql_integer(record.revision)? != row.get::<_, i64>(0)?
            || i64::from(record.minimum_days) != row.get::<_, i64>(1)?
            || crate::sql_integer(record.observed_at_ms)? != row.get::<_, i64>(2)?
        {
            return Err(invalid("retention explicit policy chain differs"));
        }
        retention_milliseconds(u64::from(record.minimum_days))?;
        prior_time = record.observed_at_ms;
        previous = Some(hash.parse()?);
        answer.minimum_days = record.minimum_days;
        answer.revision = record.revision;
        answer.policy_hash = previous.clone();
    }
    if answer.revision != 0 && clock(connection, space)?.is_none_or(|c| c.watermark_ms < prior_time)
    {
        return Err(invalid("retention policy clock dependency absent"));
    }
    Ok(answer)
}

fn spend_bytes(bytes: &mut u64, additional: usize, max_entries: usize) -> Result<()> {
    *bytes = bytes
        .checked_add(additional as u64)
        .filter(|n| *n <= MAX_LOOKUP_BYTES.min(max_entries as u64 * 1024))
        .ok_or(invalid("retention lookup aggregate byte limit"))?;
    Ok(())
}

fn operation(
    connection: &Connection,
    space: &SpaceId,
    id: &OperationId,
    bytes: &mut u64,
    max_entries: usize,
) -> Result<Operation> {
    let row: (String, String, i64, String, String, i64) = connection.query_row(
        "SELECT space_id,origin_device_id,origin_seq,state,
         CASE WHEN length(CAST(payload AS BLOB))<=?2 THEN payload ELSE '' END,
         length(CAST(payload AS BLOB)) FROM main.operations WHERE op_id=?1",
        params![id.as_str(), MAX_OPERATION_BYTES as i64],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
            ))
        },
    )?;
    if !(1..=MAX_OPERATION_BYTES as i64).contains(&row.5) {
        return Err(invalid("retention exact operation byte limit"));
    }
    spend_bytes(bytes, row.4.len(), max_entries)?;
    let operation: Operation = serde_json::from_str(&row.4)?;
    operation.validate()?;
    if operation.op_id != *id
        || operation.payload.space_id != *space
        || row.0 != space.as_str()
        || operation.payload.origin_device_id.as_str() != row.1
        || crate::sql_integer(operation.payload.origin_seq)? != row.2
        || row.3 != "materialized"
        || !matches!(operation.payload.change, Change::Delete { .. })
    {
        return Err(invalid("retention stored Delete row differs"));
    }
    Ok(operation)
}

fn anchor(
    connection: &Connection,
    space: &SpaceId,
    root: &SnapshotId,
    cache: &mut BTreeMap<SnapshotId, Manifest>,
    bytes: &mut u64,
    max_entries: usize,
) -> Result<()> {
    if cache.contains_key(root) {
        return Ok(());
    }
    if cache.len() >= max_entries {
        return Err(invalid("retention anchor count limit"));
    }
    let (json, length, state): (String, i64, String) = connection.query_row(
        "SELECT CASE WHEN length(CAST(manifest AS BLOB))<=?3 THEN manifest ELSE '' END,
         length(CAST(manifest AS BLOB)),state FROM main.snapshots WHERE space_id=?1 AND snapshot_id=?2",
        params![space.as_str(), root.as_str(), MAX_OPERATION_BYTES as i64],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if !(1..=MAX_OPERATION_BYTES as i64).contains(&length) || state != "materialized" {
        return Err(invalid("retention effective anchor metadata limit/state"));
    }
    spend_bytes(bytes, json.len(), max_entries)?;
    let manifest: Manifest = serde_json::from_str(&json)?;
    if manifest.space_id != *space || manifest.root()? != *root {
        return Err(invalid("retention effective anchor hash differs"));
    }
    cache.insert(root.clone(), manifest);
    Ok(())
}

fn observation(
    connection: &Connection,
    operation: &Operation,
    clock: Option<&ClockRecord>,
    cache: &mut BTreeMap<SnapshotId, Manifest>,
    bytes: &mut u64,
    max_entries: usize,
) -> Result<Option<DeletionObservation>> {
    let row: Option<(String, String, i64, i64, String, String, i64)> = connection
        .query_row(
            "SELECT entry_id,effective_snapshot,observed_at_ms,clock_revision,
         CASE WHEN length(CAST(record AS BLOB))<=?3 THEN record ELSE '' END,
         record_hash,length(CAST(record AS BLOB)) FROM main.deletion_retention_observations
         WHERE space_id=?1 AND operation_id=?2",
            params![
                operation.payload.space_id.as_str(),
                operation.op_id.as_str(),
                schema::MAX_RECORD_BYTES as i64
            ],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some(row) = row else { return Ok(None) };
    if !(1..=schema::MAX_RECORD_BYTES as i64).contains(&row.6) {
        return Err(invalid("retention observation metadata limit"));
    }
    spend_bytes(bytes, row.4.len(), max_entries)?;
    let record: DeletionObservation = decode(&row.4, &row.5)?;
    record.validate(operation)?;
    if record.entry_id.as_str() != row.0
        || record.effective_snapshot.as_str() != row.1
        || crate::sql_integer(record.observed_at_ms)? != row.2
        || row.2 <= 0
        || crate::sql_integer(record.clock_revision)? != row.3
        || clock.is_none_or(|c| {
            c.watermark_ms < record.observed_at_ms || c.clock_revision != record.clock_revision
        })
    {
        return Err(invalid("retention first observation columns/clock differ"));
    }
    anchor(
        connection,
        &record.space_id,
        &record.effective_snapshot,
        cache,
        bytes,
        max_entries,
    )?;
    let manifest = &cache[&record.effective_snapshot];
    if manifest.tombstones.get(&record.entry_id) != Some(&record.operation_id)
        || manifest.entries.contains_key(&record.entry_id)
        || !manifest.version_vector.dominates(&operation.payload.causal)
        || manifest
            .version_vector
            .get(&operation.payload.origin_device_id)
            < operation.payload.origin_seq
    {
        return Err(invalid("retention observation was not effective at anchor"));
    }
    Ok(Some(record))
}

pub(crate) fn audit(connection: &Connection, space: &SpaceId, max_entries: usize) -> Result<()> {
    preflight_records(connection, max_entries)?;
    let clock = clock(connection, space)?;
    policy(connection, space, max_entries)?;
    let foreign: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.deletion_retention_clock WHERE space_id!=?1)
         OR EXISTS(SELECT 1 FROM main.deletion_retention_policies WHERE space_id!=?1)
         OR EXISTS(SELECT 1 FROM main.deletion_retention_observations WHERE space_id!=?1)",
        [space.as_str()],
        |r| r.get(0),
    )?;
    if foreign {
        return Err(invalid("retention metadata foreign space"));
    }
    let mut query = connection.prepare_cached(
        "SELECT operation_id FROM main.deletion_retention_observations WHERE space_id=?1 ORDER BY operation_id LIMIT ?2"
    )?;
    let mut rows = query.query(params![space.as_str(), max_entries as i64 + 1])?;
    let mut count = 0;
    let mut bytes = 0;
    let mut cache = BTreeMap::new();
    while let Some(row) = rows.next()? {
        count += 1;
        if count > max_entries {
            return Err(invalid("retention observation row limit"));
        }
        let id: OperationId = row.get::<_, String>(0)?.parse()?;
        let operation = operation(connection, space, &id, &mut bytes, max_entries)?;
        if observation(
            connection,
            &operation,
            clock.as_ref(),
            &mut cache,
            &mut bytes,
            max_entries,
        )?
        .is_none()
        {
            return Err(invalid("retention audited observation disappeared"));
        }
    }
    Ok(())
}

pub(crate) fn metadata_budget(connection: &Connection) -> Result<(u64, u64)> {
    let tables = preflight(
        connection,
        schema::TABLES,
        limits::MAX_ENTRIES,
        limits::MAX_ENTRIES as u64 * 1024,
    )?;
    tables
        .iter()
        .try_fold((0u64, 0u64), |(rows, bytes), table| {
            Ok((
                crate::storage_inventory::reader::add(rows, table.rows)?,
                crate::storage_inventory::reader::add(bytes, table.logical_bytes)?,
            ))
        })
}

pub(crate) fn protections(
    connection: &Connection,
    space: &SpaceId,
    snapshots: &[crate::RetainedSnapshot],
    days: u32,
    now: i64,
    max_entries: usize,
) -> Result<BTreeMap<SnapshotId, BTreeSet<&'static str>>> {
    if days == 0 {
        return Ok(BTreeMap::new());
    }
    let clock = clock(connection, space)?;
    let mut ids = BTreeMap::<OperationId, EntryId>::new();
    let mut visits = 0usize;
    for snapshot in snapshots {
        for (entry, id) in &snapshot.manifest.tombstones {
            visits = visits
                .checked_add(1)
                .filter(|n| *n <= max_entries)
                .ok_or(invalid("retention tombstone traversal limit"))?;
            if ids
                .insert(id.clone(), entry.clone())
                .is_some_and(|prior| prior != *entry)
            {
                return Err(invalid("retention tombstone entry differs"));
            }
        }
    }
    let mut bytes = 0;
    let mut cache = BTreeMap::new();
    let mut deletions = BTreeMap::new();
    for (id, entry) in ids {
        let operation = operation(connection, space, &id, &mut bytes, max_entries)?;
        if operation.payload.change != (Change::Delete { entry_id: entry }) {
            return Err(invalid("retention tombstone operation binding differs"));
        }
        let observation = observation(
            connection,
            &operation,
            clock.as_ref(),
            &mut cache,
            &mut bytes,
            max_entries,
        )?;
        deletions.insert(
            id,
            ObservedDeletion {
                operation,
                observation,
            },
        );
    }
    let inputs: Vec<_> = snapshots
        .iter()
        .map(|snapshot| DeletionRetentionSnapshot {
            snapshot_id: &snapshot.snapshot_id,
            manifest: &snapshot.manifest,
        })
        .collect();
    Ok(deletion_retention_protection(
        space,
        &inputs,
        &deletions,
        u64::from(days),
        RetentionClockView {
            now_ms: now,
            watermark_ms: clock.as_ref().map(|c| c.watermark_ms),
            revision: clock.as_ref().map(|c| c.clock_revision),
        },
        max_entries,
    )?)
}

pub(crate) fn effective_policy(
    connection: &Connection,
    space: &SpaceId,
    mut requested: HistoryPolicy,
    max_entries: usize,
) -> Result<(HistoryPolicy, DeletionRetentionPolicy)> {
    retention_milliseconds(u64::from(requested.deleted_min_retention_days))?;
    let durable = policy(connection, space, max_entries)?;
    requested.deleted_min_retention_days = requested
        .deleted_min_retention_days
        .max(durable.minimum_days);
    Ok((requested, durable))
}

fn preview(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    requested: HistoryPolicy,
    max_entries: usize,
) -> Result<RetentionPreviewInputs> {
    let bounds = storage_policy::capacity_limits(max_entries)?;
    view.audit_history_capacity(space, bounds)?;
    let (policy, deletion_policy) =
        effective_policy(view.connection, space, requested, max_entries)?;
    let snapshots = view.retained_snapshots(space)?;
    let current = view.current(space)?;
    if let Some(current) = &current {
        let root = current.root()?;
        if !snapshots
            .iter()
            .any(|snapshot| snapshot.snapshot_id == root && snapshot.manifest == *current)
        {
            return Err(invalid(
                "retention current missing from exact retained history union",
            ));
        }
    }
    let now = local_now_ms().unwrap_or(0);
    let deletion_protection = protections(
        view.connection,
        space,
        &snapshots,
        policy.deleted_min_retention_days,
        now,
        max_entries,
    )?;
    view.cleanup_plans(space)?;
    let mutations = view.mutations(space)?;
    for mutation in &mutations {
        view.verify_mutation_references(&mutation.intent.transaction_id)?;
    }
    Ok(RetentionPreviewInputs {
        policy,
        deletion_policy,
        snapshots,
        current,
        pruned_snapshots: view
            .snapshot_audit(space)?
            .into_iter()
            .filter(|s| !s.content_retained)
            .count(),
        trees: view.complete_tree_restore_audit(space, max_entries, bounds)?,
        leases: view.read_leases(space)?,
        mutations,
        publications: view.publications(space)?,
        deletion_protection,
    })
}

impl JournalReadView<'_> {
    /// The complete former Journal tree audit, also available to a true reader.
    /// No native-progress, full-value, capacity or coverage predicate is omitted.
    pub(crate) fn complete_tree_restore_audit(
        &self,
        space: &SpaceId,
        max: usize,
        bounds: crate::JournalCapacityLimits,
    ) -> Result<Vec<crate::TreeRestorePreparation>> {
        if max == 0 || max > limits::MAX_ENTRIES {
            return Err(JournalError::Invariant(
                "tree restore audit inventory limit",
            ));
        }
        crate::tree_native_storage::preflight_all(self.connection, max)?;
        let native_progress: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.tree_native_action_attempts)",
            [],
            |row| row.get(0),
        )?;
        if !native_progress {
            crate::check_storage_metadata_limit(self.connection, max, 0, 0)?;
        }
        let preparations = self.audit_tree_restore_preparations(space, max)?;
        crate::tree_native_effects::validate_all(self.connection, &preparations, max)?;
        if native_progress {
            let capacity = self.audit_local_commit_capacity(space, bounds)?;
            if !capacity.report.within_accounted_limits()
                || !capacity.report.coverage_gaps().is_empty()
            {
                return Err(JournalError::Invariant(
                    "tree native exact capacity refused",
                ));
            }
        }
        Ok(preparations)
    }
}

impl Journal {
    pub fn retention_preview_inputs(
        &self,
        space: &SpaceId,
        requested: HistoryPolicy,
        max_entries: usize,
    ) -> Result<RetentionPreviewInputs> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        self.integrity_check()?;
        let inputs = preview(
            &self.read_view(),
            space,
            requested,
            self.max_storage_entries.min(max_entries),
        )?;
        tx.commit()?;
        Ok(inputs)
    }
}

impl ReadOnlyJournal {
    pub fn retention_preview_inputs(
        &self,
        space: &SpaceId,
        requested: HistoryPolicy,
        max_entries: usize,
    ) -> Result<RetentionPreviewInputs> {
        self.verify_readonly_files()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        self.integrity_check()?;
        let inputs = preview(&self.read_view(), space, requested, max_entries)?;
        tx.commit()?;
        self.verify_readonly_files()?;
        Ok(inputs)
    }
}

pub(crate) fn clock_columns(record: &ClockRecord) -> Result<Vec<crate::JournalStorageColumn>> {
    let (json, hash) = encode(record)?;
    Ok(vec![
        capacity::text("space_id", record.space_id.as_str()),
        capacity::number("clock_revision", record.clock_revision),
        capacity::number("watermark_ms", record.watermark_ms),
        capacity::text("record", &json),
        capacity::text("record_hash", hash.as_str()),
    ])
}

fn policy_columns(record: &PolicyRecord) -> Result<Vec<crate::JournalStorageColumn>> {
    let (json, hash) = encode(record)?;
    Ok(vec![
        capacity::text("space_id", record.space_id.as_str()),
        capacity::number("revision", record.revision),
        capacity::number("minimum_days", u64::from(record.minimum_days)),
        capacity::number("observed_at_ms", record.observed_at_ms),
        capacity::text("record", &json),
        capacity::text("record_hash", hash.as_str()),
    ])
}

fn observation_columns(record: &DeletionObservation) -> Result<Vec<crate::JournalStorageColumn>> {
    let (json, hash) = encode(record)?;
    Ok(vec![
        capacity::text("space_id", record.space_id.as_str()),
        capacity::text("operation_id", record.operation_id.as_str()),
        capacity::text("entry_id", record.entry_id.as_str()),
        capacity::text("effective_snapshot", record.effective_snapshot.as_str()),
        capacity::number("observed_at_ms", record.observed_at_ms),
        capacity::number("clock_revision", record.clock_revision),
        capacity::text("record", &json),
        capacity::text("record_hash", hash.as_str()),
    ])
}

fn next_clock(connection: &Connection, space: &SpaceId, now: i64) -> Result<ClockRecord> {
    let now = u64::try_from(now).ok().filter(|now| *now != 0).ok_or(
        JournalError::RetentionClockUncertain("local observation time unknown"),
    )?;
    if clock(connection, space)?.is_some_and(|prior| now < prior.watermark_ms) {
        return Err(JournalError::RetentionClockUncertain(
            "local retention clock moved backwards",
        ));
    }
    Ok(ClockRecord {
        format_version: FORMAT_VERSION,
        space_id: space.clone(),
        clock_revision: DELETION_CLOCK_REVISION,
        watermark_ms: now,
    })
}

fn pending_observations(
    connection: &Connection,
    space: &SpaceId,
    current: Option<&Manifest>,
    now: &ClockRecord,
    basis: DeletionObservationBasis,
    max_entries: usize,
) -> Result<Vec<DeletionObservation>> {
    let Some(current) = current else {
        return Ok(Vec::new());
    };
    if current.space_id != *space || current.tombstones.len() > max_entries {
        return Err(invalid("retention actual current tombstone limit/space"));
    }
    let root = current.root()?;
    let previous_clock = clock(connection, space)?;
    let mut result = Vec::new();
    let mut bytes = 0;
    let mut cache = BTreeMap::new();
    for (entry, id) in &current.tombstones {
        let operation = operation(connection, space, id, &mut bytes, max_entries)?;
        if operation.payload.change
            != (Change::Delete {
                entry_id: entry.clone(),
            })
            || !current.version_vector.dominates(&operation.payload.causal)
            || current
                .version_vector
                .get(&operation.payload.origin_device_id)
                < operation.payload.origin_seq
        {
            return Err(invalid(
                "retention current Delete is not causally effective",
            ));
        }
        if observation(
            connection,
            &operation,
            previous_clock.as_ref(),
            &mut cache,
            &mut bytes,
            max_entries,
        )?
        .is_none()
        {
            let record = DeletionObservation {
                format_version: FORMAT_VERSION,
                space_id: space.clone(),
                operation_id: id.clone(),
                entry_id: entry.clone(),
                effective_snapshot: root.clone(),
                observed_at_ms: now.watermark_ms,
                clock_revision: now.clock_revision,
                basis: basis.clone(),
            };
            record.validate(&operation)?;
            result.push(record);
        }
    }
    Ok(result)
}

impl Journal {
    pub(crate) fn write_retention_clock(
        &self,
        tx: &Transaction<'_>,
        record: &ClockRecord,
    ) -> Result<()> {
        let (json, hash) = encode(record)?;
        self.deletion_retention_issuance
            .issue(hash.to_string(), record.watermark_ms, || {
                if tx.execute(
                "UPDATE main.deletion_retention_clock SET watermark_ms=?1,record=?2,record_hash=?3
                 WHERE space_id=?4 AND clock_revision=?5 AND watermark_ms<=?1",
                params![crate::sql_integer(record.watermark_ms)?, json, hash.as_str(),
                    record.space_id.as_str(), crate::sql_integer(record.clock_revision)?],
            )? == 0 {
                tx.execute(
                    "INSERT INTO main.deletion_retention_clock VALUES(?1,?2,?3,?4,?5)",
                    params![record.space_id.as_str(), crate::sql_integer(record.clock_revision)?,
                        crate::sql_integer(record.watermark_ms)?, json, hash.as_str()],
                )?;
            }
                Ok(())
            })
    }

    fn write_observations(
        &self,
        tx: &Transaction<'_>,
        observations: &[DeletionObservation],
    ) -> Result<()> {
        for record in observations {
            let (json, hash) = encode(record)?;
            self.deletion_retention_issuance.issue(hash.to_string(), record.observed_at_ms, || {
                tx.execute(
                    "INSERT INTO main.deletion_retention_observations VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![record.space_id.as_str(), record.operation_id.as_str(), record.entry_id.as_str(),
                        record.effective_snapshot.as_str(), crate::sql_integer(record.observed_at_ms)?,
                        crate::sql_integer(record.clock_revision)?, json, hash.as_str()],
                )?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Explicit policy mutation, including explicit lowering. Reports never call
    /// this. The expected revision prevents a stale invocation from lowering a floor.
    pub fn set_deletion_retention_policy(
        &mut self,
        space: &SpaceId,
        minimum_days: u32,
        expected_revision: u64,
        max_entries: usize,
    ) -> Result<DeletionRetentionPolicy> {
        retention_milliseconds(u64::from(minimum_days))?;
        let bounds = self.writer_capacity_limits(max_entries)?;
        let physical = physical::PhysicalMetadataGuard::capture(self)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.read_view().audit_history_capacity(space, bounds)?;
        if self.read_view().state("space_id")?.as_deref() != Some(space.as_str())
            || self.read_view().state("worktree")?.is_none()
        {
            return Err(invalid(
                "deletion retention policy requires this initialized local client",
            ));
        }
        let prior = policy(&tx, space, bounds.max_rows as usize)?;
        if prior.revision != expected_revision {
            return Err(invalid("explicit retention policy revision changed"));
        }
        if prior.minimum_days == minimum_days {
            physical.verify(self)?;
            tx.commit()?;
            physical.verify(self)?;
            return Ok(prior);
        }
        let now = next_clock(&tx, space, local_now_ms()?)?;
        let revision = prior
            .revision
            .checked_add(1)
            .ok_or(invalid("retention policy revision overflow"))?;
        crate::sql_integer(revision)?;
        let record = PolicyRecord {
            format_version: FORMAT_VERSION,
            space_id: space.clone(),
            revision,
            minimum_days,
            observed_at_ms: now.watermark_ms,
            previous: prior.policy_hash,
        };
        let current = self.read_view().current(space)?;
        let observations = if minimum_days == 0 {
            Vec::new()
        } else {
            pending_observations(
                &tx,
                space,
                current.as_ref(),
                &now,
                DeletionObservationBasis::LegacyLocalObservation,
                bounds.max_rows as usize,
            )?
        };
        let mut changes = capacity::Changes::new();
        changes.insert(
            ("deletion_retention_clock".into(), vec![space.to_string()]),
            clock_columns(&now)?,
        );
        changes.insert(
            (
                "deletion_retention_policies".into(),
                vec![space.to_string(), revision.to_string()],
            ),
            policy_columns(&record)?,
        );
        for observation in &observations {
            changes.insert(
                (
                    "deletion_retention_observations".into(),
                    vec![space.to_string(), observation.operation_id.to_string()],
                ),
                observation_columns(observation)?,
            );
        }
        let projection = capacity::Projection::new(&before, changes)?;
        self.write_retention_clock(&tx, &now)?;
        let (json, hash) = encode(&record)?;
        self.deletion_retention_issuance
            .issue(hash.to_string(), record.observed_at_ms, || {
                tx.execute(
                    "INSERT INTO main.deletion_retention_policies VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        space.as_str(),
                        crate::sql_integer(revision)?,
                        i64::from(minimum_days),
                        crate::sql_integer(record.observed_at_ms)?,
                        json,
                        hash.as_str()
                    ],
                )?;
                Ok(())
            })?;
        self.write_observations(&tx, &observations)?;
        let after = self.read_view().audit_history_capacity(space, bounds)?;
        projection.verify(&after)?;
        let result = policy(&tx, space, bounds.max_rows as usize)?;
        physical.verify(self)?;
        tx.commit()?;
        physical
            .verify(self)
            .map_err(|error| JournalError::RetentionMetadataAfterCommit {
                action: "deletion retention policy revision",
                identity: result.revision.to_string(),
                error: Box::new(error),
            })?;
        Ok(result)
    }

    fn admit_effective_observations(
        &self,
        space: &SpaceId,
        expected_root: &SnapshotId,
        max_entries: usize,
    ) -> Result<usize> {
        // No new metadata, clock write or extra current transaction at default0.
        if policy(&self.connection, space, max_entries)?.minimum_days == 0 {
            return Ok(0);
        }
        let bounds = self.writer_capacity_limits(max_entries)?;
        let physical = physical::PhysicalMetadataGuard::capture(self)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if policy(&tx, space, bounds.max_rows as usize)?.minimum_days == 0 {
            tx.commit()?;
            return Ok(0);
        }
        let before = self.read_view().audit_history_capacity(space, bounds)?;
        let current = self
            .read_view()
            .current(space)?
            .ok_or(invalid("retention committed current missing"))?;
        if current.root()? != *expected_root {
            return Err(JournalError::RetentionAdmissionDeferred(
                "current changed before bounded deletion observation",
            ));
        }
        let now = next_clock(&tx, space, local_now_ms()?)?;
        let observations = pending_observations(
            &tx,
            space,
            Some(&current),
            &now,
            DeletionObservationBasis::LocalEffectiveCommit,
            bounds.max_rows as usize,
        )?;
        let mut changes = capacity::Changes::new();
        changes.insert(
            ("deletion_retention_clock".into(), vec![space.to_string()]),
            clock_columns(&now)?,
        );
        for observation in &observations {
            changes.insert(
                (
                    "deletion_retention_observations".into(),
                    vec![space.to_string(), observation.operation_id.to_string()],
                ),
                observation_columns(observation)?,
            );
        }
        let projection = capacity::Projection::new(&before, changes)?;
        self.write_retention_clock(&tx, &now)?;
        self.write_observations(&tx, &observations)?;
        let after = self.read_view().audit_history_capacity(space, bounds)?;
        projection.verify(&after)?;
        physical.verify(self)?;
        tx.commit()?;
        physical.verify(self)?;
        Ok(observations.len())
    }

    pub(crate) fn observe_after_current(&self, space: &SpaceId, root: &SnapshotId) -> Result<()> {
        match self.admit_effective_observations(space, root, self.max_storage_entries) {
            Ok(_) => Ok(()),
            // No row is invented on rollback or capacity refusal. Missing age
            // remains visible as protection in every nonzero preview/prune.
            Err(
                JournalError::RetentionAdmissionDeferred(_)
                | JournalError::RetentionClockUncertain(_),
            ) => Ok(()),
            Err(error) => Err(JournalError::RetentionObservationAfterCommit {
                snapshot_id: root.clone(),
                error: Box::new(error),
            }),
        }
    }

    /// Admit a delayed local observation after an actual committed current or
    /// completed native cleanup. The owned write transaction rechecks the root;
    /// an old completion cannot backdate or observe a changed current.
    pub fn admit_committed_deletion_observations(
        &mut self,
        space: &SpaceId,
        root: &SnapshotId,
    ) -> Result<()> {
        self.observe_after_current(space, root)
    }

    pub(crate) fn pruning_retention_clock(
        &self,
        space: &SpaceId,
        days: u32,
        now: i64,
    ) -> Result<Option<ClockRecord>> {
        if days == 0 {
            return Ok(None);
        }
        if clock(&self.connection, space)?.is_none() {
            // No clock/anchor can safely expire a relevant live history.
            return Ok(None);
        }
        Ok(Some(next_clock(&self.connection, space, now)?))
    }
}
