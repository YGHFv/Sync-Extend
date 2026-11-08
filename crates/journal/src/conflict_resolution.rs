//! Immutable prospective local resolution, not a native execution or pin release.
use crate::{
    storage_inventory::reader::{hash, invalid, preflight},
    storage_policy, CasAccessGuard, Journal, JournalCapacityObligation, JournalStoredRow, Result,
};
use rusqlite::{params, types::Value, Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    causal::reduce_operations,
    conflict_resolution::{FileResolutionPlan, ResolutionLimits},
    ChunkRef, ContentId, EntryId, EntryKind, Manifest, Operation, SnapshotId, SpaceId,
    VersionVector,
};

pub(crate) mod issuance;
mod native_binding;
mod native_effects;
pub(crate) mod native_future_schema;
mod native_history_templates;
mod native_ledger;
mod native_ledger_storage;
mod native_template_schema;
mod native_templates;
mod proof;
pub use proof::{
    ConflictResolutionKey, ConflictResolutionPayload, ConflictResolutionProof,
    ConflictSignedOperation,
};
#[cfg(windows)]
mod native_baseline;
pub(crate) mod schema;
#[cfg(windows)]
pub use native_baseline::{
    ConflictNativeAdmission, ConflictNativeAdmissionLimits, ConflictNativeAdmissionReport,
    ConflictNativeBaseline, ConflictNativeBaselineReport, ConflictNativeCreation,
    ConflictNativeReadiness,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictResolutionAdmissionIntent {
    pub proof: ConflictResolutionProof,
    pub approved_keys: Vec<ConflictResolutionKey>,
    pub baseline: Manifest,
    pub worktree: String,
    pub root_identity: ContentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format_version: u32,
    transaction_id: EntryId,
    intent: ConflictResolutionAdmissionIntent,
    original_states: BTreeMap<String, String>,
    target: Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConflictResolutionAdmission {
    pub transaction_id: EntryId,
    pub plan_fingerprint: ContentId,
    pub baseline_root: SnapshotId,
    pub reserved_first_sequence: u64,
    pub reserved_last_sequence: u64,
    pub protected_chunks: Vec<ChunkRef>,
    pub signed_sequence_reserved: bool,
    pub original_signatures_retained: bool,
    pub resolution_applied: bool,
    pub worktree_materialized: bool,
    pub release_available: bool,
}

fn transaction_id(proof: &ConflictResolutionProof) -> Result<EntryId> {
    Ok(
        hash(&("SyncExtend local conflict resolution admission v1", proof))?.as_str()[..32]
            .parse()?,
    )
}

fn flat_baseline(baseline: &Manifest, originals: &[Operation]) -> Result<()> {
    baseline.validate()?;
    if baseline
        .entries
        .values()
        .any(|e| e.kind != EntryKind::File || e.path.parent().is_some())
    {
        return Err(invalid(
            "conflict admission baseline supports flat files only",
        ));
    }
    let applied: Vec<_> = originals
        .iter()
        .filter(|op| {
            baseline.version_vector.get(&op.payload.origin_device_id) >= op.payload.origin_seq
        })
        .cloned()
        .collect();
    let reduced = reduce_operations(&baseline.space_id, &applied, 10_000)?;
    if reduced.received_vector != baseline.version_vector
        || !reduced.path_collisions.is_empty()
        || reduced.entries.len() != baseline.entries.len() + baseline.tombstones.len()
    {
        return Err(invalid(
            "conflict baseline is not exact applied genesis prefix",
        ));
    }
    for (id, frontier) in reduced.entries {
        if let Some(entry) = baseline.entries.get(&id) {
            if frontier.deleted
                || frontier.delete_conflict
                || frontier.paths.len() != 1
                || frontier.paths[0].path != entry.path
                || frontier.contents.len() != 1
                || frontier.contents[0].kind != entry.kind
                || frontier.contents[0].content != entry.content
            {
                return Err(invalid(
                    "conflict baseline differs from original applied projection",
                ));
            }
        } else if !frontier.deleted
            || !baseline
                .tombstones
                .get(&id)
                .is_some_and(|op| frontier.deletions.contains(op))
        {
            return Err(invalid("conflict baseline tombstone provenance differs"));
        }
    }
    Ok(())
}

impl Header {
    fn plan(&self) -> Result<FileResolutionPlan> {
        if self.format_version != 1
            || self.transaction_id != transaction_id(&self.intent.proof)?
            || self.intent.worktree.is_empty()
            || self.intent.worktree.len() > 32 * 1024
            || self
                .intent
                .approved_keys
                .windows(2)
                .any(|k| k[0].device_id >= k[1].device_id)
        {
            return Err(invalid("conflict admission immutable header differs"));
        }
        let p = &self.intent.proof.payload;
        let plan = self
            .intent
            .proof
            .verify(&self.intent.approved_keys, ResolutionLimits::default())?;
        let originals: Vec<_> = p.originals.iter().map(|s| s.operation.clone()).collect();
        flat_baseline(&self.intent.baseline, &originals)?;
        let mut vector = plan.received_vector.clone();
        for signed in &p.resolving {
            let op = &signed.operation;
            vector.observe(op.payload.origin_device_id.clone(), op.payload.origin_seq);
        }
        let mut target = plan.projected.clone();
        target.version_vector = vector;
        if target != self.target
            || target.space_id != self.intent.baseline.space_id
            || self.original_states.len() != p.originals.len()
        {
            return Err(invalid("conflict admission target/states differ"));
        }
        for signed in &p.originals {
            let op = &signed.operation;
            let state = if self
                .intent
                .baseline
                .version_vector
                .get(&op.payload.origin_device_id)
                >= op.payload.origin_seq
            {
                "materialized"
            } else {
                "received"
            };
            if self
                .original_states
                .get(op.op_id.as_str())
                .map(String::as_str)
                != Some(state)
            {
                return Err(invalid(
                    "conflict original applied/received binding differs",
                ));
            }
        }
        pins(self)?;
        Ok(plan)
    }

    fn receipt(&self) -> Result<ConflictResolutionAdmission> {
        let p = &self.intent.proof.payload;
        let mut protected = BTreeMap::new();
        for ((_, id), length) in pins(self)? {
            protected.insert(id, length);
        }
        Ok(ConflictResolutionAdmission {
            transaction_id: self.transaction_id.clone(),
            plan_fingerprint: p.plan_fingerprint.clone(),
            baseline_root: self.intent.baseline.root()?,
            reserved_first_sequence: p
                .resolving
                .first()
                .ok_or(invalid("empty resolving prefix"))?
                .operation
                .payload
                .origin_seq,
            reserved_last_sequence: p.resolving.last().unwrap().operation.payload.origin_seq,
            protected_chunks: protected
                .into_iter()
                .map(|(content_id, length)| ChunkRef { content_id, length })
                .collect(),
            signed_sequence_reserved: true,
            original_signatures_retained: true,
            resolution_applied: false,
            worktree_materialized: false,
            release_available: false,
        })
    }
}

fn pins(header: &Header) -> Result<BTreeMap<(String, ContentId), u32>> {
    let mut all_lengths = BTreeMap::new();
    let mut result = BTreeMap::new();
    let originals = header
        .intent
        .proof
        .payload
        .originals
        .iter()
        .filter_map(|signed| match &signed.operation.payload.change {
            sync_extend_core_model::Change::Put { entry } => entry.content.as_ref(),
            _ => None,
        });
    let baseline = header
        .intent
        .baseline
        .entries
        .values()
        .filter_map(|e| e.content.as_ref());
    let projected = header
        .target
        .entries
        .values()
        .filter_map(|e| e.content.as_ref());
    for (role, file) in originals
        .chain(baseline)
        .map(|f| ("original", f))
        .chain(projected.map(|f| ("projected", f)))
    {
        file.validate()?;
        for chunk in &file.chunks {
            if all_lengths
                .insert(chunk.content_id.clone(), chunk.length)
                .is_some_and(|length| length != chunk.length)
            {
                return Err(invalid("conflict branch chunk length collision"));
            }
            result.insert((role.to_string(), chunk.content_id.clone()), chunk.length);
        }
    }
    Ok(result)
}

fn bind(connection: &Connection, header: &Header, plan: &FileResolutionPlan) -> Result<()> {
    let intent = &header.intent;
    let p = &intent.proof.payload;
    let state = |name: &str| -> Result<String> {
        Ok(connection.query_row(
            "SELECT value FROM main.local_state WHERE key=?1",
            [name],
            |r| r.get(0),
        )?)
    };
    if state("space_id")? != p.space_id.as_str()
        || state("device_id")? != p.resolver_device.as_str()
        || state("worktree")? != intent.worktree
    {
        return Err(invalid(
            "conflict admission requires exact local resolver/root",
        ));
    }
    let view = crate::JournalReadView { connection };
    if view.current(&p.space_id)?.as_ref() != Some(&intent.baseline) {
        return Err(invalid("conflict admission current baseline changed"));
    }
    // The complete local table, including pending rows, must equal the bundle.
    let count: i64 =
        connection.query_row("SELECT count(*) FROM main.operations", [], |r| r.get(0))?;
    if count != p.originals.len() as i64 {
        return Err(invalid(
            "conflict admission incomplete received original log",
        ));
    }
    for signed in &p.originals {
        let op = &signed.operation;
        let (space, device, seq, json, state): (String, String, i64, String, String) = connection
            .query_row(
            "SELECT space_id,origin_device_id,origin_seq,payload,state
                 FROM main.operations WHERE op_id=?1",
            [op.op_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        if space != p.space_id.as_str()
            || device != op.payload.origin_device_id.as_str()
            || seq != op.payload.origin_seq as i64
            || json != serde_json::to_string(op)?
            || header.original_states.get(op.op_id.as_str()) != Some(&state)
        {
            return Err(invalid(
                "conflict admission exact received original differs",
            ));
        }
    }
    let mut cursors = VersionVector::default();
    let mut stmt =
        connection.prepare("SELECT space_id,device_id,contiguous_seq FROM main.receive_cursors")?;
    let mut rows = stmt.query([])?;
    let mut seen = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let space: String = row.get(0)?;
        let device: sync_extend_core_model::DeviceId = row.get::<_, String>(1)?.parse()?;
        let seq: i64 = row.get(2)?;
        if space != p.space_id.as_str() || seq <= 0 || !seen.insert(device.clone()) {
            return Err(invalid("conflict admission cursor scope differs"));
        }
        cursors.observe(device, seq as u64);
    }
    if cursors != plan.received_vector {
        return Err(invalid("conflict admission complete cursor differs"));
    }
    let first = p
        .resolving
        .first()
        .ok_or(invalid("conflict admission empty prefix"))?;
    if cursors.get(&p.resolver_device).checked_add(1) != Some(first.operation.payload.origin_seq) {
        return Err(invalid("conflict admission own sequence already consumed"));
    }
    let pruned: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.snapshot_prunings WHERE snapshot_id=?1 OR snapshot_id=?2)",
        params![intent.baseline.root()?.as_str(), header.target.root()?.as_str()], |r| r.get(0),
    )?;
    if pruned {
        return Err(invalid("conflict admission baseline/target pruned"));
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    fn objects(db: &Connection) -> Result<Vec<(String, String, Option<String>)>> {
        Ok(db.prepare("SELECT type,name,sql FROM main.sqlite_schema WHERE name LIKE 'conflict_resolution_%' OR tbl_name LIKE 'conflict_resolution_%' ORDER BY type,name")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?)
    }
    let expected = Connection::open_in_memory()?;
    for table in [
        "operations",
        "receive_cursors",
        "current_manifests",
        "snapshots",
        "snapshot_objects",
        "rename_observations",
        "local_state",
        "publications",
        "mutations",
        "cleanup_plans",
        "snapshot_prunings",
        "tree_restore_preparations",
        "tree_restore_histories",
        "tree_restore_cancellations",
        "remote_rename_headers",
        "remote_delete_headers",
        "remote_replace_headers",
        "native_publication_headers",
        "gc_marks",
        "gc_executions",
    ] {
        expected.execute_batch(&format!(
            "CREATE TABLE {table}(snapshot_id TEXT PRIMARY KEY);"
        ))?;
    }
    expected.execute_batch(include_str!("migration-042.sql"))?;
    expected.execute_batch(include_str!("migration-043.sql"))?;
    expected.execute_batch(include_str!("migration-044.sql"))?;
    if objects(connection)? != objects(&expected)? {
        return Err(invalid(
            "conflict resolution exact schema/trigger/index differs",
        ));
    }
    Ok(())
}

pub(crate) fn all_tables() -> Vec<crate::storage_inventory::reader::TableSpec> {
    [schema::TABLES, native_future_schema::TABLES].concat()
}

pub(crate) fn metadata_budget(connection: &Connection) -> Result<(u64, u64)> {
    let tables = preflight(
        connection,
        &all_tables(),
        sync_extend_core_model::limits::MAX_ENTRIES,
        sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let (reserved_rows,reserved_bytes):(i64,i64)=connection.query_row(
        "SELECT coalesce(sum(reserved_rows),0),coalesce(sum(reserved_bytes),0) FROM main.conflict_resolution_native_headers",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    let reserved_rows = u64::try_from(reserved_rows)
        .map_err(|_| invalid("conflict future negative reserved rows"))?;
    let reserved_bytes = u64::try_from(reserved_bytes)
        .map_err(|_| invalid("conflict future negative reserved bytes"))?;
    let rows = tables.iter().try_fold(reserved_rows, |total, t| {
        total
            .checked_add(t.rows)
            .ok_or(invalid("conflict future legacy row budget overflow"))
    })?;
    let bytes = tables.iter().try_fold(reserved_bytes, |total, t| {
        total
            .checked_add(t.logical_bytes)
            .ok_or(invalid("conflict future legacy byte budget overflow"))
    })?;
    Ok((rows, bytes))
}

fn expected_values(header: &Header) -> Result<Vec<(&'static str, Vec<Value>)>> {
    let p = &header.intent.proof.payload;
    let id = header.transaction_id.as_str();
    let text = |s: &str| Value::Text(s.to_string());
    let mut rows = vec![(
        "admissions",
        vec![
            text(id),
            text(p.space_id.as_str()),
            text(p.resolver_device.as_str()),
            text(p.plan_fingerprint.as_str()),
            text(header.intent.baseline.root()?.as_str()),
            text(header.intent.root_identity.as_str()),
            text(hash(header)?.as_str()),
            text(&serde_json::to_string(header)?),
        ],
    )];
    let receipt = header.receipt()?;
    rows.push((
        "sequences",
        vec![
            text(id),
            text(p.resolver_device.as_str()),
            Value::Integer(receipt.reserved_first_sequence as i64),
            Value::Integer(receipt.reserved_last_sequence as i64),
        ],
    ));
    for (role, signed) in p
        .originals
        .iter()
        .map(|s| ("original", s))
        .chain(p.resolving.iter().map(|s| ("resolving", s)))
    {
        rows.push((
            "signatures",
            vec![
                text(id),
                text(role),
                text(signed.operation.op_id.as_str()),
                text(&serde_json::to_string(signed)?),
            ],
        ));
    }
    for ((role, content), length) in pins(header)? {
        rows.push((
            "objects",
            vec![
                text(id),
                text(&role),
                text(content.as_str()),
                Value::Integer(length as i64),
            ],
        ));
    }
    Ok(rows)
}

type RowKey = (String, Vec<String>);
type RowValue = Vec<crate::JournalStorageColumn>;
type RowMap = BTreeMap<RowKey, RowValue>;

fn value_columns(suffix: &str, values: &[Value]) -> Result<(RowKey, RowValue)> {
    use crate::{JournalStorageColumn, JournalStorageColumnValue};
    let name = format!("conflict_resolution_{suffix}");
    let specs = all_tables();
    let spec = specs
        .iter()
        .find(|s| s.name == name)
        .ok_or(invalid("conflict row table"))?;
    if spec.columns.len() != values.len() {
        return Err(invalid("conflict row column count"));
    }
    let mut columns = Vec::new();
    let mut primary = BTreeMap::new();
    for (column, value) in spec.columns.iter().zip(values) {
        let value = match value {
            Value::Text(s) => JournalStorageColumnValue::Text(s.clone()),
            Value::Integer(n) if *n >= 0 => JournalStorageColumnValue::Integer(*n as u64),
            _ => return Err(invalid("conflict row value")),
        };
        if column.primary_key != 0 {
            let key = match &value {
                JournalStorageColumnValue::Text(s) => s.clone(),
                JournalStorageColumnValue::Integer(n) => n.to_string(),
                _ => return Err(invalid("conflict row primary key")),
            };
            primary.insert(column.primary_key, key);
        }
        columns.push(JournalStorageColumn {
            name: column.name.into(),
            value,
        });
    }
    Ok(((name, primary.into_values().collect()), columns))
}

fn row_map(rows: &[JournalStoredRow]) -> RowMap {
    rows.iter()
        .map(|r| {
            (
                (r.table().to_string(), r.primary_key().to_vec()),
                r.columns().to_vec(),
            )
        })
        .collect()
}

pub(crate) fn obligations(
    rows: &[JournalStoredRow],
    connection: &Connection,
) -> Result<Vec<JournalCapacityObligation>> {
    validate_schema(connection)?;
    let own: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.table().starts_with("conflict_resolution_")
                && !r.table().starts_with("conflict_resolution_native_")
        })
        .collect();
    let headers: Vec<_> = own
        .iter()
        .filter(|r| r.table() == "conflict_resolution_admissions")
        .collect();
    if headers.len() > 1 {
        return Err(invalid("multiple prospective conflict resolution owners"));
    }
    let mut expected = RowMap::new();
    for row in headers {
        let json = row
            .columns()
            .iter()
            .find(|c| c.name == "header")
            .ok_or(invalid("conflict header column"))?;
        let crate::JournalStorageColumnValue::Text(json) = &json.value else {
            return Err(invalid("conflict header value"));
        };
        let header: Header = serde_json::from_str(json)?;
        let plan = header.plan()?;
        bind(connection, &header, &plan)?;
        for (suffix, values) in expected_values(&header)? {
            let (key, columns) = value_columns(suffix, &values)?;
            if expected.insert(key, columns).is_some() {
                return Err(invalid("duplicate conflict admission row"));
            }
        }
    }
    let actual: RowMap = own
        .into_iter()
        .map(|r| {
            (
                (r.table().to_string(), r.primary_key().to_vec()),
                r.columns().to_vec(),
            )
        })
        .collect();
    if actual != expected {
        return Err(invalid(
            "conflict admission exact signature/sequence/pins rows differ",
        ));
    }
    native_binding::audit(connection)?;
    // Schema42 admission has no future writer/Final authority or liability
    // reservation. Native capacity must be reserved separately before C4 effects.
    native_ledger_storage::audit(rows, connection)
}

impl Journal {
    pub fn require_no_conflict_resolution(&self) -> Result<()> {
        if self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.conflict_resolution_admissions)",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(invalid("prospective conflict resolution owns writer gate"));
        }
        Ok(())
    }

    pub fn conflict_resolution_admissions(
        &self,
        space: &SpaceId,
    ) -> Result<Vec<ConflictResolutionAdmission>> {
        let inventory = self.storage_inventory(
            space,
            sync_extend_core_model::limits::MAX_ENTRIES,
            crate::TreeRestoreInventoryLimits {
                max_rows: sync_extend_core_model::limits::MAX_ENTRIES,
                max_logical_bytes: sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024,
            },
        )?;
        inventory
            .rows()
            .iter()
            .filter(|r| r.table() == "conflict_resolution_admissions")
            .map(|r| {
                let column = r.columns().iter().find(|c| c.name == "header").unwrap();
                let crate::JournalStorageColumnValue::Text(json) = &column.value else {
                    return Err(invalid("conflict header expected text"));
                };
                serde_json::from_str::<Header>(json)?.receipt()
            })
            .collect()
    }

    /// CAS exclusion precedes IMMEDIATE SQL. The exact same receipt is read-only;
    /// no original receive/applied cursor or worktree mutation occurs.
    pub fn with_conflict_resolution_admission<T, E>(
        &self,
        intent: &ConflictResolutionAdmissionIntent,
        inspect: impl FnOnce(&ConflictResolutionAdmission) -> std::result::Result<T, E>,
    ) -> std::result::Result<(CasAccessGuard, T, ConflictResolutionAdmission), E>
    where
        E: From<crate::JournalError>,
    {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict admission refuses caller transaction").into());
        }
        let p = &intent.proof.payload;
        let plan = intent
            .proof
            .verify(&intent.approved_keys, ResolutionLimits::default())?;
        let original_states = p
            .originals
            .iter()
            .map(|s| {
                let op = &s.operation;
                (
                    op.op_id.to_string(),
                    if intent
                        .baseline
                        .version_vector
                        .get(&op.payload.origin_device_id)
                        >= op.payload.origin_seq
                    {
                        "materialized"
                    } else {
                        "received"
                    }
                    .to_string(),
                )
            })
            .collect();
        let mut target = plan.projected.clone();
        for signed in &p.resolving {
            let op = &signed.operation;
            target
                .version_vector
                .observe(op.payload.origin_device_id.clone(), op.payload.origin_seq);
        }
        let header = Header {
            format_version: 1,
            transaction_id: transaction_id(&intent.proof)?,
            intent: intent.clone(),
            original_states,
            target,
        };
        header.plan()?;
        if serde_json::to_vec(&header)
            .map_err(crate::JournalError::from)?
            .len()
            > crate::MAX_OPERATION_BYTES
        {
            return Err(invalid("conflict admission header byte budget").into());
        }
        let guard = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(crate::JournalError::from)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&p.space_id, bounds)?;
        bind(&self.connection, &header, &plan)?;
        let candidate = expected_values(&header)?;
        let prior_rows = row_map(&before.rows);
        let mut expected = prior_rows.clone();
        let exists = expected.contains_key(&(
            "conflict_resolution_admissions".into(),
            vec![header.transaction_id.to_string()],
        ));
        if exists {
            for (suffix, values) in &candidate {
                let (key, columns) = value_columns(suffix, values)?;
                if expected.get(&key) != Some(&columns) {
                    return Err(invalid("conflict duplicate admission differs").into());
                }
            }
        } else {
            self.require_no_conflict_resolution()?;
            self.require_no_tree_restore(&p.space_id, sync_extend_core_model::limits::MAX_ENTRIES)?;
            storage_policy::receive::completion_gate(&before)?;
            self.require_no_remote_replace(&p.space_id)?;
            self.require_no_remote_delete(&p.space_id)?;
            self.require_no_remote_rename(&p.space_id)?;
            let busy: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.publications WHERE state!='committed' OR cleaned=0)
                 OR EXISTS(SELECT 1 FROM main.cleanup_plans WHERE state='executing')",
                [], |r| r.get(0),
            ).map_err(crate::JournalError::from)?;
            if busy {
                return Err(invalid("conflict admission requires completed native cleanup").into());
            }
            for (_, content) in pins(&header)?.keys() {
                self.require_cas_access(content)?;
            }
            for (suffix, values) in &candidate {
                let (key, columns) = value_columns(suffix, values)?;
                if expected.insert(key, columns).is_some() {
                    return Err(invalid("conflict prospective row collision").into());
                }
            }
            let ids: BTreeSet<_> = pins(&header)?
                .keys()
                .map(|(_, id)| id.to_string())
                .collect();
            for row in before.rows.iter().filter(|r| r.table() == "gc_marks") {
                let content = row
                    .columns()
                    .iter()
                    .find(|c| c.name == "content_id")
                    .unwrap();
                let crate::JournalStorageColumnValue::Text(id) = &content.value else {
                    continue;
                };
                if ids.contains(id)
                    && !expected
                        .contains_key(&("gc_cancellations".into(), row.primary_key().to_vec()))
                {
                    expected
                        .entry(("gc_invalidations".into(), row.primary_key().to_vec()))
                        .or_insert_with(|| {
                            vec![crate::JournalStorageColumn {
                                name: "mark_id".into(),
                                value: crate::JournalStorageColumnValue::Text(
                                    row.primary_key()[0].clone(),
                                ),
                            }]
                        });
                }
            }
            let added_rows = expected.len() as u64 - before.rows.len() as u64;
            let added_bytes: u64 = expected
                .iter()
                .filter(|(key, _)| !prior_rows.contains_key(*key))
                .flat_map(|(_, c)| c)
                .map(|c| match &c.value {
                    crate::JournalStorageColumnValue::Text(s) => s.len() as u64,
                    crate::JournalStorageColumnValue::Integer(_) => 8,
                    crate::JournalStorageColumnValue::Null => 0,
                })
                .sum();
            let prior = before.report.accounted_total();
            if prior
                .rows
                .checked_add(added_rows)
                .is_none_or(|n| n > bounds.max_rows)
                || prior
                    .logical_bytes
                    .checked_add(added_bytes)
                    .is_none_or(|n| n > bounds.max_logical_bytes)
            {
                return Err(invalid("conflict pre-effect full admission capacity exceeded").into());
            }
            for (suffix, values) in candidate {
                let mut issued = vec![Value::Text(suffix.into())];
                issued.extend(values.clone());
                let _permit = self.conflict_resolution_issuance.permit(Some(issued))?;
                let placeholders = (1..=values.len())
                    .map(|n| format!("?{n}"))
                    .collect::<Vec<_>>()
                    .join(",");
                tx.execute(
                    &format!(
                        "INSERT INTO main.conflict_resolution_{suffix} VALUES({placeholders})"
                    ),
                    rusqlite::params_from_iter(values),
                )
                .map_err(crate::JournalError::from)?;
            }
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&p.space_id, bounds)?;
        if row_map(&after.rows) != expected {
            return Err(invalid("conflict admission changed unrelated actual rows").into());
        }
        let receipt = header.receipt()?;
        let held = inspect(&receipt)?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&p.space_id, bounds)?;
        if row_map(&after.rows) != expected {
            return Err(invalid("conflict admission callback changed journal").into());
        }
        tx.commit().map_err(crate::JournalError::from)?;
        Ok((guard, held, receipt))
    }
}
