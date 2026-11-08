//! Original signed Replace receipts; never local reauthoring or legacy owner adoption.
use crate::{
    storage_inventory::reader::{hash, invalid},
    Journal, JournalCapacityObligation, JournalStoredRow, RemotePublicationProof, Result,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, *};

#[cfg(windows)]
mod cleanup;
#[cfg(windows)]
mod directories;
pub(crate) mod issuance;
#[cfg(windows)]
mod payload;
#[cfg(windows)]
mod view;
#[cfg(windows)]
pub use view::RemoteReplaceFileView;
pub(crate) mod schema;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use payload::{RemoteReplaceCreation, RemoteReplaceReadiness};
#[cfg(windows)]
pub use windows::{RemoteReplaceObservation, RemoteReplaceSource};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteReplaceStage {
    Selected,
    Creating,
    Created,
    Ready,
    Quarantined,
    Publishing,
    Executing,
    Observed,
    Final,
    Cleanup,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RemoteReplaceReceipt {
    pub transaction_id: EntryId,
    pub operation_id: OperationId,
    pub source_path: PortablePath,
    pub native_cleanup_complete: bool,
    pub stage: RemoteReplaceStage,
    pub snapshot_id: Option<SnapshotId>,
    pub local_committed: bool,
    pub remote_backup_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    volume: String,
    id: String,
}
impl Key {
    fn validate(&self) -> Result<()> {
        if ![(&self.volume, 16), (&self.id, 32)]
            .into_iter()
            .all(|(s, n)| {
                s.len() == n
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        {
            return Err(invalid("remote Replace full native key"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ancestor {
    path: String,
    key: Key,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: u32,
    transaction_id: EntryId,
    generation: EntryId,
    proof: RemotePublicationProof,
    baseline: Manifest,
    target: Manifest,
    target_root: SnapshotId,
    source: Entry,
    root: Ancestor,
    source_chain: Vec<Ancestor>,
    existing_base: Option<Key>,
    history_reserved: TreeStorageCharge,
    source_key: Key,
    reserved: TreeStorageCharge,
}
pub fn remote_replace_transaction(operation: &OperationId) -> Result<EntryId> {
    Ok(
        ContentId::hash(format!("original-remote-replace-v1:{operation}").as_bytes()).as_str()
            [..32]
            .parse()?,
    )
}
fn target(baseline: &Manifest, proof: &RemotePublicationProof) -> Result<(Manifest, Entry)> {
    proof.verify()?;
    baseline.validate()?;
    let operation = &proof.operation;
    let payload = &operation.payload;
    let Change::Put { entry: incoming } = &payload.change else {
        return Err(invalid("remote Replace requires original file Put"));
    };
    let source = baseline
        .entries
        .get(&incoming.entry_id)
        .ok_or(invalid("remote Replace original live identity missing"))?;
    if baseline.space_id != payload.space_id
        || source.kind != EntryKind::File
        || incoming.kind != EntryKind::File
        || source.path != incoming.path
        || source.content == incoming.content
        || baseline.tombstones.contains_key(&incoming.entry_id)
        || !baseline.version_vector.dominates(&payload.causal)
        || baseline
            .version_vector
            .get(&payload.origin_device_id)
            .checked_add(1)
            != Some(payload.origin_seq)
    {
        return Err(invalid(
            "remote Replace baseline, same-path scope or causal",
        ));
    }
    let mut manifest = baseline.clone();
    manifest
        .entries
        .insert(incoming.entry_id.clone(), incoming.clone());
    manifest
        .version_vector
        .observe(payload.origin_device_id.clone(), payload.origin_seq);
    manifest.validate()?;
    Ok((manifest, source.clone()))
}
fn contents(manifest: &Manifest) -> BTreeSet<ContentId> {
    manifest
        .entries
        .values()
        .filter_map(|e| e.content.as_ref())
        .flat_map(|f| f.chunks.iter().map(|c| c.content_id.clone()))
        .collect()
}
fn history_reserve(header: &Header) -> Result<TreeStorageCharge> {
    Ok(TreeStorageCharge {
        rows: 2 + contents(&header.target).len() as u64,
        logical_bytes: serde_json::to_vec(&header.target)?.len() as u64
            + 256
            + contents(&header.target).len() as u64 * 128,
    })
}
fn component(header: &Header, step: u64) -> String {
    if step == 0 {
        ".sync-tmp".into()
    } else if step == 1 {
        format!("remote-replace-{}", header.generation)
    } else {
        "payload-0".into()
    }
}
fn creator_charge(header: &Header, step: u64) -> TreeStorageCharge {
    let bytes = 32
        + 32
        + 8
        + 64
        + component(header, step).len() as u64
        + creator_kind(step).len() as u64
        + 16
        + 32;
    TreeStorageCharge {
        rows: 2,
        logical_bytes: bytes * 2 + 48,
    }
}
fn creator_kind(step: u64) -> &'static str {
    if step == 2 {
        "file"
    } else {
        "directory"
    }
}
fn pins(header: &Header) -> Vec<(&'static str, ContentId)> {
    contents(&header.baseline)
        .into_iter()
        .map(|id| ("original", id))
        .chain(
            contents(&header.target)
                .into_iter()
                .map(|id| ("incoming", id)),
        )
        .collect()
}
fn disposition_charge(stage: &str) -> u64 {
    32 + 32 + 8 + 64 + stage.len() as u64 + 16 + 32
}
fn reserve(header: &Header) -> Result<TreeStorageCharge> {
    let mut charge = history_reserve(header)?;
    for phase in [
        "ready",
        "executing",
        "quarantined",
        "publishing",
        "observed",
        "final",
        "cleanup",
    ] {
        charge.rows += 1;
        charge.logical_bytes += 32 + 32 + 64 + phase.len() as u64 + 16 + 32 + 64;
    }
    for step in 0..=3 {
        if step == 0 && header.existing_base.is_some() {
            continue;
        }
        if step < 3 {
            let creator = creator_charge(header, step);
            charge.rows += creator.rows;
            charge.logical_bytes += creator.logical_bytes;
        }
        if step != 2 {
            for stage in ["intended", "absent", "terminal"] {
                charge.rows += 1;
                charge.logical_bytes += disposition_charge(stage);
            }
        }
    }
    Ok(charge)
}
impl Header {
    fn validate(&self) -> Result<()> {
        let (manifest, source) = target(&self.baseline, &self.proof)?;
        self.source_key.validate()?;
        self.root.key.validate()?;
        if self.format != 1
            || self.transaction_id != remote_replace_transaction(&self.proof.operation.op_id)?
            || manifest != self.target
            || self.target_root != self.target.root()?
            || source != self.source
            || self.reserved != reserve(self)?
            || self.history_reserved != history_reserve(self)?
            || !std::path::Path::new(&self.root.path).is_absolute()
        {
            return Err(invalid("remote Replace exact original header"));
        }
        if let Some(base) = &self.existing_base {
            base.validate()?;
            if base.volume != self.source_key.volume
                || base == &self.source_key
                || self
                    .source_chain
                    .iter()
                    .any(|ancestor| &ancestor.key == base)
            {
                return Err(invalid(
                    "remote Replace existing base native alias or volume",
                ));
            }
        }
        for (chain, path) in [(&self.source_chain, &self.source.path)] {
            let parent = path
                .parent()
                .map_or(std::path::PathBuf::from(&self.root.path), |p| {
                    std::path::Path::new(&self.root.path).join(p.as_str())
                });
            let paths: Vec<_> = parent.ancestors().collect();
            if chain.is_empty()
                || chain.len() > 256
                || paths.len() != chain.len()
                || !chain.iter().any(|a| a == &self.root)
            {
                return Err(invalid("remote Replace ancestor scope"));
            }
            for (a, p) in chain.iter().zip(paths) {
                a.key.validate()?;
                if p.to_str() != Some(&a.path) || a.key.volume != self.source_key.volume {
                    return Err(invalid("remote Replace parent fullkey or volume"));
                }
            }
        }
        Ok(())
    }
}
fn field<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|c| c.name == name)
        .map(|c| &c.value)
    {
        Some(crate::JournalStorageColumnValue::Text(s)) => Ok(s),
        _ => Err(invalid("remote Replace expected text column")),
    }
}
fn number(row: &JournalStoredRow, name: &str) -> Result<u64> {
    match row
        .columns()
        .iter()
        .find(|c| c.name == name)
        .map(|c| &c.value)
    {
        Some(crate::JournalStorageColumnValue::Integer(n)) => Ok(*n),
        _ => Err(invalid("remote Replace expected integer column")),
    }
}
pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    fn objects(db: &Connection) -> Result<Vec<(String, String, Option<String>)>> {
        Ok(db.prepare("SELECT type,name,sql FROM main.sqlite_schema WHERE (name LIKE 'remote_replace_%' OR tbl_name LIKE 'remote_replace_%') AND name NOT LIKE 'conflict_resolution_%' ORDER BY type,name")?
            .query_map([],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?
            .collect::<std::result::Result<_,_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    for table in [
        "operations",
        "current_manifests",
        "snapshots",
        "snapshot_objects",
        "rename_observations",
        "publications",
        "mutations",
        "local_state",
        "tree_restore_preparations",
        "snapshot_prunings",
        "receive_cursors",
        "remote_rename_headers",
        "remote_delete_headers",
        "gc_marks",
        "gc_executions",
    ] {
        expected.execute_batch(&format!(
            "CREATE TABLE {table}(snapshot_id TEXT PRIMARY KEY);"
        ))?;
    }
    expected.execute_batch(include_str!("migration-041.sql"))?;
    if objects(connection)? != objects(&expected)? {
        return Err(invalid("remote Replace schema/trigger/index differs"));
    }
    Ok(())
}
pub(crate) fn metadata_budget(connection: &Connection) -> Result<(u64, u64)> {
    let tables = crate::storage_inventory::reader::preflight(
        connection,
        schema::TABLES,
        limits::MAX_ENTRIES,
        limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let rows = tables.iter().map(|table| table.rows).sum::<u64>();
    let bytes = tables.iter().map(|table| table.logical_bytes).sum::<u64>();
    let (reserved_rows,reserved_bytes):(i64,i64)=connection.query_row(
        "SELECT coalesce(sum(reserved_rows),0),coalesce(sum(reserved_bytes),0) FROM main.remote_replace_headers h
         WHERE NOT EXISTS(SELECT 1 FROM main.remote_replace_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='cleanup')",
        [],|r|Ok((r.get(0)?,r.get(1)?)))?;
    Ok((
        rows.checked_add(
            u64::try_from(reserved_rows).map_err(|_| invalid("remote Replace reserved rows"))?,
        )
        .ok_or(invalid("remote Replace row budget overflow"))?,
        bytes
            .checked_add(
                u64::try_from(reserved_bytes)
                    .map_err(|_| invalid("remote Replace reserved bytes"))?,
            )
            .ok_or(invalid("remote Replace byte budget overflow"))?,
    ))
}
pub(crate) fn obligations(
    rows: &[JournalStoredRow],
    connection: &Connection,
) -> Result<Vec<JournalCapacityObligation>> {
    validate_schema(connection)?;
    let mut owners = BTreeSet::new();
    let mut obligations = Vec::new();
    let mut active = 0;
    for row in rows
        .iter()
        .filter(|r| r.table() == "remote_replace_headers")
    {
        let json = field(row, "header")?;
        let header: Header = serde_json::from_str(json)?;
        header.validate()?;
        let id = header.transaction_id.as_str();
        if json != serde_json::to_string(&header)?
            || field(row, "transaction_id")? != id
            || field(row, "space_id")? != header.baseline.space_id.as_str()
            || field(row, "generation")? != header.generation.as_str()
            || field(row, "header_hash")? != hash(&header)?.as_str()
            || field(row, "baseline_root")? != header.baseline.root()?.as_str()
            || number(row, "reserved_rows")? != header.reserved.rows
            || number(row, "reserved_bytes")? != header.reserved.logical_bytes
        {
            return Err(invalid("remote Replace physical header differs"));
        }
        owners.insert(id.to_string());
        let stored_root: Option<String> = connection
            .query_row(
                "SELECT value FROM main.local_state WHERE key='worktree'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if stored_root.as_deref() != Some(&header.root.path) {
            return Err(invalid("remote Replace initialized root differs"));
        }
        let mut used = TreeStorageCharge::default();
        let mut activated = BTreeSet::new();
        let mut created = std::collections::BTreeMap::new();
        for effect in rows.iter().filter(|r| {
            matches!(
                r.table(),
                "remote_replace_activations" | "remote_replace_creators"
            ) && r.primary_key().first().map(String::as_str) == Some(id)
        }) {
            if number(effect, "step")? > 2 {
                return Err(invalid("remote Replace unsupported original creator step"));
            }
        }
        for selected_step in 0..=2 {
            for suffix in ["activations", "creators"] {
                for effect in rows.iter().filter(|r| {
                    r.table() == format!("remote_replace_{suffix}")
                        && r.primary_key().first().map(String::as_str) == Some(id)
                        && number(r, "step").is_ok_and(|s| s == selected_step)
                }) {
                    let step = number(effect, "step")?;
                    if step > 2
                        || (step == 0 && header.existing_base.is_some())
                        || field(effect, "generation")? != header.generation.as_str()
                        || field(effect, "header_hash")? != hash(&header)?.as_str()
                        || field(effect, "component")? != component(&header, step)
                        || field(effect, "kind")? != creator_kind(step)
                    {
                        return Err(invalid("remote Replace exact original creator scope"));
                    }
                    let parent = if step == 0 {
                        &header.source_chain[0].key
                    } else if step == 2 {
                        created
                            .get(&1)
                            .ok_or(invalid("remote Replace payload original owner missing"))?
                    } else {
                        header
                            .existing_base
                            .as_ref()
                            .or_else(|| created.get(&0))
                            .ok_or(invalid("remote Replace original base receipt missing"))?
                    };
                    if field(effect, "parent_volume")? != parent.volume
                        || field(effect, "parent_id")? != parent.id
                    {
                        return Err(invalid("remote Replace creator parent differs"));
                    }
                    if suffix == "activations" {
                        activated.insert(step);
                    } else {
                        if !activated.contains(&step) {
                            return Err(invalid("remote Replace receipt without activation"));
                        }
                        let key = Key {
                            volume: field(effect, "volume")?.into(),
                            id: field(effect, "full_id")?.into(),
                        };
                        key.validate()?;
                        if key.volume != header.source_key.volume
                            || key == header.source_key
                            || key == *parent
                            || header.source_chain.iter().any(|a| a.key == key)
                            || header.existing_base.as_ref() == Some(&key)
                            || created.values().any(|k| k == &key)
                        {
                            return Err(invalid("remote Replace original creator alias"));
                        }
                        created.insert(step, key);
                    }
                    used.rows += 1;
                    used.logical_bytes += effect.logical_bytes();
                }
            }
        }
        let mut phases = BTreeSet::new();
        for phase in rows.iter().filter(|r| {
            r.table() == "remote_replace_phases"
                && r.primary_key().first().map(String::as_str) == Some(id)
        }) {
            let name = field(phase, "phase")?;
            if !matches!(
                name,
                "ready"
                    | "executing"
                    | "quarantined"
                    | "publishing"
                    | "observed"
                    | "final"
                    | "cleanup"
            ) || field(phase, "generation")? != header.generation.as_str()
                || field(phase, "header_hash")? != hash(&header)?.as_str()
                || field(phase, "volume")? != header.source_key.volume
                || field(phase, "full_id")? != header.source_key.id
                || field(phase, "snapshot_id")? != header.target.root()?.as_str()
            {
                return Err(invalid("remote Replace exact phase differs"));
            }
            phases.insert(name);
            used.rows += 1;
            used.logical_bytes += phase.logical_bytes();
        }
        for pair in [
            ["ready", "executing"],
            ["executing", "quarantined"],
            ["quarantined", "publishing"],
            ["publishing", "observed"],
            ["observed", "final"],
            ["final", "cleanup"],
        ] {
            if phases.contains(pair[1]) && !phases.contains(pair[0]) {
                return Err(invalid("remote Replace skipped original phase"));
            }
        }
        if phases.contains("ready") && !created.contains_key(&2) {
            return Err(invalid("remote Replace Ready lacks original payload"));
        }
        let final_history = phases.contains("final");
        let cleaned = phases.contains("cleanup");
        let mut dispositions = std::collections::BTreeMap::<u64, BTreeSet<&str>>::new();
        for effect in rows.iter().filter(|r| {
            r.table() == "remote_replace_dispositions"
                && r.primary_key().first().map(String::as_str) == Some(id)
        }) {
            let step = number(effect, "step")?;
            if !matches!(step, 0 | 1 | 3) {
                return Err(invalid("remote Replace cannot dispose published payload"));
            }
            let key = if step == 3 {
                &header.source_key
            } else {
                created
                    .get(&step)
                    .ok_or(invalid("remote Replace disposition lacks original creator"))?
            };
            let stage = field(effect, "stage")?;
            if !final_history
                || !matches!(stage, "intended" | "absent" | "terminal")
                || field(effect, "generation")? != header.generation.as_str()
                || field(effect, "header_hash")? != hash(&header)?.as_str()
                || field(effect, "volume")? != key.volume
                || field(effect, "full_id")? != key.id
            {
                return Err(invalid("remote Replace original disposition differs"));
            }
            dispositions.entry(step).or_default().insert(stage);
            used.rows += 1;
            used.logical_bytes += effect.logical_bytes();
        }
        for (&step, stages) in &dispositions {
            if (stages.contains("absent") && !stages.contains("intended"))
                || (stages.contains("terminal") && !stages.contains("absent"))
                || (step < 2
                    && !dispositions
                        .get(&(if step == 1 { 3 } else { 1 }))
                        .is_some_and(|s| s.contains("terminal")))
            {
                return Err(invalid("remote Replace disposition prefix differs"));
            }
        }
        if cleaned
            && [0, 1, 3].into_iter().any(|step| {
                !(step == 0 && header.existing_base.is_some()
                    || dispositions
                        .get(&step)
                        .is_some_and(|s| s.contains("terminal")))
            })
        {
            return Err(invalid(
                "remote Replace cleanup original closure incomplete",
            ));
        }
        if final_history {
            used.rows += header.history_reserved.rows;
            used.logical_bytes += header.history_reserved.logical_bytes;
        }

        let operation = rows
            .iter()
            .find(|r| {
                r.table() == "operations"
                    && r.primary_key() == [header.proof.operation.op_id.as_str()]
            })
            .ok_or(invalid(
                "remote Replace original received operation missing",
            ))?;
        if field(operation, "payload")? != serde_json::to_string(&header.proof.operation)?
            || field(operation, "state")?
                != if final_history {
                    "materialized"
                } else {
                    "received"
                }
            || field(operation, "space_id")? != header.baseline.space_id.as_str()
            || field(operation, "origin_device_id")?
                != header.proof.operation.payload.origin_device_id.as_str()
            || number(operation, "origin_seq")? != header.proof.operation.payload.origin_seq
        {
            return Err(invalid("remote Replace original operation differs"));
        }
        let actual_pins: BTreeSet<(String, ContentId)> = rows
            .iter()
            .filter(|r| {
                r.table() == "remote_replace_objects"
                    && r.primary_key().first().map(String::as_str) == Some(id)
            })
            .map(|r| {
                Ok((
                    field(r, "role")?.to_string(),
                    field(r, "content_id")?.parse()?,
                ))
            })
            .collect::<Result<_>>()?;
        let expected_pins = if cleaned {
            BTreeSet::new()
        } else {
            pins(&header)
                .into_iter()
                .map(|(role, id)| (role.to_string(), id))
                .collect()
        };
        if actual_pins != expected_pins {
            return Err(invalid(
                "remote Replace exact original/incoming own pins differ",
            ));
        }
        let baseline = rows
            .iter()
            .find(|r| {
                r.table() == "snapshots"
                    && r.primary_key() == [header.baseline.root().unwrap().as_str()]
            })
            .ok_or(invalid("remote Replace retained baseline missing"))?;
        if field(baseline, "manifest")? != serde_json::to_string(&header.baseline)?
            || rows.iter().any(|r| {
                r.table() == "snapshot_prunings"
                    && (r.primary_key() == [header.baseline.root().unwrap().as_str()]
                        || r.primary_key() == [header.target_root.as_str()])
            })
        {
            return Err(invalid(
                "remote Replace historical snapshot changed or pruned",
            ));
        }
        if final_history {
            let snapshot = rows
                .iter()
                .find(|r| {
                    r.table() == "snapshots"
                        && r.primary_key() == [header.target.root().unwrap().as_str()]
                })
                .ok_or(invalid("remote Replace final snapshot missing"))?;
            if field(snapshot, "manifest")? != serde_json::to_string(&header.target)?
                || field(snapshot, "state")? != "materialized"
            {
                return Err(invalid("remote Replace final snapshot differs"));
            }
        }
        if !cleaned {
            active += 1;
            let current = rows
                .iter()
                .find(|r| {
                    r.table() == "current_manifests"
                        && r.primary_key() == [header.baseline.space_id.as_str()]
                })
                .ok_or(invalid("remote Replace baseline pointer missing"))?;
            if !final_history && field(current, "snapshot_id")? != header.baseline.root()?.as_str()
            {
                return Err(invalid("remote Replace current baseline differs"));
            }
            obligations.push(JournalCapacityObligation {
                family: "original_remote_replace_remaining",
                owner_key: vec![id.into()],
                charge: TreeStorageCharge {
                    rows: header
                        .reserved
                        .rows
                        .checked_sub(used.rows)
                        .ok_or(invalid("remote Replace row liability"))?,
                    logical_bytes: header
                        .reserved
                        .logical_bytes
                        .checked_sub(used.logical_bytes)
                        .ok_or(invalid("remote Replace byte liability"))?,
                },
            });
        }
    }
    if active > 1 {
        return Err(invalid("multiple original remote Replace owners"));
    }
    for row in rows.iter().filter(|r| {
        matches!(
            r.table(),
            "remote_replace_phases"
                | "remote_replace_objects"
                | "remote_replace_activations"
                | "remote_replace_creators"
                | "remote_replace_dispositions"
        )
    }) {
        if !owners.contains(field(row, "transaction_id")?) {
            return Err(invalid("remote Replace orphan effect"));
        }
    }
    Ok(obligations)
}
impl Journal {
    pub fn remote_replace_receipts(&self, space: &SpaceId) -> Result<Vec<RemoteReplaceReceipt>> {
        let inventory = self.storage_inventory(
            space,
            limits::MAX_ENTRIES,
            crate::TreeRestoreInventoryLimits {
                max_rows: limits::MAX_ENTRIES,
                max_logical_bytes: limits::MAX_ENTRIES as u64 * 1024,
            },
        )?;
        let mut result = Vec::new();
        for row in inventory
            .rows()
            .iter()
            .filter(|r| r.table() == "remote_replace_headers")
        {
            let header: Header = serde_json::from_str(field(row, "header")?)?;
            if header.baseline.space_id != *space {
                return Err(invalid("remote Replace receipt space differs"));
            }
            let phases: BTreeSet<_> = inventory
                .rows()
                .iter()
                .filter(|r| {
                    r.table() == "remote_replace_phases"
                        && r.primary_key().first() == Some(&header.transaction_id.to_string())
                })
                .map(|r| field(r, "phase"))
                .collect::<Result<_>>()?;
            let stage = if phases.contains("cleanup") {
                RemoteReplaceStage::Cleanup
            } else if phases.contains("final") {
                RemoteReplaceStage::Final
            } else if phases.contains("observed") {
                RemoteReplaceStage::Observed
            } else if phases.contains("publishing") {
                RemoteReplaceStage::Publishing
            } else if phases.contains("quarantined") {
                RemoteReplaceStage::Quarantined
            } else if phases.contains("executing") {
                RemoteReplaceStage::Executing
            } else if phases.contains("ready") {
                RemoteReplaceStage::Ready
            } else if inventory.rows().iter().any(|r| {
                r.table() == "remote_replace_creators"
                    && r.primary_key() == [header.transaction_id.to_string(), "1".into()]
            }) {
                RemoteReplaceStage::Created
            } else if inventory.rows().iter().any(|r| {
                r.table() == "remote_replace_activations"
                    && r.primary_key().first() == Some(&header.transaction_id.to_string())
            }) {
                RemoteReplaceStage::Creating
            } else {
                RemoteReplaceStage::Selected
            };
            let committed = matches!(
                stage,
                RemoteReplaceStage::Final | RemoteReplaceStage::Cleanup
            );
            result.push(RemoteReplaceReceipt {
                transaction_id: header.transaction_id.clone(),
                operation_id: header.proof.operation.op_id.clone(),
                source_path: header.source.path.clone(),
                native_cleanup_complete: stage == RemoteReplaceStage::Cleanup,
                stage: stage.clone(),
                snapshot_id: if committed {
                    Some(header.target.root()?)
                } else {
                    None
                },
                local_committed: committed,
                remote_backup_complete: false,
            });
        }
        Ok(result)
    }
    pub fn require_no_remote_replace(&self, space: &SpaceId) -> Result<()> {
        if self
            .remote_replace_receipts(space)?
            .iter()
            .any(|r| !r.native_cleanup_complete)
        {
            return Err(invalid(
                "original remote Replace requires explicit forward recovery",
            ));
        }
        Ok(())
    }
}
