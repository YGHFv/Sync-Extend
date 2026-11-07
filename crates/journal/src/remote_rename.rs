//! Original signed Rename receipts; never local reauthoring or legacy owner adoption.
use crate::{
    storage_inventory::reader::{hash, invalid},
    Journal, JournalCapacityObligation, JournalStoredRow, RemotePublicationProof, Result,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, *};

pub(crate) mod issuance;
pub(crate) mod schema;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{RemoteRenameObservation, RemoteRenameSource};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRenameStage {
    Selected,
    Executing,
    Observed,
    Final,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RemoteRenameReceipt {
    pub transaction_id: EntryId,
    pub operation_id: OperationId,
    pub source_path: PortablePath,
    pub target_path: PortablePath,
    pub stage: RemoteRenameStage,
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
            return Err(invalid("remote Rename full native key"));
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
    target_chain: Vec<Ancestor>,
    source_key: Key,
    reserved: TreeStorageCharge,
}
pub fn remote_rename_transaction(operation: &OperationId) -> Result<EntryId> {
    Ok(
        ContentId::hash(format!("original-remote-rename-v1:{operation}").as_bytes()).as_str()[..32]
            .parse()?,
    )
}
fn target(baseline: &Manifest, proof: &RemotePublicationProof) -> Result<(Manifest, Entry)> {
    proof.verify()?;
    baseline.validate()?;
    let operation = &proof.operation;
    let payload = &operation.payload;
    let Change::Rename { entry_id, path } = &payload.change else {
        return Err(invalid("remote Rename requires original Rename"));
    };
    let source = baseline
        .entries
        .get(entry_id)
        .ok_or(invalid("remote Rename source missing"))?;
    if baseline.space_id != payload.space_id
        || source.kind != EntryKind::File
        || source.path.collision_key() == path.collision_key()
        || baseline
            .entries
            .values()
            .any(|e| e.path.collision_key() == path.collision_key())
        || !baseline.version_vector.dominates(&payload.causal)
        || baseline
            .version_vector
            .get(&payload.origin_device_id)
            .checked_add(1)
            != Some(payload.origin_seq)
    {
        return Err(invalid(
            "remote Rename baseline, causal or occupied destination",
        ));
    }
    let mut manifest = baseline.clone();
    manifest.entries.get_mut(entry_id).unwrap().path = path.clone();
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
fn reserve(header: &Header) -> Result<TreeStorageCharge> {
    // Exact fixed phase widths and an independently conservative final-history peak.
    let phases = ["executing", "observed", "final"]
        .iter()
        .map(|s| 32 + 32 + 64 + s.len() as u64 + 16 + 32 + 64)
        .sum::<u64>();
    let manifest = serde_json::to_vec(&header.target)?.len() as u64;
    Ok(TreeStorageCharge {
        rows: 5 + contents(&header.target).len() as u64,
        logical_bytes: phases
            .checked_add(manifest)
            .and_then(|n| n.checked_add(256))
            .and_then(|n| n.checked_add(contents(&header.target).len() as u64 * 128))
            .ok_or(invalid("remote Rename capacity overflow"))?,
    })
}
impl Header {
    fn validate(&self) -> Result<()> {
        let (manifest, source) = target(&self.baseline, &self.proof)?;
        self.source_key.validate()?;
        self.root.key.validate()?;
        if self.format != 1
            || self.transaction_id != remote_rename_transaction(&self.proof.operation.op_id)?
            || manifest != self.target
            || self.target_root != self.target.root()?
            || source != self.source
            || self.reserved != reserve(self)?
            || !std::path::Path::new(&self.root.path).is_absolute()
        {
            return Err(invalid("remote Rename exact original header"));
        }
        for (chain, path) in [
            (&self.source_chain, &self.source.path),
            (
                &self.target_chain,
                &self.target.entries[&self.source.entry_id].path,
            ),
        ] {
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
                return Err(invalid("remote Rename ancestor scope"));
            }
            for (a, p) in chain.iter().zip(paths) {
                a.key.validate()?;
                if p.to_str() != Some(&a.path) || a.key.volume != self.source_key.volume {
                    return Err(invalid("remote Rename parent fullkey or volume"));
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
        _ => Err(invalid("remote Rename expected text column")),
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
        _ => Err(invalid("remote Rename expected integer column")),
    }
}
pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    fn objects(db: &Connection) -> Result<Vec<(String, String, Option<String>)>> {
        Ok(db.prepare("SELECT type,name,sql FROM main.sqlite_schema WHERE name LIKE 'remote_rename_%' OR tbl_name LIKE 'remote_rename_%' ORDER BY type,name")?
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
    ] {
        expected.execute_batch(&format!(
            "CREATE TABLE {table}(snapshot_id TEXT PRIMARY KEY);"
        ))?;
    }
    expected.execute_batch(include_str!("migration-039.sql"))?;
    if objects(connection)? != objects(&expected)? {
        return Err(invalid("remote Rename schema/trigger/index differs"));
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
        "SELECT coalesce(sum(reserved_rows),0),coalesce(sum(reserved_bytes),0) FROM main.remote_rename_headers h
         WHERE NOT EXISTS(SELECT 1 FROM main.remote_rename_phases p WHERE p.transaction_id=h.transaction_id AND p.phase='final')",
        [],|r|Ok((r.get(0)?,r.get(1)?)))?;
    Ok((
        rows.checked_add(
            u64::try_from(reserved_rows).map_err(|_| invalid("remote Rename reserved rows"))?,
        )
        .ok_or(invalid("remote Rename row budget overflow"))?,
        bytes
            .checked_add(
                u64::try_from(reserved_bytes)
                    .map_err(|_| invalid("remote Rename reserved bytes"))?,
            )
            .ok_or(invalid("remote Rename byte budget overflow"))?,
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
    for row in rows.iter().filter(|r| r.table() == "remote_rename_headers") {
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
            return Err(invalid("remote Rename physical header differs"));
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
            return Err(invalid("remote Rename initialized root differs"));
        }
        let mut phases = BTreeSet::new();
        let mut used = TreeStorageCharge::default();
        for phase in rows.iter().filter(|r| {
            r.table() == "remote_rename_phases"
                && r.primary_key().first().map(String::as_str) == Some(id)
        }) {
            let name = field(phase, "phase")?;
            if !matches!(name, "executing" | "observed" | "final")
                || field(phase, "generation")? != header.generation.as_str()
                || field(phase, "header_hash")? != hash(&header)?.as_str()
                || field(phase, "volume")? != header.source_key.volume
                || field(phase, "full_id")? != header.source_key.id
                || field(phase, "snapshot_id")? != header.target.root()?.as_str()
            {
                return Err(invalid("remote Rename exact phase differs"));
            }
            phases.insert(name);
            used.rows += 1;
            used.logical_bytes += phase.logical_bytes();
        }
        if (phases.contains("observed") && !phases.contains("executing"))
            || (phases.contains("final") && !phases.contains("observed"))
        {
            return Err(invalid("remote Rename skipped phase"));
        }
        let final_history = phases.contains("final");
        let operation = rows
            .iter()
            .find(|r| {
                r.table() == "operations"
                    && r.primary_key() == [header.proof.operation.op_id.as_str()]
            })
            .ok_or(invalid("remote Rename original received operation missing"))?;
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
            return Err(invalid("remote Rename original operation differs"));
        }
        let pins: BTreeSet<ContentId> = rows
            .iter()
            .filter(|r| {
                r.table() == "remote_rename_objects"
                    && r.primary_key().first().map(String::as_str) == Some(id)
            })
            .map(|r| Ok(field(r, "content_id")?.parse()?))
            .collect::<Result<_>>()?;
        if pins
            != if final_history {
                BTreeSet::new()
            } else {
                contents(&header.baseline)
            }
        {
            return Err(invalid("remote Rename exact own pins differ"));
        }
        let baseline = rows
            .iter()
            .find(|r| {
                r.table() == "snapshots"
                    && r.primary_key() == [header.baseline.root().unwrap().as_str()]
            })
            .ok_or(invalid("remote Rename retained baseline missing"))?;
        if field(baseline, "manifest")? != serde_json::to_string(&header.baseline)?
            || rows.iter().any(|r| {
                r.table() == "snapshot_prunings"
                    && (r.primary_key() == [header.baseline.root().unwrap().as_str()]
                        || r.primary_key() == [header.target_root.as_str()])
            })
        {
            return Err(invalid(
                "remote Rename historical snapshot changed or pruned",
            ));
        }
        if final_history {
            let snapshot = rows
                .iter()
                .find(|r| {
                    r.table() == "snapshots"
                        && r.primary_key() == [header.target.root().unwrap().as_str()]
                })
                .ok_or(invalid("remote Rename final snapshot missing"))?;
            if field(snapshot, "manifest")? != serde_json::to_string(&header.target)?
                || field(snapshot, "state")? != "materialized"
            {
                return Err(invalid("remote Rename final snapshot differs"));
            }
        } else {
            active += 1;
            let current = rows
                .iter()
                .find(|r| {
                    r.table() == "current_manifests"
                        && r.primary_key() == [header.baseline.space_id.as_str()]
                })
                .ok_or(invalid("remote Rename baseline pointer missing"))?;
            if field(current, "snapshot_id")? != header.baseline.root()?.as_str() {
                return Err(invalid("remote Rename current baseline differs"));
            }
            obligations.push(JournalCapacityObligation {
                family: "original_remote_rename_remaining",
                owner_key: vec![id.into()],
                charge: TreeStorageCharge {
                    rows: header
                        .reserved
                        .rows
                        .checked_sub(used.rows)
                        .ok_or(invalid("remote Rename row liability"))?,
                    logical_bytes: header
                        .reserved
                        .logical_bytes
                        .checked_sub(used.logical_bytes)
                        .ok_or(invalid("remote Rename byte liability"))?,
                },
            });
        }
    }
    if active > 1 {
        return Err(invalid("multiple original remote Rename owners"));
    }
    for row in rows
        .iter()
        .filter(|r| matches!(r.table(), "remote_rename_phases" | "remote_rename_objects"))
    {
        if !owners.contains(field(row, "transaction_id")?) {
            return Err(invalid("remote Rename orphan effect"));
        }
    }
    Ok(obligations)
}
impl Journal {
    pub fn remote_rename_receipts(&self, space: &SpaceId) -> Result<Vec<RemoteRenameReceipt>> {
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
            .filter(|r| r.table() == "remote_rename_headers")
        {
            let header: Header = serde_json::from_str(field(row, "header")?)?;
            if header.baseline.space_id != *space {
                return Err(invalid("remote Rename receipt space differs"));
            }
            let phases: BTreeSet<_> = inventory
                .rows()
                .iter()
                .filter(|r| {
                    r.table() == "remote_rename_phases"
                        && r.primary_key().first() == Some(&header.transaction_id.to_string())
                })
                .map(|r| field(r, "phase"))
                .collect::<Result<_>>()?;
            let stage = if phases.contains("final") {
                RemoteRenameStage::Final
            } else if phases.contains("observed") {
                RemoteRenameStage::Observed
            } else if phases.contains("executing") {
                RemoteRenameStage::Executing
            } else {
                RemoteRenameStage::Selected
            };
            let committed = stage == RemoteRenameStage::Final;
            result.push(RemoteRenameReceipt {
                transaction_id: header.transaction_id.clone(),
                operation_id: header.proof.operation.op_id.clone(),
                source_path: header.source.path.clone(),
                target_path: header.target.entries[&header.source.entry_id].path.clone(),
                stage,
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
    pub fn require_no_remote_rename(&self, space: &SpaceId) -> Result<()> {
        if self
            .remote_rename_receipts(space)?
            .iter()
            .any(|r| !r.local_committed)
        {
            return Err(invalid(
                "original remote Rename requires explicit forward recovery",
            ));
        }
        Ok(())
    }
}
