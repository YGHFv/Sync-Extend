//! Exact bounded node image portability preflight; never authorizes a target or writer.
use crate::{JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use std::path::PathBuf;
use sync_extend_core_model::{DeviceId, SpaceId};

pub struct PortableNodeImageScope {
    space: SpaceId,
    device: DeviceId,
    original_worktree: PathBuf,
}

impl PortableNodeImageScope {
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn device(&self) -> &DeviceId {
        &self.device
    }
    pub fn original_worktree(&self) -> &std::path::Path {
        &self.original_worktree
    }
}

impl JournalBackupImage {
    /// Inspect the actual validated immutable image and conservatively refuse
    /// any state family whose native identity cannot safely map to a new root.
    /// No rows, triggers, hashes or scopes are modified by this preflight.
    pub fn portable_node_scope(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<PortableNodeImageScope> {
        self.with_audited_readonly(space, bounds, |database| {
            let mut tables = database.prepare(
                "SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )?;
            let names = tables.query_map([], |row| row.get::<_,String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            // Every nonempty family must have an explicit portable contract.
            // Native terminal history is not made portable merely by being terminal.
            const PORTABLE: &[&str] = &[
                "local_state", "operations", "receive_cursors", "snapshots",
                "current_manifests", "snapshot_objects", "snapshot_prunings",
                "read_lease_clock", "gc_clock",
                "original_operation_provenance", "original_page_inbox", "forwarded_page_inbox",
            ];
            for name in names {
                if PORTABLE.contains(&name.as_str()) { continue; }
                let quoted = format!("\"{}\"", name.replace('"', "\"\""));
                let exists:bool = database.query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM main.{quoted} LIMIT 1)"), [], |row| row.get(0)
                )?;
                if exists {
                    return Err(JournalError::Invariant("node root mapping refuses unsupported original owner history"));
                }
            }
            let state=database.prepare("SELECT key,value FROM main.local_state ORDER BY key")?
                .query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)))?
                .collect::<rusqlite::Result<std::collections::BTreeMap<_,_>>>()?;
            if state.len()!=3 || state.get("space_id").map(String::as_str)!=Some(space.as_str()) {
                return Err(JournalError::Invariant("portable node exact client state required"));
            }
            let device:DeviceId=state.get("device_id")
                .ok_or(JournalError::Invariant("portable node original device absent"))?.parse()?;
            let worktree=PathBuf::from(state.get("worktree")
                .ok_or(JournalError::Invariant("portable node original worktree absent"))?);
            if !worktree.is_absolute() {
                return Err(JournalError::Invariant("portable node original worktree not absolute"));
            }
            Ok(PortableNodeImageScope {space:space.clone(),device,original_worktree:worktree})
        })
    }
}
