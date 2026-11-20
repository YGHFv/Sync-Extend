//! Exact bounded node image portability preflight; never authorizes a target or writer.
use crate::read_lease::recovery_hold;
use crate::{
    JournalBackupImage, JournalError, JournalStorageColumnValue, JournalStoredRow,
    NodeInspectionBounds, Result,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use sync_extend_core_model::{ContentId, DeviceId, SpaceId};

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

#[derive(serde::Serialize)]
pub struct ArchivedReadLeaseHold {
    pub clock_watermark_ms: u64,
    pub active_leases: usize,
    pub released_leases: usize,
    pub expired_leases: usize,
    pub pin_rows: usize,
    pub distinct_pinned_objects: usize,
    pub inventory_digest: ContentId,
    pub other_owner_tables: Vec<String>,
    pub root_bound_local_state: bool,
}

fn other_owner_tables(database: &rusqlite::Connection) -> Result<Vec<String>> {
    let mut tables = database.prepare(
        "SELECT name FROM main.sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names = tables
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    // Every nonempty family must have an explicit portable contract.
    // A terminal state alone does not make native history portable.
    const PORTABLE: &[&str] = &[
        "local_state",
        "operations",
        "receive_cursors",
        "snapshots",
        "current_manifests",
        "snapshot_objects",
        "snapshot_prunings",
        "read_lease_clock",
        "read_leases",
        "read_lease_objects",
        "gc_clock",
        "original_operation_provenance",
        "original_page_inbox",
        "forwarded_page_inbox",
    ];
    let mut other = Vec::new();
    for name in names {
        if PORTABLE.contains(&name.as_str()) {
            continue;
        }
        let quoted = format!("\"{}\"", name.replace('"', "\"\""));
        let exists: bool = database.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM main.{quoted} LIMIT 1)"),
            [],
            |row| row.get(0),
        )?;
        if exists {
            other.push(name);
        }
    }
    Ok(other)
}

fn client_identity(
    database: &rusqlite::Connection,
    space: &SpaceId,
) -> Result<PortableNodeImageScope> {
    let state = database
        .prepare("SELECT key,value FROM main.local_state ORDER BY key")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    if state.len() != 3 || state.get("space_id").map(String::as_str) != Some(space.as_str()) {
        return Err(JournalError::Invariant(
            "portable node exact client state required",
        ));
    }
    let device = state
        .get("device_id")
        .ok_or(JournalError::Invariant(
            "portable node original device absent",
        ))?
        .parse()?;
    let original_worktree = PathBuf::from(state.get("worktree").ok_or(JournalError::Invariant(
        "portable node original worktree absent",
    ))?);
    if !original_worktree.is_absolute() {
        return Err(JournalError::Invariant(
            "portable node original worktree not absolute",
        ));
    }
    Ok(PortableNodeImageScope {
        space: space.clone(),
        device,
        original_worktree,
    })
}

fn column<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a JournalStorageColumnValue> {
    row.columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
        .ok_or(JournalError::Invariant("archived read lease column absent"))
}

fn read_lease_hold(
    database: &rusqlite::Connection,
    rows: &[JournalStoredRow],
) -> Result<ArchivedReadLeaseHold> {
    let mut active_leases = 0;
    let mut released_leases = 0;
    let mut expired_leases = 0;
    let mut clock_watermark_ms = None;
    let mut pin_rows = 0;
    let mut pins = BTreeSet::new();
    let mut root_bound_local_state = false;
    // The complete Journal audit has already established each exact lease,
    // clock and pin. The inventory commits even to distinct owners of one ID.
    for row in rows {
        match row.table() {
            "read_lease_clock" => match column(row, "observed_at_ms")? {
                JournalStorageColumnValue::Integer(value) if clock_watermark_ms.is_none() => {
                    clock_watermark_ms = Some(*value);
                }
                _ => return Err(JournalError::Invariant("archived read lease clock shape")),
            },
            "read_leases" => match column(row, "state")? {
                JournalStorageColumnValue::Text(value) if value == "active" => active_leases += 1,
                JournalStorageColumnValue::Text(value) if value == "released" => {
                    released_leases += 1;
                }
                JournalStorageColumnValue::Text(value) if value == "expired" => expired_leases += 1,
                _ => return Err(JournalError::Invariant("archived read lease state shape")),
            },
            "read_lease_objects" => match column(row, "content_id")? {
                JournalStorageColumnValue::Text(value) => {
                    pins.insert(value.as_str());
                    pin_rows += 1;
                }
                _ => return Err(JournalError::Invariant("archived read lease pin shape")),
            },
            "local_state" => {
                if !matches!(
                    row.primary_key(),
                    [key] if matches!(key.as_str(), "space_id" | "device_id" | "worktree")
                ) {
                    root_bound_local_state = true;
                }
            }
            _ => (),
        }
    }
    if active_leases + released_leases + expired_leases == 0 {
        return Err(JournalError::Invariant(
            "original image has no read lease history",
        ));
    }
    Ok(ArchivedReadLeaseHold {
        clock_watermark_ms: clock_watermark_ms
            .ok_or(JournalError::Invariant("archived read lease clock absent"))?,
        active_leases,
        released_leases,
        expired_leases,
        pin_rows,
        distinct_pinned_objects: pins.len(),
        inventory_digest: recovery_hold::inventory(rows),
        other_owner_tables: other_owner_tables(database)?,
        root_bound_local_state,
    })
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
            // Historical terminal rows have no pins after the complete audit.
            // An active empty-file lease still has an owner without any pins.
            let active: bool = database.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.read_leases WHERE state='active')",
                [],
                |row| row.get(0),
            )?;
            if active || !other_owner_tables(database)?.is_empty() {
                return Err(JournalError::Invariant(
                    "node root mapping refuses unsupported original owner history",
                ));
            }
            client_identity(database, space)
        })
    }

    pub(super) fn portable_node_scope_with_read_lease_hold(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
        expected: &ContentId,
    ) -> Result<PortableNodeImageScope> {
        Self::inspect_current_node_image_with_audit_rows(
            self.bytes(),
            self.digest(),
            self.bytes().len(),
            space,
            bounds,
            |database, rows, _| {
                let hold = read_lease_hold(database, rows)?;
                if &hold.inventory_digest != expected {
                    return Err(JournalError::Invariant(
                        "archived read lease hold digest differs",
                    ));
                }
                if hold.active_leases == 0 {
                    return Err(JournalError::Invariant(
                        "archived read lease hold requires an active owner",
                    ));
                }
                if hold.root_bound_local_state || !hold.other_owner_tables.is_empty() {
                    return Err(JournalError::Invariant(
                        "read lease hold refuses other original owner history",
                    ));
                }
                client_identity(database, space)
            },
        )
        .map(|(_, scope)| scope)
    }

    /// Inspect the preserved read lease clock and independent CAS pin owners.
    /// Full original audits precede the preview. The result carries no issuer.
    pub fn inspect_archived_read_lease_hold(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<ArchivedReadLeaseHold> {
        Self::inspect_current_node_image_with_audit_rows(
            self.bytes(),
            self.digest(),
            self.bytes().len(),
            space,
            bounds,
            |database, rows, _| read_lease_hold(database, rows),
        )
        .map(|(_, hold)| hold)
    }
}
