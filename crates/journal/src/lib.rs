use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::{path::Path, time::Duration};
use sync_extend_core_model::*;

const MAX_OPERATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_PENDING_OPS: u64 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("journal serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid journal model: {0}")]
    Model(#[from] ModelError),
    #[error("journal invariant failed: {0}")]
    Invariant(&'static str),
}

pub type Result<T> = std::result::Result<T, JournalError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Duplicate,
    Pending,
    Received,
}

pub struct Journal {
    connection: Connection,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", true)?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => {
                let tx = connection.transaction()?;
                tx.execute_batch(include_str!("schema.sql"))?;
                tx.commit()?;
            }
            1 => {}
            _ => return Err(JournalError::Invariant("unsupported schema version")),
        }
        Ok(Self { connection })
    }

    pub fn state(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row("SELECT value FROM local_state WHERE key=?1", [key], |row| {
                row.get(0)
            })
            .optional()?)
    }

    pub fn initialize(&mut self, space: &SpaceId, device: &DeviceId, root: &str) -> Result<()> {
        let tx = self.connection.transaction()?;
        for (key, value) in [
            ("space_id", space.as_str()),
            ("device_id", device.as_str()),
            ("worktree", root),
        ] {
            let old: Option<String> = tx
                .query_row("SELECT value FROM local_state WHERE key=?1", [key], |row| {
                    row.get(0)
                })
                .optional()?;
            if old.as_deref().is_some_and(|old| old != value) {
                return Err(JournalError::Invariant("local identity/root mismatch"));
            }
            tx.execute(
                "INSERT OR IGNORE INTO local_state VALUES (?1, ?2)",
                params![key, value],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn current(&self, space: &SpaceId) -> Result<Option<Manifest>> {
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT s.manifest FROM current_manifests c JOIN snapshots s USING(snapshot_id)
             WHERE c.space_id=?1",
                [space.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|json| {
            let manifest: Manifest = serde_json::from_str(&json)?;
            manifest.validate()?;
            Ok(manifest)
        })
        .transpose()
    }

    pub fn operations(&self, space: &SpaceId) -> Result<Vec<Operation>> {
        let mut statement = self.connection.prepare(
            "SELECT payload FROM operations WHERE space_id=?1 ORDER BY origin_device_id, origin_seq",
        )?;
        let rows = statement.query_map([space.as_str()], |row| row.get::<_, String>(0))?;
        let mut operations = Vec::new();
        for row in rows {
            let op: Operation = serde_json::from_str(&row?)?;
            op.validate()?;
            operations.push(op);
        }
        Ok(operations)
    }

    pub fn snapshots(&self, space: &SpaceId) -> Result<Vec<(SnapshotId, String)>> {
        let mut statement = self.connection.prepare(
            "SELECT snapshot_id,state FROM snapshots WHERE space_id=?1 ORDER BY created_at_ms, snapshot_id",
        )?;
        let rows = statement.query_map([space.as_str()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, state) = row?;
            Ok((id.parse()?, state))
        })
        .collect()
    }

    pub fn cursor(&self, space: &SpaceId, device: &DeviceId) -> Result<u64> {
        cursor(&self.connection, space, device)
    }

    // Trusted local transport only. Authentication must precede this API in M2.
    pub fn receive(&mut self, op: &Operation) -> Result<ReceiveOutcome> {
        op.validate()?;
        let json = serde_json::to_string(op)?;
        if json.len() > MAX_OPERATION_BYTES || op.payload.origin_seq > i64::MAX as u64 {
            return Err(JournalError::Invariant("operation resource limit"));
        }
        let tx = self.connection.transaction()?;
        if let Some(existing) = tx
            .query_row(
                "SELECT payload FROM operations WHERE op_id=?1",
                [op.op_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            if existing != json {
                return Err(JournalError::Invariant("operation ID collision"));
            }
            return Ok(ReceiveOutcome::Duplicate);
        }
        let pending: i64 = tx.query_row(
            "SELECT count(*) FROM operations WHERE state='pending'",
            [],
            |r| r.get(0),
        )?;
        if pending >= MAX_PENDING_OPS as i64 {
            return Err(JournalError::Invariant("pending queue full"));
        }
        tx.execute(
            "INSERT INTO operations VALUES (?1,?2,?3,?4,?5,'pending')",
            params![
                op.op_id.as_str(),
                op.payload.space_id.as_str(),
                op.payload.origin_device_id.as_str(),
                sql_integer(op.payload.origin_seq)?,
                json
            ],
        )?;
        promote_pending(&tx)?;
        let state: String = tx.query_row(
            "SELECT state FROM operations WHERE op_id=?1",
            [op.op_id.as_str()],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(if state == "pending" {
            ReceiveOutcome::Pending
        } else {
            ReceiveOutcome::Received
        })
    }

    pub fn commit_local(
        &mut self,
        expected_root: Option<&SnapshotId>,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
    ) -> Result<SnapshotId> {
        manifest.validate()?;
        let root = manifest.root()?;
        let tx = self.connection.transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT snapshot_id FROM current_manifests WHERE space_id=?1",
                [manifest.space_id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if existing.as_deref() != expected_root.map(SnapshotId::as_str) {
            return Err(JournalError::Invariant("manifest baseline changed"));
        }
        for op in operations {
            op.validate()?;
            let p = &op.payload;
            if p.space_id != manifest.space_id
                || p.origin_seq != cursor(&tx, &p.space_id, &p.origin_device_id)? + 1
            {
                return Err(JournalError::Invariant("local sequence discontinuity"));
            }
            for (device, seq) in &p.causal.0 {
                if cursor(&tx, &p.space_id, device)? < *seq {
                    return Err(JournalError::Invariant("missing causal dependency"));
                }
            }
            tx.execute(
                "INSERT INTO operations VALUES (?1,?2,?3,?4,?5,'materialized')",
                params![
                    op.op_id.as_str(),
                    p.space_id.as_str(),
                    p.origin_device_id.as_str(),
                    sql_integer(p.origin_seq)?,
                    serde_json::to_string(op)?
                ],
            )?;
            set_cursor(&tx, &p.space_id, &p.origin_device_id, p.origin_seq)?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO snapshots VALUES (?1,?2,?3,?4,'materialized',0)",
            params![
                root.as_str(),
                manifest.space_id.as_str(),
                serde_json::to_string(manifest)?,
                sql_integer(timestamp)?
            ],
        )?;
        tx.execute(
            "INSERT INTO current_manifests VALUES (?1,?2)
             ON CONFLICT(space_id) DO UPDATE SET snapshot_id=excluded.snapshot_id",
            params![manifest.space_id.as_str(), root.as_str()],
        )?;
        tx.commit()?;
        Ok(root)
    }

    pub fn integrity_check(&self) -> Result<()> {
        let result: String = self
            .connection
            .pragma_query_value(None, "integrity_check", |r| r.get(0))?;
        if result != "ok" {
            return Err(JournalError::Invariant("SQLite integrity check failed"));
        }
        Ok(())
    }
}

fn cursor(connection: &Connection, space: &SpaceId, device: &DeviceId) -> Result<u64> {
    let value: i64 = connection
        .query_row(
            "SELECT contiguous_seq FROM receive_cursors WHERE space_id=?1 AND device_id=?2",
            params![space.as_str(), device.as_str()],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(value).map_err(|_| JournalError::Invariant("negative sequence"))
}

fn set_cursor(tx: &Transaction<'_>, space: &SpaceId, device: &DeviceId, seq: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO receive_cursors VALUES (?1,?2,?3)
         ON CONFLICT(space_id,device_id) DO UPDATE SET contiguous_seq=excluded.contiguous_seq",
        params![space.as_str(), device.as_str(), sql_integer(seq)?],
    )?;
    Ok(())
}

fn sql_integer(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| JournalError::Invariant("SQLite integer overflow"))
}

fn promote_pending(tx: &Transaction<'_>) -> Result<()> {
    loop {
        let candidates: Vec<String> = {
            let mut statement = tx.prepare(
                "SELECT payload FROM operations WHERE state='pending' ORDER BY origin_seq",
            )?;
            let rows = statement.query_map([], |r| r.get(0))?;
            rows.collect::<std::result::Result<_, _>>()?
        };
        let mut progressed = false;
        for json in candidates {
            let op: Operation = serde_json::from_str(&json)?;
            let p = &op.payload;
            if p.origin_seq != cursor(tx, &p.space_id, &p.origin_device_id)? + 1 {
                continue;
            }
            let mut ready = true;
            for (device, seq) in &p.causal.0 {
                if cursor(tx, &p.space_id, device)? < *seq {
                    ready = false;
                    break;
                }
            }
            if ready {
                tx.execute(
                    "UPDATE operations SET state='received' WHERE op_id=?1",
                    [op.op_id.as_str()],
                )?;
                set_cursor(tx, &p.space_id, &p.origin_device_id, p.origin_seq)?;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    Ok(())
}
