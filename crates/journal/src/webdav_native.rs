//! Durable DAV descriptions and content pins. Native effects require a later
//! adapter with independent, private receipts for real retained handles.
use crate::{
    snapshot_retention::audit_snapshot,
    storage_capacity::CapacitySnapshot,
    storage_inventory::reader::{add, preflight},
    CasAccessGuard, Journal, JournalError, Result,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{
    webdav_mutation::WebDavMutationRequest,
    webdav_native::{
        plan_webdav_native, WebDavNativeInventory, WebDavNativeLimits, WebDavNativePlan,
    },
    ContentId, DeviceId, SpaceId,
};

pub(crate) mod schema;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebDavNativeDescription {
    pub request: WebDavMutationRequest,
    pub inventory: WebDavNativeInventory,
    pub limits: WebDavNativeLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WebDavNativeAdmission {
    pub description: WebDavNativeDescription,
    pub description_hash: ContentId,
    pub plan_hash: ContentId,
    pub admitted_at_ms: u64,
    pub cancelled_at_ms: Option<u64>,
    pub writer_gate_held: bool,
    pub native_execution_admitted: bool,
}

fn invalid() -> JournalError {
    JournalError::Invariant("exact retained DAV description")
}

fn scope(connection: &Connection, space: &SpaceId, device: &DeviceId) -> Result<()> {
    let identity: Vec<(String, String)> = connection
        .prepare("SELECT key,value FROM main.local_state ORDER BY key")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    if identity.len() != 3
        || identity[0] != ("device_id".into(), device.to_string())
        || identity[1] != ("space_id".into(), space.to_string())
        || identity[2].0 != "worktree"
        || identity[2].1.is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

fn ordinary_idle(connection: &Connection, space: &SpaceId) -> Result<()> {
    let busy: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.publications WHERE space_id=?1
            AND (state!='committed' OR cleaned=0))
         OR EXISTS(SELECT 1 FROM main.mutations WHERE space_id=?1
            AND state IN ('prepared','executing','quarantined','moved','replaced'))
         OR EXISTS(SELECT 1 FROM main.cleanup_plans WHERE space_id=?1 AND state='executing')",
        [space.as_str()],
        |r| r.get(0),
    )?;
    if busy {
        return Err(invalid());
    }
    Ok(())
}

struct Prepared {
    plan: WebDavNativePlan,
    json: String,
    chunks: BTreeMap<ContentId, u64>,
}

fn prepare(
    connection: &Connection,
    description: &WebDavNativeDescription,
    space: &SpaceId,
    admitted_at_ms: u64,
    active: bool,
) -> Result<Prepared> {
    crate::sql_integer(admitted_at_ms)?;
    scope(connection, space, &description.request.origin_device)?;
    let baseline = audit_snapshot(connection, space, &description.request.baseline)?;
    if baseline.created_at_ms > description.request.created_at_ms
        || description.request.created_at_ms > admitted_at_ms
        || (active && baseline.state != "materialized")
    {
        return Err(invalid());
    }
    if active {
        crate::snapshot_pruning::require_unpruned(connection, &description.request.baseline)?;
        let current: Option<String> = connection
            .query_row(
                "SELECT snapshot_id FROM main.current_manifests WHERE space_id=?1",
                [space.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if current.as_deref() != Some(description.request.baseline.as_str()) {
            return Err(invalid());
        }
        ordinary_idle(connection, space)?;
    }
    let plan = plan_webdav_native(
        &baseline.manifest,
        &description.request,
        &description.inventory,
        description.limits,
    )?;
    let mut chunks = BTreeMap::new();
    let mut visits = 0usize;
    for chunk in baseline
        .manifest
        .entries
        .values()
        .chain(plan.final_manifest().entries.values())
        .filter_map(|entry| entry.content.as_ref())
        .flat_map(|file| &file.chunks)
    {
        visits = visits.checked_add(1).ok_or_else(invalid)?;
        if visits > crate::limits::MAX_CHUNKS
            || chunks
                .insert(chunk.content_id.clone(), u64::from(chunk.length))
                .is_some_and(|length| length != u64::from(chunk.length))
        {
            return Err(invalid());
        }
        crate::sql_integer(u64::from(chunk.length))?;
    }
    if chunks.len() > crate::limits::MAX_ENTRIES {
        return Err(invalid());
    }
    let json = serde_json::to_string(description)?;
    if json.is_empty() || json.len() > crate::MAX_OPERATION_BYTES {
        return Err(invalid());
    }
    Ok(Prepared { plan, json, chunks })
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<WebDavNativeAdmission>> {
    schema::validate(connection)?;
    preflight(
        connection,
        schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.webdav_native_objects o
            LEFT JOIN main.webdav_native_admissions a USING(transaction_id) WHERE a.transaction_id IS NULL)
         OR EXISTS(SELECT 1 FROM main.webdav_native_cancellations c
            LEFT JOIN main.webdav_native_admissions a USING(transaction_id) WHERE a.transaction_id IS NULL)",
        [], |r| r.get(0),
    )?;
    if orphan {
        return Err(invalid());
    }
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.webdav_native_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )
        .optional()?;
    let mut statement = connection.prepare(
        "SELECT transaction_id,space_id,baseline_snapshot,request_hash,plan_hash,
            admitted_at_ms,description,future_rows,future_bytes
         FROM main.webdav_native_admissions ORDER BY transaction_id",
    )?;
    let mut rows = statement.query([])?;
    let mut result = Vec::new();
    let mut active_count = 0usize;
    while let Some(row) = rows.next()? {
        let id: String = row.get(0)?;
        let space: SpaceId = row.get::<_, String>(1)?.parse()?;
        let time: u64 = crate::sql_u64(row, 5)?;
        let json: String = row.get(6)?;
        let description: WebDavNativeDescription = serde_json::from_str(&json)?;
        let cancelled: Option<u64> = connection.query_row(
            "SELECT cancelled_at_ms FROM main.webdav_native_cancellations WHERE transaction_id=?1",
            [&id], |r| crate::sql_u64(r, 0),
        ).optional()?;
        let active = cancelled.is_none();
        let prepared = prepare(connection, &description, &space, time, active)?;
        if description.request.transaction_id.as_str() != id
            || description.request.baseline.as_str() != row.get::<_, String>(2)?
            || prepared.plan.request_hash().as_str() != row.get::<_, String>(3)?
            || prepared.plan.fingerprint().as_str() != row.get::<_, String>(4)?
            || prepared.json != json
            || crate::sql_u64(row, 7)? != 1
            || crate::sql_u64(row, 8)? != 40
            || clock.is_none_or(|value| value < time)
            || cancelled.is_some_and(|value| value < time || clock.is_none_or(|c| value > c))
        {
            return Err(invalid());
        }
        let actual: BTreeMap<ContentId, u64> = connection.prepare(
            "SELECT content_id,length FROM main.webdav_native_objects WHERE transaction_id=?1 ORDER BY content_id",
        )?.query_map([&id], |r| Ok((r.get::<_, String>(0)?, crate::sql_u64(r, 1)?)))?
            .map(|row| { let (id, length) = row?; Ok((id.parse()?, length)) })
            .collect::<Result<_>>()?;
        let plan_hash: ContentId = row.get::<_, String>(4)?.parse()?;
        if actual != prepared.chunks {
            return Err(invalid());
        }
        active_count += usize::from(active);
        result.push(WebDavNativeAdmission {
            description_hash: ContentId::hash(json.as_bytes()),
            description,
            plan_hash,
            admitted_at_ms: time,
            cancelled_at_ms: cancelled,
            writer_gate_held: active,
            native_execution_admitted: false,
        });
    }
    if active_count > 1 {
        return Err(invalid());
    }
    Ok(result)
}

pub(crate) fn outstanding(
    connection: &Connection,
) -> Result<sync_extend_core_model::tree_storage_capacity::TreeStorageCharge> {
    let count = audit(connection)?
        .iter()
        .filter(|row| row.writer_gate_held)
        .count() as u64;
    Ok(
        sync_extend_core_model::tree_storage_capacity::TreeStorageCharge {
            rows: count,
            logical_bytes: count.checked_mul(40).ok_or_else(invalid)?,
        },
    )
}

pub(crate) fn require_idle(connection: &Connection) -> Result<()> {
    if audit(connection)?.iter().any(|row| row.writer_gate_held) {
        return Err(invalid());
    }
    Ok(())
}

fn unchanged(before: &CapacitySnapshot, after: &CapacitySnapshot) -> Result<()> {
    let original = |snapshot: &CapacitySnapshot| {
        snapshot
            .rows
            .iter()
            .filter(|row| !row.table().starts_with("webdav_native_"))
            .map(|row| {
                (
                    row.table().to_owned(),
                    row.primary_key().to_vec(),
                    row.fingerprint().clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    if original(before) != original(after)
        || !after.report.within_accounted_limits()
        || !after.report.coverage_gaps().is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

fn advance_clock(connection: &Connection, time: u64) -> Result<()> {
    let old: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.webdav_native_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )
        .optional()?;
    if old.is_some_and(|value| value > time) {
        return Err(invalid());
    }
    connection.execute(
        "INSERT INTO main.webdav_native_clock VALUES(1,?1)
         ON CONFLICT(singleton) DO UPDATE SET observed_at_ms=excluded.observed_at_ms",
        [crate::sql_integer(time)?],
    )?;
    Ok(())
}

impl Journal {
    pub fn webdav_native_admissions(&self) -> Result<Vec<WebDavNativeAdmission>> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let rows = audit(&tx)?;
        tx.commit()?;
        Ok(rows)
    }

    /// Persist the exact bounded description while retaining all CAS input
    /// observations. Replay is metadata-only and never reacquires worktree slots.
    pub fn with_webdav_native_description<T, E>(
        &self,
        space: &SpaceId,
        description: &WebDavNativeDescription,
        time: u64,
        inspect: impl FnOnce(&WebDavNativePlan) -> std::result::Result<T, E>,
    ) -> std::result::Result<(Option<(CasAccessGuard, T)>, WebDavNativeAdmission), E>
    where
        E: From<JournalError>,
    {
        if !self.connection.is_autocommit() {
            return Err(invalid().into());
        }
        let find = || -> Result<Option<WebDavNativeAdmission>> {
            let old = audit(&self.connection)?.into_iter().find(|row| {
                row.description.request.transaction_id == description.request.transaction_id
            });
            if old
                .as_ref()
                .is_some_and(|row| row.description != *description)
            {
                return Err(invalid());
            }
            Ok(old)
        };
        // Even replay has one owned read snapshot and exact retained identity.
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(JournalError::from)?;
            scope(&tx, space, &description.request.origin_device)?;
            if let Some(old) = find()? {
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, old));
            }
            tx.commit().map_err(JournalError::from)?;
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        if let Some(old) = find()? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        self.require_no_tree_restore(space, crate::limits::MAX_ENTRIES)?;
        let prepared = prepare(&tx, description, space, time, true)?;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let before = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid().into());
        }
        for id in prepared.chunks.keys() {
            self.require_cas_access(id)?;
        }
        let held = inspect(&prepared.plan)?;
        // Admission row (32+32+64+64+64+8+JSON+8+8), chunk rows
        // (32+64+8), full cancellation (32+8) and singleton clock (8+8).
        let new_rows = add(3, prepared.chunks.len() as u64)?;
        let new_bytes = add(
            336 + prepared.json.len() as u64,
            (prepared.chunks.len() as u64)
                .checked_mul(104)
                .ok_or_else(invalid)?,
        )?;
        if add(before.report.accounted_total().rows, new_rows)? > bounds.max_rows
            || add(before.report.accounted_total().logical_bytes, new_bytes)?
                > bounds.max_logical_bytes
        {
            return Err(invalid().into());
        }
        advance_clock(&tx, time)?;
        self.webdav_native_description_issue.issue(
            prepared.plan.fingerprint().to_string(),
            time,
            || {
                tx.execute(
                    "INSERT INTO main.webdav_native_admissions VALUES(?1,?2,?3,?4,?5,?6,?7,1,40)",
                    params![
                        description.request.transaction_id.as_str(),
                        space.as_str(),
                        description.request.baseline.as_str(),
                        prepared.plan.request_hash().as_str(),
                        prepared.plan.fingerprint().as_str(),
                        crate::sql_integer(time)?,
                        &prepared.json
                    ],
                )?;
                Ok(())
            },
        )?;
        for (id, length) in &prepared.chunks {
            self.webdav_native_object_issue
                .issue(id.to_string(), time, || {
                    tx.execute(
                        "INSERT INTO main.webdav_native_objects VALUES(?1,?2,?3)",
                        params![
                            description.request.transaction_id.as_str(),
                            id.as_str(),
                            crate::sql_integer(*length)?
                        ],
                    )?;
                    Ok(())
                })?;
        }
        let after = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        unchanged(&before, &after)?;
        let accepted = find()?.ok_or_else(invalid)?;
        checkpoint("webdav_native_description_before_commit");
        tx.commit().map_err(JournalError::from)?;
        checkpoint("webdav_native_description_after_commit");
        Ok((Some((coordination, held)), accepted))
    }

    /// Explicit cancellation of a description that has never granted native
    /// activation. Historical descriptions remain replayable after pin release.
    pub fn cancel_webdav_native_description(
        &self,
        space: &SpaceId,
        id: &sync_extend_core_model::EntryId,
        time: u64,
    ) -> Result<WebDavNativeAdmission> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let old = audit(&tx)?
            .into_iter()
            .find(|row| &row.description.request.transaction_id == id)
            .ok_or_else(invalid)?;
        scope(&tx, space, &old.description.request.origin_device)?;
        if old.cancelled_at_ms.is_some() {
            tx.commit()?;
            return Ok(old);
        }
        if time < old.admitted_at_ms {
            return Err(invalid());
        }
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let before = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        advance_clock(&tx, time)?;
        self.webdav_native_cancel_issue
            .issue(id.to_string(), time, || {
                tx.execute(
                    "INSERT INTO main.webdav_native_cancellations VALUES(?1,?2)",
                    params![id.as_str(), crate::sql_integer(time)?],
                )?;
                Ok(())
            })?;
        let after = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        unchanged(&before, &after)?;
        let accepted = audit(&tx)?
            .into_iter()
            .find(|row| &row.description.request.transaction_id == id)
            .ok_or_else(invalid)?;
        checkpoint("webdav_native_cancel_before_commit");
        tx.commit()?;
        checkpoint("webdav_native_cancel_after_commit");
        Ok(accepted)
    }
}

fn checkpoint(_phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(_phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{_phase}");
        loop {
            if std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
                .is_some_and(|path| std::path::Path::new(&path).is_file())
            {
                break;
            }
            std::thread::park_timeout(std::time::Duration::from_millis(25));
        }
    }
}
