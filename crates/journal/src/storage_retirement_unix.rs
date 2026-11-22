//! Independent Unix immutable fences. Serialized history never reacquires an FD.
use crate::{
    storage_capacity::CapacitySnapshot,
    storage_inventory::reader::{add, preflight},
    storage_retirement::{retained_scope, RetainedScope},
    Journal, JournalError, Result,
};
use rusqlite::{
    params, types::Value, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::Serialize;
use sync_extend_core_model::{
    storage_node::StorageNodeConfig,
    storage_retirement_unix::{
        UnixStorageRetirementBinding, UnixStorageRetirementExpectation,
        UnixStorageRetirementIntent, UnixStorageRetirementRequest,
    },
    tree_storage_capacity::TreeStorageCharge,
    ContentId, DeviceId, EntryId,
};

pub(crate) mod schema;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnixStorageRetirementAdmission {
    pub request: UnixStorageRetirementRequest,
    pub request_fingerprint: ContentId,
    pub binding_fingerprint: ContentId,
    pub admitted_at_ms: u64,
    pub cancelled_at_ms: Option<u64>,
    pub content_fenced: bool,
    pub native_activation_authorized: bool,
    pub marker_creation_authorized: bool,
    pub payload_move_authorized: bool,
    pub deletion_authorized: bool,
    pub backup_complete: bool,
    pub pending_resume_authorized: bool,
}

fn invalid() -> JournalError {
    JournalError::Invariant("exact Unix storage retirement immutable fence")
}

fn scope(
    connection: &Connection,
    request: &UnixStorageRetirementRequest,
    config: &StorageNodeConfig,
    device: &DeviceId,
) -> Result<()> {
    request.validate(config, device)?;
    retained_scope(
        connection,
        config,
        device,
        RetainedScope {
            storage_id: &request.storage_id,
            original_owner_id: &request.original_owner_id,
            content_id: &request.content_id,
            metadata_hash: &request.original_metadata_hash,
            length: request.binding.length,
        },
    )
}

fn values(
    request: &UnixStorageRetirementRequest,
    config: &StorageNodeConfig,
    device: &DeviceId,
    time: u64,
) -> Result<Vec<Value>> {
    request.validate(config, device)?;
    if time < request.grace_until_ms || time >= request.expires_at_ms {
        return Err(invalid());
    }
    let json = serde_json::to_string(request)?;
    let config_json = serde_json::to_string(config)?;
    if json.len() > 16384 || config_json.len() > crate::MAX_OPERATION_BYTES {
        return Err(invalid());
    }
    Ok(vec![
        Value::Text(request.request_id.to_string()),
        Value::Text(request.space_id.to_string()),
        Value::Text(request.storage_id.to_string()),
        Value::Text(request.original_owner_id.to_string()),
        Value::Text(device.to_string()),
        Value::Text(request.storage_policy.to_string()),
        Value::Text(request.content_id.to_string()),
        Value::Text(request.original_metadata_hash.to_string()),
        Value::Text(request.binding.fingerprint()?.to_string()),
        Value::Text(request.fingerprint(config, device)?.to_string()),
        Value::Integer(crate::sql_integer(request.requested_at_ms)?),
        Value::Integer(crate::sql_integer(request.grace_until_ms)?),
        Value::Integer(crate::sql_integer(request.expires_at_ms)?),
        Value::Integer(crate::sql_integer(time)?),
        Value::Text(json),
        Value::Text(config_json),
    ])
}

fn referenced(connection: &Connection, content: &ContentId) -> Result<bool> {
    let query = schema::REFERENCES
        .iter()
        .map(|table| format!("EXISTS(SELECT 1 FROM main.{table} WHERE content_id=?1)"))
        .collect::<Vec<_>>()
        .join(" OR ");
    Ok(
        connection.query_row(&format!("SELECT {query}"), [content.as_str()], |row| {
            row.get(0)
        })?,
    )
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<UnixStorageRetirementAdmission>> {
    schema::validate(connection)?;
    preflight(
        connection,
        schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    // A malformed older family must not be interpreted as an absent fence.
    let windows = crate::storage_retirement::audit(connection)?;
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_v1_clock WHERE singleton=1",
            [],
            |row| crate::sql_u64(row, 0),
        )
        .optional()?;
    let stored = connection
        .prepare(
            "SELECT request_id,space_id,storage_id,owner_id,device_id,policy_hash,content_id,
             metadata_hash,binding_hash,request_hash,requested_at_ms,grace_until_ms,
             expires_at_ms,admitted_at_ms,request,config
             FROM main.unix_storage_retirement_v1_requests ORDER BY request_id",
        )?
        .query_map([], |row| {
            (0..16)
                .map(|index| row.get(index))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if stored.is_empty() != clock.is_none() {
        return Err(invalid());
    }
    let mut result = Vec::new();
    let mut active = std::collections::BTreeSet::new();
    for row in stored {
        let (Value::Text(json), Value::Text(config)) = (&row[14], &row[15]) else {
            return Err(invalid());
        };
        let request: UnixStorageRetirementRequest = serde_json::from_str(json)?;
        let config: StorageNodeConfig = serde_json::from_str(config)?;
        let device = request.storage_device.clone();
        let Value::Integer(time) = row[13] else {
            return Err(invalid());
        };
        let time = u64::try_from(time).map_err(|_| invalid())?;
        if values(&request, &config, &device, time)? != row
            || clock.is_none_or(|clock| clock < time)
        {
            return Err(invalid());
        }
        scope(connection, &request, &config, &device)?;
        let cancelled: Option<u64> = connection
            .query_row(
                "SELECT cancelled_at_ms FROM main.unix_storage_retirement_v1_cancellations
                 WHERE request_id=?1",
                [request.request_id.as_str()],
                |row| crate::sql_u64(row, 0),
            )
            .optional()?;
        if cancelled.is_some_and(|cancelled| {
            cancelled < time || clock.is_none_or(|clock| cancelled > clock)
        }) {
            return Err(invalid());
        }
        if cancelled.is_none()
            && (!active.insert(request.content_id.clone())
                || referenced(connection, &request.content_id)?
                || windows
                    .iter()
                    .any(|old| old.content_fenced && old.request.content_id == request.content_id))
        {
            return Err(invalid());
        }
        result.push(UnixStorageRetirementAdmission {
            request_fingerprint: request.fingerprint(&config, &device)?,
            binding_fingerprint: request.binding.fingerprint()?,
            request,
            admitted_at_ms: time,
            cancelled_at_ms: cancelled,
            content_fenced: cancelled.is_none(),
            native_activation_authorized: false,
            marker_creation_authorized: false,
            payload_move_authorized: false,
            deletion_authorized: false,
            backup_complete: false,
            pending_resume_authorized: false,
        });
    }
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.unix_storage_retirement_v1_cancellations c
         LEFT JOIN main.unix_storage_retirement_v1_requests r USING(request_id)
         WHERE r.request_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if orphan {
        return Err(invalid());
    }
    Ok(result)
}

pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    let count = audit(connection)?
        .iter()
        .filter(|row| row.content_fenced)
        .count() as u64;
    Ok(TreeStorageCharge {
        rows: count,
        logical_bytes: count.checked_mul(40).ok_or_else(invalid)?,
    })
}

pub(crate) fn metadata_budget(connection: &Connection) -> Result<TreeStorageCharge> {
    let future = outstanding(connection)?;
    let actual = preflight(
        connection,
        schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    actual.iter().try_fold(future, |sum, table| {
        Ok(TreeStorageCharge {
            rows: add(sum.rows, table.rows)?,
            logical_bytes: add(sum.logical_bytes, table.logical_bytes)?,
        })
    })
}

#[cfg(target_os = "linux")]
fn unchanged(before: &CapacitySnapshot, after: &CapacitySnapshot) -> Result<()> {
    let collateral = |snapshot: &CapacitySnapshot| {
        snapshot
            .rows
            .iter()
            .filter(|row| !row.table().starts_with("unix_storage_retirement_v1_"))
            .map(|row| {
                (
                    row.table().to_owned(),
                    row.primary_key().to_vec(),
                    row.fingerprint().clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    if collateral(before) != collateral(after)
        || !after.report.within_accounted_limits()
        || !after.report.coverage_gaps().is_empty()
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn native_binding(
    expected: &UnixStorageRetirementExpectation,
    exclusive: &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
    original: &sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
) -> Result<UnixStorageRetirementBinding> {
    use std::io::Read;
    use sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementKey;
    let key = |value: sync_extend_platform_fs::UnixFileKey| UnixStorageRetirementKey {
        device: value.device,
        inode: value.inode,
    };
    original.verify(exclusive)?;
    let layout = original.layout_observation(exclusive)?;
    let payload = original.payload_observation(exclusive)?;
    let mut stat = String::new();
    std::fs::File::open("/proc/self/stat")?
        .take(4097)
        .read_to_string(&mut stat)?;
    let start_ticks = stat
        .rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|ticks| ticks.parse::<u64>().ok())
        .filter(|ticks| *ticks != 0 && *ticks <= i64::MAX as u64)
        .ok_or_else(invalid)?;
    if stat.len() > 4096 || !payload.single_link || !payload.mandatory_original_write_lease {
        return Err(invalid());
    }
    let binding = UnixStorageRetirementBinding {
        format_version: 1,
        owner_config_fingerprint: expected.owner_config_fingerprint.clone(),
        persistent_metadata_owner_generation: expected.persistent_metadata_owner_generation,
        outside_data: key(exclusive.outside_data_key()?),
        coordination: key(exclusive.coordination_key()?),
        backing_image: key(layout.expected_layout.backing_image),
        image_filesystem_id: layout.expected_layout.image_filesystem_id,
        owner_uid: layout.expected_layout.owner_uid,
        owner_process_id: std::process::id(),
        owner_process_start_ticks: start_ticks,
        owner_generation: layout.owner_generation,
        namespace: key(layout.namespace),
        runtime_mount_id: layout.runtime_mount_id,
        mounted_root: key(layout.mounted_root),
        cas: key(layout.cas),
        objects: key(layout.objects),
        temporary: key(layout.temporary),
        realm: key(layout.realm),
        realm_fingerprint: std::str::from_utf8(&layout.expected_layout.realm_fingerprint)
            .map_err(|_| invalid())?
            .parse()?,
        shard: key(payload.parent),
        payload: key(payload.identity),
        length: u32::try_from(payload.length).map_err(|_| invalid())?,
        modified_seconds: payload.modified_seconds,
        modified_nanoseconds: u32::try_from(payload.modified_nanoseconds).map_err(|_| invalid())?,
    };
    // This recomputes the durable realm from the full owner config fingerprint,
    // original outside/image/coordination keys and persistent metadata owner.
    binding.validate()?;
    if UnixStorageRetirementExpectation::from_binding(&binding)? != *expected {
        return Err(invalid());
    }
    original.verify(exclusive)?;
    Ok(binding)
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_original(
    request: &UnixStorageRetirementRequest,
    exclusive: &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
    original: &sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
) -> Result<()> {
    let expected = UnixStorageRetirementExpectation::from_binding(&request.binding)?;
    let actual = native_binding(&expected, exclusive, original)?;
    let bytes = original.read_bytes(exclusive)?;
    if actual != request.binding
        || bytes.len() != request.binding.length as usize
        || ContentId::hash(&bytes) != request.content_id
    {
        return Err(invalid());
    }
    original.verify(exclusive)?;
    Ok(())
}

#[cfg(target_os = "linux")]
enum FreshInput<'a> {
    Request(&'a UnixStorageRetirementRequest),
    Intent(&'a UnixStorageRetirementIntent),
}

#[cfg(target_os = "linux")]
impl FreshInput<'_> {
    fn request_id(&self) -> &EntryId {
        match self {
            Self::Request(request) => &request.request_id,
            Self::Intent(intent) => &intent.request_id,
        }
    }
    fn content_id(&self) -> &ContentId {
        match self {
            Self::Request(request) => &request.content_id,
            Self::Intent(intent) => &intent.content_id,
        }
    }
    fn validate(&self, config: &StorageNodeConfig, device: &DeviceId) -> Result<()> {
        match self {
            Self::Request(request) => request.validate(config, device)?,
            Self::Intent(intent) => intent.validate(config, device)?,
        }
        Ok(())
    }
    fn scope(
        &self,
        connection: &Connection,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<()> {
        self.validate(config, device)?;
        match self {
            Self::Request(request) => scope(connection, request, config, device),
            Self::Intent(intent) => retained_scope(
                connection,
                config,
                device,
                RetainedScope {
                    storage_id: &intent.storage_id,
                    original_owner_id: &intent.original_owner_id,
                    content_id: &intent.content_id,
                    metadata_hash: &intent.original_metadata_hash,
                    length: intent.expected_original.length,
                },
            ),
        }
    }
    fn replay(
        &self,
        rows: Vec<UnixStorageRetirementAdmission>,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<Option<UnixStorageRetirementAdmission>> {
        let old = rows
            .into_iter()
            .find(|row| &row.request.request_id == self.request_id());
        if let Some(old) = &old {
            match self {
                Self::Intent(_) => return Err(invalid()),
                Self::Request(request) => {
                    if old.request != **request
                        || old.request_fingerprint != request.fingerprint(config, device)?
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        Ok(old)
    }
    fn materialize(
        &self,
        config: &StorageNodeConfig,
        device: &DeviceId,
        exclusive: &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
        original: &sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
    ) -> Result<UnixStorageRetirementRequest> {
        match self {
            Self::Request(request) => {
                verify_original(request, exclusive, original)?;
                Ok((*request).clone())
            }
            Self::Intent(intent) => Ok(intent.materialize(
                native_binding(&intent.expected_original, exclusive, original)?,
                config,
                device,
            )?),
        }
    }
}

impl Journal {
    pub fn unix_storage_retirement_admissions(
        &self,
    ) -> Result<Vec<UnixStorageRetirementAdmission>> {
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let rows = audit(&tx)?;
            tx.commit()?;
            return Ok(rows);
        }
        audit(&self.connection)
    }

    pub fn replay_unix_storage_retirement(
        &self,
        request: &UnixStorageRetirementRequest,
        config: &StorageNodeConfig,
        device: &DeviceId,
    ) -> Result<UnixStorageRetirementAdmission> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        request.validate(config, device)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        scope(&tx, request, config, device)?;
        let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
        let full = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        if !full.report.within_accounted_limits() || !full.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        let fingerprint = request.fingerprint(config, device)?;
        let old = audit(&tx)?
            .into_iter()
            .find(|old| old.request.request_id == request.request_id)
            .ok_or_else(invalid)?;
        if old.request != *request || old.request_fingerprint != fingerprint {
            return Err(invalid());
        }
        tx.commit()?;
        Ok(old)
    }

    /// Exact replay is metadata-only. A fresh admission must return the actual
    /// original inspection, issued from the same borrowed exclusive guard.
    #[cfg(target_os = "linux")]
    pub fn with_unix_storage_retirement_admission<E>(
        &self,
        request: &UnixStorageRetirementRequest,
        config: &StorageNodeConfig,
        device: &DeviceId,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(
            &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
        ) -> std::result::Result<
            sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
            E,
        >,
    ) -> std::result::Result<
        (
            Option<(
                crate::CasAccessGuard,
                sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
            )>,
            UnixStorageRetirementAdmission,
        ),
        E,
    >
    where
        E: From<JournalError>,
    {
        self.with_unix_retirement_input(FreshInput::Request(request), config, device, now, inspect)
    }

    #[cfg(target_os = "linux")]
    pub fn with_unix_storage_retirement_intent<E>(
        &self,
        intent: &UnixStorageRetirementIntent,
        config: &StorageNodeConfig,
        device: &DeviceId,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(
            &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
        ) -> std::result::Result<
            sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
            E,
        >,
    ) -> std::result::Result<
        (
            Option<(
                crate::CasAccessGuard,
                sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
            )>,
            UnixStorageRetirementAdmission,
        ),
        E,
    >
    where
        E: From<JournalError>,
    {
        self.with_unix_retirement_input(FreshInput::Intent(intent), config, device, now, inspect)
    }

    #[cfg(target_os = "linux")]
    fn with_unix_retirement_input<E>(
        &self,
        input: FreshInput<'_>,
        config: &StorageNodeConfig,
        device: &DeviceId,
        now: impl Fn() -> std::result::Result<u64, E>,
        inspect: impl FnOnce(
            &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
        ) -> std::result::Result<
            sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
            E,
        >,
    ) -> std::result::Result<
        (
            Option<(
                crate::CasAccessGuard,
                sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
            )>,
            UnixStorageRetirementAdmission,
        ),
        E,
    >
    where
        E: From<JournalError>,
    {
        input.validate(config, device)?;
        if !self.connection.is_autocommit() {
            return Err(invalid().into());
        }
        let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)
                .map_err(JournalError::from)?;
            input.scope(&tx, config, device)?;
            let full = self
                .read_view()
                .audit_storage_receive_capacity(&config.space_id, bounds)?;
            if !full.report.within_accounted_limits() || !full.report.coverage_gaps().is_empty() {
                return Err(invalid().into());
            }
            if let Some(old) = input.replay(audit(&tx)?, config, device)? {
                tx.commit().map_err(JournalError::from)?;
                return Ok((None, old));
            }
        }
        if self.original_linux_cas_coordination.is_none() {
            return Err(invalid().into());
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        input.scope(&tx, config, device)?;
        let before = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid().into());
        }
        if let Some(old) = input.replay(audit(&tx)?, config, device)? {
            tx.commit().map_err(JournalError::from)?;
            coordination.close_linux_storage_original()?;
            return Ok((None, old));
        }
        if referenced(&tx, input.content_id())? || self.gc_protected(input.content_id())? {
            return Err(invalid().into());
        }
        self.require_cas_access(input.content_id())?;
        let exclusive = coordination.linux_storage_exclusive()?;
        let held = inspect(&exclusive)?;
        let request = input.materialize(config, device, &exclusive, &held)?;
        verify_original(&request, &exclusive, &held)?;
        let fingerprint = request
            .fingerprint(config, device)
            .map_err(JournalError::from)?;
        let time = now()?;
        let issued = values(&request, config, device, time)?;
        let old_clock: Option<u64> = tx.query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_v1_clock WHERE singleton=1",
            [], |row| crate::sql_u64(row, 0),
        ).optional().map_err(JournalError::from)?;
        if old_clock.is_some_and(|old| time < old) {
            return Err(invalid().into());
        }
        let width = issued.iter().try_fold(0u64, |sum, value| {
            add(
                sum,
                match value {
                    Value::Text(text) => text.len() as u64,
                    Value::Integer(_) => 8,
                    _ => 0,
                },
            )
        })?;
        let delta = TreeStorageCharge {
            // The request, optional exact clock row and one finite cancel row.
            rows: 2 + u64::from(old_clock.is_none()),
            logical_bytes: add(add(width, 40)?, if old_clock.is_none() { 16 } else { 0 })?,
        };
        let expected = TreeStorageCharge {
            rows: add(before.report.accounted_total().rows, delta.rows)?,
            logical_bytes: add(
                before.report.accounted_total().logical_bytes,
                delta.logical_bytes,
            )?,
        };
        if expected.rows > bounds.max_rows || expected.logical_bytes > bounds.max_logical_bytes {
            return Err(invalid().into());
        }
        self.unix_storage_retirement_clock_issue.issue("unix-retirement-clock-v1".into(), time, || {
            if old_clock.is_some() {
                tx.execute(
                    "UPDATE main.unix_storage_retirement_v1_clock SET observed_at_ms=?1 WHERE singleton=1",
                    [crate::sql_integer(time)?],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO main.unix_storage_retirement_v1_clock VALUES(1,?1)",
                    [crate::sql_integer(time)?],
                )?;
            }
            Ok(())
        })?;
        self.unix_storage_retirement_issuance
            .issue(fingerprint.to_string(), time, || {
                tx.execute(
                    "INSERT INTO main.unix_storage_retirement_v1_requests VALUES
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                    rusqlite::params_from_iter(issued.iter()),
                )?;
                Ok(())
            })?;
        verify_original(&request, &exclusive, &held)?;
        let after = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        unchanged(&before, &after)?;
        if after.report.accounted_total() != expected {
            return Err(invalid().into());
        }
        let result = audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == request.request_id)
            .ok_or_else(invalid)?;
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), result))
    }

    /// This family has no native activation in this phase. A cancelled row
    /// consumes its already charged finite liability and never releases an FD.
    #[cfg(target_os = "linux")]
    pub fn cancel_unix_storage_retirement(
        &self,
        request_id: &EntryId,
        config: &StorageNodeConfig,
        device: &DeviceId,
        time: u64,
    ) -> Result<UnixStorageRetirementAdmission> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let old = audit(&tx)?
                .into_iter()
                .find(|row| row.request.request_id == *request_id)
                .ok_or_else(invalid)?;
            scope(&tx, &old.request, config, device)?;
            let before = self
                .read_view()
                .audit_storage_receive_capacity(&config.space_id, bounds)?;
            if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty()
            {
                return Err(invalid());
            }
            if old.cancelled_at_ms.is_some() {
                tx.commit()?;
                return Ok(old);
            }
        }
        if self.original_linux_cas_coordination.is_none() {
            return Err(invalid());
        }
        let mut coordination = self.acquire_cas_coordination()?;
        coordination.try_exclusive()?;
        coordination.linux_storage_exclusive()?.verify()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let old = audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == *request_id)
            .ok_or_else(invalid)?;
        scope(&tx, &old.request, config, device)?;
        let before = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        if !before.report.within_accounted_limits() || !before.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        if old.cancelled_at_ms.is_some() {
            tx.commit()?;
            coordination.close_linux_storage_original()?;
            return Ok(old);
        }
        let clock: u64 = tx.query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_v1_clock WHERE singleton=1",
            [],
            |row| crate::sql_u64(row, 0),
        )?;
        if time < clock {
            return Err(invalid());
        }
        self.unix_storage_retirement_clock_issue.issue("unix-retirement-clock-v1".into(), time, || {
            tx.execute(
                "UPDATE main.unix_storage_retirement_v1_clock SET observed_at_ms=?1 WHERE singleton=1",
                [crate::sql_integer(time)?],
            )?;
            Ok(())
        })?;
        self.unix_storage_retirement_cancellation
            .issue(request_id.to_string(), time, || {
                tx.execute(
                    "INSERT INTO main.unix_storage_retirement_v1_cancellations VALUES(?1,?2)",
                    params![request_id.as_str(), crate::sql_integer(time)?],
                )?;
                Ok(())
            })?;
        let after = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, bounds)?;
        unchanged(&before, &after)?;
        if before.report.accounted_total() != after.report.accounted_total() {
            return Err(invalid());
        }
        let result = audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == *request_id)
            .ok_or_else(invalid)?;
        tx.commit()?;
        coordination.close_linux_storage_original()?;
        Ok(result)
    }
}
