//! Fresh original creator custody and independent terminal release.
//! Every issuing entry point acquires its own fresh admission. Durable facts
//! cannot construct the original boundary or the sealed terminal below.
use super::{
    EVENT_PEAK_BYTES, MAX_EVENTS, RELEASE_PEAK_BYTES,
    UnixStorageRetirementNativeActivation as Activation,
    UnixStorageRetirementNativeDisposition as Disposition,
    UnixStorageRetirementNativeEvent as Event, UnixStorageRetirementNativeEvidence as Evidence,
    UnixStorageRetirementNativeKind as Kind, UnixStorageRetirementNativePayloadSlot as Slot,
    UnixStorageRetirementNativeRelease as Release, UnixStorageRetirementNativeState as State,
    audit, invalid,
};
use crate::{
    CasAccessGuard, Journal, JournalError, Result, storage_capacity::CapacitySnapshot,
    storage_inventory::reader::add, storage_retirement_unix::UnixStorageRetirementAdmission,
};
use rusqlite::{
    OptionalExtension, Transaction, TransactionBehavior, params, params_from_iter, types::Value,
};
use sync_extend_core_model::{
    ContentId, DeviceId, EntryId,
    storage_node::StorageNodeConfig,
    storage_retirement_unix::{
        UnixStorageRetirementBinding, UnixStorageRetirementIntent, UnixStorageRetirementKey,
    },
    tree_storage_capacity::TreeStorageCharge,
};
use sync_extend_platform_fs::{
    LinuxStorageCasDirectoryGuard, LinuxStorageCasExclusiveCoordination,
    LinuxStorageCasExpectedLayout, LinuxStorageCasObservation,
    LinuxStorageRetirementBoundary as Boundary,
    LinuxStorageRetirementClosedBoundary as ClosedBoundary,
    LinuxStorageRetirementInventoryContext as InventoryContext,
    LinuxStorageRetirementInventoryPhase as Phase, LinuxStorageRetirementInventoryPrefix as Prefix,
    LinuxStorageRetirementPayloadSlot as PhysicalSlot, UnixFileKey,
};

fn key(value: UnixFileKey) -> UnixStorageRetirementKey {
    UnixStorageRetirementKey {
        device: value.device,
        inode: value.inode,
    }
}

fn width(values: &[Value]) -> Result<u64> {
    values.iter().try_fold(0u64, |sum, value| {
        add(
            sum,
            match value {
                Value::Text(text) => text.len() as u64,
                Value::Integer(_) => 8,
                _ => return Err(invalid()),
            },
        )
    })
}

fn combine<T>(operation: Result<T>, closed: Result<()>) -> Result<T> {
    match (operation, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(closed)) => Err(JournalError::Io(std::io::Error::other(format!(
            "{error}; original Unix retirement descriptor closure also refused: {closed}"
        )))),
    }
}

fn at_native_step<T>(step: &'static str, result: Result<T>) -> Result<T> {
    result.map_err(|error| {
        JournalError::Io(std::io::Error::other(format!(
            "Unix native retirement {step}: {error}"
        )))
    })
}

fn close_resources(
    coordination: CasAccessGuard,
    boundary: Option<Boundary>,
    closed: Option<ClosedBoundary>,
) -> Result<()> {
    let mut first = None;
    let mut directories: Vec<LinuxStorageCasDirectoryGuard> = Vec::new();
    if let Some(boundary) = boundary {
        match boundary.close() {
            Ok(guard) => directories.push(guard),
            Err(error) => {
                first = Some(JournalError::from(error));
            }
        }
    }
    if let Some(closed) = closed {
        match closed.close() {
            Ok(guard) => directories.push(guard),
            Err(error) => {
                first.get_or_insert(JournalError::from(error));
            }
        }
    }
    if let Err(error) = coordination.close_linux_storage_original() {
        first.get_or_insert(error);
    }
    for directories in directories {
        if let Err(error) = directories.close() {
            first.get_or_insert(JournalError::from(error));
        }
    }
    first.map_or(Ok(()), Err)
}

fn close_inspection(
    coordination: CasAccessGuard,
    original: sync_extend_platform_fs::LinuxStorageCasRetirementInspection,
) -> Result<()> {
    let closed = original.close_file().map_err(JournalError::from);
    let coordination = coordination.close_linux_storage_original();
    match closed {
        Ok(directories) => combine(
            coordination,
            directories.close().map_err(JournalError::from),
        ),
        Err(error) => combine(Err(error), coordination),
    }
}

fn verify_layout(
    binding: &UnixStorageRetirementBinding,
    exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    layout: &LinuxStorageCasObservation,
) -> Result<()> {
    binding.validate()?;
    exclusive.verify()?;
    if binding.owner_process_id != std::process::id()
        || binding.outside_data != key(exclusive.outside_data_key()?)
        || binding.coordination != key(exclusive.coordination_key()?)
        || binding.backing_image != key(layout.expected_layout.backing_image)
        || binding.image_filesystem_id != layout.expected_layout.image_filesystem_id
        || binding.owner_uid != layout.expected_layout.owner_uid
        || binding.owner_generation != layout.owner_generation
        || binding.namespace != key(layout.namespace)
        || binding.runtime_mount_id != layout.runtime_mount_id
        || binding.mounted_root != key(layout.mounted_root)
        || binding.cas != key(layout.cas)
        || binding.objects != key(layout.objects)
        || binding.temporary != key(layout.temporary)
        || binding.realm != key(layout.realm)
        || binding.realm_fingerprint.as_str().as_bytes() != layout.expected_layout.realm_fingerprint
    {
        return Err(invalid());
    }
    Ok(())
}

fn physical_evidence(
    activation: &Activation,
    content: &ContentId,
    exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    boundary: &Boundary,
) -> Result<Evidence> {
    boundary.verify(exclusive)?;
    verify_layout(
        &activation.runtime_binding,
        exclusive,
        &boundary.layout_observation(exclusive)?,
    )?;
    let marker = boundary.original_marker_observation(exclusive)?;
    let payload = boundary.payload_observation(exclusive)?;
    let slot = boundary.current_payload_slot(exclusive)?;
    let binding = &activation.runtime_binding;
    if key(payload.identity) != binding.payload
        || key(payload.parent) != binding.shard
        || payload.length != u64::from(binding.length)
        || payload.modified_seconds != binding.modified_seconds
        || payload.modified_nanoseconds != i64::from(binding.modified_nanoseconds)
        || !marker.original_creator
        || !marker.mandatory_original_write_lease
    {
        return Err(invalid());
    }
    let closed = matches!(slot, PhysicalSlot::Unlinked | PhysicalSlot::RestoredClosed);
    if !closed {
        let bytes = boundary.read_payload(exclusive)?;
        if !payload.mandatory_original_write_lease || ContentId::hash(&bytes) != *content {
            return Err(invalid());
        }
    }
    let slot = match slot {
        PhysicalSlot::Original => Slot::Original,
        PhysicalSlot::Quarantine => Slot::Quarantine,
        PhysicalSlot::Restored => Slot::Restored,
        PhysicalSlot::UnlinkedLive => Slot::UnlinkedLive,
        PhysicalSlot::Unlinked => Slot::UnlinkedClosed,
        PhysicalSlot::RestoredClosed => Slot::RestoredClosed,
    };
    let moved = slot != Slot::Original;
    if matches!(
        slot,
        Slot::Quarantine | Slot::Restored | Slot::RestoredClosed
    ) {
        let observed = boundary.move_observation(exclusive)?;
        if !observed.source_slot_absent
            || !observed.both_original_parents_synced
            || observed.original_payload_descriptor_closed != closed
        {
            return Err(invalid());
        }
    } else if matches!(slot, Slot::UnlinkedLive | Slot::UnlinkedClosed) {
        let observed = boundary.unlink_observation(exclusive)?;
        if !observed.original_nlink_zero_verified
            || !observed.parent_synced
            || !observed.original_slot_absent
            || !observed.quarantine_slot_absent
            || observed.original_payload_descriptor_closed != closed
        {
            return Err(invalid());
        }
    }
    let marker_unlinked = !marker.private_single_link;
    if marker_unlinked {
        let observed = boundary.marker_unlink_observation(exclusive)?;
        if !observed.original_nlink_zero_verified
            || !observed.parent_synced
            || observed.original_marker_descriptor_closed
        {
            return Err(invalid());
        }
    }
    Ok(Evidence {
        format_version: 1,
        request_id: activation.request_id.clone(),
        activation_id: activation.activation_id.clone(),
        runtime_binding_fingerprint: binding.fingerprint()?,
        marker_identity: key(marker.identity),
        marker_parent: key(marker.parent),
        marker_component: marker.component,
        marker_bytes_hash: ContentId::hash(&marker.bytes),
        payload_slot: slot,
        payload_hash_observed: !closed,
        original_payload_nlink_zero_verified: matches!(
            slot,
            Slot::UnlinkedLive | Slot::UnlinkedClosed
        ),
        original_payload_descriptor_closed: closed,
        original_marker_nlink_zero_verified: marker_unlinked,
        original_marker_descriptor_closed: false,
        original_owner_descriptors_closed: false,
        original_slot_absent: !matches!(
            slot,
            Slot::Original | Slot::Restored | Slot::RestoredClosed
        ),
        quarantine_slot_absent: slot != Slot::Quarantine,
        marker_slot_absent: marker_unlinked,
        payload_parents_synced: moved,
        marker_parent_synced: true,
        independent_owner_slots_observed: false,
        backup_complete: false,
    })
}

fn closed_evidence(
    activation: &Activation,
    exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    closed: &ClosedBoundary,
) -> Result<Evidence> {
    closed.verify(exclusive)?;
    verify_layout(
        &activation.runtime_binding,
        exclusive,
        &closed.layout_observation(exclusive)?,
    )?;
    let observed = closed.observation(exclusive)?;
    let restored = observed.restored_payload_identity.is_some();
    if !observed.original_owner_descriptors_closed
        || !observed.original_marker_nlink_zero_verified
        || !observed.independent_marker_slot_absent
        || !observed.independent_quarantine_slot_absent
        || observed.independent_original_slot_absent == restored
        || key(observed.original_parent) != activation.runtime_binding.shard
        || observed
            .restored_payload_identity
            .is_some_and(|value| key(value) != activation.runtime_binding.payload)
    {
        return Err(invalid());
    }
    Ok(Evidence {
        format_version: 1,
        request_id: activation.request_id.clone(),
        activation_id: activation.activation_id.clone(),
        runtime_binding_fingerprint: activation.runtime_binding.fingerprint()?,
        marker_identity: key(observed.marker_identity),
        marker_parent: key(observed.marker_parent),
        marker_component: observed.marker_component,
        marker_bytes_hash: ContentId::hash(
            format!("{}:{}", activation.request_id, activation.activation_id).as_bytes(),
        ),
        payload_slot: if restored {
            Slot::RestoredClosed
        } else {
            Slot::UnlinkedClosed
        },
        payload_hash_observed: false,
        original_payload_nlink_zero_verified: !restored,
        original_payload_descriptor_closed: true,
        original_marker_nlink_zero_verified: observed.original_marker_nlink_zero_verified,
        original_marker_descriptor_closed: observed.original_owner_descriptors_closed,
        original_owner_descriptors_closed: observed.original_owner_descriptors_closed,
        original_slot_absent: observed.independent_original_slot_absent,
        quarantine_slot_absent: observed.independent_quarantine_slot_absent,
        marker_slot_absent: observed.independent_marker_slot_absent,
        payload_parents_synced: true,
        marker_parent_synced: observed.marker_parent_synced,
        independent_owner_slots_observed: true,
        backup_complete: false,
    })
}

fn phase(state: &State) -> Result<Phase> {
    let deleted = state.deleted_branch();
    let branched = |yes, no| {
        deleted
            .map(|deleted| if deleted { yes } else { no })
            .ok_or_else(invalid)
    };
    if state.release.is_some() {
        return branched(Phase::ReleasedDeleted, Phase::ReleasedRestored);
    }
    Ok(match state.events.last().map(|event| event.kind) {
        None => Phase::ActivationUnreceipted,
        Some(Kind::CreatorReceipted) => Phase::CreatorReceipted,
        Some(Kind::QuarantineRequested) => Phase::QuarantineRequested,
        Some(Kind::QuarantineObserved) => Phase::Quarantined,
        Some(Kind::DeleteRequested) => Phase::DeleteRequested,
        Some(Kind::RestoreRequested) => Phase::RestoreRequested,
        Some(Kind::PayloadUnlinked) => Phase::PayloadUnlinked,
        Some(Kind::RestoreObserved) => Phase::Restored,
        Some(Kind::PayloadCloseRequested) => Phase::PayloadCloseRequested,
        Some(Kind::RestoredCloseRequested) => Phase::RestoredCloseRequested,
        Some(Kind::PayloadClosed) => Phase::PayloadUnlinkedClosed,
        Some(Kind::RestoredClosed) => Phase::RestoredClosed,
        Some(Kind::MarkerUnlinkRequested) => {
            return branched(
                Phase::MarkerUnlinkRequestedDeleted,
                Phase::MarkerUnlinkRequestedRestored,
            );
        }
        Some(Kind::MarkerUnlinked) => {
            return branched(Phase::MarkerUnlinkedDeleted, Phase::MarkerUnlinkedRestored);
        }
        Some(Kind::OwnerCloseRequested) => {
            return branched(
                Phase::OwnerCloseRequestedDeleted,
                Phase::OwnerCloseRequestedRestored,
            );
        }
        Some(Kind::OwnerClosed) => {
            return branched(Phase::OwnerClosedDeleted, Phase::OwnerClosedRestored);
        }
        Some(Kind::TerminalDeleted) => Phase::TerminalDeleted,
        Some(Kind::TerminalRestoredClosed) => Phase::TerminalRestored,
    })
}

impl Journal {
    /// Accounting expectations from the complete immutable family. This object
    /// grants no CREATE, descriptor custody, recovery or release capability.
    pub fn unix_storage_retirement_inventory_context(
        &self,
        expected: LinuxStorageCasExpectedLayout,
    ) -> Result<InventoryContext> {
        let states = self.unix_storage_retirement_native_states()?;
        let mut prefixes = Vec::with_capacity(states.len());
        for state in states {
            let binding = &state.activation.runtime_binding;
            if binding.backing_image != key(expected.backing_image)
                || binding.image_filesystem_id != expected.image_filesystem_id
                || binding.mounted_root.inode != expected.mounted_root_inode
                || binding.cas.inode != expected.cas_inode
                || binding.objects.inode != expected.objects_inode
                || binding.temporary.inode != expected.temporary_inode
                || binding.realm.inode != expected.realm_inode
                || binding.owner_uid != expected.owner_uid
                || binding.realm_fingerprint.as_str().as_bytes() != expected.realm_fingerprint
            {
                return Err(invalid());
            }
            prefixes.push(Prefix {
                request_id: state.activation.request_id.to_string(),
                activation_id: state.activation.activation_id.to_string(),
                content: state.request.request.content_id.to_string(),
                original_parent_inode: binding.shard.inode,
                original_payload_inode: binding.payload.inode,
                length: u64::from(binding.length),
                modified_seconds: binding.modified_seconds,
                modified_nanoseconds: i64::from(binding.modified_nanoseconds),
                marker_inode: state
                    .events
                    .first()
                    .map(|event| event.evidence.marker_identity.inode),
                phase: phase(&state)?,
            });
        }
        Ok(InventoryContext::from_audited_prefixes(expected, prefixes)?)
    }

    fn native_capacity(&self, config: &StorageNodeConfig) -> Result<CapacitySnapshot> {
        let full = self.read_view().audit_storage_receive_capacity(
            &config.space_id,
            self.writer_capacity_limits(config.max_metadata_entries)?,
        )?;
        if !full.report.within_accounted_limits() || !full.report.coverage_gaps().is_empty() {
            return Err(invalid());
        }
        Ok(full)
    }

    fn native_clock(&self, tx: &Transaction<'_>, time: u64) -> Result<()> {
        let base: u64 = tx.query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_v1_clock WHERE singleton=1",
            [],
            |row| crate::sql_u64(row, 0),
        )?;
        let native: Option<u64> = tx.query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_native_v1_clock WHERE singleton=1",
            [], |row| crate::sql_u64(row, 0),
        ).optional()?;
        if time < base || native.is_some_and(|old| time < old) {
            return Err(invalid());
        }
        self.unix_storage_retirement_clock_issue.issue("unix-retirement-clock-v1".into(), time, || {
            if tx.execute(
                "UPDATE main.unix_storage_retirement_v1_clock SET observed_at_ms=?1 WHERE singleton=1",
                [crate::sql_integer(time)?],
            )? != 1 { return Err(invalid()); }
            Ok(())
        })?;
        self.unix_storage_retirement_native_gates.clock.issue("unix-retirement-native-clock-v1".into(), time, || {
            let changed = if native.is_some() {
                tx.execute(
                    "UPDATE main.unix_storage_retirement_native_v1_clock SET observed_at_ms=?1 WHERE singleton=1",
                    [crate::sql_integer(time)?],
                )?
            } else {
                tx.execute(
                    "INSERT INTO main.unix_storage_retirement_native_v1_clock VALUES(1,?1)",
                    [crate::sql_integer(time)?],
                )?
            };
            if changed != 1 { return Err(invalid()); }
            Ok(())
        })
    }

    fn native_activation(
        &self,
        admission: &UnixStorageRetirementAdmission,
        activation_id: &EntryId,
        config: &StorageNodeConfig,
        device: &DeviceId,
        time: u64,
    ) -> Result<Activation> {
        if !self.connection.is_autocommit()
            || admission.cancelled_at_ms.is_some()
            || !admission.content_fenced
        {
            return Err(invalid());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        super::super::scope(&tx, &admission.request, config, device)?;
        if audit(&tx)?.iter().any(|state| {
            state.activation.request_id == admission.request.request_id
                || state.activation.activation_id == *activation_id
        }) {
            return Err(invalid());
        }
        let before = self.native_capacity(config)?;
        let activation = Activation {
            format_version: 1,
            activation_id: activation_id.clone(),
            request_id: admission.request.request_id.clone(),
            request_fingerprint: admission.request_fingerprint.clone(),
            runtime_binding: admission.request.binding.clone(),
            activated_at_ms: time,
        };
        activation.validate(admission)?;
        let values = activation.values()?;
        let native_clock: Option<u64> = tx.query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_native_v1_clock WHERE singleton=1",
            [], |row| crate::sql_u64(row, 0),
        ).optional()?;
        let delta = TreeStorageCharge {
            rows: 1 + u64::from(MAX_EVENTS) + 1 + u64::from(native_clock.is_none()),
            logical_bytes: add(
                add(
                    width(&values)?,
                    add(
                        u64::from(MAX_EVENTS)
                            .checked_mul(EVENT_PEAK_BYTES)
                            .ok_or_else(invalid)?,
                        RELEASE_PEAK_BYTES,
                    )?,
                )?,
                if native_clock.is_none() { 16 } else { 0 },
            )?,
        };
        let bounds = self.writer_capacity_limits(config.max_metadata_entries)?;
        let expected = TreeStorageCharge {
            rows: add(before.report.accounted_total().rows, delta.rows)?,
            logical_bytes: add(
                before.report.accounted_total().logical_bytes,
                delta.logical_bytes,
            )?,
        };
        if expected.rows > bounds.max_rows || expected.logical_bytes > bounds.max_logical_bytes {
            return Err(invalid());
        }
        self.native_clock(&tx, time)?;
        self.unix_storage_retirement_native_gates.activation.issue(activation.fingerprint()?.to_string(), time, || {
            if tx.execute(
                "INSERT INTO main.unix_storage_retirement_native_v1_activations VALUES(?1,?2,?3,?4,?5,?6)",
                params_from_iter(values.iter()),
            )? != 1 { return Err(invalid()); }
            Ok(())
        })?;
        let after = self.native_capacity(config)?;
        collateral(&before, &after)?;
        if after.report.accounted_total() != expected {
            return Err(invalid());
        }
        tx.commit()?;
        Ok(activation)
    }

    fn native_event(
        &self,
        activation: &Activation,
        kind: Kind,
        evidence: Evidence,
        config: &StorageNodeConfig,
        device: &DeviceId,
        time: u64,
    ) -> Result<State> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let current = at_native_step("event prior durable audit", audit(&tx))?
            .into_iter()
            .find(|state| state.activation == *activation)
            .ok_or_else(invalid)?;
        at_native_step("event retained scope", super::super::scope(&tx, &current.request.request, config, device))?;
        if current.release.is_some()
            || current.sequence() + 1 != kind.sequence()
            || time
                < current
                    .events
                    .last()
                    .map_or(activation.activated_at_ms, |event| event.observed_at_ms)
            || (kind.request() && time >= current.request.request.expires_at_ms)
        {
            return Err(JournalError::Invariant("Unix native event sequence, release or time differs"));
        }
        let deleted = if kind.sequence() == 4 {
            kind.deleted_branch()
        } else {
            current.deleted_branch()
        };
        at_native_step("event evidence validation", evidence.validate(activation, kind, deleted))?;
        let event = at_native_step("event fingerprint", Event::new(activation, kind, current.previous_hash(), time, evidence))?;
        let values = at_native_step("event durable values", event.values())?;
        let actual_width = width(&values)?;
        if actual_width > EVENT_PEAK_BYTES {
            return Err(JournalError::Invariant("Unix native event exceeds reserved width"));
        }
        let before = at_native_step("event before capacity", self.native_capacity(config))?;
        at_native_step("event monotonic clock", self.native_clock(&tx, time))?;
        self.unix_storage_retirement_native_gates.event.issue(event.event_fingerprint.to_string(), time, || {
            if tx.execute(
                "INSERT INTO main.unix_storage_retirement_native_v1_events VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params_from_iter(values.iter()),
            )? != 1 { return Err(invalid()); }
            Ok(())
        })?;
        let after = at_native_step("event after capacity", self.native_capacity(config))?;
        at_native_step("event collateral comparison", collateral(&before, &after))?;
        if after.report.accounted_total().rows != before.report.accounted_total().rows
            || after.report.accounted_total().logical_bytes
                != before
                    .report
                    .accounted_total()
                    .logical_bytes
                    .checked_sub(EVENT_PEAK_BYTES)
                    .and_then(|bytes| bytes.checked_add(actual_width))
                    .ok_or_else(invalid)?
        {
            return Err(JournalError::Invariant("Unix native event accounted capacity delta differs"));
        }
        let state = at_native_step("event new durable audit", audit(&tx))?
            .into_iter()
            .find(|state| state.activation == *activation)
            .ok_or_else(invalid)?;
        tx.commit()?;
        Ok(state)
    }

    fn native_effect_time_and_scope(
        &self,
        activation: &Activation,
        config: &StorageNodeConfig,
        time: u64,
    ) -> Result<State> {
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let state = audit(&self.connection)?
            .into_iter()
            .find(|state| state.activation == *activation)
            .ok_or_else(invalid)?;
        super::super::scope(
            &self.connection,
            &state.request.request,
            config,
            &state.request.request.storage_device,
        )?;
        if time < activation.activated_at_ms
            || time >= state.request.request.expires_at_ms
            || state.release.is_some()
            || state.request.cancelled_at_ms.is_some()
            || !state.request.content_fenced
            || state
                .events
                .last()
                .is_some_and(|event| time < event.observed_at_ms)
        {
            return Err(invalid());
        }
        for table in [
            "unix_storage_retirement_v1_clock",
            "unix_storage_retirement_native_v1_clock",
        ] {
            let current: u64 = self.connection.query_row(
                &format!("SELECT observed_at_ms FROM main.{table} WHERE singleton=1"),
                [],
                |row| crate::sql_u64(row, 0),
            )?;
            if time < current {
                return Err(invalid());
            }
        }
        self.native_capacity(config)?;
        tx.rollback()?;
        Ok(state)
    }

    fn native_pre_effect(
        &self,
        activation: &Activation,
        config: &StorageNodeConfig,
        time: u64,
    ) -> Result<()> {
        let state = self.native_effect_time_and_scope(activation, config, time)?;
        if state
            .events
            .last()
            .is_none_or(|event| !event.kind.request())
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// Consume a freshly inspected intent in this same original owner. The
    /// twelve-step terminal keeps both its content fence and original loan.
    pub fn execute_unix_storage_retirement_intent<'journal>(
        &'journal self,
        intent: &UnixStorageRetirementIntent,
        config: &StorageNodeConfig,
        device: &DeviceId,
        activation_id: &EntryId,
        disposition: Disposition,
        now: impl Fn() -> Result<u64>,
        inspect: impl FnOnce(
            &LinuxStorageCasExclusiveCoordination<'_>,
        )
            -> Result<sync_extend_platform_fs::LinuxStorageCasRetirementInspection>,
    ) -> Result<UnixStorageRetirementNativeTerminal<'journal>> {
        if activation_id == &intent.request_id {
            return Err(invalid());
        }
        let (held, admission) =
            self.with_unix_storage_retirement_intent(intent, config, device, &now, inspect)?;
        let (coordination, original) = held.ok_or_else(invalid)?;
        let verified = (|| {
            let exclusive = coordination.linux_storage_exclusive()?;
            super::super::verify_original(&admission.request, &exclusive, &original)
        })();
        if let Err(error) = verified {
            return combine(Err(error), close_inspection(coordination, original));
        }
        let boundary = {
            // The exclusive borrow above was verified while the same actual
            // coordination and original inspection remained live.
            let exclusive = match coordination.linux_storage_exclusive() {
                Ok(exclusive) => exclusive,
                Err(error) => return combine(Err(error), close_inspection(coordination, original)),
            };
            original.into_storage_retirement_boundary(
                &exclusive,
                admission.request.request_id.as_str(),
                activation_id.as_str(),
            )
        };
        let boundary = match boundary {
            Ok(boundary) => boundary,
            Err(error) => {
                return combine(
                    Err(error.into()),
                    coordination.close_linux_storage_original(),
                );
            }
        };
        let mut boundary = Some(boundary);
        let mut closed = None;
        let operation = (|| {
            let exclusive = coordination.linux_storage_exclusive()?;
            let activation =
                self.native_activation(&admission, activation_id, config, device, now()?)?;
            let live = boundary.as_mut().expect("live original boundary");
            verify_layout(
                &activation.runtime_binding,
                &exclusive,
                &live.layout_observation(&exclusive)?,
            )?;
            let context = self.unix_storage_retirement_inventory_context(
                live.layout_observation(&exclusive)?.expected_layout,
            )?;
            let create_time = now()?;
            let before_create =
                self.native_effect_time_and_scope(&activation, config, create_time)?;
            if !before_create.events.is_empty() {
                return Err(invalid());
            }
            live.create_marker(&exclusive, &context)?;
            {
                let receipt = live.consume_creator_receipt(&exclusive)?;
                let marker = receipt.observation(&exclusive)?;
                let bytes = receipt.read_payload(&exclusive)?;
                if ContentId::hash(&bytes) != admission.request.content_id
                    || ContentId::hash(&marker.bytes)
                        != ContentId::hash(
                            format!("{}:{}", admission.request.request_id, activation_id)
                                .as_bytes(),
                        )
                {
                    return Err(invalid());
                }
            }
            let evidence = |live: &Boundary| {
                let context = at_native_step("physical evidence inventory context", self.unix_storage_retirement_inventory_context(
                    live.layout_observation(&exclusive)?.expected_layout,
                ))?;
                live.inventory_with_retirement_prefixes(&exclusive, &context)?;
                at_native_step("physical evidence original payload", physical_evidence(&activation, &admission.request.content_id, &exclusive, live))
            };
            self.native_event(
                &activation,
                Kind::CreatorReceipted,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_event(
                &activation,
                Kind::QuarantineRequested,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_pre_effect(&activation, config, now()?)?;
            live.quarantine(&exclusive)?;
            self.native_event(
                &activation,
                Kind::QuarantineObserved,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            let delete = disposition == Disposition::Delete;
            let request = if delete {
                Kind::DeleteRequested
            } else {
                Kind::RestoreRequested
            };
            self.native_event(
                &activation,
                request,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_pre_effect(&activation, config, now()?)?;
            if delete {
                live.unlink_payload(&exclusive)?;
            } else {
                live.restore(&exclusive)?;
            }
            self.native_event(
                &activation,
                if delete {
                    Kind::PayloadUnlinked
                } else {
                    Kind::RestoreObserved
                },
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            at_native_step("record restored/deleted payload close request", self.native_event(
                &activation,
                if delete {
                    Kind::PayloadCloseRequested
                } else {
                    Kind::RestoredCloseRequested
                },
                at_native_step("observe restored/deleted payload before close request", evidence(live))?,
                config,
                device,
                now()?,
            ))?;
            self.native_pre_effect(&activation, config, now()?)?;
            if delete {
                live.close_unlinked_payload(&exclusive)?;
            } else {
                live.close_restored_payload(&exclusive)?;
            }
            self.native_event(
                &activation,
                if delete {
                    Kind::PayloadClosed
                } else {
                    Kind::RestoredClosed
                },
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_event(
                &activation,
                Kind::MarkerUnlinkRequested,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_pre_effect(&activation, config, now()?)?;
            live.unlink_marker(&exclusive)?;
            self.native_event(
                &activation,
                Kind::MarkerUnlinked,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_event(
                &activation,
                Kind::OwnerCloseRequested,
                evidence(live)?,
                config,
                device,
                now()?,
            )?;
            self.native_pre_effect(&activation, config, now()?)?;
            closed = Some(
                boundary
                    .take()
                    .expect("original owner still held")
                    .close_unlinked_marker_owner(&exclusive)?,
            );
            let witness = closed.as_ref().expect("independent owner witnesses");
            let context = self.unix_storage_retirement_inventory_context(
                witness.layout_observation(&exclusive)?.expected_layout,
            )?;
            witness.inventory_with_retirement_prefixes(&exclusive, &context)?;
            self.native_event(
                &activation,
                Kind::OwnerClosed,
                closed_evidence(&activation, &exclusive, witness)?,
                config,
                device,
                now()?,
            )?;
            self.native_event(
                &activation,
                if delete {
                    Kind::TerminalDeleted
                } else {
                    Kind::TerminalRestoredClosed
                },
                closed_evidence(&activation, &exclusive, witness)?,
                config,
                device,
                now()?,
            )
        })();
        match operation {
            Ok(state) => Ok(UnixStorageRetirementNativeTerminal {
                journal: self,
                coordination: Some(coordination),
                closed,
                config: config.clone(),
                device: device.clone(),
                state,
            }),
            Err(error) => combine(Err(error), close_resources(coordination, boundary, closed)),
        }
    }
}

fn collateral(before: &CapacitySnapshot, after: &CapacitySnapshot) -> Result<()> {
    let collateral = |snapshot: &CapacitySnapshot| {
        snapshot
            .rows
            .iter()
            .filter(|row| {
                !row.table()
                    .starts_with("unix_storage_retirement_native_v1_")
                    && row.table() != "unix_storage_retirement_v1_clock"
                    && row.table() != "unix_storage_retirement_v1_cancellations"
            })
            .map(|row| {
                (
                    row.table().to_owned(),
                    row.primary_key().to_vec(),
                    row.fingerprint().clone(),
                )
            })
            .collect::<Vec<_>>()
    };
    if collateral(before) != collateral(after) {
        return Err(invalid());
    }
    Ok(())
}

/// Actual terminal custody. No Clone, Deserialize, identifier-only constructor
/// or recovered-history constructor exists. Closing it preserves the fence;
/// releasing it is a distinct invocation through the live original gate.
#[must_use = "explicitly release or close every original terminal witness"]
pub struct UnixStorageRetirementNativeTerminal<'journal> {
    journal: &'journal Journal,
    coordination: Option<CasAccessGuard>,
    closed: Option<ClosedBoundary>,
    config: StorageNodeConfig,
    device: DeviceId,
    state: State,
}

impl UnixStorageRetirementNativeTerminal<'_> {
    pub fn observation(&self) -> Result<State> {
        let coordination = self.coordination.as_ref().ok_or_else(invalid)?;
        let exclusive = coordination.linux_storage_exclusive()?;
        let closed = self.closed.as_ref().ok_or_else(invalid)?;
        let context = self.journal.unix_storage_retirement_inventory_context(
            closed.layout_observation(&exclusive)?.expected_layout,
        )?;
        closed.inventory_with_retirement_prefixes(&exclusive, &context)?;
        let evidence = closed_evidence(&self.state.activation, &exclusive, closed)?;
        evidence.validate(
            &self.state.activation,
            self.state.events.last().ok_or_else(invalid)?.kind,
            self.state.deleted_branch(),
        )?;
        let current = self
            .journal
            .unix_storage_retirement_native_states()?
            .into_iter()
            .find(|state| state.activation == self.state.activation)
            .ok_or_else(invalid)?;
        if !current.terminal_recorded
            || current.previous_hash() != self.state.previous_hash()
            || current.release.is_some()
        {
            return Err(invalid());
        }
        Ok(current)
    }

    pub fn close(mut self) -> Result<()> {
        close_resources(
            self.coordination.take().ok_or_else(invalid)?,
            None,
            self.closed.take(),
        )
    }

    /// Independent explicit release consumes this same original terminal and
    /// a newly observed monotonic time. Terminal history alone cannot call it.
    pub fn release(mut self, now: impl Fn() -> Result<u64>) -> Result<State> {
        let operation = (|| {
            let current = self.observation()?;
            let time = now()?;
            let tx = Transaction::new_unchecked(
                &self.journal.connection,
                TransactionBehavior::Immediate,
            )?;
            super::super::scope(&tx, &current.request.request, &self.config, &self.device)?;
            let before = self.journal.native_capacity(&self.config)?;
            if time < current.events.last().ok_or_else(invalid)?.observed_at_ms {
                return Err(invalid());
            }
            let release = Release {
                format_version: 1,
                activation_id: current.activation.activation_id.clone(),
                request_id: current.activation.request_id.clone(),
                terminal_fingerprint: current.previous_hash().clone(),
                released_at_ms: time,
                backup_complete: false,
            };
            let values = release.values()?;
            let actual_width = width(&values)?;
            if actual_width > RELEASE_PEAK_BYTES {
                return Err(invalid());
            }
            self.journal.native_clock(&tx, time)?;
            self.journal.unix_storage_retirement_native_gates.release.issue(
                release.fingerprint()?.to_string(), time, || {
                    if tx.execute(
                        "INSERT INTO main.unix_storage_retirement_native_v1_releases VALUES(?1,?2,?3,?4,?5,?6)",
                        params_from_iter(values.iter()),
                    )? != 1 { return Err(invalid()); }
                    Ok(())
                },
            )?;
            self.journal.unix_storage_retirement_cancellation.issue(
                release.request_id.to_string(),
                time,
                || {
                    if tx.execute(
                        "INSERT INTO main.unix_storage_retirement_v1_cancellations VALUES(?1,?2)",
                        params![release.request_id.as_str(), crate::sql_integer(time)?],
                    )? != 1
                    {
                        return Err(invalid());
                    }
                    Ok(())
                },
            )?;
            let after = self.journal.native_capacity(&self.config)?;
            collateral(&before, &after)?;
            if after.report.accounted_total().rows != before.report.accounted_total().rows
                || after.report.accounted_total().logical_bytes
                    != before
                        .report
                        .accounted_total()
                        .logical_bytes
                        .checked_sub(RELEASE_PEAK_BYTES)
                        .and_then(|bytes| bytes.checked_add(actual_width))
                        .ok_or_else(invalid)?
            {
                return Err(invalid());
            }
            let state = audit(&tx)?
                .into_iter()
                .find(|state| state.activation == current.activation)
                .ok_or_else(invalid)?;
            let coordination = self.coordination.as_ref().ok_or_else(invalid)?;
            let exclusive = coordination.linux_storage_exclusive()?;
            self.closed
                .as_ref()
                .ok_or_else(invalid)?
                .verify(&exclusive)?;
            tx.commit()?;
            Ok(state)
        })();
        let closed = self.close();
        combine(operation, closed)
    }
}
