//! Immutable native history is an audited prefix, never reconstructed authority.
use crate::{
    Journal, JournalError, Result,
    storage_inventory::reader::{add, preflight},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, types::Value};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    ContentId, EntryId,
    storage_retirement_unix::{
        UnixStorageRetirementBinding, UnixStorageRetirementExpectation, UnixStorageRetirementKey,
    },
    tree_storage_capacity::TreeStorageCharge,
};

#[cfg(target_os = "linux")]
#[path = "native_linux.rs"]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::UnixStorageRetirementNativeTerminal;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixStorageRetirementNativeDisposition {
    Delete,
    Restore,
}

pub(super) const MAX_EVENTS: u32 = 12;
pub(super) const EVENT_PEAK_BYTES: u64 = 32 + 8 + 48 + 8 + 64 + 64 + 4096;
pub(super) const RELEASE_PEAK_BYTES: u64 = 32 + 32 + 64 + 8 + 64 + 2048;

pub(super) fn invalid() -> JournalError {
    JournalError::Invariant("complete original Unix native durable prefix")
}

pub(crate) struct Gates {
    activation: crate::storage_retirement::gate::Gate,
    event: crate::storage_retirement::gate::Gate,
    clock: crate::storage_retirement::gate::Gate,
    release: crate::storage_retirement::gate::Gate,
}

impl Gates {
    pub(crate) fn register(connection: &Connection) -> Result<Self> {
        super::schema::validate(connection)?;
        super::native_schema::validate(connection)?;
        Ok(Self {
            activation: crate::storage_retirement::gate::Gate::register(
                connection,
                "sync_unix_storage_retirement_native_activation",
            )?,
            event: crate::storage_retirement::gate::Gate::register(
                connection,
                "sync_unix_storage_retirement_native_event",
            )?,
            clock: crate::storage_retirement::gate::Gate::register(
                connection,
                "sync_unix_storage_retirement_native_clock",
            )?,
            release: crate::storage_retirement::gate::Gate::register(
                connection,
                "sync_unix_storage_retirement_native_release",
            )?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixStorageRetirementNativeKind {
    CreatorReceipted,
    QuarantineRequested,
    QuarantineObserved,
    DeleteRequested,
    RestoreRequested,
    PayloadUnlinked,
    RestoreObserved,
    PayloadCloseRequested,
    RestoredCloseRequested,
    PayloadClosed,
    RestoredClosed,
    MarkerUnlinkRequested,
    MarkerUnlinked,
    OwnerCloseRequested,
    OwnerClosed,
    TerminalDeleted,
    TerminalRestoredClosed,
}

impl UnixStorageRetirementNativeKind {
    pub fn as_str(self) -> &'static str {
        use UnixStorageRetirementNativeKind as K;
        match self {
            K::CreatorReceipted => "creator_receipted",
            K::QuarantineRequested => "quarantine_requested",
            K::QuarantineObserved => "quarantine_observed",
            K::DeleteRequested => "delete_requested",
            K::RestoreRequested => "restore_requested",
            K::PayloadUnlinked => "payload_unlinked",
            K::RestoreObserved => "restore_observed",
            K::PayloadCloseRequested => "payload_close_requested",
            K::RestoredCloseRequested => "restored_close_requested",
            K::PayloadClosed => "payload_closed",
            K::RestoredClosed => "restored_closed",
            K::MarkerUnlinkRequested => "marker_unlink_requested",
            K::MarkerUnlinked => "marker_unlinked",
            K::OwnerCloseRequested => "owner_close_requested",
            K::OwnerClosed => "owner_closed",
            K::TerminalDeleted => "terminal_deleted",
            K::TerminalRestoredClosed => "terminal_restored_closed",
        }
    }

    pub(super) fn sequence(self) -> u32 {
        use UnixStorageRetirementNativeKind as K;
        match self {
            K::CreatorReceipted => 1,
            K::QuarantineRequested => 2,
            K::QuarantineObserved => 3,
            K::DeleteRequested | K::RestoreRequested => 4,
            K::PayloadUnlinked | K::RestoreObserved => 5,
            K::PayloadCloseRequested | K::RestoredCloseRequested => 6,
            K::PayloadClosed | K::RestoredClosed => 7,
            K::MarkerUnlinkRequested => 8,
            K::MarkerUnlinked => 9,
            K::OwnerCloseRequested => 10,
            K::OwnerClosed => 11,
            K::TerminalDeleted | K::TerminalRestoredClosed => 12,
        }
    }

    pub(super) fn request(self) -> bool {
        use UnixStorageRetirementNativeKind as K;
        matches!(
            self,
            K::QuarantineRequested
                | K::DeleteRequested
                | K::RestoreRequested
                | K::PayloadCloseRequested
                | K::RestoredCloseRequested
                | K::MarkerUnlinkRequested
                | K::OwnerCloseRequested
        )
    }

    pub(super) fn deleted_branch(self) -> Option<bool> {
        use UnixStorageRetirementNativeKind as K;
        match self {
            K::DeleteRequested
            | K::PayloadUnlinked
            | K::PayloadCloseRequested
            | K::PayloadClosed
            | K::TerminalDeleted => Some(true),
            K::RestoreRequested
            | K::RestoreObserved
            | K::RestoredCloseRequested
            | K::RestoredClosed
            | K::TerminalRestoredClosed => Some(false),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnixStorageRetirementNativePayloadSlot {
    Original,
    Quarantine,
    Restored,
    UnlinkedLive,
    UnlinkedClosed,
    RestoredClosed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixStorageRetirementNativeActivation {
    pub format_version: u32,
    pub activation_id: EntryId,
    pub request_id: EntryId,
    pub request_fingerprint: ContentId,
    pub runtime_binding: UnixStorageRetirementBinding,
    pub activated_at_ms: u64,
}

impl UnixStorageRetirementNativeActivation {
    pub(super) fn validate(&self, request: &super::UnixStorageRetirementAdmission) -> Result<()> {
        self.runtime_binding.validate()?;
        if self.format_version != 1
            || self.activation_id == self.request_id
            || self.request_id != request.request.request_id
            || self.request_fingerprint != request.request_fingerprint
            || self.activated_at_ms < request.admitted_at_ms
            || self.activated_at_ms >= request.request.expires_at_ms
            || UnixStorageRetirementExpectation::from_binding(&self.runtime_binding)?
                != UnixStorageRetirementExpectation::from_binding(&request.request.binding)?
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(super) fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend.unix-storage-retirement.native.activation.v1",
            self,
        ))?))
    }

    pub(super) fn values(&self) -> Result<Vec<Value>> {
        let json = serde_json::to_string(self)?;
        if json.is_empty() || json.len() > 16384 {
            return Err(invalid());
        }
        Ok(vec![
            Value::Text(self.activation_id.to_string()),
            Value::Text(self.request_id.to_string()),
            Value::Text(self.runtime_binding.fingerprint()?.to_string()),
            Value::Text(self.fingerprint()?.to_string()),
            Value::Integer(crate::sql_integer(self.activated_at_ms)?),
            Value::Text(json),
        ])
    }
}

/// Freely serializable facts for rejection and reporting. No writer accepts
/// this object, a recovered key, or a caller-supplied successful-close flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixStorageRetirementNativeEvidence {
    pub format_version: u32,
    pub request_id: EntryId,
    pub activation_id: EntryId,
    pub runtime_binding_fingerprint: ContentId,
    pub marker_identity: UnixStorageRetirementKey,
    pub marker_parent: UnixStorageRetirementKey,
    pub marker_component: String,
    pub marker_bytes_hash: ContentId,
    pub payload_slot: UnixStorageRetirementNativePayloadSlot,
    pub payload_hash_observed: bool,
    pub original_payload_nlink_zero_verified: bool,
    pub original_payload_descriptor_closed: bool,
    pub original_marker_nlink_zero_verified: bool,
    pub original_marker_descriptor_closed: bool,
    pub original_owner_descriptors_closed: bool,
    pub original_slot_absent: bool,
    pub quarantine_slot_absent: bool,
    pub marker_slot_absent: bool,
    pub payload_parents_synced: bool,
    pub marker_parent_synced: bool,
    pub independent_owner_slots_observed: bool,
    pub backup_complete: bool,
}

impl UnixStorageRetirementNativeEvidence {
    pub(super) fn validate(
        &self,
        activation: &UnixStorageRetirementNativeActivation,
        kind: UnixStorageRetirementNativeKind,
        deleted: Option<bool>,
    ) -> Result<()> {
        use UnixStorageRetirementNativeKind as K;
        use UnixStorageRetirementNativePayloadSlot as S;
        self.marker_identity.validate()?;
        self.marker_parent.validate()?;
        let binding = &activation.runtime_binding;
        let inside = [
            binding.mounted_root,
            binding.cas,
            binding.objects,
            binding.temporary,
            binding.realm,
            binding.shard,
            binding.payload,
        ];
        let sequence = kind.sequence();
        let expected_slot = match kind {
            K::CreatorReceipted | K::QuarantineRequested => S::Original,
            K::QuarantineObserved | K::DeleteRequested | K::RestoreRequested => S::Quarantine,
            K::PayloadUnlinked | K::PayloadCloseRequested => S::UnlinkedLive,
            K::RestoreObserved | K::RestoredCloseRequested => S::Restored,
            K::PayloadClosed => S::UnlinkedClosed,
            K::RestoredClosed => S::RestoredClosed,
            _ => match deleted {
                Some(true) => S::UnlinkedClosed,
                Some(false) => S::RestoredClosed,
                None => return Err(invalid()),
            },
        };
        let payload_closed = matches!(expected_slot, S::UnlinkedClosed | S::RestoredClosed);
        let original_absent =
            !matches!(expected_slot, S::Original | S::Restored | S::RestoredClosed);
        let unlinked = matches!(expected_slot, S::UnlinkedLive | S::UnlinkedClosed);
        if self.format_version != 1
            || self.request_id != activation.request_id
            || self.activation_id != activation.activation_id
            || self.runtime_binding_fingerprint != binding.fingerprint()?
            || self.marker_identity.device != binding.temporary.device
            || inside.contains(&self.marker_identity)
            || self.marker_parent != binding.temporary
            || self.marker_component != format!("retirement-{}.owner", activation.activation_id)
            || self.marker_bytes_hash
                != ContentId::hash(
                    format!("{}:{}", activation.request_id, activation.activation_id).as_bytes(),
                )
            || self.payload_slot != expected_slot
            || self.payload_hash_observed == payload_closed
            || self.original_payload_descriptor_closed != payload_closed
            || self.original_payload_nlink_zero_verified != unlinked
            || self.original_marker_nlink_zero_verified != (sequence >= 9)
            || self.original_marker_descriptor_closed != (sequence >= 11)
            || self.original_owner_descriptors_closed != (sequence >= 11)
            || self.original_slot_absent != original_absent
            || self.quarantine_slot_absent != (expected_slot != S::Quarantine)
            || self.marker_slot_absent != (sequence >= 9)
            || self.payload_parents_synced != (sequence >= 3)
            || !self.marker_parent_synced
            || self.independent_owner_slots_observed != (sequence >= 11)
            || self.backup_complete
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnixStorageRetirementNativeEvent {
    pub sequence: u32,
    pub kind: UnixStorageRetirementNativeKind,
    pub observed_at_ms: u64,
    pub previous_fingerprint: ContentId,
    pub event_fingerprint: ContentId,
    pub evidence: UnixStorageRetirementNativeEvidence,
}

impl UnixStorageRetirementNativeEvent {
    pub(super) fn new(
        activation: &UnixStorageRetirementNativeActivation,
        kind: UnixStorageRetirementNativeKind,
        previous: &ContentId,
        time: u64,
        evidence: UnixStorageRetirementNativeEvidence,
    ) -> Result<Self> {
        let event_fingerprint = ContentId::hash(&serde_json::to_vec(&(
            "sync-extend.unix-storage-retirement.native.event.v1",
            &activation.activation_id,
            kind.sequence(),
            kind.as_str(),
            time,
            previous,
            &evidence,
        ))?);
        Ok(Self {
            sequence: kind.sequence(),
            kind,
            observed_at_ms: time,
            previous_fingerprint: previous.clone(),
            event_fingerprint,
            evidence,
        })
    }

    pub(super) fn values(&self) -> Result<Vec<Value>> {
        let evidence = serde_json::to_string(&self.evidence)?;
        if evidence.is_empty() || evidence.len() > 4096 {
            return Err(invalid());
        }
        Ok(vec![
            Value::Text(self.evidence.activation_id.to_string()),
            Value::Integer(i64::from(self.sequence)),
            Value::Text(self.kind.as_str().into()),
            Value::Integer(crate::sql_integer(self.observed_at_ms)?),
            Value::Text(self.previous_fingerprint.to_string()),
            Value::Text(self.event_fingerprint.to_string()),
            Value::Text(evidence),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixStorageRetirementNativeRelease {
    pub format_version: u32,
    pub activation_id: EntryId,
    pub request_id: EntryId,
    pub terminal_fingerprint: ContentId,
    pub released_at_ms: u64,
    pub backup_complete: bool,
}

impl UnixStorageRetirementNativeRelease {
    pub(super) fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "sync-extend.unix-storage-retirement.native.release.v1",
            self,
        ))?))
    }

    pub(super) fn values(&self) -> Result<Vec<Value>> {
        let json = serde_json::to_string(self)?;
        if json.is_empty() || json.len() > 2048 {
            return Err(invalid());
        }
        Ok(vec![
            Value::Text(self.activation_id.to_string()),
            Value::Text(self.request_id.to_string()),
            Value::Text(self.terminal_fingerprint.to_string()),
            Value::Integer(crate::sql_integer(self.released_at_ms)?),
            Value::Text(self.fingerprint()?.to_string()),
            Value::Text(json),
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UnixStorageRetirementNativeState {
    pub activation: UnixStorageRetirementNativeActivation,
    pub activation_fingerprint: ContentId,
    pub request: super::UnixStorageRetirementAdmission,
    pub events: Vec<UnixStorageRetirementNativeEvent>,
    pub release: Option<UnixStorageRetirementNativeRelease>,
    pub payload_slot_absent: bool,
    pub original_payload_descriptor_closed: bool,
    pub original_owner_descriptors_closed: bool,
    pub independent_slots_observed: bool,
    pub terminal_recorded: bool,
    pub content_fence_released: bool,
    pub backup_complete: bool,
    pub serialized_history_confers_native_authority: bool,
}

impl UnixStorageRetirementNativeState {
    pub(super) fn sequence(&self) -> u32 {
        self.events.last().map_or(0, |event| event.sequence)
    }

    pub(super) fn deleted_branch(&self) -> Option<bool> {
        self.events
            .get(3)
            .and_then(|event| event.kind.deleted_branch())
    }

    pub(super) fn previous_hash(&self) -> &ContentId {
        self.events
            .last()
            .map_or(&self.activation_fingerprint, |event| {
                &event.event_fingerprint
            })
    }
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<UnixStorageRetirementNativeState>> {
    audit_with_requests(connection, super::audit)
}

pub(crate) fn audit_archived_unix(
    connection: &Connection,
) -> Result<Vec<UnixStorageRetirementNativeState>> {
    audit_with_requests(connection, super::audit_archived_unix)
}

fn audit_with_requests(
    connection: &Connection,
    audit_requests: fn(&Connection) -> Result<Vec<super::UnixStorageRetirementAdmission>>,
) -> Result<Vec<UnixStorageRetirementNativeState>> {
    super::native_schema::validate(connection)?;
    preflight(
        connection,
        super::native_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let requests = audit_requests(connection)?;
    let clock: Option<u64> = connection.query_row(
        "SELECT observed_at_ms FROM main.unix_storage_retirement_native_v1_clock WHERE singleton=1",
        [], |row| crate::sql_u64(row, 0),
    ).optional()?;
    let base_clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.unix_storage_retirement_v1_clock WHERE singleton=1",
            [],
            |row| crate::sql_u64(row, 0),
        )
        .optional()?;
    if clock.is_some_and(|clock| base_clock.is_none_or(|base| base < clock)) {
        return Err(invalid());
    }
    let stored = connection.prepare(
        "SELECT activation_id,request_id,binding_hash,activation_hash,activated_at_ms,activation
         FROM main.unix_storage_retirement_native_v1_activations ORDER BY activation_id"
    )?.query_map([], |row| (0..6).map(|index| row.get(index))
        .collect::<rusqlite::Result<Vec<Value>>>())?.collect::<rusqlite::Result<Vec<_>>>()?;
    if stored.is_empty() != clock.is_none() {
        return Err(invalid());
    }
    let mut result = Vec::new();
    let mut request_ids = std::collections::BTreeSet::new();
    let mut active_markers = std::collections::BTreeSet::new();
    let mut counted_events = 0u64;
    let mut counted_releases = 0u64;
    for row in stored {
        let Value::Text(json) = &row[5] else {
            return Err(invalid());
        };
        let activation: UnixStorageRetirementNativeActivation = serde_json::from_str(json)?;
        let request = requests
            .iter()
            .find(|row| row.request.request_id == activation.request_id)
            .ok_or_else(invalid)?
            .clone();
        activation.validate(&request)?;
        if activation.values()? != row
            || !request_ids.insert(activation.request_id.clone())
            || clock.is_none_or(|clock| clock < activation.activated_at_ms)
        {
            return Err(invalid());
        }
        let activation_hash = activation.fingerprint()?;
        let rows = connection.prepare(
            "SELECT activation_id,sequence,kind,observed_at_ms,previous_hash,event_hash,evidence
             FROM main.unix_storage_retirement_native_v1_events WHERE activation_id=?1 ORDER BY sequence"
        )?.query_map([activation.activation_id.as_str()], |row| (0..7).map(|index| row.get(index))
            .collect::<rusqlite::Result<Vec<Value>>>())?.collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.len() > MAX_EVENTS as usize {
            return Err(invalid());
        }
        let mut events: Vec<UnixStorageRetirementNativeEvent> = Vec::new();
        let mut deleted = None;
        let mut marker = None;
        let mut previous = activation_hash.clone();
        let mut last_time = activation.activated_at_ms;
        for (index, row) in rows.into_iter().enumerate() {
            let (Value::Text(kind), Value::Integer(time), Value::Text(json)) =
                (&row[2], &row[3], &row[6])
            else {
                return Err(invalid());
            };
            let kind: UnixStorageRetirementNativeKind =
                serde_json::from_value(serde_json::Value::String(kind.clone()))?;
            let time = u64::try_from(*time).map_err(|_| invalid())?;
            let evidence: UnixStorageRetirementNativeEvidence = serde_json::from_str(json)?;
            if kind.sequence() as usize != index + 1
                || time < last_time
                || clock.is_none_or(|clock| time > clock)
                || (kind.request() && time >= request.request.expires_at_ms)
            {
                return Err(invalid());
            }
            if kind.sequence() == 4 {
                deleted = kind.deleted_branch();
                if deleted.is_none() {
                    return Err(invalid());
                }
            } else if kind
                .deleted_branch()
                .is_some_and(|branch| Some(branch) != deleted)
            {
                return Err(invalid());
            }
            evidence.validate(&activation, kind, deleted)?;
            if marker.is_some_and(|key| key != evidence.marker_identity) {
                return Err(invalid());
            }
            marker = Some(evidence.marker_identity);
            let event = UnixStorageRetirementNativeEvent::new(
                &activation,
                kind,
                &previous,
                time,
                evidence,
            )?;
            if event.values()? != row {
                return Err(invalid());
            }
            previous = event.event_fingerprint.clone();
            last_time = time;
            events.push(event);
            counted_events = add(counted_events, 1)?;
        }
        let release_row: Option<Vec<Value>> = connection
            .query_row(
                "SELECT activation_id,request_id,terminal_hash,released_at_ms,release_hash,release
             FROM main.unix_storage_retirement_native_v1_releases WHERE activation_id=?1",
                [activation.activation_id.as_str()],
                |row| {
                    (0..6)
                        .map(|index| row.get(index))
                        .collect::<rusqlite::Result<_>>()
                },
            )
            .optional()?;
        let release = if let Some(row) = release_row {
            let Value::Text(json) = &row[5] else {
                return Err(invalid());
            };
            let release: UnixStorageRetirementNativeRelease = serde_json::from_str(json)?;
            if release.format_version != 1
                || release.backup_complete
                || release.activation_id != activation.activation_id
                || release.request_id != activation.request_id
                || release.values()? != row
                || events.len() != MAX_EVENTS as usize
                || release.terminal_fingerprint != previous
                || release.released_at_ms < last_time
                || clock.is_none_or(|clock| release.released_at_ms > clock)
                || request.cancelled_at_ms != Some(release.released_at_ms)
                || request.content_fenced
            {
                return Err(invalid());
            }
            counted_releases = add(counted_releases, 1)?;
            Some(release)
        } else {
            if request.cancelled_at_ms.is_some() || !request.content_fenced {
                return Err(invalid());
            }
            if let Some(marker) = marker {
                if !active_markers.insert((marker.device, marker.inode)) {
                    return Err(invalid());
                }
            }
            None
        };
        let last = events.last();
        result.push(UnixStorageRetirementNativeState {
            activation,
            activation_fingerprint: activation_hash,
            request,
            payload_slot_absent: last.is_some_and(|event| {
                event.evidence.original_slot_absent && event.evidence.quarantine_slot_absent
            }),
            original_payload_descriptor_closed: last
                .is_some_and(|event| event.evidence.original_payload_descriptor_closed),
            original_owner_descriptors_closed: last
                .is_some_and(|event| event.evidence.original_owner_descriptors_closed),
            independent_slots_observed: last
                .is_some_and(|event| event.evidence.independent_owner_slots_observed),
            terminal_recorded: events.len() == MAX_EVENTS as usize,
            content_fence_released: release.is_some(),
            events,
            release,
            backup_complete: false,
            serialized_history_confers_native_authority: false,
        });
    }
    let actual_events: u64 = connection.query_row(
        "SELECT count(*) FROM main.unix_storage_retirement_native_v1_events",
        [],
        |row| crate::sql_u64(row, 0),
    )?;
    let actual_releases: u64 = connection.query_row(
        "SELECT count(*) FROM main.unix_storage_retirement_native_v1_releases",
        [],
        |row| crate::sql_u64(row, 0),
    )?;
    if actual_events != counted_events || actual_releases != counted_releases {
        return Err(invalid());
    }
    Ok(result)
}

pub(crate) fn has_activation(connection: &Connection, request_id: &EntryId) -> Result<bool> {
    Ok(audit(connection)?
        .iter()
        .any(|row| row.activation.request_id == *request_id))
}

pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    audit(connection)?
        .iter()
        .filter(|row| row.release.is_none())
        .try_fold(TreeStorageCharge::default(), |sum, row| {
            let events = u64::from(MAX_EVENTS - row.sequence());
            Ok(TreeStorageCharge {
                rows: add(sum.rows, add(events, 1)?)?,
                logical_bytes: add(
                    sum.logical_bytes,
                    add(
                        events.checked_mul(EVENT_PEAK_BYTES).ok_or_else(invalid)?,
                        RELEASE_PEAK_BYTES,
                    )?,
                )?,
            })
        })
}

pub(crate) fn metadata_budget(connection: &Connection) -> Result<TreeStorageCharge> {
    let future = outstanding(connection)?;
    preflight(
        connection,
        super::native_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?
    .iter()
    .try_fold(future, |sum, row| {
        Ok(TreeStorageCharge {
            rows: add(sum.rows, row.rows)?,
            logical_bytes: add(sum.logical_bytes, row.logical_bytes)?,
        })
    })
}

impl Journal {
    pub fn unix_storage_retirement_native_states(
        &self,
    ) -> Result<Vec<UnixStorageRetirementNativeState>> {
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let result = audit(&tx)?;
            tx.commit()?;
            return Ok(result);
        }
        audit(&self.connection)
    }
}
