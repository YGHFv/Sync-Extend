//! Append-only recovered history pins. Rows are conservative GC references,
//! never native issuers; only a held fresh WAL lease executes their transitions.
use crate::{JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SnapshotId, SpaceId};

pub(crate) const RETAIN: &str = "recovered_history_retain:";
pub(crate) const RELEASE: &str = "recovered_history_release:";
const MAX_RECORDS: usize = 128;
const MAX_RECORD_BYTES: usize = 65536;
pub const MAX_RECOVERED_PINS: usize = 512;

/// Explicit immutable data returned to the caller; this is not a capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredRetentionMapping {
    pub version: u32,
    pub retention_id: EntryId,
    pub archive_digest: ContentId,
    pub original_frames_digest: ContentId,
    pub source_history_receipt: ContentId,
    pub source_image: ContentId,
    pub source_inventory: ContentId,
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub original_worktree: String,
    pub mapped_worktree: String,
    pub session: SpaceId,
    pub native_keys: [String; 4],
    pub generation: u32,
    pub snapshot_id: SnapshotId,
    pub pins: BTreeSet<ContentId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredRetentionRelease {
    pub version: u32,
    pub retention_id: EntryId,
    pub mapping_digest: ContentId,
    pub pins_digest: ContentId,
    pub session: SpaceId,
    pub native_keys: [String; 4],
    pub generation: u32,
    pub released_at_ms: u64,
}

#[derive(Clone, Serialize)]
pub struct RecoveredRetentionAudit {
    pub mapping: RecoveredRetentionMapping,
    pub mapping_digest: ContentId,
    pub release: Option<RecoveredRetentionRelease>,
}

fn keys(keys: &[String; 4]) -> Result<()> {
    if keys.iter().collect::<BTreeSet<_>>().len() != 4
        || keys
            .iter()
            .any(|key| key.len() > 128 || !key.starts_with("windows:"))
    {
        return Err(JournalError::Invariant(
            "recovered retention exact native identities",
        ));
    }
    Ok(())
}
impl RecoveredRetentionMapping {
    pub fn digest(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(self)?))
    }
    pub fn pins_digest(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(&self.pins)?))
    }
    pub(crate) fn validate(&self) -> Result<()> {
        keys(&self.native_keys)?;
        if self.version != 1
            || self.generation >= 64
            || self.pins.len() > MAX_RECOVERED_PINS
            || !std::path::Path::new(&self.original_worktree).is_absolute()
            || !std::path::Path::new(&self.mapped_worktree).is_absolute()
            || self.original_worktree.len() > 32768
            || self.mapped_worktree.len() > 32768
            || self.pins.is_empty()
            || serde_json::to_vec(self)?.len() > MAX_RECORD_BYTES
        {
            return Err(JournalError::Invariant(
                "recovered retention bounded original mapping",
            ));
        }
        Ok(())
    }
}

/// All source GC pin families share the production predicate. Unknown nonempty
/// families are rejected by the original complete provenance audit beforehand.
pub(crate) fn original_pins(connection: &Connection) -> Result<BTreeSet<ContentId>> {
    let mut statement = connection.prepare(
        "SELECT content_id FROM main.snapshot_objects
         UNION SELECT content_id FROM main.publication_objects
         UNION SELECT content_id FROM main.remote_replace_objects
         UNION SELECT content_id FROM main.conflict_resolution_native_history_objects
         UNION SELECT content_id FROM main.conflict_resolution_objects
         UNION SELECT content_id FROM main.mutation_objects
         UNION SELECT content_id FROM main.read_lease_objects
         UNION SELECT content_id FROM main.reference_reservation_objects
         UNION SELECT content_id FROM main.tree_restore_original_objects
         UNION SELECT content_id FROM main.tree_restore_objects
         UNION SELECT o.content_id FROM main.webdav_native_objects o
           LEFT JOIN main.webdav_native_cancellations c USING(transaction_id)
           WHERE c.transaction_id IS NULL ORDER BY 1",
    )?;
    let mut result = BTreeSet::new();
    for row in statement.query_map([], |row| row.get::<_, String>(0))? {
        if result.len() >= MAX_RECOVERED_PINS {
            return Err(JournalError::Invariant("recovered retention pin set bound"));
        }
        result.insert(row?.parse()?);
    }
    Ok(result)
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<RecoveredRetentionAudit>> {
    let mut rows = connection.prepare(
        "SELECT key,CASE WHEN length(CAST(value AS BLOB))<=65536 THEN value ELSE '' END
         FROM main.local_state WHERE instr(key,'recovered_history_')=1 ORDER BY key",
    )?;
    let mut mappings = BTreeMap::new();
    let mut releases = BTreeMap::new();
    let mut count = 0;
    for row in rows.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (key, value) = row?;
        count += 1;
        if count > MAX_RECORDS * 2 || value.is_empty() {
            return Err(JournalError::Invariant(
                "recovered retention metadata bound",
            ));
        }
        if let Some(id) = key.strip_prefix(RETAIN) {
            let mapping: RecoveredRetentionMapping = serde_json::from_str(&value)?;
            mapping.validate()?;
            if id != mapping.retention_id.as_str()
                || serde_json::to_string(&mapping)? != value
                || mappings
                    .insert(mapping.retention_id.clone(), mapping)
                    .is_some()
            {
                return Err(JournalError::Invariant(
                    "recovered retention exact immutable record",
                ));
            }
        } else if let Some(id) = key.strip_prefix(RELEASE) {
            let release: RecoveredRetentionRelease = serde_json::from_str(&value)?;
            keys(&release.native_keys)?;
            crate::sql_integer(release.released_at_ms)?;
            if release.version != 1
                || release.generation >= 64
                || id != release.retention_id.as_str()
                || serde_json::to_string(&release)? != value
                || releases
                    .insert(release.retention_id.clone(), release)
                    .is_some()
            {
                return Err(JournalError::Invariant(
                    "recovered retention exact release record",
                ));
            }
        } else {
            return Err(JournalError::Invariant(
                "unknown recovered history state family",
            ));
        }
    }
    let view = crate::JournalReadView {
        connection,
        dav_read_charge_cache: None,
    };
    let mut result = Vec::new();
    for (id, mapping) in mappings {
        if view.state("space_id")?.as_deref() != Some(mapping.space_id.as_str())
            || view.state("device_id")?.as_deref() != Some(mapping.device_id.as_str())
            || view.state("worktree")?.as_deref() != Some(mapping.mapped_worktree.as_str())
        {
            return Err(JournalError::Invariant(
                "recovered retention original space device root",
            ));
        }
        let mapping_digest = mapping.digest()?;
        let release = releases.remove(&id);
        if let Some(release) = &release {
            if release.mapping_digest != mapping_digest
                || release.pins_digest != mapping.pins_digest()?
                || release.generation < mapping.generation
                || release.native_keys[..3] != mapping.native_keys[..3]
            {
                return Err(JournalError::Invariant(
                    "recovered retention release mapping pins lineage",
                ));
            }
        }
        result.push(RecoveredRetentionAudit {
            mapping,
            mapping_digest,
            release,
        });
    }
    if !releases.is_empty() {
        return Err(JournalError::Invariant(
            "orphan recovered retention release",
        ));
    }
    Ok(result)
}

pub(crate) fn active_pins(connection: &Connection) -> Result<BTreeSet<ContentId>> {
    let mut pins = BTreeSet::new();
    for record in audit(connection)? {
        if record.release.is_none() {
            pins.extend(record.mapping.pins);
        }
    }
    Ok(pins)
}

pub(crate) fn no_pending(
    connection: &Connection,
    space: &SpaceId,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    let view = crate::JournalReadView {
        connection,
        dav_read_charge_cache: None,
    };
    let capacity =
        view.audit_original_provenance_capacity(space, bounds.max_entries, bounds.capacity)?;
    if crate::history_reservation::audit_recovered_attempt_rows(
        &capacity.rows,
        space,
        bounds.max_entries,
    )?
    .iter()
    .any(|row| row.state != "cancelled_metadata_only")
    {
        return Err(JournalError::Invariant(
            "recovered retention release has pending local history attempt",
        ));
    }
    for table in [
        "mutation_objects",
        "publication_objects",
        "read_lease_objects",
        "reference_reservation_objects",
        "tree_restore_objects",
        "remote_replace_objects",
        "conflict_resolution_objects",
    ] {
        if connection.query_row(
            &format!("SELECT count(*) FROM main.\"{table}\""),
            [],
            |row| row.get::<_, i64>(0),
        )? != 0
        {
            return Err(JournalError::Invariant(
                "recovered retention release has pending pinned owner",
            ));
        }
    }
    // Do not derive completion from a phase number or descriptive catalogue.
    for table in [
        "webdav_native_executions",
        "tree_native_effects",
        "tree_native_future_effects",
    ] {
        let query = format!("SELECT count(*) FROM main.\"{table}\"");
        // The original complete catalogue establishes the exact schema. These
        // effect families have no recovered release adapter in this contract.
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name=?1)",
            [table],
            |row| row.get(0),
        )?;
        if exists && connection.query_row(&query, [], |row| row.get::<_, i64>(0))? != 0 {
            return Err(JournalError::Invariant(
                "recovered retention unsupported nonempty pending effect family",
            ));
        }
    }
    Ok(())
}

impl JournalBackupImage {
    pub fn recovered_retention_records(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<Vec<RecoveredRetentionAudit>> {
        self.with_audited_readonly(space, bounds, audit)
    }
    pub fn recovered_pin_ids(
        &self,
        space: &SpaceId,
        bounds: NodeInspectionBounds,
    ) -> Result<BTreeSet<ContentId>> {
        self.with_audited_readonly(space, bounds, original_pins)
    }
    /// A preeffect rejection only; this result carries no retention issuer.
    pub fn preflight_recovered_release(
        &self,
        mapping: &RecoveredRetentionMapping,
        bounds: NodeInspectionBounds,
    ) -> Result<()> {
        self.with_audited_readonly(&mapping.space_id, bounds, |connection| {
            let current = audit(connection)?
                .into_iter()
                .find(|r| r.mapping.retention_id == mapping.retention_id)
                .ok_or(JournalError::Invariant(
                    "recovered release immutable mapping absent",
                ))?;
            if current.mapping != *mapping || current.release.is_some() {
                return Err(JournalError::Invariant(
                    "recovered release immutable mapping differs",
                ));
            }
            no_pending(connection, &mapping.space_id, bounds)
        })
    }
    pub fn preflight_recovered_gc(
        &self,
        space: &SpaceId,
        id: &ContentId,
        bounds: NodeInspectionBounds,
    ) -> Result<()> {
        self.with_audited_readonly(space, bounds, |connection| {
            no_pending(connection, space, bounds)?;
            if (crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            })
            .gc_protected(id)?
            {
                return Err(JournalError::Invariant(
                    "recovered GC admission content is pinned",
                ));
            }
            Ok(())
        })
    }
    pub fn preflight_recovered_retain(
        &self,
        space: &SpaceId,
        extra: &[ContentId],
        bounds: NodeInspectionBounds,
    ) -> Result<BTreeSet<ContentId>> {
        self.with_audited_readonly(space, bounds, |connection| {
            let records = audit(connection)?;
            if records.len() >= MAX_RECORDS || extra.len() > MAX_RECOVERED_PINS {
                return Err(JournalError::Invariant(
                    "recovered retention owner or requested pin bound",
                ));
            }
            let mut pins = original_pins(connection)?;
            pins.extend(extra.iter().cloned());
            if pins.is_empty() || pins.len() > MAX_RECOVERED_PINS {
                return Err(JournalError::Invariant(
                    "recovered retention complete nonempty pin set bound",
                ));
            }
            let marks = (crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            })
            .gc_marks(space)?;
            if marks.iter().any(|mark| {
                mark.state == crate::GcState::Marked && pins.contains(&mark.intent.content_id)
            }) {
                return Err(JournalError::Invariant(
                    "recovered retention conflicts with admitted GC mark",
                ));
            }
            Ok(pins)
        })
    }
}

/// Mutation of the private planning Journal still uses production GC and
/// capacity audits. The opaque plan is constructed only with a live native lease.
pub(crate) fn insert_mapping(
    connection: &Connection,
    mapping: &RecoveredRetentionMapping,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    mapping.validate()?;
    let before = audit(connection)?;
    if before.len() >= MAX_RECORDS
        || before
            .iter()
            .any(|r| r.mapping.retention_id == mapping.retention_id)
    {
        return Err(JournalError::Invariant(
            "recovered retention distinct bounded owner",
        ));
    }
    let source = original_pins(connection)?;
    if !source.is_subset(&mapping.pins) {
        return Err(JournalError::Invariant(
            "recovered retention omitted an original history pin",
        ));
    }
    if (crate::JournalReadView {
        connection,
        dav_read_charge_cache: None,
    })
    .state("original_recovery_session")?
    .as_deref()
        != Some(mapping.session.as_str())
    {
        return Err(JournalError::Invariant(
            "recovered retention exact current session",
        ));
    }
    let value = serde_json::to_string(mapping)?;
    crate::check_storage_metadata_limit(
        connection,
        bounds.max_entries,
        2,
        value.len() as u64 + MAX_RECORD_BYTES as u64,
    )?;
    connection.execute(
        "INSERT INTO main.local_state(key,value) VALUES(?1,?2)",
        params![format!("{RETAIN}{}", mapping.retention_id), value],
    )?;
    audit(connection)?;
    Ok(())
}

pub(crate) fn insert_release(
    connection: &Connection,
    expected: &RecoveredRetentionMapping,
    release: &RecoveredRetentionRelease,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    no_pending(connection, &expected.space_id, bounds)?;
    let current = audit(connection)?
        .into_iter()
        .find(|r| r.mapping.retention_id == expected.retention_id)
        .ok_or(JournalError::Invariant(
            "recovered retention release owner absent",
        ))?;
    if current.mapping != *expected
        || current.release.is_some()
        || release.mapping_digest != expected.digest()?
        || release.pins_digest != expected.pins_digest()?
        || (crate::JournalReadView {
            connection,
            dav_read_charge_cache: None,
        })
        .state("original_recovery_session")?
        .as_deref()
            != Some(release.session.as_str())
    {
        return Err(JournalError::Invariant(
            "recovered retention release exact current mapping pins session",
        ));
    }
    let value = serde_json::to_string(release)?;
    crate::check_storage_metadata_limit(connection, bounds.max_entries, 1, value.len() as u64)?;
    connection.execute(
        "INSERT INTO main.local_state(key,value) VALUES(?1,?2)",
        params![format!("{RELEASE}{}", expected.retention_id), value],
    )?;
    audit(connection)?;
    Ok(())
}
