//! Recovered history operations issued only inside an exact live native owner.
use super::{
    FreshRecoveredNodeWalV2Session, HistoryChain8Record, HistoryRestartObject,
    LoadedHistoryGeneration, ReacquiredClosedNodeLockedReadScope, ReacquiredFile, ReconcileError,
    Result,
};
use crate::node_archive::VerifiedNodeStateArchive;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Write,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SnapshotId, SpaceId};
use sync_extend_journal::{
    JournalBackupImage, NodeInspectionBounds, RecoveredMetadataOutcome, RecoveredRetentionMapping,
    RecoveredRetentionPlan, RecoveredRetentionRelease,
};

/// A requested operation is data for preeffect refusal, never an issuer.
pub enum RecoveredHistoryOperation<'a> {
    Retain(&'a [ContentId]),
    Release(&'a RecoveredRetentionMapping),
    GcMark(&'a ContentId),
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MetadataOperation {
    Retain,
    Release,
    GcMark,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionReceiptAudit {
    mapping: RecoveredRetentionMapping,
    mapping_digest: ContentId,
    release: Option<RecoveredRetentionRelease>,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GcReceiptState {
    Marked,
    Cancelled,
    Invalidated,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcReceiptAudit {
    intent: sync_extend_journal::GcMark,
    state: GcReceiptState,
    cancelled_at_ms: Option<u64>,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "audit",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum MetadataReceiptOutcome {
    Retention(RetentionReceiptAudit),
    GcMark(GcReceiptAudit),
}

impl MetadataReceiptOutcome {
    fn production_outcome(&self) -> RecoveredMetadataOutcome {
        match self {
            Self::Retention(audit) => {
                RecoveredMetadataOutcome::Retention(sync_extend_journal::RecoveredRetentionAudit {
                    mapping: audit.mapping.clone(),
                    mapping_digest: audit.mapping_digest.clone(),
                    release: audit.release.clone(),
                })
            }
            Self::GcMark(audit) => {
                RecoveredMetadataOutcome::GcMark(sync_extend_journal::GcMarkAudit {
                    intent: audit.intent.clone(),
                    state: match audit.state {
                        GcReceiptState::Marked => sync_extend_journal::GcState::Marked,
                        GcReceiptState::Cancelled => sync_extend_journal::GcState::Cancelled,
                        GcReceiptState::Invalidated => sync_extend_journal::GcState::Invalidated,
                    },
                    cancelled_at_ms: audit.cancelled_at_ms,
                })
            }
        }
    }
}

type MetadataIntention = (
    u32,
    MetadataOperation,
    EntryId,
    ContentId,
    SpaceId,
    ContentId,
);
type MetadataTerminal = (u32, String, MetadataReceiptOutcome, ContentId);

#[derive(Clone, Eq, PartialEq)]
struct MetadataReceiptPair {
    intention: MetadataIntention,
    terminal: MetadataTerminal,
}

/// This proof has no Deserialize implementation. It is created only after the
/// live lease executed and the exact original receipt creator was synced/sealed.
pub(super) struct RecoveredMetadataReceiptProof {
    object: HistoryRestartObject,
    pair: MetadataReceiptPair,
    original_worktree: Option<PathBuf>,
}

/// Descriptive close data. Reacquisition must additionally read the held receipt,
/// verify its typed pair and compare the actual SQL transition. This is no issuer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveredMetadataCloseEvidence {
    version: u32,
    metadata_count: u32,
    generation: u32,
    source_history_receipt: ContentId,
    source_image: ContentId,
    source_inventory: ContentId,
    receipt: (String, ContentId, u64),
    operation: MetadataOperation,
    object_id: EntryId,
    final_image: ContentId,
}

struct MetadataScope<'a> {
    archive: &'a ContentId,
    original_frames: &'a ContentId,
    space: &'a SpaceId,
    device: &'a DeviceId,
    original_worktree: Option<&'a Path>,
    mapped_worktree: &'a Path,
    session: &'a SpaceId,
    native_keys: &'a [String; 4],
    generation: u32,
    source_history_receipt: &'a ContentId,
    source_image: &'a ContentId,
    source_inventory: &'a ContentId,
    root: &'a SnapshotId,
}

fn metadata_pair(bytes: &[u8]) -> Result<MetadataReceiptPair> {
    if bytes.len() > 256 * 1024 {
        return Err(ReconcileError::ResourceLimit(
            "recovered metadata receipt aggregate bound",
        ));
    }
    let mut offset = 0usize;
    let mut payloads = Vec::with_capacity(2);
    for _ in 0..2 {
        let prefix_end = offset.checked_add(4).ok_or(ReconcileError::ResourceLimit(
            "metadata receipt size overflow",
        ))?;
        let size = u32::from_le_bytes(
            bytes
                .get(offset..prefix_end)
                .ok_or(ReconcileError::Invariant("metadata receipt truncated size"))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("metadata receipt size encoding"))?,
        ) as usize;
        if size == 0 || size > 128 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "metadata receipt payload bound",
            ));
        }
        offset = prefix_end;
        let end = offset
            .checked_add(size)
            .ok_or(ReconcileError::ResourceLimit(
                "metadata receipt payload overflow",
            ))?;
        payloads.push(bytes.get(offset..end).ok_or(ReconcileError::Invariant(
            "metadata receipt truncated payload",
        ))?);
        offset = end;
    }
    let intention: MetadataIntention = serde_json::from_slice(payloads[0])?;
    let terminal: MetadataTerminal = serde_json::from_slice(payloads[1])?;
    if offset != bytes.len()
        || intention.0 != 1
        || terminal.0 != 1
        || terminal.1 != "committed"
        || serde_json::to_vec(&intention)? != payloads[0]
        || serde_json::to_vec(&terminal)? != payloads[1]
        || !matches!(
            (&intention.1, &terminal.2),
            (
                MetadataOperation::Retain | MetadataOperation::Release,
                MetadataReceiptOutcome::Retention(_)
            ) | (MetadataOperation::GcMark, MetadataReceiptOutcome::GcMark(_))
        )
    {
        return Err(ReconcileError::Invariant(
            "metadata receipt exact canonical committed pair",
        ));
    }
    Ok(MetadataReceiptPair {
        intention,
        terminal,
    })
}

pub(super) fn require_committed_receipt(name: &str, bytes: &[u8]) -> Result<()> {
    if name.starts_with("node-recovered-retention-") {
        metadata_pair(bytes)?;
        return Ok(());
    }
    // The existing native receipt framing/count contract remains unchanged.
    let values = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<serde_json::Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if values.len() < 2
        || values
            .last()
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(1))
            .and_then(|v| v.as_str())
            != Some("committed")
    {
        return Err(ReconcileError::Invariant(
            "history close unresolved receipt",
        ));
    }
    Ok(())
}

pub(super) fn validate_close_metadata(
    metadata: Option<&RecoveredMetadataCloseEvidence>,
    history_count: u32,
    receipts: &[(String, ContentId, u64)],
    session: &SpaceId,
    main: &ContentId,
) -> Result<()> {
    let count = receipts
        .iter()
        .filter(|r| r.0.starts_with("node-recovered-retention-"))
        .count();
    match metadata {
        None if count == 0 => Ok(()),
        Some(evidence)
            if evidence.version == 1
                && evidence.metadata_count == 1
                && (1..64).contains(&evidence.generation)
                && history_count == 0
                && count == evidence.metadata_count as usize
                && receipts.len() == 1
                && receipts[0] == evidence.receipt
                && evidence.receipt.0 == format!("node-recovered-retention-{session}-0.frames")
                && evidence.receipt.2 <= 256 * 1024
                && evidence.source_image != evidence.final_image
                && evidence.final_image == *main =>
        {
            Ok(())
        }
        _ => Err(ReconcileError::Invariant(
            "metadata close separate exact committed count and bindings",
        )),
    }
}

fn retention_records(
    image: &JournalBackupImage,
    space: &SpaceId,
    bounds: NodeInspectionBounds,
) -> Result<BTreeMap<EntryId, RetentionReceiptAudit>> {
    Ok(image
        .recovered_retention_records(space, bounds)?
        .into_iter()
        .map(|record| {
            (
                record.mapping.retention_id.clone(),
                RetentionReceiptAudit {
                    mapping: record.mapping,
                    mapping_digest: record.mapping_digest,
                    release: record.release,
                },
            )
        })
        .collect())
}

fn verify_pair_scope(
    pair: &MetadataReceiptPair,
    scope: &MetadataScope<'_>,
    main: &ContentId,
) -> Result<()> {
    let (_, operation, id, archive, session, before) = &pair.intention;
    if archive != scope.archive
        || session != scope.session
        || before != scope.source_image
        || pair.terminal.3 != *main
        || before == main
        || !(1..64).contains(&scope.generation)
    {
        return Err(ReconcileError::Invariant(
            "metadata receipt exact fresh native source boundary",
        ));
    }
    match (operation, &pair.terminal.2) {
        (MetadataOperation::Retain, MetadataReceiptOutcome::Retention(audit)) => {
            let mapping = &audit.mapping;
            if audit.release.is_some()
                || mapping.version != 1
                || mapping.retention_id != *id
                || mapping.archive_digest != *scope.archive
                || mapping.original_frames_digest != *scope.original_frames
                || mapping.source_history_receipt != *scope.source_history_receipt
                || mapping.source_image != *scope.source_image
                || mapping.source_inventory != *scope.source_inventory
                || mapping.space_id != *scope.space
                || mapping.device_id != *scope.device
                || scope
                    .original_worktree
                    .is_some_and(|root| mapping.original_worktree != root.to_string_lossy())
                || mapping.mapped_worktree != scope.mapped_worktree.to_string_lossy()
                || mapping.session != *scope.session
                || mapping.native_keys != *scope.native_keys
                || mapping.generation != scope.generation
                || mapping.snapshot_id != *scope.root
                || mapping.pins.is_empty()
                || mapping.pins.len() > sync_extend_journal::MAX_RECOVERED_PINS
                || mapping.digest()? != audit.mapping_digest
            {
                return Err(ReconcileError::Invariant(
                    "metadata retain canonical original mapping pins generation root",
                ));
            }
        }
        (MetadataOperation::Release, MetadataReceiptOutcome::Retention(audit)) => {
            let mapping = &audit.mapping;
            let release = audit.release.as_ref().ok_or(ReconcileError::Invariant(
                "metadata release exact terminal release absent",
            ))?;
            if mapping.retention_id != *id
                || mapping.archive_digest != *scope.archive
                || mapping.original_frames_digest != *scope.original_frames
                || mapping.space_id != *scope.space
                || mapping.device_id != *scope.device
                || scope
                    .original_worktree
                    .is_some_and(|root| mapping.original_worktree != root.to_string_lossy())
                || mapping.mapped_worktree != scope.mapped_worktree.to_string_lossy()
                || mapping.generation >= scope.generation
                || mapping.session == *scope.session
                || mapping.native_keys[..3] != scope.native_keys[..3]
                || mapping.digest()? != audit.mapping_digest
                || release.version != 1
                || release.retention_id != *id
                || release.mapping_digest != audit.mapping_digest
                || release.pins_digest != mapping.pins_digest()?
                || release.session != *scope.session
                || release.native_keys != *scope.native_keys
                || release.generation != scope.generation
                || release.released_at_ms > i64::MAX as u64
            {
                return Err(ReconcileError::Invariant(
                    "metadata release canonical original mapping pins native lineage",
                ));
            }
        }
        (MetadataOperation::GcMark, MetadataReceiptOutcome::GcMark(audit)) => {
            let mark = &audit.intent;
            let grace = mark.grace_until_ms.checked_sub(mark.marked_at_ms);
            if mark.mark_id != *id
                || mark.space_id != *scope.space
                || mark.format_version != sync_extend_core_model::FORMAT_VERSION
                || audit.state != GcReceiptState::Marked
                || audit.cancelled_at_ms.is_some()
                || grace.is_none_or(|n| !(1000..=604800000).contains(&n) || n % 1000 != 0)
                || mark.grace_until_ms > i64::MAX as u64
                || !(1..=4 * 1024 * 1024).contains(&mark.observation.length)
            {
                return Err(ReconcileError::Invariant(
                    "metadata GC canonical committed observation",
                ));
            }
        }
        _ => {
            return Err(ReconcileError::Invariant(
                "metadata committed outcome family",
            ))
        }
    }
    Ok(())
}

fn verify_image_scope(
    image: &JournalBackupImage,
    scope: &MetadataScope<'_>,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    image.with_audited_readonly(scope.space, bounds, |connection| {
        for (key, expected) in [
            ("space_id", scope.space.as_str()),
            ("device_id", scope.device.as_str()),
            (
                "worktree",
                scope.mapped_worktree.to_str().ok_or(
                    sync_extend_journal::JournalError::Invariant("metadata worktree encoding"),
                )?,
            ),
            ("original_recovery_session", scope.session.as_str()),
        ] {
            let actual: String = connection.query_row(
                "SELECT value FROM main.local_state WHERE key=?1",
                [key],
                |row| row.get(0),
            )?;
            if actual != expected {
                return Err(sync_extend_journal::JournalError::Invariant(
                    "metadata actual SQL space device root fresh session",
                ));
            }
        }
        Ok(())
    })?;
    if super::manifest_root_from_recovered_image(image, scope.space, bounds)? != *scope.root {
        return Err(ReconcileError::Invariant(
            "metadata actual SQL current manifest root",
        ));
    }
    Ok(())
}

fn verify_sql_transition(
    before: &JournalBackupImage,
    after: &JournalBackupImage,
    pair: &MetadataReceiptPair,
    scope: &MetadataScope<'_>,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    verify_image_scope(before, scope, bounds)?;
    verify_image_scope(after, scope, bounds)?;
    after.audit_recovered_history_extension(before, scope.space, bounds)?;
    after.audit_recovered_metadata_transition(
        before,
        scope.space,
        &pair.terminal.2.production_outcome(),
        bounds,
    )?;
    let original_pins = before.recovered_pin_ids(scope.space, bounds)?;
    if original_pins != after.recovered_pin_ids(scope.space, bounds)? {
        return Err(ReconcileError::Invariant(
            "metadata close changed an original production GC pin family",
        ));
    }
    let mut expected = retention_records(before, scope.space, bounds)?;
    match &pair.terminal.2 {
        MetadataReceiptOutcome::Retention(audit) => match pair.intention.1 {
            MetadataOperation::Retain => {
                if !original_pins.is_subset(&audit.mapping.pins)
                    || expected
                        .insert(audit.mapping.retention_id.clone(), audit.clone())
                        .is_some()
                {
                    return Err(ReconcileError::Invariant(
                        "metadata retain exact SQL insertion complete original pins",
                    ));
                }
            }
            MetadataOperation::Release => {
                let prior = expected.get_mut(&audit.mapping.retention_id).ok_or(
                    ReconcileError::Invariant("metadata release original SQL mapping absent"),
                )?;
                if prior.mapping != audit.mapping
                    || prior.mapping_digest != audit.mapping_digest
                    || prior.release.is_some()
                {
                    return Err(ReconcileError::Invariant(
                        "metadata release changed or already released SQL mapping",
                    ));
                }
                *prior = audit.clone();
                before.preflight_recovered_release(&audit.mapping, bounds)?;
            }
            _ => return Err(ReconcileError::Invariant("metadata SQL retention family")),
        },
        MetadataReceiptOutcome::GcMark(audit) => {
            before.preflight_recovered_gc(scope.space, &audit.intent.content_id, bounds)?;
            let json = serde_json::to_string(&audit.intent)?;
            let valid = after.with_audited_readonly(scope.space, bounds, |connection| {
                connection.query_row(
                    "SELECT count(*)=1 FROM main.gc_marks m
                     WHERE m.mark_id=?1 AND m.intent=?2 AND m.intent_hash=?3
                       AND NOT EXISTS(SELECT 1 FROM main.gc_cancellations c WHERE c.mark_id=m.mark_id)
                       AND NOT EXISTS(SELECT 1 FROM main.gc_invalidations i WHERE i.mark_id=m.mark_id)",
                    [
                        audit.intent.mark_id.as_str(),
                        json.as_str(),
                        ContentId::hash(json.as_bytes()).as_str(),
                    ],
                    |row| row.get::<_, bool>(0),
                ).map_err(Into::into)
            })?;
            if !valid {
                return Err(ReconcileError::Invariant(
                    "metadata GC terminal differs from actual production SQL mark",
                ));
            }
        }
    }
    if expected != retention_records(after, scope.space, bounds)? {
        return Err(ReconcileError::Invariant(
            "metadata close complete SQL mapping and release record set differs",
        ));
    }
    // This complete catalogue audit includes metadata row/byte capacity. The
    // close envelope separately binds its digest and the native main/SHM bytes.
    after.closed_node_complete_rows_digest(scope.space, bounds)?;
    Ok(())
}

fn verify_mapping_source(
    mapping: &RecoveredRetentionMapping,
    retained: &[&ReacquiredFile],
    space: &SpaceId,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    let parent = retained
        .iter()
        .find(|file| file.digest == mapping.source_history_receipt)
        .ok_or(ReconcileError::Invariant(
            "metadata retained original history parent absent",
        ))?;
    let parent_record = super::history_chain8_records(&parent.file.exact_bytes(parent.bytes)?)?;
    if parent_record.archive != mapping.archive_digest
        || parent_record.original_frames != mapping.original_frames_digest
        || parent_record.worktree != mapping.mapped_worktree
        || parent_record.root != mapping.snapshot_id
        || parent_record.native_keys[..3] != mapping.native_keys[..3]
        || parent_record.session == mapping.session
    {
        return Err(ReconcileError::Invariant(
            "metadata mapping exact immutable original history parent",
        ));
    }
    let source = retained
        .iter()
        .find(|file| file.digest == mapping.source_image)
        .ok_or(ReconcileError::Invariant(
            "metadata retained exact mapping source image absent",
        ))?;
    let bytes = source.file.exact_bytes(source.bytes)?;
    let image = JournalBackupImage::from_current_node_image(
        bytes.clone(),
        mapping.source_image.as_str(),
        bytes.len(),
        space,
        bounds,
    )?;
    let scope = MetadataScope {
        archive: &mapping.archive_digest,
        original_frames: &mapping.original_frames_digest,
        space: &mapping.space_id,
        device: &mapping.device_id,
        original_worktree: Some(Path::new(&mapping.original_worktree)),
        mapped_worktree: Path::new(&mapping.mapped_worktree),
        session: &mapping.session,
        native_keys: &mapping.native_keys,
        generation: mapping.generation,
        source_history_receipt: &mapping.source_history_receipt,
        source_image: &mapping.source_image,
        source_inventory: &mapping.source_inventory,
        root: &mapping.snapshot_id,
    };
    verify_image_scope(&image, &scope, bounds)?;
    if image
        .recovered_history_tables(space, bounds)?
        .catalog_digest
        != mapping.source_inventory
        || !image
            .recovered_pin_ids(space, bounds)?
            .is_subset(&mapping.pins)
    {
        return Err(ReconcileError::Invariant(
            "metadata mapping source complete inventory pins root differs",
        ));
    }
    Ok(())
}

fn require_new_gc_mark(
    image: &JournalBackupImage,
    space: &SpaceId,
    id: &ContentId,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    let active = image.with_audited_readonly(space, bounds, |connection| {
        connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.gc_marks m WHERE m.content_id=?1
                 AND NOT EXISTS(SELECT 1 FROM main.gc_cancellations c WHERE c.mark_id=m.mark_id)
                 AND NOT EXISTS(SELECT 1 FROM main.gc_invalidations i WHERE i.mark_id=m.mark_id))",
                [id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(Into::into)
    })?;
    if active {
        return Err(ReconcileError::Invariant(
            "recovered GC mark already has a distinct committed original owner",
        ));
    }
    Ok(())
}

pub(super) fn verify_generation_metadata(
    archive: &VerifiedNodeStateArchive,
    record: &HistoryChain8Record,
    metadata: Option<&RecoveredMetadataCloseEvidence>,
    baseline: &JournalBackupImage,
    retained: &BTreeMap<String, ReacquiredFile>,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    let metadata_receipts = record
        .receipts
        .iter()
        .filter(|item| item.name.starts_with("node-recovered-retention-"))
        .collect::<Vec<_>>();
    let Some(evidence) = metadata else {
        if !metadata_receipts.is_empty() {
            return Err(ReconcileError::Invariant(
                "metadata receipt lacks separate close evidence",
            ));
        }
        return Ok(());
    };
    let predecessor = record
        .predecessor
        .as_ref()
        .ok_or(ReconcileError::Invariant(
            "metadata generation original predecessor absent",
        ))?;
    if metadata_receipts.len() != 1
        || record.receipts.len() != 1
        || evidence.source_image != record.baseline.digest
        || evidence.source_history_receipt != predecessor.digest
        || evidence.source_inventory
            != baseline
                .recovered_history_tables(archive.space(), bounds)?
                .catalog_digest
        || evidence.receipt
            != (
                metadata_receipts[0].name.clone(),
                metadata_receipts[0].digest.clone(),
                metadata_receipts[0].bytes,
            )
    {
        return Err(ReconcileError::Invariant(
            "metadata generation exact held source and native receipt",
        ));
    }
    let file = retained
        .get(&evidence.receipt.0)
        .ok_or(ReconcileError::Invariant(
            "metadata generation receipt unheld",
        ))?;
    let pair = metadata_pair(&file.file.exact_bytes(file.bytes)?)?;
    if pair.intention.1 != evidence.operation || pair.intention.2 != evidence.object_id {
        return Err(ReconcileError::Invariant(
            "metadata generation canonical intended operation differs",
        ));
    }
    let scope = MetadataScope {
        archive: archive.digest(),
        original_frames: &record.original_frames,
        space: archive.space(),
        device: archive.device(),
        original_worktree: Some(archive.original_worktree()),
        mapped_worktree: Path::new(&record.worktree),
        session: &record.session,
        native_keys: &record.native_keys,
        generation: evidence.generation,
        source_history_receipt: &predecessor.digest,
        source_image: &record.baseline.digest,
        source_inventory: &evidence.source_inventory,
        root: &record.root,
    };
    verify_pair_scope(&pair, &scope, &record.main)?;
    verify_image_scope(baseline, &scope, bounds)
}

pub(super) fn verify_chain_metadata_sql(
    archive: &VerifiedNodeStateArchive,
    generations: &[LoadedHistoryGeneration],
    current: &JournalBackupImage,
    retained: &BTreeMap<String, ReacquiredFile>,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    for (index, generation) in generations.iter().enumerate() {
        let newer;
        let after = if index == 0 {
            current
        } else {
            newer = generations[index - 1]
                .baseline
                .normalize_recovered_history_session(
                    archive.space(),
                    bounds,
                    &generation.record.session,
                    &generations[index - 1].record.session,
                )?;
            &newer
        };
        let Some(evidence) = generation.metadata.as_ref() else {
            if retention_records(&generation.baseline, archive.space(), bounds)?
                != retention_records(after, archive.space(), bounds)?
            {
                return Err(ReconcileError::Invariant(
                    "native history generation changed metadata without committed proof",
                ));
            }
            after.audit_recovered_gc_transition(&generation.baseline, archive.space(), bounds)?;
            continue;
        };
        if evidence.generation as usize != generations.len() - index - 1 {
            return Err(ReconcileError::Invariant(
                "metadata exact SQL generation depth differs",
            ));
        }
        let file = retained
            .get(&evidence.receipt.0)
            .ok_or(ReconcileError::Invariant(
                "metadata SQL exact held receipt absent",
            ))?;
        let pair = metadata_pair(&file.file.exact_bytes(file.bytes)?)?;
        let scope = MetadataScope {
            archive: archive.digest(),
            original_frames: &generation.record.original_frames,
            space: archive.space(),
            device: archive.device(),
            original_worktree: Some(archive.original_worktree()),
            mapped_worktree: Path::new(&generation.record.worktree),
            session: &generation.record.session,
            native_keys: &generation.record.native_keys,
            generation: evidence.generation,
            source_history_receipt: &evidence.source_history_receipt,
            source_image: &evidence.source_image,
            source_inventory: &evidence.source_inventory,
            root: &generation.record.root,
        };
        verify_sql_transition(&generation.baseline, after, &pair, &scope, bounds)?;
        if let MetadataReceiptOutcome::Retention(audit) = &pair.terminal.2 {
            verify_mapping_source(
                &audit.mapping,
                &retained.values().collect::<Vec<_>>(),
                archive.space(),
                bounds,
            )?;
        }
    }
    Ok(())
}

fn object_path(data: &Path, id: &ContentId) -> std::path::PathBuf {
    data.join("cas")
        .join("objects")
        .join(&id.as_str()[..2])
        .join(id.as_str())
}
fn held_content<'a>(
    read: &'a ReacquiredClosedNodeLockedReadScope,
    id: &ContentId,
) -> Result<&'a ReacquiredFile> {
    let path = object_path(&read.read.data, id);
    let file = read
        .read
        .files
        .iter()
        .find(|file| file.path == path)
        .ok_or(ReconcileError::Invariant(
            "recovered retention CAS object is not originally held",
        ))?;
    file.file.verify()?;
    if file.digest != *id
        || !file.file.matches_path(&path)?
        || !(1..=4 * 1024 * 1024).contains(&file.bytes)
        || ContentId::hash(&file.file.exact_bytes(file.bytes)?) != *id
    {
        return Err(ReconcileError::Invariant(
            "recovered retention CAS key slot bytes differ",
        ));
    }
    Ok(file)
}

pub(super) fn preflight_operation(
    archive: &VerifiedNodeStateArchive,
    read: &ReacquiredClosedNodeLockedReadScope,
    image: &JournalBackupImage,
    retained: &BTreeMap<String, ReacquiredFile>,
    native_keys: &[String; 4],
    original_frames: &ContentId,
    operation: RecoveredHistoryOperation<'_>,
    bounds: NodeInspectionBounds,
) -> Result<()> {
    match operation {
        RecoveredHistoryOperation::Retain(extra) => {
            for id in image.preflight_recovered_retain(archive.space(), extra, bounds)? {
                held_content(read, &id)?;
            }
        }
        RecoveredHistoryOperation::Release(mapping) => {
            if mapping.archive_digest != *archive.digest()
                || mapping.space_id != *archive.space()
                || mapping.original_frames_digest != *original_frames
                || mapping.device_id != *archive.device()
                || Path::new(&mapping.original_worktree) != archive.original_worktree()
                || Path::new(&mapping.mapped_worktree) != read.read.worktree
                || mapping.native_keys[..3] != native_keys[..3]
            {
                return Err(ReconcileError::Invariant(
                    "recovered release foreign original receipt mapping",
                ));
            }
            verify_mapping_source(
                mapping,
                &retained.values().collect::<Vec<_>>(),
                archive.space(),
                bounds,
            )?;
            image.preflight_recovered_release(mapping, bounds)?;
            for id in &mapping.pins {
                held_content(read, id)?;
            }
        }
        RecoveredHistoryOperation::GcMark(id) => {
            image.preflight_recovered_gc(archive.space(), id, bounds)?;
            require_new_gc_mark(image, archive.space(), id, bounds)?;
            held_content(read, id)?;
        }
    }
    Ok(())
}

impl VerifiedNodeStateArchive {
    /// Preeffect selection runs after closed-chain/held-object verification and
    /// before CREATE of a fresh owner, SHM epoch or recovery session.
    #[allow(clippy::too_many_arguments)]
    pub fn open_recovered_history_operation(
        &self,
        worktree: &Path,
        data: &Path,
        original_frames: &Path,
        restore_ledger: &Path,
        history_chain: &Path,
        bounds: NodeInspectionBounds,
        ledger_bounds: crate::node_archive::LedgerBounds,
        operation: RecoveredHistoryOperation<'_>,
    ) -> Result<crate::RecoveredLocalSpace> {
        let mut session = self.reacquire_closed_history_chain8_internal(
            worktree,
            data,
            original_frames,
            restore_ledger,
            history_chain,
            bounds,
            ledger_bounds,
            true,
            Some(operation),
            None,
        )?;
        session.verify()?;
        session.commit_fresh_session()?;
        session.verify()?;
        crate::RecoveredLocalSpace::from_reacquired_session(session)
    }
}

impl FreshRecoveredNodeWalV2Session {
    pub(super) fn verified_metadata_close_evidence(
        &self,
    ) -> Result<Option<RecoveredMetadataCloseEvidence>> {
        if self.metadata_count == 0 {
            if !self.retained_metadata_receipts.is_empty()
                || self
                    .retained_receipts
                    .keys()
                    .any(|name| name.starts_with("node-recovered-retention-"))
            {
                return Err(ReconcileError::Invariant(
                    "metadata receipt without actual live committed proof",
                ));
            }
            return Ok(None);
        }
        if self.metadata_count != 1
            || self.retained_metadata_receipts.len() != self.metadata_count as usize
            || self.history_count != 0
            || !self.committed
            || self.closed
            || self.poisoned
            || self.next != 2
        {
            return Err(ReconcileError::Invariant(
                "metadata close requires separate actual committed live owner",
            ));
        }
        let proof = &self.retained_metadata_receipts[0];
        let name = format!("node-recovered-retention-{}-0.frames", self.fresh);
        let file = self
            .retained_receipts
            .get(&name)
            .ok_or(ReconcileError::Invariant(
                "metadata original receipt creator absent",
            ))?;
        let object = super::history_object(file)?;
        if serde_json::to_vec(&object)? != serde_json::to_vec(&proof.object)? {
            return Err(ReconcileError::Invariant(
                "metadata original creator native identity or bytes differs",
            ));
        }
        let pair = metadata_pair(&file.file.exact_bytes(file.bytes)?)?;
        if pair != proof.pair {
            return Err(ReconcileError::Invariant(
                "metadata original canonical pair differs from live committed proof",
            ));
        }
        let predecessor = self
            .history_chain_parent
            .as_ref()
            .ok_or(ReconcileError::Invariant(
                "metadata original source parent absent",
            ))?;
        let parent = self
            .retained_history_evidence
            .iter()
            .find(|item| item.path.file_name().and_then(|n| n.to_str()) == Some(&predecessor.name))
            .ok_or(ReconcileError::Invariant(
                "metadata original source parent unheld",
            ))?;
        if serde_json::to_vec(&super::history_object(parent)?)? != serde_json::to_vec(predecessor)?
        {
            return Err(ReconcileError::Invariant(
                "metadata original source parent native identity or bytes differs",
            ));
        }
        let source_image = ContentId::hash(&self.history_baseline);
        let baseline = JournalBackupImage::from_current_node_image(
            self.history_baseline.clone(),
            source_image.as_str(),
            self.history_baseline.len(),
            &self.space,
            self.bounds,
        )?;
        let source_inventory = baseline
            .recovered_history_tables(&self.space, self.bounds)?
            .catalog_digest;
        let main = self.native.exact_main_bytes()?;
        let digest = ContentId::hash(&main);
        let current = JournalBackupImage::from_current_node_image(
            main.clone(),
            digest.as_str(),
            main.len(),
            &self.space,
            self.bounds,
        )?;
        let device = self.recovered_device_id()?;
        let root = self.read.read.manifest.root()?;
        let scope = MetadataScope {
            archive: &self.archive,
            original_frames: &self.original_frames,
            space: &self.space,
            device: &device,
            original_worktree: proof.original_worktree.as_deref(),
            mapped_worktree: &self.read.read.worktree,
            session: &self.fresh,
            native_keys: &self.native_keys,
            generation: self.history_chain_depth,
            source_history_receipt: &predecessor.digest,
            source_image: &source_image,
            source_inventory: &source_inventory,
            root: &root,
        };
        verify_pair_scope(&pair, &scope, &digest)?;
        verify_sql_transition(&baseline, &current, &pair, &scope, self.bounds)?;
        match &pair.terminal.2 {
            MetadataReceiptOutcome::Retention(audit) => {
                for pin in &audit.mapping.pins {
                    held_content(&self.read, pin)?;
                }
                if pair.intention.1 == MetadataOperation::Release {
                    verify_mapping_source(
                        &audit.mapping,
                        &self.retained_history_evidence.iter().collect::<Vec<_>>(),
                        &self.space,
                        self.bounds,
                    )?;
                }
            }
            MetadataReceiptOutcome::GcMark(audit) => {
                let file = held_content(&self.read, &audit.intent.content_id)?;
                if audit.intent.observation.length as u64 != file.bytes
                    || audit.intent.observation.physical_identity
                        != crate::filesystem::physical_identity(&file.path)?
                {
                    return Err(ReconcileError::Invariant(
                        "metadata GC terminal original held CAS observation differs",
                    ));
                }
            }
        }
        let evidence = RecoveredMetadataCloseEvidence {
            version: 1,
            metadata_count: self.metadata_count,
            generation: self.history_chain_depth,
            source_history_receipt: predecessor.digest.clone(),
            source_image,
            source_inventory,
            receipt: (object.name, object.digest, object.bytes),
            operation: pair.intention.1,
            object_id: pair.intention.2.clone(),
            final_image: digest.clone(),
        };
        validate_close_metadata(
            Some(&evidence),
            self.history_count,
            std::slice::from_ref(&evidence.receipt),
            &self.fresh,
            &digest,
        )?;
        Ok(Some(evidence))
    }

    fn require_metadata_boundary(&self) -> Result<()> {
        self.verify()?;
        if !self.committed
            || self.closed
            || !self.mutation_requested
            || self.next != 2
            || self.history_count != 0
            || self.metadata_count != 0
            || !self.retained_metadata_receipts.is_empty()
            || self.history_chain_parent.is_none()
            || !(1..64).contains(&self.history_chain_depth)
            || self.history_baseline != self.native.exact_main_bytes()?
            || self
                .retained_receipt_bytes
                .checked_add(256 * 1024)
                .is_none_or(|n| n > 4 * 1024 * 1024)
        {
            return Err(ReconcileError::Invariant(
                "recovered retention requires fresh exact committed history owner",
            ));
        }
        Ok(())
    }

    fn commit_metadata(
        &mut self,
        plan: RecoveredRetentionPlan,
        operation: MetadataOperation,
        id: &EntryId,
        original_worktree: Option<&Path>,
    ) -> Result<RecoveredMetadataOutcome> {
        self.require_metadata_boundary()?;
        let committed_count = self
            .metadata_count
            .checked_add(1)
            .filter(|count| *count < 128)
            .ok_or(ReconcileError::ResourceLimit(
                "metadata committed count bound",
            ))?;
        let before = ContentId::hash(&self.native.exact_main_bytes()?);
        let external = self
            .path
            .parent()
            .ok_or(ReconcileError::Invariant("retention external root"))?;
        let held = self
            .read
            .read
            .directories
            .iter()
            .find(|d| d.path == external)
            .ok_or(ReconcileError::Invariant(
                "retention exact held external root",
            ))?;
        let intention =
            serde_json::to_vec(&(1u32, operation, id, &self.archive, &self.fresh, &before))?;
        self.poisoned = true;
        let mut receipt = held.file.create_new_file(&format!(
            "node-recovered-retention-{}-{}.frames",
            self.fresh, self.metadata_count
        ))?;
        receipt
            .writer()
            .write_all(&(intention.len() as u32).to_le_bytes())?;
        receipt.writer().write_all(&intention)?;
        receipt.writer().sync_all()?;
        crate::fault::checkpoint("recovered_retention_intended_before_sql");
        let outcome = plan.execute(&mut self.native)?;
        crate::fault::checkpoint("recovered_retention_committed_before_receipt");
        let bytes = self.native.exact_main_bytes()?;
        let image = JournalBackupImage::from_current_node_image(
            bytes.clone(),
            ContentId::hash(&bytes).as_str(),
            bytes.len(),
            &self.space,
            self.bounds,
        )?;
        self.before_rows = image.recovered_session_preserved_rows_digest(
            &self.space,
            self.bounds,
            &self.previous,
            &self.fresh,
        )?;
        let terminal = serde_json::to_vec(&(1u32, "committed", &outcome, ContentId::hash(&bytes)))?;
        if terminal.len() > 128 * 1024 {
            return Err(ReconcileError::ResourceLimit(
                "retention immutable receipt terminal budget",
            ));
        }
        receipt
            .writer()
            .write_all(&(terminal.len() as u32).to_le_bytes())?;
        receipt.writer().write_all(&terminal)?;
        receipt.writer().sync_all()?;
        self.retain_recovered_receipt(receipt)?;
        let name = format!(
            "node-recovered-retention-{}-{}.frames",
            self.fresh, self.metadata_count
        );
        let file = self
            .retained_receipts
            .get(&name)
            .ok_or(ReconcileError::Invariant(
                "metadata synced original receipt absent",
            ))?;
        let pair = metadata_pair(&file.file.exact_bytes(file.bytes)?)?;
        if pair.intention
            != (
                1,
                operation,
                id.clone(),
                self.archive.clone(),
                self.fresh.clone(),
                before,
            )
        {
            return Err(ReconcileError::Invariant(
                "metadata actual committed receipt differs from live intention",
            ));
        }
        self.retained_metadata_receipts
            .push(RecoveredMetadataReceiptProof {
                object: super::history_object(file)?,
                pair,
                original_worktree: original_worktree.map(Path::to_path_buf),
            });
        self.metadata_count = committed_count;
        self.poisoned = false;
        let result = (|| -> Result<()> {
            self.verify()?;
            self.verified_metadata_close_evidence()?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        Ok(outcome)
    }

    pub fn retain_recovered_history(
        &mut self,
        archive: &VerifiedNodeStateArchive,
        extra: &[ContentId],
    ) -> Result<sync_extend_journal::RecoveredRetentionAudit> {
        self.require_metadata_boundary()?;
        if self.archive != *archive.digest()
            || self.space != *archive.space()
            || self.recovered_device_id()? != *archive.device()
        {
            return Err(ReconcileError::Invariant(
                "retention archive is not this live original owner",
            ));
        }
        let image = self.recovered_local_query_image()?;
        let pins = image.preflight_recovered_retain(&self.space, extra, self.bounds)?;
        for id in &pins {
            held_content(&self.read, id)?;
        }
        let mapping = RecoveredRetentionMapping {
            version: 1,
            retention_id: EntryId::random()?,
            archive_digest: self.archive.clone(),
            original_frames_digest: self.original_frames.clone(),
            source_history_receipt: self
                .history_chain_parent
                .as_ref()
                .ok_or(ReconcileError::Invariant(
                    "retention immutable original history receipt",
                ))?
                .digest
                .clone(),
            source_image: ContentId::hash(image.bytes()),
            source_inventory: image
                .recovered_history_tables(&self.space, self.bounds)?
                .catalog_digest,
            space_id: self.space.clone(),
            device_id: archive.device().clone(),
            original_worktree: archive.original_worktree().to_string_lossy().into(),
            mapped_worktree: self.read.read.worktree.to_string_lossy().into(),
            session: self.fresh.clone(),
            native_keys: self.native_keys.clone(),
            generation: self.history_chain_depth,
            snapshot_id: self.read.read.manifest.root()?,
            pins,
        };
        let lease = self
            .native
            .issue_retention_lease(self.history_chain_depth)?;
        let plan = image.plan_recovered_retain(lease, &mapping, self.bounds)?;
        match self.commit_metadata(
            plan,
            MetadataOperation::Retain,
            &mapping.retention_id,
            Some(archive.original_worktree()),
        )? {
            RecoveredMetadataOutcome::Retention(audit) => Ok(audit),
            _ => Err(ReconcileError::Invariant("retention outcome family")),
        }
    }

    pub fn release_recovered_history(
        &mut self,
        mapping: &RecoveredRetentionMapping,
        timestamp: u64,
    ) -> Result<sync_extend_journal::RecoveredRetentionAudit> {
        self.require_metadata_boundary()?;
        if mapping.archive_digest != self.archive
            || mapping.original_frames_digest != self.original_frames
            || mapping.space_id != self.space
            || mapping.device_id != self.recovered_device_id()?
            || mapping.mapped_worktree != self.read.read.worktree.to_string_lossy()
            || mapping.native_keys[..3] != self.native_keys[..3]
        {
            return Err(ReconcileError::Invariant(
                "release foreign original mapping at live native boundary",
            ));
        }
        let image = self.recovered_local_query_image()?;
        image.preflight_recovered_release(mapping, self.bounds)?;
        verify_mapping_source(
            mapping,
            &self.retained_history_evidence.iter().collect::<Vec<_>>(),
            &self.space,
            self.bounds,
        )?;
        let release = RecoveredRetentionRelease {
            version: 1,
            retention_id: mapping.retention_id.clone(),
            mapping_digest: mapping.digest()?,
            pins_digest: mapping.pins_digest()?,
            session: self.fresh.clone(),
            native_keys: self.native_keys.clone(),
            generation: self.history_chain_depth,
            released_at_ms: timestamp,
        };
        let lease = self
            .native
            .issue_retention_lease(self.history_chain_depth)?;
        let plan = image.plan_recovered_release(lease, mapping, &release, self.bounds)?;
        match self.commit_metadata(
            plan,
            MetadataOperation::Release,
            &mapping.retention_id,
            Some(Path::new(&mapping.original_worktree)),
        )? {
            RecoveredMetadataOutcome::Retention(audit) => Ok(audit),
            _ => Err(ReconcileError::Invariant("release outcome family")),
        }
    }

    pub fn admit_recovered_gc_mark(
        &mut self,
        id: &ContentId,
        grace_secs: u64,
    ) -> Result<sync_extend_journal::GcMarkAudit> {
        self.require_metadata_boundary()?;
        let image = self.recovered_local_query_image()?;
        image.preflight_recovered_gc(&self.space, id, self.bounds)?;
        require_new_gc_mark(&image, &self.space, id, self.bounds)?;
        let file = held_content(&self.read, id)?;
        let path = object_path(&self.read.read.data, id);
        let metadata = std::fs::symlink_metadata(&path)?;
        let modified_at_ns = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReconcileError::Invariant("recovered GC modification before epoch"))?
            .as_nanos()
            .try_into()
            .map_err(|_| ReconcileError::ResourceLimit("recovered GC modification bound"))?;
        let observed = sync_extend_journal::GcObservation {
            physical_identity: crate::filesystem::physical_identity(&path)?,
            length: file
                .bytes
                .try_into()
                .map_err(|_| ReconcileError::ResourceLimit("recovered GC object length"))?,
            modified_at_ns,
        };
        let now = crate::now_ms()?;
        let mark = sync_extend_journal::GcMark {
            format_version: sync_extend_core_model::FORMAT_VERSION,
            mark_id: EntryId::random()?,
            space_id: self.space.clone(),
            content_id: id.clone(),
            observation: observed,
            marked_at_ms: now,
            grace_until_ms: sync_extend_journal::gc_grace_until(now, grace_secs)?,
        };
        let lease = self
            .native
            .issue_retention_lease(self.history_chain_depth)?;
        let plan = image.plan_recovered_gc_mark(lease, &mark, self.bounds)?;
        match self.commit_metadata(plan, MetadataOperation::GcMark, &mark.mark_id, None)? {
            RecoveredMetadataOutcome::GcMark(audit) => Ok(audit),
            _ => Err(ReconcileError::Invariant("GC mark outcome family")),
        }
    }
}
