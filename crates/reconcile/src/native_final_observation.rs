//! Original native CREATE + original frozen pair + original complete Journal evidence.
use crate::{ReconcileError, Result, ScanResult};
use sync_extend_core_model::{ContentId, Manifest, Operation};
use sync_extend_platform_fs::{
    HeldPrivateVolume, OriginalOutsideIntent, OriginalPairFrozenObservation,
    OriginalPrivateVolumeFile, OutsidePreparationPair, UnixFileKey,
};

/// Read-only live Final observation. No public constructor, Clone or Deserialize.
/// It cannot grant cleanup or continued namespace exclusion.
pub struct OriginalLinuxNativeFinalObservation<'a, 'p, 'v> {
    _creator: &'a OriginalPrivateVolumeFile<'p, 'v>,
    _intent: &'a OriginalOutsideIntent,
    _volume: &'v HeldPrivateVolume,
    _frozen: &'a OriginalPairFrozenObservation<'v>,
    _pair: &'a OutsidePreparationPair,
    _history: sync_extend_journal::OriginalReservedHistoryCommitReceipt,
    _vacated: sync_extend_platform_fs::OriginalCreateVacatedObservation<'a, 'p, 'v>,
    original_key: UnixFileKey,
    parent_key: UnixFileKey,
    exact_history_digest: ContentId,
}

impl<'a, 'p, 'v> OriginalLinuxNativeFinalObservation<'a, 'p, 'v> {
    /// Descriptive evidence only; no removal/cleanup operation is exposed.
    pub fn original_key(&self) -> UnixFileKey {
        self.original_key
    }
    pub fn parent_key(&self) -> UnixFileKey {
        self.parent_key
    }
    pub fn original_attempt(&self) -> &sync_extend_core_model::EntryId {
        self._history.original_attempt()
    }
    pub fn exact_native_phase_digest(&self) -> &ContentId {
        self._history.native_phase_chain().exact_digest()
    }
    pub fn exact_history_digest(&self) -> &ContentId {
        &self.exact_history_digest
    }
    pub(crate) fn original_history_receipt(
        &self,
    ) -> &sync_extend_journal::OriginalReservedHistoryCommitReceipt {
        &self._history
    }
}

/// This consumes the real commit receipt and borrows all original native
/// holders. The full pre-effect plan is independently matched against it.
pub fn observe_original_linux_native_final<'a, 'p, 'v>(
    creator: &'a OriginalPrivateVolumeFile<'p, 'v>,
    intent: &'a OriginalOutsideIntent,
    volume: &'v HeldPrivateVolume,
    frozen: &'a OriginalPairFrozenObservation<'v>,
    pair: &'a OutsidePreparationPair,
    result: &ScanResult,
    history: sync_extend_journal::OriginalReservedHistoryCommitReceipt,
) -> Result<OriginalLinuxNativeFinalObservation<'a, 'p, 'v>> {
    creator.verify()?;
    intent.verify(volume)?;
    frozen.verify_original_binding(pair)?;
    let value: serde_json::Value = serde_json::from_slice(intent.exact_bytes())?;
    let parts = value
        .as_array()
        .ok_or(ReconcileError::Invariant("original Linux intent array"))?;
    if parts.len() != 11 || parts[0] != 1u32 {
        return Err(ReconcileError::Invariant("original Linux intent schema"));
    }
    if parts[10].as_str() != Some(history.exact_reservation_json()) {
        return Err(ReconcileError::Invariant(
            "original Final reserved transaction differs",
        ));
    }
    let prior: Manifest = serde_json::from_value(parts[4].clone())?;
    let planned: Manifest = serde_json::from_value(parts[5].clone())?;
    let operations: Vec<Operation> = serde_json::from_value(parts[6].clone())?;
    let actual: Manifest = serde_json::from_str(history.snapshot_json())?;
    let actual_operations = history
        .operation_json()
        .iter()
        .map(|bytes| serde_json::from_str::<Operation>(bytes))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if planned != actual
        || operations != actual_operations
        || prior.root()?.as_str()
            != history
                .baseline()
                .ok_or(ReconcileError::Invariant("original baseline"))?
                .as_str()
        || planned.root()? != result.snapshot_id
        || history.snapshot() != &result.snapshot_id
        || operations.len() != result.operations
        || history.observation_json().is_none()
    {
        return Err(ReconcileError::Invariant(
            "original Linux complete planned Final differs",
        ));
    }
    let path = parts[3]
        .as_str()
        .ok_or(ReconcileError::Invariant("original Linux intent path"))?;
    let entry = planned
        .entries
        .values()
        .find(|entry| entry.path.as_str() == path)
        .ok_or(ReconcileError::Invariant(
            "original Linux planned target entry",
        ))?;
    let content = entry
        .content
        .as_ref()
        .ok_or(ReconcileError::Invariant("original Linux target content"))?;

    let worktree = parts[8]
        .as_str()
        .ok_or(ReconcileError::Invariant("original Linux worktree"))?;
    let actual_root = crate::filesystem::physical_identity(std::path::Path::new(worktree))?;
    if parts[9].as_str() != Some(actual_root.as_str())
        || parts[1].as_str() != Some(planned.space_id.as_str())
        || parts[1].as_str() != Some(result.space_id.as_str())
        || operations.iter().any(|operation| {
            parts[2].as_str() != Some(operation.payload.origin_device_id.as_str())
                || parts[7].as_u64() != Some(operation.payload.created_at_ms)
                || operation.payload.space_id != planned.space_id
        })
    {
        return Err(ReconcileError::Invariant(
            "original Linux exact request root or operation scope",
        ));
    }
    let target = std::path::Path::new(worktree).join(path);
    creator.verify_original_slot(&target)?;
    let bytes = creator.exact_bytes()?;
    if bytes.len() as u64 != content.length || ContentId::hash(&bytes) != content.content_id {
        return Err(ReconcileError::Invariant(
            "original Linux created bytes differ from Final",
        ));
    }
    // This is an observation, not a namespace certificate: syscall identities
    // and the armed pair are rechecked after exact native byte verification.
    creator.verify_original_slot(&target)?;
    intent.verify(volume)?;
    frozen.verify_original_binding(pair)?;
    let original_key = creator.original_key()?;
    let parent_key = creator.original_parent_key()?;
    if history.native_phase_chain().original_attempt() != history.original_attempt() {
        return Err(ReconcileError::Invariant(
            "original Final phase attempt differs",
        ));
    }
    history.native_phase_chain().verify_original_native(
        intent.exact_bytes(),
        (original_key.device, original_key.inode),
        (parent_key.device, parent_key.inode),
        &bytes,
    )?;

    if original_key.device != frozen.observation().root_key.device {
        return Err(ReconcileError::Invariant(
            "original Linux Final cross-volume",
        ));
    }
    let observations: sync_extend_core_model::persisted_rename::RenameObservationMap =
        serde_json::from_str(history.observation_json().ok_or(ReconcileError::Invariant(
            "original Linux Final observation bytes required",
        ))?)?;
    observations.validate(&planned, sync_extend_core_model::limits::MAX_ENTRIES)?;
    let native_identity =
        ContentId::hash(format!("inode:{}:{}", original_key.device, original_key.inode).as_bytes());
    let observed = observations
        .entries
        .iter()
        .find(|record| record.entry_id == entry.entry_id)
        .ok_or(ReconcileError::Invariant(
            "original Linux Final target observation missing",
        ))?;
    let timestamp = parts[7].as_u64().ok_or(ReconcileError::Invariant(
        "original Linux Final timestamp required",
    ))?;
    let vacated = creator.observe_original_create_slot_absence()?;
    vacated.verify()?;
    let exact_history_digest = ContentId::hash(&serde_json::to_vec(&(
        1u32,
        history.baseline(),
        history.snapshot_json(),
        history.operation_json(),
        history.observation_json(),
        timestamp,
    ))?);
    if observations.scope.local_root_identity != actual_root
        || observed.observed.path != entry.path
        || observed.observed.kind != entry.kind
        || observed.observed.content != entry.content
        || observed.observed.physical_identity != native_identity
        || !observed.observed.single_link
        || !creator.observed_single_link()?
        || exact_history_digest != *history.evidence_digest()
        || result.entries != planned.entries.len()
        || result.files
            != planned
                .entries
                .values()
                .filter(|entry| entry.kind == sync_extend_core_model::EntryKind::File)
                .count()
    {
        return Err(ReconcileError::Invariant(
            "original Linux Final physical observation or complete commit digest differs",
        ));
    }
    creator.verify_original_slot(&target)?;
    intent.verify(volume)?;
    frozen.verify_original_binding(pair)?;
    Ok(OriginalLinuxNativeFinalObservation {
        _creator: creator,
        _intent: intent,
        _volume: volume,
        _frozen: frozen,
        _pair: pair,
        _history: history,
        _vacated: vacated,
        original_key,
        parent_key,
        exact_history_digest,
    })
}
