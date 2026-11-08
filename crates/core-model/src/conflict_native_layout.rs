//! Complete descriptive flat-file partition; never native execution authority.
use crate::{
    conflict_resolution::MAX_RESOLUTION_FILES, limits::MAX_CHUNKS, ContentId, Entry, EntryId,
    EntryKind, Manifest, ModelError, Result, SnapshotId, SpaceId,
};
use serde::Serialize;
use std::{collections::BTreeSet, io::Write};

const MAX_ACTIONS: usize = MAX_RESOLUTION_FILES * 2;
const MAX_LAYOUT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConflictNativeLayoutLimits {
    pub max_actions: usize,
    pub max_chunks: usize,
    pub max_input_bytes: usize,
    pub max_layout_bytes: usize,
    pub max_file_bytes: u64,
    pub max_baseline_bytes: u64,
    pub max_target_bytes: u64,
    pub max_internal_bytes: u64,
}
impl Default for ConflictNativeLayoutLimits {
    fn default() -> Self {
        Self {
            max_actions: MAX_ACTIONS,
            max_chunks: MAX_CHUNKS,
            max_input_bytes: MAX_LAYOUT_BYTES,
            max_layout_bytes: MAX_LAYOUT_BYTES,
            max_file_bytes: 64 * 1024 * 1024 * 1024,
            max_baseline_bytes: 1024 * 1024 * 1024 * 1024,
            max_target_bytes: 1024 * 1024 * 1024 * 1024,
            max_internal_bytes: 10 * 1024 * 1024 * 1024,
        }
    }
}
impl ConflictNativeLayoutLimits {
    fn validate(self) -> Result<()> {
        if self.max_actions == 0
            || self.max_actions > MAX_ACTIONS
            || self.max_chunks == 0
            || self.max_chunks > MAX_CHUNKS
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_LAYOUT_BYTES
            || self.max_layout_bytes == 0
            || self.max_layout_bytes > MAX_LAYOUT_BYTES
            || self.max_file_bytes == 0
            || self.max_file_bytes > MAX_CHUNKS as u64 * 4 * 1024 * 1024
            || self.max_baseline_bytes == 0
            || self.max_target_bytes == 0
            || self.max_internal_bytes == 0
        {
            return Err(invalid("conflict native layout limits"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictNativeActionKind {
    HoldOriginal,
    QuarantineOriginal,
    PublishOriginal,
    ReplaceOriginal,
    CreatePayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConflictNativeAction {
    pub entry_id: EntryId,
    pub kind: ConflictNativeActionKind,
    pub baseline: Option<Entry>,
    pub target: Option<Entry>,
    pub original_component: Option<String>,
    pub payload_component: Option<String>,
}

/// Components and ordering are proposals, not creator receipts or native keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConflictNativeLayout {
    pub format_version: u32,
    pub space_id: SpaceId,
    pub baseline_root: SnapshotId,
    pub target_root: SnapshotId,
    pub actions: Vec<ConflictNativeAction>,
    pub quarantine_order: Vec<EntryId>,
    pub publication_order: Vec<EntryId>,
    pub baseline_bytes: u64,
    pub target_bytes: u64,
    pub quarantine_bytes: u64,
    pub payload_bytes: u64,
    pub internal_peak_bytes: u64,
    pub execution_authorized: bool,
    pub worktree_materialized: bool,
}
impl ConflictNativeLayout {
    pub fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(self)?))
    }
    pub fn verify_against(
        &self,
        baseline: &Manifest,
        target: &Manifest,
        limits: ConflictNativeLayoutLimits,
    ) -> Result<()> {
        if *self != plan_conflict_native_layout(baseline, target, limits)? {
            return Err(invalid(
                "conflict native layout differs from complete partition",
            ));
        }
        Ok(())
    }
}

fn invalid(message: &'static str) -> ModelError {
    ModelError::InvalidData(message)
}
fn add(value: &mut u64, amount: u64, maximum: u64) -> Result<()> {
    *value = value
        .checked_add(amount)
        .filter(|total| *total <= maximum)
        .ok_or(invalid("conflict native layout byte budget"))?;
    Ok(())
}
struct EncodedBudget {
    used: usize,
    maximum: usize,
}
impl Write for EncodedBudget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.maximum)
            .ok_or_else(|| std::io::Error::other("conflict native encoded budget"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encoded(value: &impl Serialize, maximum: usize) -> Result<()> {
    serde_json::to_writer(&mut EncodedBudget { used: 0, maximum }, value)?;
    Ok(())
}
fn check_manifest(
    manifest: &Manifest,
    maximum: u64,
    limits: ConflictNativeLayoutLimits,
    chunks: &mut usize,
) -> Result<u64> {
    if manifest.entries.len() > MAX_RESOLUTION_FILES
        || manifest.tombstones.len() > MAX_RESOLUTION_FILES
    {
        return Err(invalid("conflict native flat manifest entry budget"));
    }
    let mut bytes = 0;
    for entry in manifest.entries.values() {
        if entry.kind != EntryKind::File || entry.path.parent().is_some() {
            return Err(invalid("conflict native layout supports flat files only"));
        }
        let content = entry
            .content
            .as_ref()
            .ok_or(invalid("conflict native layout file content missing"))?;
        if content.length > limits.max_file_bytes {
            return Err(invalid("conflict native layout individual file budget"));
        }
        *chunks = chunks
            .checked_add(content.chunks.len())
            .filter(|count| *count <= limits.max_chunks)
            .ok_or(invalid("conflict native layout aggregate chunk budget"))?;
        add(&mut bytes, content.length, maximum)?;
    }
    manifest.validate()?;
    Ok(bytes)
}

/// All displaced originals leave live slots before the first publication. Exact
/// same-ID content descriptions alone may reuse a retained original on Rename.
pub fn plan_conflict_native_layout(
    baseline: &Manifest,
    target: &Manifest,
    limits: ConflictNativeLayoutLimits,
) -> Result<ConflictNativeLayout> {
    limits.validate()?;
    if baseline.space_id != target.space_id
        || baseline.policy_version != target.policy_version
        || !target.version_vector.dominates(&baseline.version_vector)
    {
        return Err(invalid("conflict native layout manifest scope"));
    }
    let mut chunks = 0;
    let baseline_bytes = check_manifest(baseline, limits.max_baseline_bytes, limits, &mut chunks)?;
    let target_bytes = check_manifest(target, limits.max_target_bytes, limits, &mut chunks)?;
    encoded(&(baseline, target), limits.max_input_bytes)?;
    let ids: BTreeSet<_> = baseline
        .entries
        .keys()
        .chain(target.entries.keys())
        .cloned()
        .collect();
    if ids.len() > limits.max_actions {
        return Err(invalid("conflict native layout complete union budget"));
    }
    let mut layout = ConflictNativeLayout {
        format_version: 1,
        space_id: baseline.space_id.clone(),
        baseline_root: baseline.root()?,
        target_root: target.root()?,
        actions: Vec::with_capacity(ids.len()),
        quarantine_order: Vec::new(),
        publication_order: Vec::new(),
        baseline_bytes,
        target_bytes,
        quarantine_bytes: 0,
        payload_bytes: 0,
        internal_peak_bytes: 0,
        execution_authorized: false,
        worktree_materialized: false,
    };
    for id in ids {
        let original = baseline.entries.get(&id);
        let projected = target.entries.get(&id);
        let kind = match (original, projected) {
            (Some(old), Some(new)) if old == new => ConflictNativeActionKind::HoldOriginal,
            (Some(old), Some(new)) if old.content == new.content => {
                ConflictNativeActionKind::PublishOriginal
            }
            (Some(_), Some(_)) => ConflictNativeActionKind::ReplaceOriginal,
            (Some(_), None) => ConflictNativeActionKind::QuarantineOriginal,
            (None, Some(_)) => ConflictNativeActionKind::CreatePayload,
            (None, None) => return Err(invalid("conflict native layout absent union identity")),
        };
        let displaced = original.is_some() && kind != ConflictNativeActionKind::HoldOriginal;
        let payload = matches!(
            kind,
            ConflictNativeActionKind::ReplaceOriginal | ConflictNativeActionKind::CreatePayload
        );
        if displaced {
            layout.quarantine_order.push(id.clone());
            add(
                &mut layout.quarantine_bytes,
                original.unwrap().content.as_ref().unwrap().length,
                limits.max_internal_bytes,
            )?;
        }
        if projected.is_some() && kind != ConflictNativeActionKind::HoldOriginal {
            layout.publication_order.push(id.clone());
        }
        if payload {
            add(
                &mut layout.payload_bytes,
                projected.unwrap().content.as_ref().unwrap().length,
                limits.max_internal_bytes,
            )?;
        }
        layout.actions.push(ConflictNativeAction {
            original_component: displaced.then(|| format!("original-{id}")),
            payload_component: payload.then(|| format!("payload-{id}")),
            entry_id: id,
            kind,
            baseline: original.cloned(),
            target: projected.cloned(),
        });
    }
    add(
        &mut layout.internal_peak_bytes,
        layout.quarantine_bytes,
        limits.max_internal_bytes,
    )?;
    add(
        &mut layout.internal_peak_bytes,
        layout.payload_bytes,
        limits.max_internal_bytes,
    )?;
    encoded(&layout, limits.max_layout_bytes)?;
    Ok(layout)
}
