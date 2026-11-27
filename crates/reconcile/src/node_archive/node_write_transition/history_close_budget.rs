//! Typed future chain8 record sizing before the first CAS/native effect.
use super::*;
use sync_extend_core_model::PortablePath;

fn largest_key() -> String { format!("windows:{}:{}", u64::MAX, u128::MAX) }
fn future_object() -> HistoryRestartObject {
    HistoryRestartObject {
        // Actual generated component names are ASCII and <=255 bytes.
        name: "x".repeat(255), key: largest_key(), parent: largest_key(),
        digest: ContentId::hash(&[]), bytes: u64::MAX,
    }
}

pub(super) fn encode(record: &HistoryChain8Record) -> Result<Vec<u8>> {
    let bytes = super::super::completion_codec::bytes(record, 384 * 1024)?;
    Ok(bytes)
}

impl FreshRecoveredNodeWalV2Session {
    pub(super) fn preflight_history_close_envelope(
        &self, additional_path: Option<&PortablePath>, additional_file: bool,
        additional_cas: usize, additional_retained: usize, additional_receipts: usize,
    ) -> Result<()> {
        let closing = additional_path.is_none() && additional_cas == 0
            && additional_retained == 0 && additional_receipts == 0;
        let mut objects = if closing { history_current_objects_with_metadata_proof(&self.read)? }
            else { history_current_objects(&self.read.read)? };
        if objects.len().checked_add(additional_cas.saturating_mul(2))
            .and_then(|n| n.checked_add(usize::from(additional_path.is_some())))
            .is_none_or(|n| n > FRESH_HELD_HISTORY_OBJECT_MAXIMUM) {
            return Err(ReconcileError::ResourceLimit("future close native object count"));
        }
        // Existing identities, metadata and paths have exact typed values. Only
        // the upcoming path/CAS objects need unknown physical-field headroom.
        if let Some(path) = additional_path {
            objects.push(HistoryCurrentObject {
                root: "work".into(), path: path.to_string(), directory: !additional_file,
                key: largest_key(), parent: largest_key(), digest: Some(ContentId::hash(&[])),
                bytes: u64::MAX, local_metadata: None,
            });
        }
        for _ in 0..additional_cas {
            for (path, directory) in [(format!("cas/objects/ff/{}", "f".repeat(64)), false), ("cas/objects/ff".into(), true)] {
                objects.push(HistoryCurrentObject {
                    root: "data".into(), path, directory, key: largest_key(), parent: largest_key(),
                    digest: Some(ContentId::hash(&[])), bytes: u64::MAX, local_metadata: None,
                });
            }
        }
        if objects.len() > FRESH_HELD_HISTORY_OBJECT_MAXIMUM {
            return Err(ReconcileError::ResourceLimit("future close native object count"));
        }
        let metadata_bytes = if additional_path.is_some() && additional_file {
            sync_extend_core_model::portable_entry_metadata::MAX_PORTABLE_ENTRY_METADATA_BYTES + 18
        } else { 0 };
        let mut receipts = self.retained_receipts.values().map(history_object).collect::<Result<Vec<_>>>()?;
        receipts.extend((0..additional_receipts).map(|_| future_object()));
        let mut retained_originals = self.history_retained_originals.clone();
        for retained in &self.retained_mutations {
            let mut original = history_object(&retained.original)?;
            let source_parent = original.parent.clone();
            original.parent = retained.directory.key()?.to_string();
            retained_originals.push(HistoryRetainedOriginal {
                name: retained.path.file_name().and_then(|s| s.to_str()).ok_or(ReconcileError::Unstable)?.into(),
                key: retained.directory.key()?.to_string(), parent: retained.directory.original_creation()?.parent_key()?.to_string(),
                source_parent, original,
            });
        }
        retained_originals.extend((0..additional_retained).map(|_| HistoryRetainedOriginal {
            name: "x".repeat(255), key: largest_key(), parent: largest_key(), source_parent: largest_key(), original: future_object(),
        }));
        let external = self.path.parent().ok_or(ReconcileError::Unstable)?;
        let root_key = |path: &std::path::Path| -> Result<String> {
            self.read.read.directories.iter().find(|held| held.path == path)
                .map(|held| held.key.to_string()).ok_or(ReconcileError::Unstable)
        };
        let external_key = root_key(external)?;
        let mut baseline = future_object();
        baseline.name = format!("node-history-baseline-{}.image", self.fresh);
        baseline.parent = external_key.clone();
        baseline.bytes = self.history_baseline.len() as u64;
        let mut history_close = future_object();
        history_close.name = format!("node-recovered-mutation-history-close-{}.frames", self.fresh);
        history_close.parent = external_key.clone();
        history_close.bytes = ORIGINAL_WRITE_FRAMES_MAXIMUM;
        let epoch = self.retained_history_evidence.iter().find(|item| item.path.file_name().and_then(|name| name.to_str())
            == Some(&format!("node-recovered-shm-epoch-{}.frames", self.fresh))).map(history_object).transpose()?;
        let record = HistoryChain8Record {
            version: 8, index: 1, phase: "close_intended".into(), archive: self.archive.clone(),
            original_frames: self.original_frames.clone(), session: self.fresh.clone(),
            worktree: self.read.read.worktree.to_str().ok_or(ReconcileError::Unstable)?.into(),
            data: self.read.read.data.to_str().ok_or(ReconcileError::Unstable)?.into(),
            work_key: root_key(&self.read.read.worktree)?, data_key: root_key(&self.read.read.data)?, external_key: external_key.clone(),
            native_keys: self.native_keys.clone(), predecessor: self.history_chain_parent.clone(), epoch,
            root: self.read.read.manifest.root()?, rows: ContentId::hash(&[]), main: ContentId::hash(&[]), shm: ContentId::hash(&[]),
            owner: HistoryRestartObject {
                name: format!("node-recovered-wal-{}.owner", self.fresh), key: self.owner.original_creation()?.key()?.to_string(),
                parent: self.owner.original_creation()?.parent_key()?.to_string(), digest: ContentId::hash(&[]), bytes: self.owner.reader().metadata()?.len(),
            }, baseline, receipts, retained_originals, current_objects: objects,
            history_close: Some(history_close), wal2: Some(HistoryRestartObject {
                name: self.path.file_name().and_then(|name| name.to_str()).ok_or(ReconcileError::Unstable)?.into(),
                key: self.frames.original_creation()?.key()?.to_string(), parent: external_key, digest: ContentId::hash(&[]), bytes: ORIGINAL_WRITE_FRAMES_MAXIMUM,
            }),
        };
        let length = encode(&record)?.len().checked_add(metadata_bytes)
            .ok_or(ReconcileError::ResourceLimit("future close complete record"))?;
        if length > 384 * 1024 {
            return Err(ReconcileError::ResourceLimit("future history close record envelope"));
        }
        // The same encoder handles both actual records. Two <=384KiB records
        // plus header/lengths/hash remain inside the unchanged1MiB frame bound.
        Ok(())
    }
}
