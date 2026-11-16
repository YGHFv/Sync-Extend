//! Full ordered file hashes reconstructed from original CAS sections.
use super::layout::{ArchiveRole, FramedNodeArchive};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{ContentId, FileManifest};
use sync_extend_journal::{JournalError, Result};

pub(super) struct FileClosure {
    files: BTreeMap<ContentId, FileManifest>,
    chunks: BTreeMap<ContentId, u32>,
    visits: usize,
    hash_bytes: u64,
    max_visits: usize,
    max_hash_bytes: u64,
}

impl FileClosure {
    pub(super) fn new(max_visits: usize, max_hash_bytes: u64) -> Result<Self> {
        if max_visits == 0
            || max_visits > sync_extend_core_model::limits::MAX_CHUNKS
            || max_hash_bytes == 0
            || max_hash_bytes > 1024 * 1024 * 1024
        {
            return Err(JournalError::Invariant(
                "explicit bounded node content hash work",
            ));
        }
        Ok(Self {
            files: BTreeMap::new(),
            chunks: BTreeMap::new(),
            visits: 0,
            hash_bytes: 0,
            max_visits,
            max_hash_bytes,
        })
    }

    pub(super) fn add(&mut self, file: &FileManifest) -> Result<()> {
        file.validate()?;
        self.visits = self
            .visits
            .checked_add(file.chunks.len())
            .filter(|count| *count <= self.max_visits)
            .ok_or(JournalError::Invariant(
                "node owner content chunk visit bound",
            ))?;
        for chunk in &file.chunks {
            if self
                .chunks
                .insert(chunk.content_id.clone(), chunk.length)
                .is_some_and(|length| length != chunk.length)
            {
                return Err(JournalError::Invariant("node owner chunk length conflict"));
            }
        }
        match self.files.get(&file.content_id) {
            Some(existing) if existing != file => {
                return Err(JournalError::Invariant(
                    "node complete file description conflict",
                ));
            }
            Some(_) => {}
            None => {
                self.hash_bytes = self
                    .hash_bytes
                    .checked_add(file.length)
                    .filter(|count| *count <= self.max_hash_bytes)
                    .ok_or(JournalError::Invariant(
                        "node complete content hash byte bound",
                    ))?;
                self.files.insert(file.content_id.clone(), file.clone());
            }
        }
        Ok(())
    }

    pub(super) fn verify(
        self,
        archive: &FramedNodeArchive,
        protected: &BTreeSet<ContentId>,
    ) -> Result<()> {
        if self.chunks.keys().cloned().collect::<BTreeSet<_>>() != *protected {
            return Err(JournalError::Invariant(
                "node supported full file owners differ from all pins",
            ));
        }
        for (id, length) in &self.chunks {
            let bytes = archive
                .section(&ArchiveRole::CasObject {
                    content_id: id.clone(),
                })
                .ok_or(JournalError::Invariant("node owner content chunk missing"))?;
            if bytes.len() as u64 != u64::from(*length) || ContentId::hash(bytes) != *id {
                return Err(JournalError::Invariant(
                    "node owner original chunk length or digest differs",
                ));
            }
        }
        // Ordered repeated chunks are retained: a set of correct chunk hashes
        // does not establish the complete file digest or its concatenation order.
        for file in self.files.values() {
            let mut hasher = blake3::Hasher::new();
            let mut length = 0u64;
            for chunk in &file.chunks {
                let bytes = archive
                    .section(&ArchiveRole::CasObject {
                        content_id: chunk.content_id.clone(),
                    })
                    .ok_or(JournalError::Invariant(
                        "node full file original chunk missing",
                    ))?;
                length = length
                    .checked_add(bytes.len() as u64)
                    .ok_or(JournalError::Invariant(
                        "node full file byte count overflow",
                    ))?;
                hasher.update(bytes);
            }
            if length != file.length
                || hasher.finalize().to_hex().as_str() != file.content_id.as_str()
            {
                return Err(JournalError::Invariant(
                    "node full ordered file content hash differs",
                ));
            }
        }
        Ok(())
    }
}
