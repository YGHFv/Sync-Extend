//! Authenticated gateway operations share the core journal and native pipeline.
use crate::{now_ms, LocalSpace, ReconcileError, Result};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
};
use sync_extend_core_model::{EntryId, FileManifest, Manifest, PortablePath, SnapshotId};

#[derive(Clone, Debug, serde::Serialize)]
pub struct WebDavCommit {
    pub transaction_id: EntryId,
    pub snapshot_id: SnapshotId,
    pub local_committed: bool,
    pub remote_backup_complete: bool,
}

pub struct WebDavRead {
    pub lease_id: EntryId,
    pub content: FileManifest,
    pub snapshot_id: SnapshotId,
}

/// Request baseline includes native identity, not only equal content hashes.
/// It stays private and cannot be manufactured from a serialized ETag.
pub struct WebDavBaseline {
    manifest: Manifest,
    native: crate::scan::Scan,
    #[cfg(windows)]
    parents: Vec<sync_extend_platform_fs::LockedDirectory>,
}

impl WebDavBaseline {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub fn snapshot_id(&self) -> Result<SnapshotId> {
        Ok(self.manifest.root()?)
    }
}

impl LocalSpace {
    pub fn capture_webdav_baseline(&mut self) -> Result<WebDavBaseline> {
        self.scan()?;
        let manifest = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("DAV baseline missing"))?;
        let native = self.stable_scan()?;
        if manifest.entries.len() != native.len()
            || manifest.entries.values().any(|entry| {
                native
                    .get(&entry.path)
                    .is_none_or(|seen| seen.kind != entry.kind || seen.content != entry.content)
            })
        {
            return Err(ReconcileError::Unstable);
        }
        #[cfg(windows)]
        let parents = {
            let mut paths = std::collections::BTreeSet::from([self.worktree.clone()]);
            paths.extend(
                manifest
                    .entries
                    .values()
                    .filter(|entry| entry.kind == sync_extend_core_model::EntryKind::Directory)
                    .map(|entry| self.worktree.join(entry.path.as_str())),
            );
            let mut parents = crate::guarded_mutation::directory_chain(&self.worktree)?;
            for path in paths {
                parents.push(sync_extend_platform_fs::LockedDirectory::open(&path)?);
            }
            parents
        };
        Ok(WebDavBaseline {
            manifest,
            native,
            #[cfg(windows)]
            parents,
        })
    }

    pub fn check_webdav_baseline(&self, baseline: &WebDavBaseline) -> Result<()> {
        self.verify_root()?;
        self.require_no_mutation()?;
        #[cfg(windows)]
        for parent in &baseline.parents {
            parent.key()?;
        }
        if baseline.manifest.space_id != self.space_id
            || self.manifest()?.as_ref() != Some(&baseline.manifest)
            || self.stable_scan()? != baseline.native
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }

    /// Single sequential listener limits aggregate outstanding uploads to one.
    /// Capacity is checked before body reception and again before CAS import.
    pub fn admit_webdav_upload(&self, length: u64) -> Result<()> {
        self.verify_root()?;
        self.require_no_mutation()?;
        if length > self.limits.max_file_bytes || length > self.limits.max_staging_bytes {
            return Err(ReconcileError::ResourceLimit("DAV upload bytes"));
        }
        if fs2::available_space(&self.data_dir)? < length.saturating_mul(2)
            || fs2::available_space(&self.worktree)? < length.saturating_mul(17).saturating_add(32)
        {
            return Err(ReconcileError::ResourceLimit(
                "DAV physical storage capacity",
            ));
        }
        self.reserve_internal_worktree(length.saturating_mul(17).saturating_add(32))?;
        Ok(())
    }

    pub fn acquire_webdav_read(&mut self, path: &PortablePath) -> Result<WebDavRead> {
        let snapshot = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("DAV scan required"))?
            .root()?;
        let lease = self.acquire_read_lease(&snapshot, path, 300)?;
        Ok(WebDavRead {
            lease_id: lease.intent.lease_id,
            content: lease
                .intent
                .entry
                .content
                .ok_or(ReconcileError::Invariant("DAV file lease required"))?,
            snapshot_id: snapshot,
        })
    }

    pub fn write_webdav_read(
        &mut self,
        read: &WebDavRead,
        range: Option<(u64, u64)>,
        writer: impl Write,
    ) -> Result<()> {
        self.verify_root()?;
        let lease = self.journal.admit_leased_read(
            &self.space_id,
            &read.lease_id,
            now_ms()?,
            self.limits.max_storage_entries,
        )?;
        if lease.intent.snapshot_id != read.snapshot_id
            || lease.intent.entry.content.as_ref() != Some(&read.content)
        {
            return Err(ReconcileError::Invariant("DAV exact fixed lease differs"));
        }
        let (start, end) = range.unwrap_or((0, read.content.length.saturating_sub(1)));
        if range.is_some() && (start > end || end >= read.content.length) {
            return Err(ReconcileError::Invariant("DAV invalid admitted range"));
        }
        struct RangeWriter<W> {
            writer: W,
            offset: u64,
            start: u64,
            end: u64,
        }
        impl<W: Write> Write for RangeWriter<W> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let end = self
                    .offset
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| io::Error::other("DAV stream overflow"))?;
                let begin = self
                    .start
                    .saturating_sub(self.offset)
                    .min(bytes.len() as u64) as usize;
                let finish = self
                    .end
                    .saturating_add(1)
                    .saturating_sub(self.offset)
                    .min(bytes.len() as u64) as usize;
                if begin < finish {
                    self.writer.write_all(&bytes[begin..finish])?;
                }
                self.offset = end;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                self.writer.flush()
            }
        }
        self.cas.write_file(
            &read.content,
            RangeWriter {
                writer,
                offset: 0,
                start,
                end,
            },
        )?;
        Ok(())
    }

    pub fn finish_webdav_read(&mut self, read: WebDavRead) -> Result<()> {
        self.release_read_lease(&read.lease_id)?;
        Ok(())
    }

    /// Only the fully received original handle is read; never reopen its path.
    pub fn commit_webdav_upload(
        &mut self,
        baseline: &WebDavBaseline,
        path: &PortablePath,
        source: &File,
    ) -> Result<WebDavCommit> {
        self.check_webdav_baseline(baseline)?;
        self.admit_webdav_upload(source.metadata()?.len())?;
        let mut reader = source;
        reader.seek(SeekFrom::Start(0))?;
        let length = source.metadata()?.len();
        let content = self.cas.import_bounded(
            reader.take(length.saturating_add(1)),
            length,
            self.limits.max_scan_chunks,
        )?;
        if content.length != length || source.metadata()?.len() != length {
            return Err(ReconcileError::Unstable);
        }
        self.commit_webdav_content(baseline, path, content)
    }

    pub fn copy_webdav_file(
        &mut self,
        baseline: &WebDavBaseline,
        source: &PortablePath,
        destination: &PortablePath,
    ) -> Result<WebDavCommit> {
        let content = baseline
            .manifest
            .entries
            .values()
            .find(|entry| &entry.path == source)
            .and_then(|entry| entry.content.clone())
            .ok_or(ReconcileError::Invariant("DAV COPY file source required"))?;
        self.check_webdav_baseline(baseline)?;
        self.cas.verify(&content)?;
        // COPY always targets a new slot, assigning a fresh entry ID.
        if baseline
            .manifest
            .entries
            .values()
            .any(|entry| &entry.path == destination)
        {
            return Err(ReconcileError::Invariant(
                "DAV COPY overwrite requires separate retained deletion",
            ));
        }
        self.commit_webdav_content(baseline, destination, content)
    }

    fn commit_webdav_content(
        &mut self,
        baseline: &WebDavBaseline,
        path: &PortablePath,
        content: FileManifest,
    ) -> Result<WebDavCommit> {
        self.check_webdav_baseline(baseline)?;
        self.check_publication_limits(&content)?;
        self.cas.verify(&content)?;
        #[cfg(windows)]
        {
            let expected = baseline.snapshot_id()?;
            if let Some(current) = baseline
                .manifest
                .entries
                .values()
                .find(|entry| &entry.path == path)
            {
                if current.content.is_none() {
                    return Err(ReconcileError::Invariant("DAV target is collection"));
                }
                let intent =
                    self.prepare_mutation_content(&expected, path, None, None, Some(content))?;
                let result = self.execute_mutation(&intent.intent.transaction_id)?;
                if !result.local_committed {
                    return Err(ReconcileError::Invariant("DAV Replace pending"));
                }
                Ok(WebDavCommit {
                    transaction_id: result.transaction_id,
                    snapshot_id: result.snapshot_id,
                    local_committed: true,
                    remote_backup_complete: false,
                })
            } else {
                let peak = content
                    .length
                    .checked_mul(17)
                    .and_then(|n| n.checked_add(32))
                    .ok_or(ReconcileError::ResourceLimit(
                        "DAV native reservation overflow",
                    ))?;
                self.reserve_internal_worktree(peak)?;
                self.check_webdav_baseline(baseline)?;
                let id = self.begin_content_selected_slot(
                    path.clone(),
                    content,
                    None,
                    EntryId::random()?,
                    EntryId::random()?,
                    true,
                    true,
                )?;
                let outcome = self.create_native_pipeline(&id, peak);
                let result =
                    self.native_publish_result(&id, outcome.err().map(|error| error.to_string()))?;
                if !result.local_committed || result.conflict_copy || result.published_path != *path
                {
                    return Err(ReconcileError::Invariant(
                        "DAV native publication pending or conflicting",
                    ));
                }
                Ok(WebDavCommit {
                    transaction_id: result.transaction_id,
                    snapshot_id: result
                        .snapshot_id
                        .ok_or(ReconcileError::Invariant("DAV final snapshot absent"))?,
                    local_committed: true,
                    remote_backup_complete: false,
                })
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (path, content);
            Err(ReconcileError::Invariant(
                "DAV native write requires certified source-slot platform",
            ))
        }
    }

    pub fn delete_webdav_file(
        &mut self,
        baseline: &WebDavBaseline,
        path: &PortablePath,
    ) -> Result<WebDavCommit> {
        self.check_webdav_baseline(baseline)?;
        let intent = self.prepare_delete(&baseline.snapshot_id()?, path)?;
        let result = self.execute_mutation(&intent.intent.transaction_id)?;
        if !result.local_committed {
            return Err(ReconcileError::Invariant("DAV Delete pending"));
        }
        Ok(WebDavCommit {
            transaction_id: result.transaction_id,
            snapshot_id: result.snapshot_id,
            local_committed: true,
            remote_backup_complete: false,
        })
    }

    pub fn move_webdav_file(
        &mut self,
        baseline: &WebDavBaseline,
        path: &PortablePath,
        destination: &PortablePath,
    ) -> Result<WebDavCommit> {
        self.check_webdav_baseline(baseline)?;
        let intent = self.prepare_move(&baseline.snapshot_id()?, path, destination)?;
        let result = self.execute_mutation(&intent.intent.transaction_id)?;
        if !result.local_committed {
            return Err(ReconcileError::Invariant("DAV Move pending"));
        }
        Ok(WebDavCommit {
            transaction_id: result.transaction_id,
            snapshot_id: result.snapshot_id,
            local_committed: true,
            remote_backup_complete: false,
        })
    }
}
