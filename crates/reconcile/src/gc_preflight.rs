use crate::{LocalSpace, Result};
use serde::Serialize;
use sync_extend_core_model::EntryId;

#[derive(Debug, Serialize)]
pub struct GcPreflight {
    pub mark_id: EntryId,
    pub checked_at_ms: u64,
    pub guarded_observation_complete: bool,
    pub protection: &'static str,
    pub deletion_authorized: bool,
    pub sweep_available: bool,
    pub gc_enabled: bool,
}

impl LocalSpace {
    pub fn preflight_gc_mark(&mut self, id: &EntryId) -> Result<GcPreflight> {
        self.verify_root()?;
        self.gc_marks()?;
        self.preflight_gc_platform(id)
    }

    #[cfg(not(windows))]
    fn preflight_gc_platform(&mut self, _id: &EntryId) -> Result<GcPreflight> {
        Err(crate::ReconcileError::Invariant(
            "guarded GC preflight requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{
        fault::checkpoint, filesystem::physical_identity, guarded_mutation::directory_chain,
        now_ms, ReconcileError,
    };
    use std::{
        io::{Read, Seek, SeekFrom},
        path::Path,
        time::UNIX_EPOCH,
    };
    use sync_extend_core_model::ContentId;
    use sync_extend_journal::GcMark;
    use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory};

    struct Guards {
        _file: GuardedReadFile,
        _directories: Vec<LockedDirectory>,
    }

    fn verify(file: &GuardedReadFile, path: &Path, mark: &GcMark) -> Result<()> {
        file.verify_single_link()?;
        let metadata = file.reader().metadata()?;
        if ContentId::hash(file.key()?.to_string().as_bytes()) != mark.observation.physical_identity
            || physical_identity(path)? != mark.observation.physical_identity
            || metadata.len() != u64::from(mark.observation.length)
            || metadata
                .modified()?
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_nanos())
                != Some(u128::from(mark.observation.modified_at_ns))
        {
            return Err(ReconcileError::Invariant(
                "GC preflight physical observation changed",
            ));
        }
        let mut reader = file.reader();
        reader.seek(SeekFrom::Start(0))?;
        let mut hash = blake3::Hasher::new();
        let mut bytes = 0u64;
        let mut buffer = [0u8; 65536];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            bytes += count as u64;
            if bytes > u64::from(mark.observation.length) {
                return Err(ReconcileError::Invariant(
                    "GC preflight content length changed",
                ));
            }
            hash.update(&buffer[..count]);
        }
        if bytes != u64::from(mark.observation.length)
            || ContentId::from_hasher(&hash) != mark.content_id
        {
            return Err(ReconcileError::Invariant(
                "GC preflight content hash mismatch",
            ));
        }
        file.verify_single_link()?;
        if file.reader().metadata()?.modified()? != metadata.modified()? {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }

    impl LocalSpace {
        pub(super) fn preflight_gc_platform(&mut self, id: &EntryId) -> Result<GcPreflight> {
            self.storage_report()?;
            self.verify()?;
            let worktree = self.worktree.clone();
            let root_identity = self.root_identity.physical.clone();
            let cas = &self.cas;
            checkpoint("before_gc_preflight");
            let (guards, checked_at_ms) = self.journal.with_gc_preflight(
                &self.space_id,
                id,
                self.limits.max_storage_entries,
                now_ms,
                |mark| -> Result<Guards> {
                    checkpoint("after_gc_preflight_journal_lock");
                    self.storage_report()?;
                    self.verify()?;
                    let path = cas.object_path(&mark.content_id);
                    let parent = path
                        .parent()
                        .ok_or(ReconcileError::Invariant("GC parent missing"))?;
                    let mut directories = directory_chain(&worktree)?;
                    directories.extend(directory_chain(parent)?);
                    for directory in &directories {
                        directory.require_case_insensitive()?;
                    }
                    if physical_identity(&worktree)? != root_identity {
                        return Err(ReconcileError::Unstable);
                    }
                    let file = GuardedReadFile::open(&path)?;
                    verify(&file, &path, mark)?;
                    checkpoint("after_gc_preflight_file_lock");
                    verify(&file, &path, mark)?;
                    for directory in &directories {
                        directory.require_case_insensitive()?;
                    }
                    if physical_identity(&worktree)? != root_identity {
                        return Err(ReconcileError::Unstable);
                    }
                    Ok(Guards {
                        _file: file,
                        _directories: directories,
                    })
                },
            )?;
            // Keep all transient guards alive until the clock transaction is committed.
            checkpoint("after_gc_preflight_commit");
            drop(guards);
            Ok(GcPreflight {
                mark_id: id.clone(), checked_at_ms, guarded_observation_complete: true,
                protection: "transient_sqlite_writer_exclusion_and_windows_read_only_single_link_ntfs_handles",
                deletion_authorized: false, sweep_available: false, gc_enabled: false,
            })
        }
    }
}
