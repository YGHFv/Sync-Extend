use crate::{LocalSpace, ReconcileError, Result};
use sync_extend_core_model::EntryId;
use sync_extend_journal::GcQuarantineAudit;
#[cfg(windows)]
use sync_extend_journal::GcQuarantineState;

impl LocalSpace {
    pub fn gc_quarantines(&self) -> Result<Vec<GcQuarantineAudit>> {
        self.verify_root()?;
        Ok(self
            .journal
            .gc_quarantines(&self.space_id, self.limits.max_storage_entries)?)
    }
    pub fn quarantine_gc_execution(&mut self, id: &EntryId) -> Result<GcQuarantineAudit> {
        self.verify_root()?;
        self.gc_quarantine_platform(id, false)
    }
    pub fn restore_gc_quarantine(&mut self, id: &EntryId) -> Result<GcQuarantineAudit> {
        self.verify_root()?;
        self.gc_quarantine_platform(id, true)
    }
    #[cfg(not(windows))]
    fn gc_quarantine_platform(&self, _id: &EntryId, _restore: bool) -> Result<GcQuarantineAudit> {
        Err(ReconcileError::Invariant(
            "GC quarantine requires Windows fixed local NTFS",
        ))
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{
        fault::checkpoint,
        filesystem::physical_identity,
        guarded_mutation::{directory_chain, identity},
    };
    use std::{
        fs,
        io::{Read, Seek, SeekFrom, Write},
        path::PathBuf,
    };
    use sync_extend_core_model::{ContentId, EntryId, FORMAT_VERSION};
    use sync_extend_journal::{GcExecutionAudit, GcQuarantineIntent};
    use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory, LockedFile};

    struct Guards {
        _directories: Vec<LockedDirectory>,
        owner: GuardedReadFile,
        object: LockedFile,
        original: PathBuf,
        quarantine: PathBuf,
        at_original: bool,
        execution: GcExecutionAudit,
    }
    fn paths(local: &LocalSpace, q: &GcQuarantineIntent) -> (PathBuf, PathBuf) {
        let tmp = local.data_dir.join("cas/tmp");
        (
            tmp.join(format!("gc-{}.owner", q.plan_id)),
            tmp.join(format!("gc-{}.object", q.plan_id)),
        )
    }
    fn inspect(local: &LocalSpace, e: &GcExecutionAudit, q: &GcQuarantineIntent) -> Result<Guards> {
        local.verify()?;
        local.storage_report()?;
        let original = local
            .cas
            .object_path(&e.intent.authorization.mark.content_id);
        let shard = original
            .parent()
            .ok_or(ReconcileError::Invariant("GC shard missing"))?;
        let tmp = local.data_dir.join("cas/tmp");
        let mut directories = directory_chain(shard)?;
        directories.extend(directory_chain(&tmp)?);
        directories.extend(directory_chain(&local.worktree)?);
        for d in &directories {
            d.require_case_insensitive()?;
        }
        let boundary = &e.intent.authorization.boundary;
        let cas = local.data_dir.join("cas");
        if physical_identity(&local.worktree)? != boundary.worktree
            || physical_identity(&cas)? != boundary.cas
            || physical_identity(&cas.join("objects"))? != boundary.objects
            || physical_identity(shard)? != boundary.shard
            || physical_identity(&tmp)? != q.tmp_identity
        {
            return Err(ReconcileError::Invariant("GC quarantine namespace changed"));
        }
        let (owner_path, quarantine) = paths(local, q);
        let owner = GuardedReadFile::open(&owner_path)?;
        if ContentId::hash(owner.key()?.to_string().as_bytes()) != q.owner_identity {
            return Err(ReconcileError::Invariant("GC quarantine owner changed"));
        }
        let mut bytes = Vec::new();
        owner.reader().take(66).read_to_end(&mut bytes)?;
        if bytes != format!("{}:{}", q.execution_id, q.plan_id).as_bytes() {
            return Err(ReconcileError::Invariant("GC quarantine owner mismatch"));
        }
        let at_original = original.try_exists()?;
        if at_original == quarantine.try_exists()? {
            return Err(ReconcileError::Invariant(
                "GC quarantine object absent or ambiguous",
            ));
        }
        let path = if at_original { &original } else { &quarantine };
        let object = LockedFile::open(path)?;
        crate::gc_preflight::windows::verify_reader(
            object.reader(),
            identity(&object)?,
            path,
            &e.intent.authorization.mark,
        )?;
        Ok(Guards {
            _directories: directories,
            owner,
            object,
            original,
            quarantine,
            at_original,
            execution: e.clone(),
        })
    }
    fn allocate(
        local: &LocalSpace,
        e: &GcExecutionAudit,
        watermark: u64,
    ) -> Result<(Guards, GcQuarantineIntent)> {
        let inventory = local.storage_inventory(crate::storage::Region::Cas)?;
        checkpoint("before_gc_quarantine_owner");
        if inventory
            .len()
            .checked_add(1)
            .is_none_or(|n| n > local.limits.max_storage_entries)
        {
            return Err(ReconcileError::ResourceLimit("GC quarantine inventory"));
        }
        let tmp = local.data_dir.join("cas/tmp");
        let _guards = directory_chain(&tmp)?;
        let q = GcQuarantineIntent {
            format_version: FORMAT_VERSION,
            execution_id: e.intent.execution_id.clone(),
            plan_id: EntryId::random()?,
            tmp_identity: physical_identity(&tmp)?,
            owner_identity: ContentId::hash(b"pending"),
            prepared_at_watermark_ms: watermark,
        };
        let (owner_path, _) = paths(local, &q);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&owner_path)?;
        write!(file, "{}:{}", q.execution_id, q.plan_id)?;
        file.sync_all()?;
        let owner_identity = ContentId::hash(
            sync_extend_platform_fs::FileKey::from_file(&file)?
                .to_string()
                .as_bytes(),
        );
        drop(file);
        sync_extend_cas::sync_directory(&tmp)?;
        let q = GcQuarantineIntent {
            owner_identity,
            ..q
        };
        let guards = inspect(local, e, &q)?;
        checkpoint("after_gc_quarantine_owner");
        Ok((guards, q))
    }
    fn apply(
        local: &LocalSpace,
        guards: &Guards,
        q: &GcQuarantineAudit,
        restore: bool,
    ) -> Result<GcQuarantineState> {
        let path = if guards.at_original {
            &guards.original
        } else {
            &guards.quarantine
        };
        verify_guards(local, guards, &q.intent, path)?;
        checkpoint("after_gc_quarantine_file_lock");
        verify_guards(local, guards, &q.intent, path)?;
        if q.state == GcQuarantineState::Quarantined && guards.at_original {
            return Err(ReconcileError::Invariant(
                "GC original reappeared before restoration admission",
            ));
        }
        if restore && q.state != GcQuarantineState::RestorePending {
            return Ok(GcQuarantineState::RestorePending);
        }
        match q.state {
            GcQuarantineState::Prepared => {
                if guards.at_original {
                    checkpoint("before_gc_quarantine_rename");
                    verify_guards(local, guards, &q.intent, &guards.original)?;
                    local.journal.recheck_gc_execution_authority(
                        &local.space_id,
                        &q.intent.execution_id,
                        local.limits.max_storage_entries,
                        crate::now_ms,
                    )?;
                    guards.object.rename_no_replace(&guards.quarantine)?;
                    checkpoint("after_gc_quarantine_rename");
                    verify_guards(local, guards, &q.intent, &guards.quarantine)?;
                }
                Ok(GcQuarantineState::Quarantined)
            }
            GcQuarantineState::Quarantined => {
                if guards.at_original {
                    return Err(ReconcileError::Invariant("GC original reappeared"));
                }
                Ok(q.state)
            }
            GcQuarantineState::RestorePending => {
                if !guards.at_original {
                    checkpoint("before_gc_quarantine_restore");
                    verify_guards(local, guards, &q.intent, &guards.quarantine)?;
                    guards.object.rename_no_replace(&guards.original)?;
                    checkpoint("after_gc_quarantine_restore");
                    verify_guards(local, guards, &q.intent, &guards.original)?;
                }
                Ok(GcQuarantineState::Restored)
            }
            GcQuarantineState::Restored => Ok(q.state),
        }
    }
    fn verify_guards(
        local: &LocalSpace,
        guards: &Guards,
        q: &GcQuarantineIntent,
        path: &std::path::Path,
    ) -> Result<()> {
        for directory in &guards._directories {
            directory.require_case_insensitive()?;
        }
        let (owner_path, _) = paths(local, q);
        guards.owner.verify_single_link()?;
        if ContentId::hash(guards.owner.key()?.to_string().as_bytes()) != q.owner_identity
            || physical_identity(&owner_path)? != q.owner_identity
        {
            return Err(ReconcileError::Invariant("GC quarantine owner changed"));
        }
        let mut reader = guards.owner.reader();
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader.take(66).read_to_end(&mut bytes)?;
        if bytes != format!("{}:{}", q.execution_id, q.plan_id).as_bytes() {
            return Err(ReconcileError::Invariant("GC quarantine owner mismatch"));
        }
        crate::gc_preflight::windows::verify_reader(
            guards.object.reader(),
            identity(&guards.object)?,
            path,
            &guards.execution.intent.authorization.mark,
        )
    }
    impl LocalSpace {
        pub(super) fn gc_quarantine_platform(
            &self,
            id: &EntryId,
            restore: bool,
        ) -> Result<GcQuarantineAudit> {
            if let Some(q) = self
                .gc_quarantines()?
                .into_iter()
                .find(|q| q.intent.execution_id == *id)
            {
                if q.state == GcQuarantineState::Restored {
                    return Ok(q);
                }
            } else {
                if restore {
                    return Err(ReconcileError::Invariant("GC quarantine plan missing"));
                }
                checkpoint("before_gc_quarantine_prepare");
                let (guards, _) = self.journal.prepare_gc_quarantine(
                    &self.space_id,
                    id,
                    self.limits.max_storage_entries,
                    crate::now_ms,
                    |e, w| allocate(self, e, w),
                )?;
                checkpoint("after_gc_quarantine_prepare");
                drop(guards);
            }
            for _ in 0..3 {
                let (guards, q) = self.journal.with_gc_quarantine_step(
                    &self.space_id,
                    id,
                    (self.limits.max_storage_entries, restore),
                    crate::now_ms,
                    |e, q| inspect(self, e, &q.intent),
                    |g, q, r| apply(self, g, q, r),
                )?;
                checkpoint("after_gc_quarantine_step");
                drop(guards);
                if q.state == GcQuarantineState::Restored
                    || q.state == GcQuarantineState::Quarantined
                {
                    return Ok(q);
                }
            }
            Err(ReconcileError::Invariant(
                "GC quarantine recovery made no progress",
            ))
        }
    }
}
