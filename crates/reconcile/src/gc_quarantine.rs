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
        object: Option<LockedFile>,
        _original_guard: Option<GuardedReadFile>,
        original: PathBuf,
        quarantine: PathBuf,
        at_original: bool,
        execution: GcExecutionAudit,
    }
    impl Guards {
        fn file(&self) -> Result<&LockedFile> {
            self.object
                .as_ref()
                .ok_or(ReconcileError::Invariant("GC payload handle missing"))
        }
    }
    fn slot_present(path: &std::path::Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn paths(local: &LocalSpace, q: &GcQuarantineIntent) -> (PathBuf, PathBuf) {
        let tmp = local.data_dir.join("cas/tmp");
        (
            tmp.join(format!("gc-{}.owner", q.plan_id)),
            tmp.join(format!("gc-{}.object", q.plan_id)),
        )
    }
    fn inspect(
        local: &LocalSpace,
        e: &GcExecutionAudit,
        q: &GcQuarantineIntent,
        allow_absent: bool,
    ) -> Result<Guards> {
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
        let at_original = slot_present(&original)?;
        let at_quarantine = slot_present(&quarantine)?;
        if (at_original && at_quarantine) || (!allow_absent && !at_original && !at_quarantine) {
            return Err(ReconcileError::Invariant(
                "GC quarantine object absent or ambiguous",
            ));
        }
        let mut original_guard = None;
        let object = if allow_absent && !at_quarantine {
            if at_original {
                let file = GuardedReadFile::open(&original)?;
                if ContentId::hash(file.key()?.to_string().as_bytes())
                    == e.intent.authorization.mark.observation.physical_identity
                {
                    return Err(ReconcileError::Invariant("GC original reappeared"));
                }
                original_guard = Some(file);
            }
            None
        } else {
            let path = if at_original { &original } else { &quarantine };
            let object = LockedFile::open(path)?;
            crate::gc_preflight::windows::verify_reader(
                object.reader(),
                identity(&object)?,
                path,
                &e.intent.authorization.mark,
            )?;
            Some(object)
        };
        Ok(Guards {
            _directories: directories,
            owner,
            object,
            _original_guard: original_guard,
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
        let guards = inspect(local, e, &q, false)?;
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
                    guards.file()?.rename_no_replace(&guards.quarantine)?;
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
                    guards.file()?.rename_no_replace(&guards.original)?;
                    checkpoint("after_gc_quarantine_restore");
                    verify_guards(local, guards, &q.intent, &guards.original)?;
                }
                Ok(GcQuarantineState::Restored)
            }
            GcQuarantineState::Restored | GcQuarantineState::Deleted => Ok(q.state),
        }
    }
    fn verify_guards(
        local: &LocalSpace,
        guards: &Guards,
        q: &GcQuarantineIntent,
        path: &std::path::Path,
    ) -> Result<()> {
        verify_namespace(local, guards, q)?;
        crate::gc_preflight::windows::verify_reader(
            guards.file()?.reader(),
            identity(guards.file()?)?,
            path,
            &guards.execution.intent.authorization.mark,
        )
    }
    fn verify_namespace(local: &LocalSpace, guards: &Guards, q: &GcQuarantineIntent) -> Result<()> {
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
        Ok(())
    }
    fn verify_absence(
        local: &LocalSpace,
        guards: &mut Guards,
        q: &GcQuarantineIntent,
    ) -> Result<()> {
        verify_namespace(local, guards, q)?;
        if slot_present(&guards.quarantine)? {
            return Err(ReconcileError::Invariant("GC quarantine reappeared"));
        }
        if slot_present(&guards.original)? && guards._original_guard.is_none() {
            let original = GuardedReadFile::open(&guards.original)?;
            if ContentId::hash(original.key()?.to_string().as_bytes())
                == guards
                    .execution
                    .intent
                    .authorization
                    .mark
                    .observation
                    .physical_identity
            {
                return Err(ReconcileError::Invariant("GC original reappeared"));
            }
            guards._original_guard = Some(original);
        }
        Ok(())
    }
    impl LocalSpace {
        pub(crate) fn execute_gc_disposal_platform(
            &self,
            id: &EntryId,
        ) -> Result<sync_extend_journal::GcDisposalAudit> {
            use sync_extend_journal::{GcDisposalState, GcDisposalStep};
            let old = self
                .gc_disposals()?
                .into_iter()
                .find(|d| d.intent.execution_id == *id)
                .ok_or(ReconcileError::Invariant("GC disposal preparation missing"))?;
            if old.state == GcDisposalState::RestorePending {
                self.gc_quarantine_platform(id, true)?;
                return self
                    .gc_disposals()?
                    .into_iter()
                    .find(|d| d.intent.execution_id == *id)
                    .ok_or(ReconcileError::Invariant("GC disposal disappeared"));
            }
            checkpoint("before_gc_disposition");
            let (guards, audit) = self.journal.with_gc_disposition(
                &self.space_id,
                id,
                self.limits.max_storage_entries,
                |e, d| {
                    checkpoint("after_gc_disposition_journal_lock");
                    let guards = inspect(self, e, &d.intent.quarantine, true)?;
                    checkpoint("after_gc_disposition_file_lock");
                    Ok(guards)
                },
                (
                    |guards: &mut Guards, d: &sync_extend_journal::GcDisposalAudit| {
                        if guards.object.is_none() {
                            verify_absence(self, guards, &d.intent.quarantine)?;
                            checkpoint("after_gc_disposition_absence");
                            verify_absence(self, guards, &d.intent.quarantine)?;
                            return Ok(GcDisposalStep::Deleted);
                        }
                        checkpoint("before_gc_disposition_request");
                        verify_guards(self, guards, &d.intent.quarantine, &guards.quarantine)?;
                        if self.journal.gc_disposition_requires_restore(
                            &self.space_id,
                            id,
                            self.limits.max_storage_entries,
                            crate::now_ms,
                        )? {
                            return Ok(GcDisposalStep::RestorePending);
                        }
                        guards.file()?.delete_on_close()?;
                        checkpoint("after_gc_disposition_request");
                        drop(guards.object.take());
                        checkpoint("after_gc_disposition_close");
                        verify_namespace(self, guards, &d.intent.quarantine)?;
                        match slot_present(&guards.quarantine) {
                            Ok(false) => {}
                            Ok(true) => return Ok(GcDisposalStep::Pending),
                            Err(ReconcileError::Io(error))
                                if error
                                    .raw_os_error()
                                    .is_some_and(|n| matches!(n, 5 | 32 | 33 | 303)) =>
                            {
                                return Ok(GcDisposalStep::Pending)
                            }
                            Err(error) => return Err(error),
                        }
                        verify_absence(self, guards, &d.intent.quarantine)?;
                        checkpoint("after_gc_disposition_absence");
                        verify_absence(self, guards, &d.intent.quarantine)?;
                        Ok(GcDisposalStep::Deleted)
                    },
                    |guards: &mut Guards, d: &sync_extend_journal::GcDisposalAudit| {
                        verify_absence(self, guards, &d.intent.quarantine)
                    },
                ),
            )?;
            checkpoint("after_gc_disposition_commit");
            drop(guards);
            if audit.state == GcDisposalState::RestorePending {
                self.gc_quarantine_platform(id, true)?;
                return self
                    .gc_disposals()?
                    .into_iter()
                    .find(|d| d.intent.execution_id == *id)
                    .ok_or(ReconcileError::Invariant("GC disposal disappeared"));
            }
            Ok(audit)
        }
        pub(crate) fn prepare_gc_disposal_platform(
            &self,
            id: &EntryId,
        ) -> Result<sync_extend_journal::GcDisposalAudit> {
            checkpoint("before_gc_disposal_prepare");
            let (guards, audit) = self.journal.prepare_gc_disposal(
                &self.space_id,
                id,
                self.limits.max_storage_entries,
                crate::now_ms,
                |e, q| {
                    checkpoint("after_gc_disposal_journal_lock");
                    let guards = inspect(self, e, &q.intent, false)?;
                    if guards.at_original {
                        return Err(ReconcileError::Invariant(
                            "GC disposal object not quarantined",
                        ));
                    }
                    checkpoint("after_gc_disposal_file_lock");
                    verify_guards(self, &guards, &q.intent, &guards.quarantine)?;
                    Ok(guards)
                },
            )?;
            checkpoint("after_gc_disposal_prepare");
            drop(guards);
            Ok(audit)
        }
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
                if matches!(
                    q.state,
                    GcQuarantineState::Restored | GcQuarantineState::Deleted
                ) {
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
                    |e, q| inspect(self, e, &q.intent, false),
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
