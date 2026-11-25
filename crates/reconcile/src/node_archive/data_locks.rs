//! Original data writer/CAS sentinels created under exact retained root and ledger.
use super::{CreatedNodeRestoreRoots, NodeRestoreLedger};
use crate::{ReconcileError, Result};
use sync_extend_platform_fs::{
    OwnedFileCreation, ReleasedOriginalCoordinationFile, ReleasedOriginalFileIdentity,
};

pub struct CreatedNodeDataLocks<'a> {
    roots: &'a CreatedNodeRestoreRoots,
    pub(super) writer: OwnedFileCreation,
    cas: Option<OwnedFileCreation>,
    failed_cas_identity: Option<ReleasedOriginalFileIdentity>,
}

impl CreatedNodeDataLocks<'_> {
    pub fn close_into_attempt<'scope>(
        self,
        attempt: &mut super::OriginalNodeResourceCloseAttempt<'scope>,
    ) where
        Self: 'scope,
    {
        let Self {
            roots,
            writer,
            cas,
            failed_cas_identity,
        } = self;
        attempt.keep_context(roots);
        if let Some(original) = failed_cas_identity {
            original.close_into_attempt(&mut attempt.native);
        }
        if let Some(original) = cas {
            original.close_into_attempt(&mut attempt.native);
        }
        writer.close_into_attempt(&mut attempt.native);
    }

    pub fn verify(&self) -> Result<()> {
        self.roots.verify()?;
        if self.failed_cas_identity.is_some() {
            return Err(ReconcileError::Invariant(
                "original CAS lock handoff failed and remains terminal-only",
            ));
        }
        let key = self.roots.data.key()?;
        for file in std::iter::once(&self.writer).chain(self.cas.iter()) {
            let original = file.original_creation()?;
            file.verify_single_link()?;
            if original.parent_key()? != key || file.reader().metadata()?.len() != 0 {
                return Err(ReconcileError::Invariant(
                    "original data writer/CAS lock lineage differs",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn matches_roots(&self, roots: &CreatedNodeRestoreRoots) -> bool {
        std::ptr::eq(self.roots, roots)
    }
    pub(super) fn verify_inventory(&self) -> Result<()> {
        self.verify()?;
        for (name, file) in [
            ("writer.lock", &self.writer),
            (
                "cas-access.lock",
                self.cas.as_ref().ok_or(ReconcileError::Invariant(
                    "original CAS lock released before inventory",
                ))?,
            ),
        ] {
            if !sync_extend_platform_fs::regular_file_matches_path(
                file.reader(),
                &self.roots.data_path.join(name),
            )? {
                return Err(ReconcileError::Invariant(
                    "original data lock named slot differs",
                ));
            }
        }
        Ok(())
    }
    pub(super) fn release_cas(&mut self) -> Result<ReleasedOriginalCoordinationFile> {
        self.verify()?;
        let creator = self.cas.take().ok_or(ReconcileError::Invariant(
            "original CAS lock already handed off",
        ))?;
        let original = match creator.release_for_identity_checked_reopen() {
            Ok(original) => original,
            Err((creator, error)) => {
                self.cas = Some(*creator);
                return Err(error.into());
            }
        };
        match original.retain_coordination_after_creation() {
            Ok(original) => Ok(original),
            Err((original, error)) => {
                self.failed_cas_identity = Some(original);
                Err(error.into())
            }
        }
    }
}

impl CreatedNodeRestoreRoots {
    pub fn create_data_locks<'a>(
        &'a self,
        ledger: &mut NodeRestoreLedger,
    ) -> Result<CreatedNodeDataLocks<'a>> {
        self.create_data_locks_retaining(ledger)
            .map_err(|original| original.retain_and_report())
    }

    pub fn create_data_locks_retaining<'a>(
        &'a self,
        ledger: &mut NodeRestoreLedger,
    ) -> std::result::Result<CreatedNodeDataLocks<'a>, OriginalNodeDataLockCreationFailure<'a>>
    {
        let mut original = OriginalNodeDataLockCreating {
            roots: self,
            writer: None,
            cas: None,
            writer_intent: None,
            cas_intent: None,
            complete: None,
        };
        let result = (|| -> Result<()> {
            self.verify()?;
            ledger.verify_external()?;
            if ledger.archive_digest() != self.archive_digest() {
                return Err(ReconcileError::Invariant(
                    "original data lock archive scope",
                ));
            }
            original.writer_intent =
                Some(ledger.intend_file(&self.data.original_creation()?, "writer.lock")?);
            crate::fault::checkpoint("node_data_writer_intended");
            original.writer = Some(self.data.create_new_file("writer.lock")?);
            let writer = original
                .writer
                .as_ref()
                .expect("same actual writer CREATE retained");
            writer.reader().sync_all()?;
            ledger.created_file(
                original
                    .writer_intent
                    .as_mut()
                    .expect("same original writer intent"),
                &writer.original_creation()?,
            )?;
            crate::fault::checkpoint("node_data_writer_created");
            original.cas_intent =
                Some(ledger.intend_file(&self.data.original_creation()?, "cas-access.lock")?);
            crate::fault::checkpoint("node_data_cas_intended");
            original.cas = Some(self.data.create_new_file("cas-access.lock")?);
            let cas = original
                .cas
                .as_ref()
                .expect("same actual CAS CREATE retained");
            cas.reader().sync_all()?;
            ledger.created_file(
                original
                    .cas_intent
                    .as_mut()
                    .expect("same original CAS intent"),
                &cas.original_creation()?,
            )?;
            crate::fault::checkpoint("node_data_cas_created");
            original.complete = Some(CreatedNodeDataLocks {
                roots: self,
                writer: original.writer.take().expect("prepared same writer CREATE"),
                cas: original.cas.take(),
                failed_cas_identity: None,
            });
            original
                .complete
                .as_ref()
                .expect("same complete data locks retained")
                .verify()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(original
                .complete
                .take()
                .expect("verified same complete data locks")),
            Err(error) => Err(OriginalNodeDataLockCreationFailure {
                error,
                original: Some(original),
                resources: None,
                actual_closed: Vec::new(),
            }),
        }
    }
}

struct OriginalNodeDataLockCreating<'scope> {
    roots: &'scope CreatedNodeRestoreRoots,
    writer: Option<OwnedFileCreation>,
    cas: Option<OwnedFileCreation>,
    writer_intent: Option<super::NodeRestoreAttempt>,
    cas_intent: Option<super::NodeRestoreAttempt>,
    complete: Option<CreatedNodeDataLocks<'scope>>,
}

pub struct OriginalNodeDataLockCreationFailure<'scope> {
    pub error: ReconcileError,
    original: Option<OriginalNodeDataLockCreating<'scope>>,
    resources: Option<super::OriginalNodeResourceCloseFailure<'scope>>,
    actual_closed: Vec<sync_extend_platform_fs::ClosedWindowsOriginalResources>,
}

impl std::fmt::Debug for OriginalNodeDataLockCreationFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalNodeDataLockCreationFailure")
            .field("error", &self.error)
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

impl OriginalNodeDataLockCreationFailure<'_> {
    pub fn has_retained_originals(&self) -> bool {
        self.original.as_ref().is_some_and(|original| {
            original.writer.is_some() || original.cas.is_some() || original.complete.is_some()
        }) || self
            .resources
            .as_ref()
            .is_some_and(|original| original.has_retained_originals())
    }

    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original.take() {
            let OriginalNodeDataLockCreating {
                roots,
                writer,
                cas,
                writer_intent,
                cas_intent,
                complete,
            } = original;
            let mut attempt = super::OriginalNodeResourceCloseAttempt::new();
            attempt.keep_context((roots, writer_intent, cas_intent));
            if let Some(original) = complete {
                original.close_into_attempt(&mut attempt);
            }
            if let Some(original) = cas {
                original.close_into_attempt(&mut attempt.native);
            }
            if let Some(original) = writer {
                original.close_into_attempt(&mut attempt.native);
            }
            match attempt.finish() {
                Ok(closed) => self.actual_closed.push(closed),
                Err(original) => self.resources = Some(original),
            }
        } else if let Some(original) = self.resources.take() {
            self.resources = Some(original.close_remaining());
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> ReconcileError {
        let error = ReconcileError::Io(std::io::Error::other(self.error.to_string()));
        let original = self.close_remaining();
        if original.has_retained_originals() {
            original.retain_until_process_exit();
        }
        error
    }
}
