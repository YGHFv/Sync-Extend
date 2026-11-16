//! Original data writer/CAS sentinels created under exact retained root and ledger.
use super::{CreatedNodeRestoreRoots, NodeRestoreLedger};
use crate::{ReconcileError, Result};
use sync_extend_platform_fs::{OwnedFileCreation, ReleasedOriginalCoordinationFile};

pub struct CreatedNodeDataLocks<'a> {
    roots: &'a CreatedNodeRestoreRoots,
    pub(super) writer: OwnedFileCreation,
    cas: Option<OwnedFileCreation>,
}

impl CreatedNodeDataLocks<'_> {
    pub fn verify(&self) -> Result<()> {
        self.roots.verify()?;
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
            Err((_creator, error)) => return Err(error.into()),
        };
        match original.retain_coordination_after_creation() {
            Ok(original) => Ok(original),
            Err((_original, error)) => Err(error.into()),
        }
    }
}

impl CreatedNodeRestoreRoots {
    pub fn create_data_locks<'a>(
        &'a self,
        ledger: &mut NodeRestoreLedger,
    ) -> Result<CreatedNodeDataLocks<'a>> {
        self.verify()?;
        ledger.verify_external()?;
        if ledger.archive_digest() != self.archive_digest() {
            return Err(ReconcileError::Invariant(
                "original data lock archive scope",
            ));
        }
        let parent = self.data.original_creation()?;
        let mut writer_intent = ledger.intend_file(&parent, "writer.lock")?;
        crate::fault::checkpoint("node_data_writer_intended");
        let writer = self.data.create_new_file("writer.lock")?;
        writer.reader().sync_all()?;
        ledger.created_file(&mut writer_intent, &writer.original_creation()?)?;
        crate::fault::checkpoint("node_data_writer_created");
        let mut cas_intent =
            ledger.intend_file(&self.data.original_creation()?, "cas-access.lock")?;
        crate::fault::checkpoint("node_data_cas_intended");
        let cas = self.data.create_new_file("cas-access.lock")?;
        cas.reader().sync_all()?;
        ledger.created_file(&mut cas_intent, &cas.original_creation()?)?;
        crate::fault::checkpoint("node_data_cas_created");
        let result = CreatedNodeDataLocks {
            roots: self,
            writer,
            cas: Some(cas),
        };
        result.verify()?;
        Ok(result)
    }
}
