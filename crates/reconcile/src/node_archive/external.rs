//! Independent external ledger construction before any target-node CREATE.
use super::{LedgerBounds, NodeRestoreLedger, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use std::{
    io::Write,
    path::{Component, Path, PathBuf},
};
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_platform_fs::{FileKey, LockedDirectory, OwnedFileCreation};

pub(super) struct ExternalLedgerOwnership {
    ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
    owner_lock: OwnedFileCreation,
}

impl ExternalLedgerOwnership {
    pub(super) fn verify(&self) -> Result<()> {
        for (path, held, key) in &self.ancestors {
            if held.key()? != *key || !held.matches_path(path)? {
                return Err(ReconcileError::Invariant(
                    "external ledger retained ancestor differs",
                ));
            }
        }
        self.owner_lock.original_creation()?.verify()?;
        self.owner_lock.verify_single_link()?;
        Ok(())
    }
}

pub(super) fn hold_ancestors(path: &Path) -> Result<Vec<(PathBuf, LockedDirectory, FileKey)>> {
    if !path.is_absolute() || path.components().count() > 256 {
        return Err(ReconcileError::Invariant(
            "bounded absolute external directory required",
        ));
    }
    // Reject ambiguous lexical spellings before opening any existing ancestor.
    let mut components = path.components();
    let prefix = match components.next() {
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::Disk(_)) => {
            prefix.as_os_str()
        }
        _ => {
            return Err(ReconcileError::Invariant(
                "external ledger local drive path required",
            ))
        }
    };
    if components.next() != Some(Component::RootDir) {
        return Err(ReconcileError::Invariant(
            "external ledger absolute local root required",
        ));
    }
    let mut current = PathBuf::from(prefix);
    current.push(std::path::MAIN_SEPARATOR.to_string());
    let mut paths = vec![current.clone()];
    for part in components {
        match part {
            Component::Normal(name) => {
                current.push(name);
                paths.push(current.clone());
            }
            _ => {
                return Err(ReconcileError::Invariant(
                    "external ledger lexical ancestor rejected",
                ))
            }
        }
    }
    let mut held = Vec::with_capacity(paths.len());
    for path in paths {
        let directory = LockedDirectory::open(&path)?;
        directory.require_local_ntfs(&path)?;
        directory.require_case_insensitive()?;
        let key = directory.key()?;
        if !directory.matches_path(&path)? {
            return Err(ReconcileError::Invariant(
                "external ledger ancestor changed during open",
            ));
        }
        held.push((path, directory, key));
    }
    Ok(held)
}

impl NodeRestoreLedger {
    /// Reserve independent evidence for the exact prepared archive and bounds.
    /// Refuse target roots and their descendants before creating any files.
    pub fn create_external_for_prepared(
        external_directory: &Path,
        archive: &VerifiedNodeStateArchive,
        prepared: &super::PreparedOriginalNodeRestore,
    ) -> Result<Self> {
        if prepared.archive_digest() != archive.digest()
            || [&prepared.worktree, &prepared.data]
                .into_iter()
                .any(|root| super::portable_source::path_within(external_directory, root))
        {
            return Err(ReconcileError::Invariant(
                "prepared restore requires its archive and independent external ledger directory",
            ));
        }
        Self::create_external(external_directory, archive, prepared.ledger_bounds)
    }

    /// Reserve new external evidence and a live exclusive ownerlock independently
    /// of all target roots. Errors preserve any original partial evidence files.
    /// Their random names never authorize adoption on a later process restart.
    pub fn create_external(
        external_directory: &Path,
        archive: &VerifiedNodeStateArchive,
        bounds: LedgerBounds,
    ) -> Result<Self> {
        Self::create_external_scope(external_directory, archive.digest(), bounds)
    }

    pub(super) fn create_external_scope(
        external_directory: &Path,
        archive_digest: &ContentId,
        bounds: LedgerBounds,
    ) -> Result<Self> {
        bounds.validate().map_err(ReconcileError::from)?;
        let ancestors = hold_ancestors(external_directory)?;
        let parent = &ancestors
            .last()
            .ok_or(ReconcileError::Invariant("external ledger parent absent"))?
            .1;
        let nonce = SpaceId::random()?;
        let lock_name = format!("node-restore-{nonce}.owner");
        let name = format!("node-restore-{nonce}.sqlite");
        let mut owner_lock = parent.create_new_file(&lock_name)?;
        owner_lock
            .writer()
            .write_all(&serde_json::to_vec(&(2u32, archive_digest, &nonce))?)?;
        owner_lock.writer().flush()?;
        owner_lock.writer().sync_all()?;
        crate::fault::checkpoint("node_ledger_external_owner_synced");
        let mut creator = parent.create_new_file(&name)?;
        let initialized = Self::initialize_created(&mut creator, archive_digest, bounds)?;
        initialized.verify()?;
        let scope = initialized.ledger_id().clone();
        drop(initialized);
        let original = match creator.release_for_identity_checked_reopen() {
            Ok(original) => original,
            Err((_creator, error)) => return Err(error.into()),
        };
        let ownership = ExternalLedgerOwnership {
            ancestors,
            owner_lock,
        };
        ownership.verify()?;
        let mut ledger = match Self::open_existing(
            &external_directory.join(name),
            original,
            archive_digest.clone(),
            &scope,
            bounds,
        ) {
            Ok(ledger) => ledger,
            Err((_original, error)) => return Err(error),
        };
        ledger.external = Some(ownership);
        ledger.verify_external()?;
        crate::fault::checkpoint("node_ledger_external_opened");
        Ok(ledger)
    }

    pub(super) fn verify_external(&self) -> Result<()> {
        self.external
            .as_ref()
            .ok_or(ReconcileError::Invariant(
                "external ledger live ownerlock and ancestors required",
            ))?
            .verify()
    }
}

// Included inside external.rs; no owner can be reconstructed from numeric evidence.
impl ExternalLedgerOwnership {
    pub(super) fn from_original(
        ancestors: Vec<(PathBuf, LockedDirectory, FileKey)>,
        owner_lock: OwnedFileCreation,
    ) -> Self {
        Self {
            ancestors,
            owner_lock,
        }
    }
}

impl ExternalLedgerOwnership {
    pub(super) fn create_ordinary_evidence(&self, name: &str) -> Result<OwnedFileCreation> {
        self.verify()?;
        let parent = &self
            .ancestors
            .last()
            .ok_or(ReconcileError::Invariant(
                "ordinary CREATE external parent absent",
            ))?
            .1;
        let file = parent.create_new_file(name)?;
        file.original_creation()?.verify()?;
        self.verify()?;
        Ok(file)
    }
}

impl ExternalLedgerOwnership {
    pub(super) fn ordinary_mutation_volume(&self) -> Result<u64> {
        self.verify()?;
        Ok(self
            .ancestors
            .last()
            .ok_or(ReconcileError::Invariant(
                "ordinary mutation external volume absent",
            ))?
            .2
            .volume)
    }
    pub(super) fn create_ordinary_mutation_directory(
        &self,
    ) -> Result<(sync_extend_platform_fs::LockedDirectoryMutation, PathBuf)> {
        self.verify()?;
        let (path, parent, _) = self.ancestors.last().ok_or(ReconcileError::Invariant(
            "ordinary mutation external parent absent",
        ))?;
        let name = format!("node-retained-{}", SpaceId::random()?);
        let directory = parent.create_new_retained_mutation_directory(&name)?;
        let target = path.join(name);
        directory.original_creation()?.verify()?;
        if !directory.matches_path(&target)? {
            return Err(ReconcileError::Invariant(
                "ordinary mutation original directory changed",
            ));
        }
        self.verify()?;
        Ok((directory, target))
    }
}
