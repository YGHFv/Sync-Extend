use crate::{check_ancestors, filesystem::physical_identity, LocalSpace, ReconcileError, Result};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use sync_extend_cas::sync_directory;
use sync_extend_core_model::*;
use sync_extend_journal::{Mutation, MutationAction, MutationExecution};
use sync_extend_platform_fs::{LockedDirectory, LockedFile};
pub(crate) fn directory_chain(path: &Path) -> Result<Vec<LockedDirectory>> {
    let mut paths: Vec<_> = path.ancestors().take_while(|p| p.is_absolute()).collect();
    paths.reverse();
    let mut guards = Vec::new();
    for path in paths {
        check_ancestors(path)?;
        let guard = LockedDirectory::open(path)?;
        if ContentId::hash(guard.key()?.to_string().as_bytes()) != physical_identity(path)? {
            return Err(ReconcileError::Unstable);
        }
        guards.push(guard);
    }
    Ok(guards)
}

pub(crate) fn identity(file: &LockedFile) -> Result<ContentId> {
    Ok(ContentId::hash(file.key()?.to_string().as_bytes()))
}

pub(crate) fn content_matches(file: &LockedFile, content: &FileManifest) -> Result<bool> {
    if file.reader().metadata()?.len() != content.length {
        return Ok(false);
    }
    let mut reader = file.reader();
    reader.seek(SeekFrom::Start(0))?;
    let mut hash = blake3::Hasher::new();
    let mut left = content.length;
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        if n as u64 > left {
            return Ok(false);
        }
        left -= n as u64;
        hash.update(&buffer[..n]);
    }
    Ok(left == 0 && ContentId::from_hasher(&hash) == content.content_id)
}

pub(crate) fn validate_directory(directory: &Path, mutation: &Mutation) -> Result<LockedFile> {
    let execution = mutation
        .execution
        .as_ref()
        .ok_or(ReconcileError::Invariant("missing mutation execution"))?;
    if physical_identity(directory)? != execution.directory_identity {
        return Err(ReconcileError::Invariant(
            "mutation transaction directory identity changed",
        ));
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name() != "owner"
            && !(matches!(
                mutation.intent.action,
                MutationAction::Delete | MutationAction::Replace { .. }
            ) && entry.file_name() == "original")
            && !(matches!(mutation.intent.action, MutationAction::Replace { .. })
                && entry.file_name() == "payload")
        {
            return Err(ReconcileError::Invariant(
                "unexpected mutation transaction path",
            ));
        }
        check_ancestors(&entry.path())?;
    }
    let owner_path = directory.join("owner");
    let owner = LockedFile::open(&owner_path)?;
    let marker = format!(
        "{}:{}",
        mutation.intent.transaction_id, execution.execution_id
    );
    let mut bytes = Vec::new();
    owner
        .reader()
        .take(marker.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if identity(&owner)? != execution.owner_identity || bytes != marker.as_bytes() {
        return Err(ReconcileError::Invariant(
            "mutation transaction ownership changed",
        ));
    }
    Ok(owner)
}

impl LocalSpace {
    pub(crate) fn validate_mutation_baseline(&self, mutation: &Mutation) -> Result<()> {
        let intent = &mutation.intent;
        let baseline = self
            .journal
            .snapshot(&self.space_id, &intent.baseline_root)?;
        let scan = self.stable_scan()?;
        if self
            .manifest()?
            .as_ref()
            .map(Manifest::root)
            .transpose()?
            .as_ref()
            != Some(&intent.baseline_root)
            || baseline.entries.len() != scan.len()
            || baseline.entries.values().any(|entry| {
                scan.get(&entry.path)
                    .is_none_or(|s| s.kind != entry.kind || s.content != entry.content)
            })
            || scan
                .get(&intent.baseline_entry.path)
                .is_none_or(|s| s.physical_identity != intent.file_identity)
        {
            return Err(ReconcileError::Invariant(
                "mutation baseline changed; all files and pins preserved",
            ));
        }
        Ok(())
    }
}

pub(crate) struct TransactionDirectory {
    pub(crate) execution: MutationExecution,
    pub(crate) _guards: Vec<LockedDirectory>,
    pub(crate) _owner: LockedFile,
    pub(crate) directory: std::path::PathBuf,
}

pub(crate) fn allocate_directory(
    parent: &Path,
    mutation: &Mutation,
) -> Result<TransactionDirectory> {
    let base = parent.join(".sync-tmp");
    if !base.try_exists()? {
        fs::create_dir(&base)?;
    }
    let mut guards = directory_chain(&base)?;
    let execution_id = EntryId::random()?;
    let directory = base.join(execution_id.as_str());
    fs::create_dir(&directory)?;
    guards.extend(directory_chain(&directory)?);
    let owner_path = directory.join("owner");
    let mut owner = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&owner_path)?;
    write!(owner, "{}:{}", mutation.intent.transaction_id, execution_id)?;
    owner.sync_all()?;
    drop(owner);
    sync_directory(&directory)?;
    sync_directory(&base)?;
    let execution = MutationExecution {
        execution_id,
        directory_identity: physical_identity(&directory)?,
        owner_identity: physical_identity(&owner_path)?,
        payload_identity: None,
    };
    let mut admitted = mutation.clone();
    admitted.execution = Some(execution.clone());
    let owner = validate_directory(&directory, &admitted)?;
    Ok(TransactionDirectory {
        execution,
        _guards: guards,
        _owner: owner,
        directory,
    })
}
