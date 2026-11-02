use crate::{check_ancestors, now_ms, LocalSpace, ReconcileError, Result};
use same_file::Handle;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use sync_extend_cas::{is_reparse, sync_directory};
use sync_extend_core_model::*;
use sync_extend_journal::{PublicationIntent, PublicationState};

#[derive(Serialize)]
pub struct PublishResult {
    pub transaction_id: EntryId,
    pub requested_path: PortablePath,
    pub published_path: PortablePath,
    pub conflict_copy: bool,
    pub snapshot_id: SnapshotId,
    pub local_committed: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub fn publish_file(&mut self, source: &Path, path: PortablePath) -> Result<PublishResult> {
        self.recover()?;
        self.scan_without_recovery()?;
        check_ancestors(source)?;
        let metadata = fs::symlink_metadata(source)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(ReconcileError::Invariant(
                "publication source must be a regular file",
            ));
        }
        let source = fs::canonicalize(source)?;
        if source.starts_with(&self.data_dir) {
            return Err(ReconcileError::Invariant(
                "cannot publish internal data or device secrets",
            ));
        }
        if source.components().any(|component| {
            component.as_os_str().to_str().is_some_and(|part| {
                [".sync-extend", ".sync-tmp", ".git"]
                    .iter()
                    .any(|reserved| part.eq_ignore_ascii_case(reserved))
            })
        }) {
            return Err(ReconcileError::Invariant(
                "cannot publish internal worktree metadata",
            ));
        }
        let file = File::open(&source)?;
        let content = self.cas.import(&file)?;
        if content.length != metadata.len()
            || metadata.modified()? != file.metadata()?.modified()?
            || !file_matches(&source, &content)?
        {
            return Err(ReconcileError::Unstable);
        }
        let id = self.begin_content(path, content, None)?;
        self.recover_transaction(&id)?;
        self.publication_result(&id)
    }

    pub fn restore_file(
        &mut self,
        snapshot: &SnapshotId,
        path: PortablePath,
    ) -> Result<PublishResult> {
        self.recover()?;
        self.scan_without_recovery()?;
        let source = self.journal.snapshot(&self.space_id, snapshot)?;
        let content = source
            .entries
            .values()
            .find(|entry| entry.path == path)
            .and_then(|entry| entry.content.clone())
            .ok_or(ReconcileError::Invariant(
                "source snapshot does not contain this file",
            ))?;
        self.cas.verify(&content)?;
        let id = self.begin_content(path, content, Some(snapshot.clone()))?;
        self.recover_transaction(&id)?;
        self.publication_result(&id)
    }

    fn begin_content(
        &mut self,
        path: PortablePath,
        content: FileManifest,
        source: Option<SnapshotId>,
    ) -> Result<EntryId> {
        self.verify_root()?;
        self.parent_for(&path)?;
        self.cas.verify(&content)?;
        let manifest = self
            .manifest()?
            .ok_or(ReconcileError::Invariant("missing scanned baseline"))?;
        let requested_baseline = manifest
            .entries
            .values()
            .find(|entry| entry.path == path)
            .cloned();
        let id = EntryId::random()?;
        let target_path = if requested_baseline.is_some() || self.occupied(&path)? {
            self.conflict_path(&path, &id, 0)?
        } else {
            path.clone()
        };
        let root_identity = Some(physical_identity(&self.worktree)?);
        let parent_identity = Some(physical_identity(&self.parent_for(&target_path)?)?);
        let intent = PublicationIntent {
            format_version: FORMAT_VERSION,
            transaction_id: id.clone(),
            space_id: self.space_id.clone(),
            entry_id: EntryId::random()?,
            requested_path: path,
            target_path,
            content,
            baseline_root: manifest.root()?,
            requested_baseline,
            source_snapshot: source,
            created_at_ms: now_ms()?,
            attempt: 0,
            root_identity,
            parent_identity,
        };
        self.journal.begin_publication(&intent)?;
        checkpoint("after_intent");
        Ok(id)
    }

    pub fn recover(&mut self) -> Result<Vec<PublishResult>> {
        self.verify_root()?;
        let publications = self.journal.outstanding_publications(&self.space_id)?;
        let mut results = Vec::new();
        for publication in publications {
            let id = publication.intent.transaction_id;
            self.recover_transaction(&id)?;
            results.push(self.publication_result(&id)?);
        }
        Ok(results)
    }

    fn publication_result(&self, id: &EntryId) -> Result<PublishResult> {
        let publication = self.journal.publication(id)?;
        Ok(PublishResult {
            transaction_id: id.clone(),
            conflict_copy: publication.intent.target_path != publication.intent.requested_path,
            requested_path: publication.intent.requested_path,
            published_path: publication.intent.target_path,
            snapshot_id: publication
                .committed_snapshot
                .ok_or(ReconcileError::Invariant("publication not committed"))?,
            local_committed: true,
            remote_backup_complete: false,
        })
    }

    fn recover_transaction(&mut self, id: &EntryId) -> Result<()> {
        loop {
            self.verify_root()?;
            let publication = self.journal.publication(id)?;
            let intent = publication.intent;
            if intent.space_id != self.space_id {
                return Err(ReconcileError::Invariant(
                    "publication belongs to another space",
                ));
            }
            let parent = self.parent_for(&intent.target_path)?;
            if intent.root_identity.as_ref() != Some(&physical_identity(&self.worktree)?)
                || intent.parent_identity.as_ref() != Some(&physical_identity(&parent)?)
            {
                return Err(ReconcileError::Invariant(
                    "persisted publication directory identity changed or missing",
                ));
            }
            let parent_identity = Handle::from_path(&parent)?;
            let root_identity = Handle::from_path(&self.worktree)?;
            let target = self.worktree.join(intent.target_path.as_str());
            let directory = parent.join(".sync-tmp").join(id.as_str());
            let payload = directory.join(format!("payload-{}", intent.attempt));
            if publication.state == PublicationState::Committed {
                self.cleanup(&intent, &directory)?;
                checkpoint("after_cleanup");
                self.journal.mark_publication_cleaned(id)?;
                return Ok(());
            }
            self.cas.verify(&intent.content)?;
            ensure_temp_directory(
                &directory,
                id,
                publication.state == PublicationState::Preparing,
            )?;
            match publication.state {
                PublicationState::Preparing => {
                    prepare_payload(&self.cas, &directory, &payload, &intent)?;
                    checkpoint("after_temp");
                    self.journal.advance_publication(
                        id,
                        PublicationState::Preparing,
                        PublicationState::Ready,
                    )?;
                    checkpoint("after_ready");
                }
                PublicationState::Ready => {
                    if !payload.try_exists()? {
                        self.retarget(&intent)?;
                        continue;
                    }
                    if !file_matches(&payload, &intent.content)? {
                        self.retarget(&intent)?;
                        continue;
                    }
                    let payload_identity = Handle::from_path(&payload)?;
                    if self.occupied(&intent.target_path)? {
                        if !same_owned_file(&payload_identity, &payload, &target, &intent.content)?
                        {
                            self.retarget(&intent)?;
                            continue;
                        }
                    } else {
                        self.verify_root()?;
                        verify_directory_identity(&self.worktree, &root_identity)?;
                        verify_directory_identity(&parent, &parent_identity)?;
                        // This primitive never replaces a destination created by a native writer.
                        match fs::hard_link(&payload, &target) {
                            Ok(()) => {
                                sync_directory(&parent)?;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                self.retarget(&intent)?;
                                continue;
                            }
                            Err(e) => return Err(e.into()),
                        }
                        checkpoint("after_link");
                    }
                    if !same_owned_file(&payload_identity, &payload, &target, &intent.content)? {
                        self.retarget(&intent)?;
                        continue;
                    }
                    self.journal.advance_publication(
                        id,
                        PublicationState::Ready,
                        PublicationState::Published,
                    )?;
                    checkpoint("after_published");
                }
                PublicationState::Published => {
                    if !payload.try_exists()? {
                        self.retarget(&intent)?;
                        continue;
                    }
                    let payload_identity = Handle::from_path(&payload)?;
                    if !same_owned_file(&payload_identity, &payload, &target, &intent.content)? {
                        self.retarget(&intent)?;
                        continue;
                    }
                    let scan = self.stable_scan()?;
                    checkpoint("before_commit");
                    self.verify_root()?;
                    verify_directory_identity(&self.worktree, &root_identity)?;
                    verify_directory_identity(&parent, &parent_identity)?;
                    if !same_owned_file(&payload_identity, &payload, &target, &intent.content)?
                        || scan
                            .get(&intent.target_path)
                            .is_none_or(|entry| entry.content.as_ref() != Some(&intent.content))
                    {
                        self.retarget(&intent)?;
                        continue;
                    }
                    self.commit_scan(&scan, Some(&intent))?;
                    checkpoint("after_commit");
                }
                PublicationState::Committed => unreachable!(),
            }
        }
    }

    fn retarget(&mut self, intent: &PublicationIntent) -> Result<()> {
        let next = intent
            .attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= 16)
            .ok_or(ReconcileError::Invariant(
                "too many publication conflicts; intent and objects preserved",
            ))?;
        let path = self.conflict_path(&intent.requested_path, &intent.transaction_id, next)?;
        self.journal
            .retarget_publication(&intent.transaction_id, path)?;
        Ok(())
    }

    fn parent_for(&self, path: &PortablePath) -> Result<PathBuf> {
        let parent = path
            .parent()
            .map_or_else(|| self.worktree.clone(), |p| self.worktree.join(p.as_str()));
        check_ancestors(&parent)?;
        let metadata = fs::symlink_metadata(&parent)?;
        if !metadata.is_dir() {
            return Err(ReconcileError::Invariant(
                "destination parent must already be an accessible directory",
            ));
        }
        Ok(parent)
    }

    fn occupied(&self, path: &PortablePath) -> Result<bool> {
        let parent = self.parent_for(path)?;
        let name = path.as_str().rsplit('/').next().unwrap_or("");
        for child in fs::read_dir(parent)? {
            let name_on_disk = child?.file_name();
            let name_on_disk = name_on_disk
                .to_str()
                .ok_or(ReconcileError::Invariant("non-UTF8 destination sibling"))?;
            if name_on_disk.to_uppercase() == name.to_uppercase() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn conflict_path(
        &self,
        requested: &PortablePath,
        id: &EntryId,
        attempt: u32,
    ) -> Result<PortablePath> {
        let parent = requested
            .parent()
            .map_or(String::new(), |p| format!("{p}/"));
        let name = requested.as_str().rsplit('/').next().unwrap_or("");
        let (stem, extension) = name
            .rsplit_once('.')
            .filter(|(stem, _)| !stem.is_empty())
            .map_or((name, ""), |(stem, extension)| (stem, extension));
        let suffix = format!(
            ".conflict-{}-{}-{attempt}",
            &self.device_id.as_str()[..8],
            id.as_str()
        );
        let extension = if extension.is_empty() {
            String::new()
        } else {
            format!(".{extension}")
        };
        let allowance = 255usize.checked_sub(suffix.len() + extension.len()).ok_or(
            ReconcileError::Invariant("extension too long for a conflict name"),
        )?;
        let mut end = stem.len().min(allowance);
        while !stem.is_char_boundary(end) {
            end -= 1;
        }
        let candidate = PortablePath::new(format!("{parent}{}{suffix}{extension}", &stem[..end]))?;
        Ok(candidate)
    }

    fn cleanup(&self, intent: &PublicationIntent, directory: &Path) -> Result<()> {
        if !directory.try_exists()? {
            return Ok(());
        }
        ensure_temp_directory(directory, &intent.transaction_id, false)?;
        for attempt in 0..=intent.attempt {
            for name in [format!("building-{attempt}"), format!("payload-{attempt}")] {
                unlink_internal(&directory.join(name))?;
                checkpoint("during_cleanup");
            }
        }
        // Keep the tiny ownership marker so cleanup remains verifiable after a crash.
        sync_directory(directory)?;
        Ok(())
    }
}

fn ensure_temp_directory(directory: &Path, id: &EntryId, create: bool) -> Result<()> {
    check_ancestors(directory)?;
    let base = directory
        .parent()
        .ok_or(ReconcileError::Invariant("missing temporary root"))?;
    if create {
        if !base.try_exists()? {
            fs::create_dir(base)?;
        }
        if !directory.try_exists()? {
            fs::create_dir(directory)?;
        }
    }
    if !fs::symlink_metadata(base)?.is_dir() || !fs::symlink_metadata(directory)?.is_dir() {
        return Err(ReconcileError::Invariant("unsafe temporary directory"));
    }
    let owner = directory.join("owner");
    if !owner.try_exists()? && create {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&owner)?;
        file.write_all(id.as_str().as_bytes())?;
        file.sync_all()?;
        sync_directory(directory)?;
        sync_directory(base)?;
    }
    check_ancestors(&owner)?;
    let metadata = fs::symlink_metadata(&owner)?;
    if !metadata.is_file() || metadata.len() != 32 || fs::read_to_string(owner)? != id.as_str() {
        return Err(ReconcileError::Invariant(
            "temporary transaction ownership mismatch",
        ));
    }
    Ok(())
}

fn prepare_payload(
    cas: &sync_extend_cas::Cas,
    directory: &Path,
    payload: &Path,
    intent: &PublicationIntent,
) -> Result<()> {
    if payload.try_exists()? {
        if file_matches(payload, &intent.content)? {
            return Ok(());
        }
        return Err(ReconcileError::Invariant(
            "transaction payload changed unexpectedly",
        ));
    }
    let building = directory.join(format!("building-{}", intent.attempt));
    unlink_internal(&building)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&building)?;
    checkpoint("after_temp_created");
    cas.write_file(&intent.content, &mut file)?;
    file.sync_all()?;
    drop(file);
    checkpoint("after_temp_flushed");
    if !file_matches(&building, &intent.content)? {
        return Err(ReconcileError::Unstable);
    }
    fs::hard_link(&building, payload)?;
    sync_directory(directory)?;
    fs::remove_file(building)?;
    Ok(())
}

fn same_owned_file(
    identity: &Handle,
    payload: &Path,
    target: &Path,
    content: &FileManifest,
) -> Result<bool> {
    match fs::symlink_metadata(target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || is_reparse(&metadata) =>
        {
            return Ok(false)
        }
        Ok(_) => {}
    }
    check_ancestors(target)?;
    let target_identity = Handle::from_path(target)?;
    Ok(identity == &target_identity
        && physical_identity(payload)? == physical_identity(target)?
        && file_matches(target, content)?)
}

fn physical_identity(path: &Path) -> Result<ContentId> {
    check_ancestors(path)?;
    let id = file_id::get_file_id(path)?;
    let text = match id {
        file_id::FileId::Inode {
            device_id,
            inode_number,
        } => format!("inode:{device_id}:{inode_number}"),
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => format!("windows:{volume_serial_number}:{file_id}"),
        file_id::FileId::LowRes { .. } => {
            return Err(ReconcileError::Invariant(
                "high-resolution Windows file identity is unavailable",
            ))
        }
    };
    Ok(ContentId::hash(text.as_bytes()))
}

fn verify_directory_identity(path: &Path, identity: &Handle) -> Result<()> {
    check_ancestors(path)?;
    if identity != &Handle::from_path(path)? {
        return Err(ReconcileError::Invariant(
            "publication directory identity changed",
        ));
    }
    Ok(())
}

fn file_matches(path: &Path, content: &FileManifest) -> Result<bool> {
    check_ancestors(path)?;
    let before = fs::symlink_metadata(path)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || is_reparse(&before)
        || before.len() != content.length
    {
        return Ok(false);
    }
    let mut file = File::open(path)?;
    let identity = Handle::from_file(file.try_clone()?)?;
    let mut hasher = blake3::Hasher::new();
    let mut remaining = content.length;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if count as u64 > remaining {
            return Ok(false);
        }
        remaining -= count as u64;
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    Ok(remaining == 0
        && ContentId::from_hasher(&hasher) == content.content_id
        && before.modified()? == after.modified()?
        && after.len() == content.length
        && identity == Handle::from_path(path)?)
}

fn unlink_internal(path: &Path) -> Result<()> {
    check_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && !is_reparse(&metadata) =>
        {
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(ReconcileError::Invariant(
                "refusing cleanup of unexpected internal path",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn checkpoint(_phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(_phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{_phase}");
        loop {
            std::thread::park();
        }
    }
}
