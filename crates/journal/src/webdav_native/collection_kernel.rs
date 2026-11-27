//! Original held native effects. Only the live Journal issuer may call these.
//! This source is not compiled until its full durable prefix integration is ready.
use super::ordered_receipts::ActionObject;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{
    tree_restore_identity::TreeNativeIdentity, ContentId, Entry, EntryKind, PortableEntryMetadata,
    PortableMetadataUnsupportedReason, PortablePath, PortableTimestamp, PortableUnixExecutable,
};
use sync_extend_platform_fs::{
    FileKey, GuardedReadFile, LockedDirectory, LockedDirectoryMutation, LockedFile,
    OwnedFileCreation, SealedOriginalFile,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn invalid() -> Box<dyn std::error::Error> {
    "original DAV collection native effect lineage".into()
}
fn identity(key: FileKey) -> TreeNativeIdentity {
    TreeNativeIdentity {
        volume_serial: key.volume,
        file_id: format!("{:032x}", key.id),
    }
}
fn component(path: &PortablePath) -> Result<&str> {
    path.as_str().rsplit('/').next().ok_or_else(invalid)
}

/// A borrowed actual original parent, never recovered from a description.
pub(super) enum Parent<'a> {
    Existing(&'a LockedDirectory),
    Mutation(&'a LockedDirectoryMutation),
}
impl Parent<'_> {
    pub(super) fn key(&self) -> Result<FileKey> {
        Ok(match self {
            Self::Existing(parent) => parent.key()?,
            Self::Mutation(parent) => parent.key()?,
        })
    }
    pub(super) fn create_directory(&self, name: &str) -> Result<LockedDirectoryMutation> {
        Ok(match self {
            Self::Existing(parent) => parent.create_new_publication_directory(name)?,
            Self::Mutation(parent) => parent.create_new_publication_directory(name)?,
        })
    }
}

pub(super) struct CreatedDirectory {
    pub entry: Entry,
    pub path: PathBuf,
    held: LockedDirectoryMutation,
    pub parent: FileKey,
    key: FileKey,
}
impl CreatedDirectory {
    pub(super) fn intent(
        parent: &Parent<'_>,
        action: usize,
        entry: &Entry,
    ) -> Result<ActionObject> {
        if entry.kind != EntryKind::Directory || entry.content.is_some() {
            return Err(invalid());
        }
        let parent = identity(parent.key()?);
        Ok(ActionObject {
            action,
            entry_id: entry.entry_id.clone(),
            path: entry.path.clone(),
            source_parent: parent.clone(),
            parent,
            original: None,
            component: component(&entry.path)?.into(),
            content_hash: None,
            length: 0,
        })
    }
    /// Caller commits the exact intent and checks the absent slot before calling.
    pub(super) fn create(
        parent: &Parent<'_>,
        root: &Path,
        action: usize,
        entry: &Entry,
    ) -> Result<(Self, ActionObject)> {
        let intent = Self::intent(parent, action, entry)?;
        // Only the explicit fault feature can pause here; all policy/intent
        // checks have finished and the next operation is the actual CREATE.
        super::checkpoint("webdav_collection_directory_create_before_call");
        let held = parent.create_directory(&intent.component)?;
        let proof = held.original_creation()?;
        let parent_key = proof.parent_key()?;
        let key = proof.key()?;
        if identity(parent_key) != intent.parent || proof.created_component() != intent.component {
            return Err(invalid());
        }
        let path = root.join(entry.path.as_str());
        if !held.matches_path(&path)? {
            return Err(invalid());
        }
        let mut evidence = intent;
        evidence.original = Some(identity(key));
        let created = Self {
            entry: entry.clone(),
            path,
            held,
            parent: parent_key,
            key,
        };
        created.verify()?;
        Ok((created, evidence))
    }
    pub(super) fn key(&self) -> FileKey {
        self.key
    }
    pub(super) fn parent(&self) -> Parent<'_> {
        Parent::Mutation(&self.held)
    }
    pub(super) fn verify(&self) -> Result<()> {
        let proof = self.held.original_creation()?;
        proof.verify()?;
        if proof.key()? != self.key
            || proof.parent_key()? != self.parent
            || proof.created_component() != component(&self.entry.path)?
            || !self.held.matches_path(&self.path)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(super) enum Quarantined {
    File {
        held: LockedFile,
        entry: Entry,
        path: PathBuf,
        key: FileKey,
    },
    Directory {
        held: LockedDirectoryMutation,
        entry: Entry,
        path: PathBuf,
        key: FileKey,
    },
}
impl Quarantined {
    // Original held object and exact source/destination evidence stay explicit.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn move_file(
        held: LockedFile,
        entry: Entry,
        original_path: &Path,
        owner_path: &Path,
        owner: &LockedDirectoryMutation,
        component: &str,
        source_parent: FileKey,
        action: usize,
    ) -> Result<(Self, ActionObject)> {
        if entry.kind != EntryKind::File || !held.matches_path(original_path)? {
            return Err(invalid());
        }
        verify_content(held.reader(), &entry)?;
        let key = held.key()?;
        let owner_key = owner.key()?;
        if owner_key.volume != key.volume {
            return Err(invalid());
        }
        let destination = owner_path.join(component);
        require_absent(&destination)?;
        held.rename_no_replace(&destination)?;
        super::checkpoint(&format!("webdav_action_{action}_original_moved"));
        if held.key()? != key || !held.matches_path(&destination)? {
            return Err(invalid());
        }
        let evidence = ActionObject {
            action,
            entry_id: entry.entry_id.clone(),
            path: entry.path.clone(),
            source_parent: identity(source_parent),
            parent: identity(owner_key),
            original: Some(identity(key)),
            component: component.into(),
            content_hash: entry
                .content
                .as_ref()
                .map(|content| content.content_id.clone()),
            length: entry.content.as_ref().ok_or_else(invalid)?.length,
        };
        let result = Self::File {
            held,
            entry,
            path: destination,
            key,
        };
        result.verify()?;
        Ok((result, evidence))
    }
    // Original held object and exact source/destination evidence stay explicit.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn move_directory(
        held: LockedDirectoryMutation,
        entry: Entry,
        original_path: &Path,
        owner_path: &Path,
        owner: &LockedDirectoryMutation,
        component: &str,
        source_parent: FileKey,
        action: usize,
    ) -> Result<(Self, ActionObject)> {
        if entry.kind != EntryKind::Directory
            || !held.matches_path(original_path)?
            || fs::read_dir(original_path)?.next().is_some()
        {
            return Err(invalid());
        }
        let key = held.key()?;
        let owner_key = owner.key()?;
        if owner_key.volume != key.volume {
            return Err(invalid());
        }
        let destination = owner_path.join(component);
        require_absent(&destination)?;
        held.rename_no_replace(&destination)?;
        super::checkpoint(&format!("webdav_action_{action}_original_moved"));
        if held.key()? != key || !held.matches_path(&destination)? {
            return Err(invalid());
        }
        let evidence = ActionObject {
            action,
            entry_id: entry.entry_id.clone(),
            path: entry.path.clone(),
            source_parent: identity(source_parent),
            parent: identity(owner_key),
            original: Some(identity(key)),
            component: component.into(),
            content_hash: None,
            length: 0,
        };
        let result = Self::Directory {
            held,
            entry,
            path: destination,
            key,
        };
        result.verify()?;
        Ok((result, evidence))
    }
    pub(super) fn verify(&self) -> Result<()> {
        match self {
            Self::File {
                held,
                entry,
                path,
                key,
            } => {
                if held.key()? != *key || !held.matches_path(path)? {
                    return Err(invalid());
                }
                verify_content(held.reader(), entry)?;
            }
            Self::Directory {
                held,
                entry,
                path,
                key,
            } => {
                held.require_case_insensitive()?;
                if entry.kind != EntryKind::Directory
                    || held.key()? != *key
                    || !held.matches_path(path)?
                    || fs::read_dir(path)?.next().is_some()
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

impl Quarantined {
    pub(super) fn dispose(self, action: usize) -> Result<()> {
        self.verify()?;
        let path = self.path().to_owned();
        match &self {
            Self::File { held, .. } => held.delete_on_close()?,
            Self::Directory { held, .. } => held.delete_empty_on_close()?,
        }
        super::checkpoint(&format!("webdav_action_{action}_delete_requested"));
        drop(self);
        super::checkpoint(&format!("webdav_action_{action}_original_handles_closed"));
        require_absent(&path)?;
        super::checkpoint(&format!("webdav_action_{action}_original_absence_verified"));
        Ok(())
    }
    pub(super) fn entry(&self) -> &Entry {
        match self {
            Self::File { entry, .. } | Self::Directory { entry, .. } => entry,
        }
    }
    pub(super) fn key(&self) -> FileKey {
        match self {
            Self::File { key, .. } | Self::Directory { key, .. } => *key,
        }
    }
    pub(super) fn path(&self) -> &Path {
        match self {
            Self::File { path, .. } | Self::Directory { path, .. } => path,
        }
    }
    pub(super) fn reader(&self) -> Option<&std::fs::File> {
        match self {
            Self::File { held, .. } => Some(held.reader()),
            _ => None,
        }
    }
}
enum Payload {
    Empty(OwnedFileCreation),
    Written(OwnedFileCreation),
    Sealed(SealedOriginalFile),
    Published(sync_extend_platform_fs::PublishedOriginalFile),
}

/// Owner-scoped payload retains its original CREATE continuously through rename.
pub(super) struct CreatedFile {
    pub entry: Entry,
    pub action: usize,
    path: PathBuf,
    component: String,
    owner: FileKey,
    key: FileKey,
    held: Option<Payload>,
    published: bool,
}
impl CreatedFile {
    pub(super) fn intent(
        owner: &LockedDirectoryMutation,
        transaction: &sync_extend_core_model::EntryId,
        action: usize,
        entry: &Entry,
    ) -> Result<ActionObject> {
        if entry.kind != EntryKind::File {
            return Err(invalid());
        }
        let content = entry.content.as_ref().ok_or_else(invalid)?;
        let parent = identity(owner.key()?);
        Ok(ActionObject {
            action,
            entry_id: entry.entry_id.clone(),
            path: entry.path.clone(),
            source_parent: parent.clone(),
            parent,
            original: None,
            component: format!("dav-{transaction}-{action}.payload"),
            content_hash: Some(content.content_id.clone()),
            length: content.length,
        })
    }
    pub(super) fn create(
        owner: &LockedDirectoryMutation,
        owner_path: &Path,
        transaction: &sync_extend_core_model::EntryId,
        action: usize,
        entry: &Entry,
    ) -> Result<(Self, ActionObject)> {
        let intent = Self::intent(owner, transaction, action, entry)?;
        let held = owner.create_new_file(&intent.component)?;
        let proof = held.original_creation()?;
        let key = proof.key()?;
        let owner_key = proof.parent_key()?;
        if identity(owner_key) != intent.parent
            || proof.created_component() != intent.component
            || held.reader().metadata()?.len() != 0
        {
            return Err(invalid());
        }
        let path = owner_path.join(&intent.component);
        if !sync_extend_platform_fs::regular_file_matches_path(held.reader(), &path)? {
            return Err(invalid());
        }
        let mut evidence = intent;
        evidence.original = Some(identity(key));
        evidence.content_hash = Some(ContentId::hash(b""));
        evidence.length = 0;
        let result = Self {
            entry: entry.clone(),
            action,
            path,
            component: evidence.component.clone(),
            owner: owner_key,
            key,
            held: Some(Payload::Empty(held)),
            published: false,
        };
        result.verify()?;
        Ok((result, evidence))
    }
    pub(super) fn materialize(
        &mut self,
        chunks: &BTreeMap<ContentId, (&GuardedReadFile, u64)>,
    ) -> Result<ActionObject> {
        self.verify()?;
        let Some(Payload::Empty(mut held)) = self.held.take() else {
            return Err(invalid());
        };
        let expected = self.entry.content.as_ref().ok_or_else(invalid)?;
        let mut whole = blake3::Hasher::new();
        let mut buffer = [0_u8; 65536];
        for chunk in &expected.chunks {
            let (source, length) = chunks.get(&chunk.content_id).ok_or_else(invalid)?;
            source.verify_single_link()?;
            if *length != u64::from(chunk.length) || source.reader().metadata()?.len() != *length {
                return Err(invalid());
            }
            let mut reader = source.reader();
            reader.seek(SeekFrom::Start(0))?;
            let mut remaining = *length;
            let mut digest = blake3::Hasher::new();
            while remaining != 0 {
                let count = usize::try_from(remaining.min(buffer.len() as u64))?;
                reader.read_exact(&mut buffer[..count])?;
                digest.update(&buffer[..count]);
                whole.update(&buffer[..count]);
                held.writer().write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            if reader.read(&mut buffer[..1])? != 0
                || ContentId::from_hasher(&digest) != chunk.content_id
            {
                return Err(invalid());
            }
            source.verify_single_link()?;
        }
        if ContentId::from_hasher(&whole) != expected.content_id
            || held.reader().metadata()?.len() != expected.length
        {
            return Err(invalid());
        }
        super::checkpoint(&format!("webdav_action_{}_payload_written", self.action));
        held.writer().sync_all()?;
        super::checkpoint(&format!("webdav_action_{}_payload_synced", self.action));
        self.held = Some(Payload::Written(held));
        self.verify()?;
        self.evidence(false)
    }
    pub(super) fn seal(&mut self) -> Result<ActionObject> {
        self.verify()?;
        let Some(Payload::Written(held)) = self.held.take() else {
            return Err(invalid());
        };
        let held = held.seal_original()?;
        if held.key()? != self.key || held.parent_key()? != self.owner {
            return Err(invalid());
        }
        self.held = Some(Payload::Sealed(held));
        self.verify()?;
        self.evidence(false)
    }
    /// No-replace rename remains on the original sealed handle.
    /// Parent binding and durable FilePublicationRequested must be checked by issuer.
    pub(super) fn publish(&mut self, parent: &Parent<'_>, root: &Path) -> Result<ActionObject> {
        self.verify()?;
        if self.published {
            return Err(invalid());
        }
        let Some(Payload::Sealed(held)) = &self.held else {
            return Err(invalid());
        };
        let destination = root.join(self.entry.path.as_str());
        require_absent(&destination)?;
        held.rename_no_replace(&destination)?;
        super::checkpoint(&format!("webdav_action_{}_file_published", self.action));
        if !held.matches_path(&destination)? {
            return Err(invalid());
        }
        self.path = destination;
        self.published = true;
        self.verify()?;
        let mut evidence = self.evidence(false)?;
        evidence.parent = identity(parent.key()?);
        evidence.component = component(&self.entry.path)?.into();
        Ok(evidence)
    }
    pub(super) fn release_owner_parent(&mut self) -> Result<()> {
        self.verify()?;
        if !self.published {
            return Err(invalid());
        }
        if matches!(&self.held, Some(Payload::Published(_))) {
            return self.verify();
        }
        let Some(Payload::Sealed(held)) = self.held.take() else {
            return Err(invalid());
        };
        self.held = Some(Payload::Published(held.release_creation_parent()?));
        apply_entry_metadata(self.reader()?, &self.entry)?;
        super::checkpoint(&format!("webdav_action_{}_metadata_applied", self.action));
        self.verify()
    }
    pub(super) fn key(&self) -> FileKey {
        self.key
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn published(&self) -> bool {
        self.published
    }
    pub(super) fn reader(&self) -> Result<&std::fs::File> {
        Ok(match self.held.as_ref().ok_or_else(invalid)? {
            Payload::Empty(held) | Payload::Written(held) => held.reader(),
            Payload::Sealed(held) => held.reader(),
            Payload::Published(held) => held.reader(),
        })
    }
    pub(super) fn evidence(&self, intended: bool) -> Result<ActionObject> {
        let content = self.entry.content.as_ref().ok_or_else(invalid)?;
        let empty = !intended && matches!(&self.held, Some(Payload::Empty(_)));
        Ok(ActionObject {
            action: self.action,
            entry_id: self.entry.entry_id.clone(),
            path: self.entry.path.clone(),
            source_parent: identity(self.owner),
            parent: identity(self.owner),
            original: Some(identity(self.key)),
            component: self.component.clone(),
            content_hash: Some(if empty {
                ContentId::hash(b"")
            } else {
                content.content_id.clone()
            }),
            length: if empty { 0 } else { content.length },
        })
    }
    pub(super) fn verify(&self) -> Result<()> {
        let reader = match self.held.as_ref().ok_or_else(invalid)? {
            Payload::Empty(held) | Payload::Written(held) => {
                let proof = held.original_creation()?;
                if proof.key()? != self.key
                    || proof.parent_key()? != self.owner
                    || proof.created_component() != self.component
                {
                    return Err(invalid());
                }
                held.reader()
            }
            Payload::Published(held) => {
                held.verify_original()?;
                if held.key()? != self.key
                    || held.original_parent_key() != self.owner
                    || held.created_component() != self.component
                {
                    return Err(invalid());
                }
                held.reader()
            }
            Payload::Sealed(held) => {
                held.verify_original()?;
                if held.key()? != self.key
                    || held.parent_key()? != self.owner
                    || held.created_component() != self.component
                {
                    return Err(invalid());
                }
                held.reader()
            }
        };
        if !sync_extend_platform_fs::regular_file_matches_path(reader, &self.path)? {
            return Err(invalid());
        }
        if matches!(&self.held, Some(Payload::Empty(_))) {
            if reader.metadata()?.len() != 0 {
                return Err(invalid());
            }
        } else {
            verify_content(reader, &self.entry)?;
            if matches!(&self.held, Some(Payload::Published(_))) {
                verify_entry_metadata(reader, &self.entry)?;
            }
        }
        Ok(())
    }
}

fn platform_unsupported(
    reason: PortableMetadataUnsupportedReason,
) -> sync_extend_platform_fs::UnsupportedReason {
    match reason {
        PortableMetadataUnsupportedReason::Platform => {
            sync_extend_platform_fs::UnsupportedReason::Platform
        }
        PortableMetadataUnsupportedReason::Filesystem => {
            sync_extend_platform_fs::UnsupportedReason::Filesystem
        }
        PortableMetadataUnsupportedReason::Permission => {
            sync_extend_platform_fs::UnsupportedReason::Permission
        }
        PortableMetadataUnsupportedReason::Api => sync_extend_platform_fs::UnsupportedReason::Api,
    }
}

fn platform_time(value: PortableTimestamp) -> Result<sync_extend_platform_fs::PortableTime> {
    let (seconds, nanos) = value.captured_value().ok_or_else(invalid)?;
    Ok(sync_extend_platform_fs::PortableTime { seconds, nanos })
}

fn platform_captured_time(
    value: PortableTimestamp,
) -> Result<sync_extend_platform_fs::CapturedTime> {
    match value {
        PortableTimestamp::Captured { .. } => Ok(sync_extend_platform_fs::CapturedTime::Value(
            platform_time(value)?,
        )),
        PortableTimestamp::Unsupported { reason } => Ok(
            sync_extend_platform_fs::CapturedTime::Unsupported(platform_unsupported(reason)),
        ),
        PortableTimestamp::Unknown => Err(invalid()),
    }
}

fn platform_captured_flag(value: PortableUnixExecutable) -> sync_extend_platform_fs::CapturedFlag {
    match value {
        PortableUnixExecutable::Captured { executable } => {
            sync_extend_platform_fs::CapturedFlag::Value(executable)
        }
        PortableUnixExecutable::Unsupported { .. } => {
            sync_extend_platform_fs::CapturedFlag::Unsupported(
                sync_extend_platform_fs::UnsupportedReason::Api,
            )
        }
        PortableUnixExecutable::Unknown => sync_extend_platform_fs::CapturedFlag::Unsupported(
            sync_extend_platform_fs::UnsupportedReason::Api,
        ),
    }
}

fn platform_metadata(
    metadata: &PortableEntryMetadata,
) -> Result<sync_extend_platform_fs::CapturedFileMetadata> {
    metadata.validate().map_err(|_| invalid())?;
    Ok(sync_extend_platform_fs::CapturedFileMetadata {
        modified: platform_time(metadata.modified)?,
        readonly: metadata.readonly.value().ok_or_else(invalid)?,
        creation: metadata
            .creation
            .map(platform_captured_time)
            .transpose()?
            .unwrap_or(sync_extend_platform_fs::CapturedTime::Unsupported(
                sync_extend_platform_fs::UnsupportedReason::Api,
            )),
        unix_executable: metadata
            .unix_executable
            .map(platform_captured_flag)
            .unwrap_or(sync_extend_platform_fs::CapturedFlag::Unsupported(
                sync_extend_platform_fs::UnsupportedReason::Api,
            )),
    })
}

fn apply_entry_metadata(reader: &std::fs::File, entry: &Entry) -> Result<()> {
    let Some(metadata) = entry.metadata.as_ref() else {
        return Ok(());
    };
    let requested = platform_metadata(metadata)?;
    sync_extend_platform_fs::apply_portable_file_metadata(reader, &requested)?;
    Ok(())
}

fn verify_entry_metadata(reader: &std::fs::File, entry: &Entry) -> Result<()> {
    let Some(metadata) = entry.metadata.as_ref() else {
        return Ok(());
    };
    let requested = platform_metadata(metadata)?;
    let observed = sync_extend_platform_fs::capture_portable_file_metadata(reader)?;
    let resolution = observed.capabilities.modified_resolution_nanos;
    let quantize =
        |time: sync_extend_platform_fs::PortableTime| sync_extend_platform_fs::PortableTime {
            seconds: time.seconds,
            nanos: time.nanos / resolution * resolution,
        };
    if quantize(observed.metadata.modified) != quantize(requested.modified)
        || observed.metadata.readonly != requested.readonly
    {
        return Err(invalid());
    }
    match requested.creation {
        sync_extend_platform_fs::CapturedTime::Value(expected) => {
            let creation_resolution = observed
                .capabilities
                .creation_resolution_nanos
                .ok_or_else(invalid)?;
            let expected = sync_extend_platform_fs::PortableTime {
                seconds: expected.seconds,
                nanos: expected.nanos / creation_resolution * creation_resolution,
            };
            if observed.metadata.creation != sync_extend_platform_fs::CapturedTime::Value(expected)
            {
                return Err(invalid());
            }
        }
        sync_extend_platform_fs::CapturedTime::Unsupported(_) => {}
    }
    match requested.unix_executable {
        sync_extend_platform_fs::CapturedFlag::Value(expected) => {
            if !observed.capabilities.unix_executable_supported
                || observed.metadata.unix_executable
                    != sync_extend_platform_fs::CapturedFlag::Value(expected)
            {
                return Err(invalid());
            }
        }
        sync_extend_platform_fs::CapturedFlag::Unsupported(_) => {}
    }
    Ok(())
}

fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(invalid()),
    }
}

fn verify_content(mut reader: &std::fs::File, entry: &Entry) -> Result<()> {
    let content = entry.content.as_ref().ok_or_else(invalid)?;
    if reader.metadata()?.len() != content.length {
        return Err(invalid());
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut whole = blake3::Hasher::new();
    let mut buffer = [0_u8; 65536];
    for chunk in &content.chunks {
        let mut part = blake3::Hasher::new();
        let mut remaining = u64::from(chunk.length);
        while remaining != 0 {
            let count = usize::try_from(remaining.min(buffer.len() as u64))?;
            reader.read_exact(&mut buffer[..count])?;
            whole.update(&buffer[..count]);
            part.update(&buffer[..count]);
            remaining -= count as u64;
        }
        if ContentId::from_hasher(&part) != chunk.content_id {
            return Err(invalid());
        }
    }
    if reader.read(&mut buffer[..1])? != 0 || ContentId::from_hasher(&whole) != content.content_id {
        return Err(invalid());
    }
    Ok(())
}
