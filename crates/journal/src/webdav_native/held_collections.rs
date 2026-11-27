//! Ownership of the original collection objects, transferred once before effects.
//! Private holders cannot be reconstructed from namespace projection or SQL rows.
use super::{
    collection_kernel::{CreatedDirectory, CreatedFile, Parent, Quarantined},
    ordered_receipts::ActionObject,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Seek, SeekFrom},
    os::windows::fs::MetadataExt,
    path::{Path, PathBuf},
};
use sync_extend_core_model::{
    tree_restore_identity::TreeNativeIdentity, ContentId, Entry, EntryKind, Manifest, PortablePath,
};
use sync_extend_platform_fs::{FileKey, LockedDirectoryMutation, LockedFile};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn invalid() -> Box<dyn std::error::Error> {
    "original held DAV collection registry".into()
}
fn native(key: FileKey) -> TreeNativeIdentity {
    TreeNativeIdentity {
        volume_serial: key.volume,
        file_id: format!("{:032x}", key.id),
    }
}

struct OriginalFile {
    entry: Entry,
    path: PathBuf,
    key: FileKey,
    held: LockedFile,
}
struct OriginalDirectory {
    entry: Entry,
    path: PathBuf,
    key: FileKey,
    held: LockedDirectoryMutation,
}

pub(super) struct HeldCollections {
    files: BTreeMap<PortablePath, OriginalFile>,
    directories: BTreeMap<PortablePath, OriginalDirectory>,
    created_directories: BTreeMap<usize, CreatedDirectory>,
    created_files: BTreeMap<usize, CreatedFile>,
    quarantine: BTreeMap<usize, (String, Quarantined)>,
    disposed: BTreeMap<PortablePath, (usize, TreeNativeIdentity)>,
}
impl HeldCollections {
    pub(super) fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            directories: BTreeMap::new(),
            created_directories: BTreeMap::new(),
            created_files: BTreeMap::new(),
            quarantine: BTreeMap::new(),
            disposed: BTreeMap::new(),
        }
    }
    pub(super) fn insert_original_file(
        &mut self,
        entry: Entry,
        path: PathBuf,
        key: FileKey,
        held: LockedFile,
    ) -> Result<()> {
        if self
            .files
            .insert(
                entry.path.clone(),
                OriginalFile {
                    entry,
                    path,
                    key,
                    held,
                },
            )
            .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn insert_original_directory(
        &mut self,
        entry: Entry,
        path: PathBuf,
        key: FileKey,
        held: LockedDirectoryMutation,
    ) -> Result<()> {
        if self
            .directories
            .insert(
                entry.path.clone(),
                OriginalDirectory {
                    entry,
                    path,
                    key,
                    held,
                },
            )
            .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn parent(&self, path: &PortablePath) -> Result<Parent<'_>> {
        if let Some(original) = self.directories.get(path) {
            if !original.held.matches_path(&original.path)? || original.held.key()? != original.key
            {
                return Err(invalid());
            }
            return Ok(Parent::Mutation(&original.held));
        }
        let created = self
            .created_directories
            .values()
            .find(|created| created.entry.path == *path)
            .ok_or_else(invalid)?;
        created.verify()?;
        Ok(created.parent())
    }
    pub(super) fn create_directory(
        &mut self,
        existing_parent: Option<&sync_extend_platform_fs::LockedDirectory>,
        root: &Path,
        action: usize,
        entry: &Entry,
    ) -> Result<ActionObject> {
        if self.created_directories.contains_key(&action) {
            return Err(invalid());
        }
        let parent = match existing_parent {
            Some(parent) => Parent::Existing(parent),
            None => self.parent(&entry.path.parent().ok_or_else(invalid)?)?,
        };
        let (created, evidence) = CreatedDirectory::create(&parent, root, action, entry)?;
        // The borrowed parent ends before inserting the owned new child.
        self.created_directories.insert(action, created);
        Ok(evidence)
    }
    pub(super) fn publish_file(
        &mut self,
        existing_parent: Option<&sync_extend_platform_fs::LockedDirectory>,
        root: &Path,
        action: usize,
    ) -> Result<ActionObject> {
        let entry = self
            .created_files
            .get(&action)
            .ok_or_else(invalid)?
            .entry
            .clone();
        let parent = match existing_parent {
            Some(parent) => Parent::Existing(parent),
            None => {
                let path = entry.path.parent().ok_or_else(invalid)?;
                if let Some(parent) = self.directories.get(&path) {
                    if parent.held.key()? != parent.key
                        || !parent.held.matches_path(&parent.path)?
                    {
                        return Err(invalid());
                    }
                    Parent::Mutation(&parent.held)
                } else {
                    let parent = self
                        .created_directories
                        .values()
                        .find(|parent| parent.entry.path == path)
                        .ok_or_else(invalid)?;
                    parent.verify()?;
                    parent.parent()
                }
            }
        };
        // Fields are independently borrowed: original/new directories remain
        // retained while the payload's original sealed handle performs rename.
        self.created_files
            .get_mut(&action)
            .ok_or_else(invalid)?
            .publish(&parent, root)
    }
    pub(super) fn create_file(
        &mut self,
        owner: &LockedDirectoryMutation,
        owner_path: &Path,
        transaction: &sync_extend_core_model::EntryId,
        action: usize,
        entry: &Entry,
    ) -> Result<ActionObject> {
        if self.created_files.contains_key(&action) {
            return Err(invalid());
        }
        let (created, evidence) =
            CreatedFile::create(owner, owner_path, transaction, action, entry)?;
        self.created_files.insert(action, created);
        Ok(evidence)
    }
    pub(super) fn verify_projection(
        &self,
        baseline: &Manifest,
        plan: &sync_extend_core_model::webdav_native::WebDavNativePlan,
        expected: &super::collection_projection::Projection,
    ) -> Result<()> {
        use super::collection_projection::ProjectedObject;
        self.verify()?;
        let mut user = baseline
            .entries
            .values()
            .map(|entry| {
                let native = plan
                    .inventory()
                    .entries
                    .get(&entry.path)
                    .ok_or_else(invalid)?;
                Ok((
                    entry.path.clone(),
                    ProjectedObject {
                        entry: entry.clone(),
                        original: native.identity.clone(),
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (_, original) in self.quarantine.values() {
            user.remove(&original.entry().path);
        }
        for path in self.disposed.keys() {
            user.remove(path);
        }
        for original in self.files.values() {
            if user.get(&original.entry.path)
                != Some(&ProjectedObject {
                    entry: original.entry.clone(),
                    original: native(original.key),
                })
            {
                return Err(invalid());
            }
        }
        for original in self.directories.values() {
            if user.get(&original.entry.path)
                != Some(&ProjectedObject {
                    entry: original.entry.clone(),
                    original: native(original.key),
                })
            {
                return Err(invalid());
            }
        }
        for created in self.created_directories.values() {
            user.insert(
                created.entry.path.clone(),
                ProjectedObject {
                    entry: created.entry.clone(),
                    original: native(created.key()),
                },
            );
        }
        let mut payloads = BTreeMap::new();
        for file in self.created_files.values() {
            let object = ProjectedObject {
                entry: file.entry.clone(),
                original: native(file.key()),
            };
            if file.published() {
                user.insert(file.entry.path.clone(), object);
            } else {
                payloads.insert(
                    file.path()
                        .file_name()
                        .and_then(|name| name.to_str())
                        .ok_or_else(invalid)?
                        .to_owned(),
                    object,
                );
            }
        }
        let quarantine: BTreeMap<_, _> = self
            .quarantine
            .values()
            .map(|(component, original)| {
                (
                    component.clone(),
                    ProjectedObject {
                        entry: original.entry().clone(),
                        original: native(original.key()),
                    },
                )
            })
            .collect();
        if user != expected.user
            || payloads != expected.payloads
            || quarantine != expected.quarantined
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn retained_handle_count(&self) -> Result<usize> {
        // Original mutation guards have one handle; every new directory and
        // unhanded payload also retains its original CREATE parent handle.
        let created = self
            .created_directories
            .len()
            .checked_add(self.created_files.len())
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(invalid)?;
        self.files
            .len()
            .checked_add(self.directories.len())
            .and_then(|count| count.checked_add(self.quarantine.len()))
            .and_then(|count| count.checked_add(created))
            .ok_or_else(invalid)
    }
    pub(super) fn materialized_bytes(&self) -> Result<u64> {
        self.verify()?;
        self.created_files.values().try_fold(0u64, |sum, file| {
            sum.checked_add(file.reader()?.metadata()?.len())
                .ok_or_else(invalid)
        })
    }
    pub(super) fn materialized_allocation(&self, unit: u64) -> Result<u64> {
        self.verify()?;
        self.created_files.values().try_fold(0u64, |sum, file| {
            let length = file.reader()?.metadata()?.len();
            let allocated = super::native_capacity::rounded_allocation(length, unit)?;
            sum.checked_add(allocated).ok_or_else(invalid)
        })
    }
    pub(super) fn file(&self, action: usize) -> Result<&CreatedFile> {
        self.created_files.get(&action).ok_or_else(invalid)
    }
    pub(super) fn file_mut(&mut self, action: usize) -> Result<&mut CreatedFile> {
        self.created_files.get_mut(&action).ok_or_else(invalid)
    }
    // Each retained original, owner and exact slot is checked independently.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn quarantine(
        &mut self,
        root: &Path,
        owner: &LockedDirectoryMutation,
        owner_path: &Path,
        component: &str,
        source_parent: FileKey,
        action: usize,
        entry: &Entry,
    ) -> Result<ActionObject> {
        if self.quarantine.contains_key(&action) {
            return Err(invalid());
        }
        let original_path = root.join(entry.path.as_str());
        let (held, evidence) = match entry.kind {
            EntryKind::File => {
                let original = self.files.remove(&entry.path).ok_or_else(invalid)?;
                if original.entry != *entry || original.path != original_path {
                    return Err(invalid());
                }
                Quarantined::move_file(
                    original.held,
                    original.entry,
                    &original_path,
                    owner_path,
                    owner,
                    component,
                    source_parent,
                    action,
                )?
            }
            EntryKind::Directory => {
                let original = self.directories.remove(&entry.path).ok_or_else(invalid)?;
                if original.entry != *entry || original.path != original_path {
                    return Err(invalid());
                }
                Quarantined::move_directory(
                    original.held,
                    original.entry,
                    &original_path,
                    owner_path,
                    owner,
                    component,
                    source_parent,
                    action,
                )?
            }
        };
        self.quarantine.insert(action, (component.into(), held));
        Ok(evidence)
    }
    pub(super) fn verify(&self) -> Result<()> {
        let mut keys = BTreeSet::new();
        for original in self.files.values() {
            if !keys.insert(native(original.key))
                || original.held.key()? != original.key
                || !original.held.matches_path(&original.path)?
            {
                return Err(invalid());
            }
            verify_content(original.held.reader(), &original.entry)?;
        }
        for original in self.directories.values() {
            original.held.require_case_insensitive()?;
            if !keys.insert(native(original.key))
                || original.held.key()? != original.key
                || !original.held.matches_path(&original.path)?
            {
                return Err(invalid());
            }
        }
        for original in self.created_directories.values() {
            original.verify()?;
            if !keys.insert(native(original.key())) {
                return Err(invalid());
            }
        }
        for original in self.created_files.values() {
            original.verify()?;
            if !keys.insert(native(original.key())) {
                return Err(invalid());
            }
        }
        for (_, original) in self.quarantine.values() {
            original.verify()?;
            if !keys.insert(native(original.key())) {
                return Err(invalid());
            }
        }
        Ok(())
    }
    pub(super) fn disposal_intent(
        &self,
        action: usize,
        quarantine_action: usize,
        owner: FileKey,
    ) -> Result<super::receipt_protocol::ReceiptEvidence> {
        let (component, original) = self
            .quarantine
            .get(&quarantine_action)
            .ok_or_else(invalid)?;
        original.verify()?;
        Ok(super::receipt_protocol::ReceiptEvidence::Disposal {
            action,
            quarantine_action,
            original: native(original.key()),
            parent: native(owner),
            component: component.clone(),
        })
    }
    pub(super) fn dispose_original(
        &mut self,
        action: usize,
        quarantine_action: usize,
    ) -> Result<()> {
        let (_, original) = self
            .quarantine
            .remove(&quarantine_action)
            .ok_or_else(invalid)?;
        let path = original.entry().path.clone();
        let key = native(original.key());
        original.dispose(action)?;
        if self
            .disposed
            .insert(path, (quarantine_action, key))
            .is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) fn release_published_owner_parents(&mut self) -> Result<()> {
        if !self.quarantine.is_empty() {
            return Err(invalid());
        }
        for file in self.created_files.values_mut() {
            file.release_owner_parent()?;
        }
        self.verify()
    }
    pub(super) fn owner_members(&self, marker: bool) -> BTreeSet<std::ffi::OsString> {
        self.quarantine
            .values()
            .map(|(component, _)| std::ffi::OsString::from(component))
            .chain(
                self.created_files
                    .values()
                    .filter(|file| !file.published())
                    .filter_map(|file| file.path().file_name().map(|name| name.to_owned())),
            )
            .chain(marker.then(|| std::ffi::OsString::from("owner-marker")))
            .collect()
    }
    pub(super) fn observe_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        self.verify()?;
        let reader = self
            .files
            .values()
            .find(|original| original.path == path)
            .map(|original| original.held.reader())
            .or_else(|| {
                self.quarantine
                    .values()
                    .find(|(_, original)| original.path() == path)
                    .and_then(|(_, original)| original.reader())
            });
        let reader = if let Some(reader) = reader {
            Some(reader)
        } else {
            self.created_files
                .values()
                .find(|file| file.path() == path)
                .map(|file| file.reader())
                .transpose()?
        };
        let Some(reader) = reader else {
            return Ok(None);
        };
        if !sync_extend_platform_fs::regular_file_matches_path(reader, path)? {
            return Err(invalid());
        }
        let key = FileKey::from_file(reader)?;
        Ok(Some(crate::NativePublicationFileObservation {
            metadata: reader.metadata()?,
            portable: None,
            physical_identity: ContentId::hash(
                format!("windows:{}:{}", key.volume, key.id).as_bytes(),
            ),
            content: None,
        }))
    }
    /// The private owner checks its actual members; this verifies every user path.
    /// This is the live actual effect state, including result-before-commit windows.
    pub(super) fn verify_namespace(
        &self,
        root: &Path,
        baseline: &Manifest,
        maximum: usize,
    ) -> Result<()> {
        self.verify()?;
        let mut expected: BTreeMap<_, _> = baseline
            .entries
            .values()
            .map(|entry| (entry.path.clone(), entry.kind))
            .collect();
        for (_, original) in self.quarantine.values() {
            expected.remove(&original.entry().path);
        }
        for path in self.disposed.keys() {
            expected.remove(path);
        }
        for created in self.created_directories.values() {
            expected.insert(created.entry.path.clone(), created.entry.kind);
        }
        for file in self.created_files.values().filter(|file| file.published()) {
            expected.insert(file.entry.path.clone(), file.entry.kind);
        }
        if maximum == 0 || expected.len() > maximum {
            return Err(invalid());
        }
        let mut pending = vec![root.to_owned()];
        let mut found = BTreeMap::new();
        let mut collisions = BTreeSet::new();
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(invalid)?;
                if directory == root && matches!(name, ".sync-extend" | ".sync-tmp") {
                    continue;
                }
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink()
                    || metadata.file_attributes() & 0x400 != 0
                    || found.len() >= maximum
                {
                    return Err(invalid());
                }
                let portable = PortablePath::new(
                    path.strip_prefix(root)?
                        .to_str()
                        .ok_or_else(invalid)?
                        .replace('\\', "/"),
                )?;
                if !collisions.insert(portable.collision_key()) {
                    return Err(invalid());
                }
                let kind = if metadata.is_dir() {
                    pending.push(path);
                    EntryKind::Directory
                } else if metadata.is_file() {
                    EntryKind::File
                } else {
                    return Err(invalid());
                };
                if found.insert(portable, kind).is_some() {
                    return Err(invalid());
                }
            }
        }
        if found != expected {
            return Err(invalid());
        }
        Ok(())
    }
}

fn verify_content(mut reader: &std::fs::File, entry: &Entry) -> Result<()> {
    let content = entry.content.as_ref().ok_or_else(invalid)?;
    if reader.metadata()?.len() != content.length {
        return Err(invalid());
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut whole = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    for chunk in &content.chunks {
        let mut remaining = u64::from(chunk.length);
        let mut part = blake3::Hasher::new();
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
