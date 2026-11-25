//! D02 source draft: exact original handles, with no public constructor or effect grant.
//! Requires real parent capture, durable binding and full ledger admission before use.
use super::initial_binding::{InitialBindingRole, InitialHeldBinding};
use std::os::windows::fs::MetadataExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{
    ContentId, Entry, EntryKind, PortablePath,
    tree_restore_identity::TreeNativeIdentity,
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
};
use sync_extend_platform_fs::{
    FileKey, GuardedReadFile, LockedDirectory, LockedDirectoryMutation, LockedFile,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// These bytes record an original capture. Deserialization never reconstructs a guard.
pub(super) struct PreparedInitialBindings {
    pub descriptions: Vec<InitialHeldBinding>,
    pub json: Vec<Vec<u8>>,
    pub hashes: Vec<ContentId>,
    pub complete_hash: ContentId,
}

pub(super) enum DirectoryGuard {
    Parent(LockedDirectory),
    Original(LockedDirectoryMutation),
}

impl DirectoryGuard {
    fn key(&self) -> std::io::Result<FileKey> {
        match self {
            Self::Parent(held) => held.key(),
            Self::Original(held) => held.key(),
        }
    }

    fn matches_path(&self, path: &Path) -> std::io::Result<bool> {
        match self {
            Self::Parent(held) => held.matches_path(path),
            Self::Original(held) => held.matches_path(path),
        }
    }

    fn verify(&self) -> std::io::Result<()> {
        match self {
            Self::Parent(held) => held.require_case_insensitive(),
            Self::Original(held) => held.require_case_insensitive(),
        }
    }
}

struct Directory {
    path: PathBuf,
    key: FileKey,
    held: DirectoryGuard,
}

struct Original {
    entry: Entry,
    path: PathBuf,
    key: FileKey,
    held: LockedFile,
}

struct CasOriginal {
    path: PathBuf,
    key: FileKey,
    content_id: ContentId,
    length: u64,
    held: GuardedReadFile,
}

fn verify_cas(original: &CasOriginal) -> Result<()> {
    original.held.verify_single_link()?;
    if original.held.key()? != original.key
        || !sync_extend_platform_fs::regular_file_matches_path(
            original.held.reader(),
            &original.path,
        )?
        || original.held.reader().metadata()?.len() != original.length
    {
        return Err("retained exact original DAV CAS identity or length changed".into());
    }
    let mut reader = original.held.reader();
    reader.seek(SeekFrom::Start(0))?;
    let mut digest = blake3::Hasher::new();
    let mut remaining = original.length;
    let mut buffer = [0_u8; 65536];
    while remaining != 0 {
        let count = usize::try_from(remaining.min(buffer.len() as u64))?;
        reader.read_exact(&mut buffer[..count])?;
        digest.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if reader.read(&mut buffer[..1])? != 0 || ContentId::from_hasher(&digest) != original.content_id
    {
        return Err("retained exact original DAV CAS content differs".into());
    }
    Ok(())
}

/// Ownership remains in live handles. A report/hash cannot reconstruct this object.
pub(super) struct RetainedDavBaseline {
    root: PathBuf,
    data: PathBuf,
    plan: WebDavNativePlan,
    space_id: sync_extend_core_model::SpaceId,
    max_entries: usize,
    directories: Vec<Directory>,
    originals: BTreeMap<PortablePath, Original>,
    cas_originals: BTreeMap<ContentId, CasOriginal>,
    marker_path: PathBuf,
    marker_key: FileKey,
    marker: GuardedReadFile,
}

fn native(key: FileKey) -> TreeNativeIdentity {
    TreeNativeIdentity {
        volume_serial: key.volume,
        file_id: format!("{:032x}", key.id),
    }
}

fn namespace(
    root: &Path,
    baseline: &sync_extend_core_model::Manifest,
    maximum: usize,
    owner: Option<&super::native_owner::InitialNativeOwner>,
) -> Result<()> {
    let expected: BTreeMap<_, _> = baseline
        .entries
        .values()
        .map(|entry| (entry.path.clone(), entry.kind))
        .collect();
    if maximum == 0 || expected.len() > maximum {
        return Err("bounded DAV namespace entries required".into());
    }
    let mut pending = vec![root.to_owned()];
    let mut found = BTreeMap::new();
    let mut collisions = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)?;
        if metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0 {
            return Err("DAV namespace directory reparse".into());
        }
        for child in fs::read_dir(&directory)? {
            let child = child?;
            let path = child.path();
            let name = child.file_name();
            let name = name.to_str().ok_or("non-UTF8 DAV namespace component")?;
            // Only the exact original root marker is excluded. A reserved
            // spelling elsewhere or unknown staging/.git occupant is refused.
            if directory == root && name == ".sync-extend" {
                continue;
            }
            if directory == root && name == ".sync-tmp" {
                match owner {
                    Some(owner) => {
                        owner.verify()?;
                        continue;
                    }
                    None => return Err("unknown original DAV staging occupant".into()),
                }
            }
            if found.len() >= maximum {
                return Err("DAV namespace entry limit".into());
            }
            let relative = path.strip_prefix(root)?;
            let portable = PortablePath::new(
                relative
                    .iter()
                    .map(|part| part.to_str().ok_or("non-UTF8 DAV namespace component"))
                    .collect::<std::result::Result<Vec<_>, _>>()?
                    .join("/"),
            )?;
            if !collisions.insert(portable.collision_key()) {
                return Err("DAV namespace case collision".into());
            }
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0 {
                return Err("DAV namespace link/reparse".into());
            }
            let kind = if metadata.is_dir() {
                EntryKind::Directory
            } else if metadata.is_file() {
                EntryKind::File
            } else {
                return Err("DAV namespace special file".into());
            };
            if expected.get(&portable) != Some(&kind) || found.insert(portable, kind).is_some() {
                return Err("DAV namespace foreign entry or duplicate".into());
            }
            if kind == EntryKind::Directory {
                pending.push(path);
            }
        }
    }
    if found != expected {
        return Err("DAV namespace original member missing".into());
    }
    Ok(())
}

fn verified_content(original: &Original) -> Result<()> {
    sync_extend_platform_fs::verify_regular_file(original.held.reader())?;
    let expected = original
        .entry
        .content
        .as_ref()
        .ok_or("original DAV file content missing")?;
    if original.held.reader().metadata()?.len() != expected.length {
        return Err("original DAV file length changed".into());
    }
    let mut reader = original.held.reader();
    reader.seek(SeekFrom::Start(0))?;
    let mut whole = blake3::Hasher::new();
    let mut buffer = [0_u8; 65536];
    for chunk in &expected.chunks {
        let mut left = u64::from(chunk.length);
        let mut part = blake3::Hasher::new();
        while left != 0 {
            let count = usize::try_from(left.min(buffer.len() as u64))?;
            reader.read_exact(&mut buffer[..count])?;
            whole.update(&buffer[..count]);
            part.update(&buffer[..count]);
            left -= count as u64;
        }
        if ContentId::from_hasher(&part) != chunk.content_id {
            return Err("original DAV file chunk changed".into());
        }
    }
    if reader.read(&mut buffer[..1])? != 0 || ContentId::from_hasher(&whole) != expected.content_id
    {
        return Err("original DAV file content changed".into());
    }
    Ok(())
}

impl RetainedDavBaseline {
    pub(super) fn observe_original_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        let ordinary = |path: &Path| {
            path.to_str()
                .and_then(|value| value.strip_prefix(r"\\?\"))
                .map(Path::new)
                .unwrap_or(path)
                .to_owned()
        };
        let file = if ordinary(path) == ordinary(&self.marker_path) {
            Some(self.marker.reader())
        } else {
            self.originals
                .values()
                .find(|original| ordinary(path) == ordinary(&original.path))
                .map(|original| original.held.reader())
        };
        let Some(file) = file else {
            return Ok(None);
        };
        if !sync_extend_platform_fs::regular_file_matches_path(file, path)? {
            return Err("DAV held file view original slot differs".into());
        }
        let key = FileKey::from_file(file)?;
        Ok(Some(crate::NativePublicationFileObservation {
            metadata: file.metadata()?,
            physical_identity: ContentId::hash(
                format!("windows:{}:{}", key.volume, key.id).as_bytes(),
            ),
            content: None,
        }))
    }
    pub(super) fn data_parent(&self) -> Result<&LockedDirectory> {
        let directory = self
            .directories
            .iter()
            .find(|directory| directory.path == self.data)
            .ok_or("original held data root absent")?;
        match &directory.held {
            DirectoryGuard::Parent(held) => Ok(held),
            _ => Err("original data root must be parent guard".into()),
        }
    }
    pub(super) fn root_parent(&self) -> Result<&LockedDirectory> {
        let directory = self
            .directories
            .iter()
            .find(|directory| directory.path == self.root)
            .ok_or("original DAV root absent")?;
        match &directory.held {
            DirectoryGuard::Parent(held) => Ok(held),
            _ => Err("original DAV root must be parent guard".into()),
        }
    }

    pub(super) fn verify_with_owner(
        &self,
        baseline: &sync_extend_core_model::Manifest,
        owner: &super::native_owner::InitialNativeOwner,
    ) -> Result<()> {
        owner.verify()?;
        self.verify_originals(true)?;
        namespace(&self.root, baseline, self.max_entries, Some(owner))
    }

    pub(super) fn verify_collection(
        &self,
        baseline: &sync_extend_core_model::Manifest,
        owner: &super::native_owner::InitialNativeOwner,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<()> {
        self.verify_originals(false)?;
        owner.verify_with_collections(collections)?;
        collections.verify_namespace(&self.root, baseline, self.max_entries)?;
        Ok(())
    }
    pub(super) fn verify_initial(&self, baseline: &sync_extend_core_model::Manifest) -> Result<()> {
        self.verify_originals(true)?;
        namespace(&self.root, baseline, self.max_entries, None)
    }
    pub(super) fn collection_cas_chunks(
        &self,
    ) -> Result<BTreeMap<ContentId, (&GuardedReadFile, u64)>> {
        let mut result = BTreeMap::new();
        for (id, original) in &self.cas_originals {
            verify_cas(original)?;
            result.insert(id.clone(), (&original.held, original.length));
        }
        Ok(result)
    }
    pub(super) fn collection_existing_parent(
        &self,
        path: Option<&PortablePath>,
    ) -> Result<Option<&LockedDirectory>> {
        let target = path
            .map(|path| self.root.join(path.as_str()))
            .unwrap_or_else(|| self.root.clone());
        let Some(directory) = self.directories.iter().find(|held| held.path == target) else {
            return Ok(None);
        };
        if directory.held.key()? != directory.key || !directory.held.matches_path(&target)? {
            return Err("original collection parent identity or slot changed".into());
        }
        match &directory.held {
            DirectoryGuard::Parent(held) => Ok(Some(held)),
            _ => Err("collection parent not transferred to exact private registry".into()),
        }
    }
    pub(super) fn take_collection_originals(
        &mut self,
    ) -> Result<super::held_collections::HeldCollections> {
        let files = std::mem::take(&mut self.originals);
        let mut retained = Vec::new();
        let mut mutation = Vec::new();
        for directory in self.directories.drain(..) {
            if matches!(&directory.held, DirectoryGuard::Original(_)) {
                mutation.push(directory);
            } else {
                retained.push(directory);
            }
        }
        self.directories = retained;
        let mut collections = super::held_collections::HeldCollections::new();
        for (_, original) in files {
            collections.insert_original_file(
                original.entry,
                original.path,
                original.key,
                original.held,
            )?;
        }
        for directory in mutation {
            let relative = directory.path.strip_prefix(&self.root)?;
            let portable = PortablePath::new(
                relative
                    .to_str()
                    .ok_or("non UTF8 original collection directory")?
                    .replace('\\', "/"),
            )?;
            let entry = self
                .plan
                .inventory()
                .entries
                .get(&portable)
                .and_then(|native| {
                    self.plan
                        .steps()
                        .iter()
                        .find_map(|step| match &step.action {
                            WebDavNativeAction::QuarantineOriginal { entry, .. }
                                if entry.entry_id == native.entry_id =>
                            {
                                Some(entry.clone())
                            }
                            _ => None,
                        })
                })
                .ok_or("original mutation directory absent from original plan")?;
            let DirectoryGuard::Original(held) = directory.held else {
                unreachable!()
            };
            collections.insert_original_directory(entry, directory.path, directory.key, held)?;
        }
        Ok(collections)
    }
    pub(super) fn retained_handle_count(&self) -> Result<usize> {
        self.directories
            .len()
            .checked_add(self.originals.len())
            .and_then(|count| count.checked_add(self.cas_originals.len()))
            .and_then(|count| count.checked_add(1))
            .ok_or("original DAV retained handle count overflow".into())
    }
    pub(super) fn plan(&self) -> &WebDavNativePlan {
        &self.plan
    }

    pub(super) fn description(
        &self,
        request: &sync_extend_core_model::webdav_mutation::WebDavMutationRequest,
        limits: sync_extend_core_model::webdav_native::WebDavNativeLimits,
    ) -> Result<crate::WebDavNativeDescription> {
        let description = crate::WebDavNativeDescription {
            request: request.clone(),
            inventory: self.plan.inventory().clone(),
            limits,
        };
        if description.inventory.request_hash
            != ContentId::hash(
                &sync_extend_core_model::tree_restore_history::encode_history_record(
                    request,
                    request.max_metadata_bytes,
                )?,
            )
        {
            return Err("first-capture original request changed".into());
        }
        Ok(description)
    }

    /// Borrow live first-capture handles without releasing or reopening any object.
    /// Must be persisted in the same private owned admission snapshot as full budget.
    pub(super) fn initial_bindings(
        &self,
        baseline: &sync_extend_core_model::Manifest,
        max_binding_json: u64,
        max_total_binding_json: u64,
    ) -> Result<PreparedInitialBindings> {
        self.verify_initial(baseline)?;
        let ceiling = sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES;
        if max_binding_json == 0
            || max_binding_json > ceiling
            || max_total_binding_json == 0
            || max_total_binding_json > ceiling
        {
            return Err("bounded exact initial DAV binding bytes required".into());
        }
        let baseline_hash = baseline.root()?;
        let marker_directory = self.marker_path.parent().ok_or("marker parent absent")?;
        let parent = |path: &Path| -> Result<Option<TreeNativeIdentity>> {
            match path.parent() {
                None => Ok(None),
                Some(parent) => self
                    .directories
                    .iter()
                    .find(|directory| directory.path == parent)
                    .map(|directory| Some(native(directory.key)))
                    .ok_or_else(|| "initial binding lacks held exact parent".into()),
            }
        };
        let mut descriptions = Vec::new();
        let mut paths = BTreeSet::new();
        let mut append = |path: &Path, key: FileKey, role: InitialBindingRole| -> Result<()> {
            if descriptions.len() >= self.max_entries || !paths.insert(path.to_owned()) {
                return Err("duplicate or excessive initial held DAV binding".into());
            }
            let absolute_path = path.to_str().ok_or("non-UTF8 original DAV binding path")?;
            let identity = native(key);
            identity.validate()?;
            descriptions.push(InitialHeldBinding {
                index: descriptions.len(),
                plan_hash: self.plan.fingerprint().clone(),
                baseline_hash: baseline_hash.clone(),
                role,
                absolute_path: absolute_path.to_owned(),
                identity,
                parent_identity: parent(path)?,
            });
            Ok(())
        };
        for directory in &self.directories {
            let role = if directory.path == self.data {
                InitialBindingRole::DataRoot
            } else if directory.path == self.root {
                InitialBindingRole::WorktreeRoot
            } else if directory.path == marker_directory {
                InitialBindingRole::MarkerDirectory
            } else if let Some(entry) = baseline.entries.values().find(|entry| {
                entry.kind == EntryKind::Directory
                    && self.root.join(entry.path.as_str()) == directory.path
            }) {
                InitialBindingRole::BaselineDirectory {
                    entry: entry.clone(),
                    mutation_handle: matches!(&directory.held, DirectoryGuard::Original(_)),
                }
            } else if self.root.starts_with(&directory.path) {
                InitialBindingRole::WorktreeAncestor
            } else if self.data.starts_with(&directory.path) {
                InitialBindingRole::DataAncestor
            } else if self
                .cas_originals
                .values()
                .any(|chunk| chunk.path.starts_with(&directory.path))
            {
                InitialBindingRole::CasAncestor
            } else {
                return Err("unknown original held DAV directory role".into());
            };
            append(&directory.path, directory.key, role)?;
        }
        append(
            &self.marker_path,
            self.marker_key,
            InitialBindingRole::MarkerFile {
                space_id: baseline.space_id.clone(),
            },
        )?;
        for original in self.originals.values() {
            append(
                &original.path,
                original.key,
                InitialBindingRole::BaselineFile {
                    entry: original.entry.clone(),
                },
            )?;
        }
        for original in self.cas_originals.values() {
            append(
                &original.path,
                original.key,
                InitialBindingRole::CasChunk {
                    content_id: original.content_id.clone(),
                    length: original.length,
                },
            )?;
        }
        let mut total = 0_u64;
        let mut json = Vec::new();
        let mut hashes = Vec::new();
        for binding in &descriptions {
            let bytes = sync_extend_core_model::tree_restore_history::encode_history_record(
                binding,
                max_binding_json,
            )?;
            total = total
                .checked_add(bytes.len() as u64)
                .filter(|value| *value <= max_total_binding_json)
                .ok_or("initial DAV binding total byte limit")?;
            hashes.push(ContentId::hash(&bytes));
            json.push(bytes);
        }
        let complete_hash = ContentId::hash(
            &sync_extend_core_model::tree_restore_history::encode_history_record(
                &(self.plan.fingerprint(), baseline_hash, &hashes),
                max_total_binding_json,
            )?,
        );
        Ok(PreparedInitialBindings {
            descriptions,
            json,
            hashes,
            complete_hash,
        })
    }

    /// Called only under actual LocalSpace process lock/CAS exclusion and exact
    /// owned Journal transaction. This constructor itself persists no binding.
    pub(super) fn capture(
        root: &Path,
        data: &Path,
        request: &sync_extend_core_model::webdav_mutation::WebDavMutationRequest,
        limits: sync_extend_core_model::webdav_native::WebDavNativeLimits,
        baseline: &sync_extend_core_model::Manifest,
        max_handles: usize,
    ) -> Result<Self> {
        if !root.is_absolute()
            || !data.is_absolute()
            || root.starts_with(data)
            || data.starts_with(root)
            || baseline.root()? != request.baseline
            || baseline.entries.len() > max_handles
            || max_handles == 0
        {
            return Err("exact original DAV baseline scope required".into());
        }
        let logical =
            sync_extend_core_model::webdav_mutation::plan_webdav_mutation(baseline, request)?;
        let quarantine: BTreeSet<_> = logical
            .retained_originals()
            .iter()
            .filter(|entry| {
                entry.kind == EntryKind::Directory
                    && match &request.mutation {
                        sync_extend_core_model::webdav_mutation::WebDavMutation::Copy {
                            destination,
                            ..
                        } => {
                            entry.path == *destination
                                || entry
                                    .path
                                    .as_str()
                                    .strip_prefix(destination.as_str())
                                    .is_some_and(|tail| tail.starts_with('/'))
                        }
                        sync_extend_core_model::webdav_mutation::WebDavMutation::Mkcol {
                            ..
                        } => false,
                        _ => true,
                    }
            })
            .map(|entry| entry.path.clone())
            .collect();
        let mut inventory_entries = BTreeMap::new();
        let mut directories = Vec::new();
        let mut ancestors: Vec<_> = root.ancestors().collect();
        ancestors.reverse();
        for path in ancestors {
            if directories.len() >= max_handles {
                return Err("DAV native ancestor handle limit".into());
            }
            let held = LockedDirectory::open(path)?;
            held.require_local_ntfs(path)?;
            held.require_case_insensitive()?;
            let key = held.key()?;
            directories.push(Directory {
                path: path.into(),
                key,
                held: DirectoryGuard::Parent(held),
            });
        }
        for path in data.ancestors().collect::<Vec<_>>().into_iter().rev() {
            if directories.iter().any(|directory| directory.path == path) {
                continue;
            }
            if directories
                .len()
                .checked_add(2)
                .is_none_or(|count| count > max_handles)
            {
                return Err("DAV complete data ancestor handle limit".into());
            }
            let held = LockedDirectory::open(path)?;
            held.require_local_ntfs(path)?;
            held.require_case_insensitive()?;
            let key = held.key()?;
            directories.push(Directory {
                path: path.into(),
                key,
                held: DirectoryGuard::Parent(held),
            });
        }
        let marker_directory = root.join(".sync-extend");
        let held = LockedDirectory::open(&marker_directory)?;
        held.require_local_ntfs(&marker_directory)?;
        held.require_case_insensitive()?;
        let key = held.key()?;
        let marker_directory_key = key;
        directories.push(Directory {
            path: marker_directory,
            key,
            held: DirectoryGuard::Parent(held),
        });
        let marker_path = root.join(".sync-extend/space-id");
        let marker = GuardedReadFile::open(&marker_path)?;
        let marker_key = marker.key()?;
        let mut originals = BTreeMap::new();
        let mut ordered: Vec<_> = baseline.entries.values().collect();
        ordered.sort_by_key(|entry| (entry.kind != EntryKind::Directory, entry.path.clone()));
        for entry in ordered {
            if directories
                .len()
                .checked_add(originals.len())
                .and_then(|count| count.checked_add(2))
                .is_none_or(|count| count > max_handles)
            {
                return Err("DAV native original handle limit".into());
            }
            let path = root.join(entry.path.as_str());
            match entry.kind {
                EntryKind::Directory => {
                    let held = if quarantine.contains(&entry.path) {
                        DirectoryGuard::Original(LockedDirectoryMutation::open(&path)?)
                    } else {
                        let guard = LockedDirectory::open(&path)?;
                        guard.require_local_ntfs(&path)?;
                        guard.require_case_insensitive()?;
                        DirectoryGuard::Parent(guard)
                    };
                    let key = held.key()?;
                    inventory_entries.insert(
                        entry.path.clone(),
                        sync_extend_core_model::tree_restore_identity::TreeNativeEntry {
                            entry_id: entry.entry_id.clone(),
                            kind: entry.kind,
                            identity: native(key),
                        },
                    );
                    directories.push(Directory { path, key, held });
                }
                EntryKind::File => {
                    let held = LockedFile::open(&path)?;
                    let key = held.key()?;
                    inventory_entries.insert(
                        entry.path.clone(),
                        sync_extend_core_model::tree_restore_identity::TreeNativeEntry {
                            entry_id: entry.entry_id.clone(),
                            kind: entry.kind,
                            identity: native(key),
                        },
                    );
                    let original = Original {
                        entry: entry.clone(),
                        path,
                        key,
                        held,
                    };
                    verified_content(&original)?;
                    originals.insert(entry.path.clone(), original);
                }
            }
        }
        let root_key = directories
            .iter()
            .find(|directory| directory.path == root)
            .ok_or("original held root absent")?
            .key;
        let inventory = sync_extend_core_model::webdav_native::WebDavNativeInventory {
            request_hash: ContentId::hash(
                &sync_extend_core_model::tree_restore_history::encode_history_record(
                    request,
                    request.max_metadata_bytes,
                )?,
            ),
            root: native(root_key),
            marker_directory: native(marker_directory_key),
            marker_file: native(marker_key),
            entries: inventory_entries,
        };
        let plan = sync_extend_core_model::webdav_native::plan_webdav_native(
            baseline, request, &inventory, limits,
        )?;
        let mut chunks = BTreeMap::new();
        for chunk in baseline
            .entries
            .values()
            .chain(plan.final_manifest().entries.values())
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| &content.chunks)
        {
            if chunks
                .insert(chunk.content_id.clone(), u64::from(chunk.length))
                .is_some_and(|old| old != u64::from(chunk.length))
            {
                return Err("DAV original/final CAS chunk length conflict".into());
            }
        }
        let mut cas_originals = BTreeMap::new();
        for (content_id, length) in chunks {
            let path = data
                .join("cas/objects")
                .join(&content_id.as_str()[..2])
                .join(content_id.as_str());
            let mut chain: Vec<_> = path
                .parent()
                .ok_or("DAV CAS parent absent")?
                .ancestors()
                .collect();
            chain.reverse();
            for parent in chain {
                if directories.iter().any(|held| held.path == parent) {
                    continue;
                }
                if directories
                    .len()
                    .checked_add(originals.len())
                    .and_then(|count| count.checked_add(cas_originals.len()))
                    .and_then(|count| count.checked_add(2))
                    .is_none_or(|count| count > max_handles)
                {
                    return Err("DAV native CAS ancestor handle limit".into());
                }
                let held = LockedDirectory::open(parent)?;
                held.require_local_ntfs(parent)?;
                held.require_case_insensitive()?;
                let key = held.key()?;
                directories.push(Directory {
                    path: parent.into(),
                    key,
                    held: DirectoryGuard::Parent(held),
                });
            }
            if directories
                .len()
                .checked_add(originals.len())
                .and_then(|count| count.checked_add(cas_originals.len()))
                .and_then(|count| count.checked_add(2))
                .is_none_or(|count| count > max_handles)
            {
                return Err("DAV native original CAS handle limit".into());
            }
            let held = GuardedReadFile::open(&path)?;
            let key = held.key()?;
            let original = CasOriginal {
                path,
                key,
                content_id: content_id.clone(),
                length,
                held,
            };
            verify_cas(&original)?;
            cas_originals.insert(content_id, original);
        }
        let result = Self {
            root: root.into(),
            data: data.into(),
            space_id: baseline.space_id.clone(),
            plan,
            max_entries: max_handles,
            directories,
            originals,
            cas_originals,
            marker_path,
            marker_key,
            marker,
        };
        result.verify_initial(baseline)?;
        Ok(result)
    }

    fn verify_originals(&self, initial: bool) -> Result<()> {
        if self
            .directories
            .len()
            .checked_add(self.originals.len())
            .and_then(|count| count.checked_add(self.cas_originals.len()))
            .and_then(|count| count.checked_add(1))
            .is_none_or(|count| count > self.max_entries)
        {
            return Err("DAV complete initial held handle limit".into());
        }
        for directory in &self.directories {
            directory.held.verify()?;
            if directory.held.key()? != directory.key
                || !directory.held.matches_path(&directory.path)?
            {
                return Err("retained DAV directory key or slot changed".into());
            }
        }
        let marker_dir = self.marker_path.parent().ok_or("marker directory absent")?;
        let names: BTreeSet<_> = fs::read_dir(marker_dir)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<_>>()?;
        if names
            != BTreeSet::from([
                std::ffi::OsString::from("space-id"),
                std::ffi::OsString::from("writer.lock"),
            ])
        {
            return Err("foreign original DAV marker directory member".into());
        }
        self.marker.verify_single_link()?;
        if self.marker.key()? != self.marker_key
            || !sync_extend_platform_fs::regular_file_matches_path(
                self.marker.reader(),
                &self.marker_path,
            )?
        {
            return Err("retained DAV marker changed".into());
        }
        let mut reader = self.marker.reader();
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader.take(33).read_to_end(&mut bytes)?;
        if bytes != self.space_id.as_str().as_bytes() {
            return Err("retained DAV marker scope differs".into());
        }
        for original in self.originals.values() {
            if original.held.key()? != original.key
                || !original.held.matches_path(&original.path)?
            {
                return Err("retained original DAV file key or slot changed".into());
            }
            verified_content(original)?;
        }
        for step in self.plan.steps().iter().filter(|_| initial) {
            if matches!(
                step.slot,
                Some(sync_extend_core_model::webdav_native::WebDavNativeSlot::InitiallyAbsent)
            ) {
                let entry = match &step.action {
                    WebDavNativeAction::CreateDirectory { entry }
                    | WebDavNativeAction::PublishFile { entry } => entry,
                    _ => return Err("DAV absent slot/action mismatch".into()),
                };
                match fs::symlink_metadata(self.root.join(entry.path.as_str())) {
                    Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => {}
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err("original DAV absent destination occupied".into()),
                }
            }
        }
        for original in self.cas_originals.values() {
            verify_cas(original)?;
        }

        Ok(())
    }
}
