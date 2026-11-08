//! Held complete baseline only; no durable native admission or execution grant.
use super::*;
mod admission;
use crate::NativePublicationFileObservation;
pub use admission::{
    ConflictNativeAdmission, ConflictNativeAdmissionLimits, ConflictNativeAdmissionReport,
};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use sync_extend_core_model::conflict_native_layout::{
    plan_conflict_native_layout, ConflictNativeLayout, ConflictNativeLayoutLimits,
};
use sync_extend_platform_fs::{FileKey, GuardedReadFile, LockedDirectory, LockedFile};

struct Directory {
    path: PathBuf,
    key: FileKey,
    held: LockedDirectory,
}
struct Original {
    entry: sync_extend_core_model::Entry,
    path: PathBuf,
    key: FileKey,
    held: LockedFile,
}

/// Read-only description of retained handles, not a serializable native token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConflictNativeBaselineReport {
    pub transaction_id: EntryId,
    pub admission_header_hash: ContentId,
    pub layout_fingerprint: ContentId,
    pub root_identity: ContentId,
    pub original_files: usize,
    pub originals_verified: bool,
    pub native_admission_persisted: bool,
    pub original_keys_persisted: bool,
    pub execution_authorized: bool,
    pub worktree_materialized: bool,
    pub cas_content_closed: bool,
}

/// All original files and ancestors remain held. No public constructor, Clone,
/// serialization, writer, rename, creator or disposition capability is exposed.
pub struct ConflictNativeBaseline {
    header: Header,
    layout: ConflictNativeLayout,
    directories: Vec<Directory>,
    marker: Directory,
    marker_file: GuardedReadFile,
    base: Option<Directory>,
    originals: BTreeMap<sync_extend_core_model::PortablePath, Original>,
    _cas: CasAccessGuard,
    bound: bool,
}

fn physical(key: FileKey) -> ContentId {
    ContentId::hash(key.to_string().as_bytes())
}
fn directory(path: &Path) -> Result<Directory> {
    let held = LockedDirectory::open(path)?;
    held.require_local_ntfs(path)?;
    held.require_case_insensitive()?;
    Ok(Directory {
        path: path.into(),
        key: held.key()?,
        held,
    })
}
fn verify_original(original: &Original) -> Result<()> {
    if original.held.key()? != original.key || !original.held.matches_path(&original.path)? {
        return Err(invalid(
            "conflict baseline original fullkey or path changed",
        ));
    }
    sync_extend_platform_fs::verify_regular_file(original.held.reader())?;
    let content = original.entry.content.as_ref().ok_or(invalid(
        "conflict baseline original content description missing",
    ))?;
    if original.held.reader().metadata()?.len() != content.length {
        return Err(invalid("conflict baseline original length changed"));
    }
    let mut reader = original.held.reader();
    reader.seek(SeekFrom::Start(0))?;
    let mut whole = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];
    for chunk in &content.chunks {
        let mut left = u64::from(chunk.length);
        let mut digest = blake3::Hasher::new();
        while left != 0 {
            let n = usize::try_from(left.min(buffer.len() as u64))
                .map_err(|_| invalid("conflict baseline chunk read width"))?;
            reader.read_exact(&mut buffer[..n])?;
            whole.update(&buffer[..n]);
            digest.update(&buffer[..n]);
            left -= n as u64;
        }
        if ContentId::from_hasher(&digest) != chunk.content_id {
            return Err(invalid("conflict baseline original chunk content changed"));
        }
    }
    if reader.read(&mut buffer[..1])? != 0 || ContentId::from_hasher(&whole) != content.content_id {
        return Err(invalid("conflict baseline original whole content changed"));
    }
    Ok(())
}
impl ConflictNativeBaseline {
    pub fn transaction_id(&self) -> &EntryId {
        &self.header.transaction_id
    }
    pub fn layout(&self) -> &ConflictNativeLayout {
        &self.layout
    }
    pub fn report(&self) -> Result<ConflictNativeBaselineReport> {
        self.verify_native()?;
        Ok(ConflictNativeBaselineReport {
            transaction_id: self.header.transaction_id.clone(),
            admission_header_hash: hash(&self.header)?,
            layout_fingerprint: self.layout.fingerprint()?,
            root_identity: physical(self.directories[0].key),
            original_files: self.originals.len(),
            originals_verified: true,
            native_admission_persisted: false,
            original_keys_persisted: self.bound,
            execution_authorized: false,
            worktree_materialized: false,
            cas_content_closed: false,
        })
    }
    pub fn verify_native(&self) -> Result<()> {
        self.marker_file.verify_single_link()?;
        let mut marker = self.marker_file.reader();
        marker.seek(SeekFrom::Start(0))?;
        let mut bytes = [0u8; 33];
        marker.read_exact(&mut bytes[..32])?;
        if marker.read(&mut bytes[32..])? != 0
            || &bytes[..32] != self.header.target.space_id.as_str().as_bytes()
        {
            return Err(invalid("conflict baseline original space marker changed"));
        }
        for selected in self
            .directories
            .iter()
            .chain(std::iter::once(&self.marker))
            .chain(self.base.iter())
        {
            selected.held.require_case_insensitive()?;
            let named = directory(&selected.path)?;
            if selected.held.key()? != selected.key || named.key != selected.key {
                return Err(invalid(
                    "conflict baseline retained ancestor or base changed",
                ));
            }
        }
        let root = &self.directories[0].path;
        let mut seen = BTreeSet::new();
        for child in fs::read_dir(root)? {
            let child = child?;
            let name = child
                .file_name()
                .to_str()
                .ok_or(invalid("conflict baseline root filename UTF8"))?
                .to_string();
            if name == ".sync-tmp" {
                if self.base.is_none() {
                    return Err(invalid("conflict baseline unexpected staging base"));
                }
                continue;
            }
            if name == ".sync-extend" {
                continue;
            }
            let path = sync_extend_core_model::PortablePath::new(name)?;
            let original = self
                .originals
                .get(&path)
                .ok_or(invalid("conflict baseline foreign root member"))?;
            if child.path() != original.path || !seen.insert(original.entry.entry_id.clone()) {
                return Err(invalid("conflict baseline root membership differs"));
            }
        }
        if seen.len() != self.originals.len() {
            return Err(invalid("conflict baseline original root member missing"));
        }
        for original in self.originals.values() {
            verify_original(original)?;
        }
        Ok(())
    }
    fn binding(&self) -> Result<super::native_binding::Binding> {
        let key = |key: FileKey| super::native_binding::Key {
            volume: format!("{:016x}", key.volume),
            id: format!("{:032x}", key.id),
        };
        Ok(super::native_binding::Binding {
            format: 1,
            transaction_id: self.header.transaction_id.clone(),
            parent_hash: hash(&self.header)?,
            ancestors: self
                .directories
                .iter()
                .map(|directory| {
                    Ok(super::native_binding::Directory {
                        path: directory
                            .path
                            .to_str()
                            .ok_or(invalid("conflict binding ancestor UTF8"))?
                            .into(),
                        key: key(directory.key),
                    })
                })
                .collect::<Result<_>>()?,
            marker_directory: key(self.marker.key),
            marker_file: key(self.marker_file.key()?),
            existing_base: self.base.as_ref().map(|base| key(base.key)),
            originals: self
                .originals
                .values()
                .map(|original| (original.entry.entry_id.clone(), key(original.key)))
                .collect(),
        })
    }
    /// Borrowed read-only observation; never a new path-open writer or creator.
    pub fn observe_file(&self, path: &Path) -> Result<Option<NativePublicationFileObservation>> {
        let canonical = fs::canonicalize(path).ok();
        let Some(original) = self.originals.values().find(|original| {
            original.path == path || canonical.as_deref() == Some(original.path.as_path())
        }) else {
            return Ok(None);
        };
        self.verify_native()?;
        if !original.held.matches_path(path)? {
            return Err(invalid(
                "conflict baseline borrowed slot is not original fullkey",
            ));
        }
        Ok(Some(NativePublicationFileObservation {
            metadata: original.held.reader().metadata()?,
            physical_identity: physical(original.key),
            content: original.entry.content.clone(),
        }))
    }
}

impl Journal {
    /// Acquire shared CAS first, then audit the admitted complete SQL snapshot
    /// and retain actual native keys before any future effect may be selected.
    pub fn hold_conflict_native_baseline(
        &self,
        transaction: &EntryId,
        limits: ConflictNativeLayoutLimits,
    ) -> Result<ConflictNativeBaseline> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict baseline refuses caller transaction"));
        }
        let cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let json: String = self.connection.query_row(
            "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
            [transaction.as_str()],
            |r| r.get(0),
        )?;
        let header: Header = serde_json::from_str(&json)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&header.intent.baseline.space_id, bounds)?;
        if !before.report.within_accounted_limits() {
            return Err(invalid("conflict baseline lowered Journal capacity"));
        }
        let plan = header.plan()?;
        bind(&self.connection, &header, &plan)?;
        let layout = plan_conflict_native_layout(&header.intent.baseline, &header.target, limits)?;
        let root = Path::new(&header.intent.worktree);
        if !root.is_absolute() {
            return Err(invalid("conflict baseline requires absolute native root"));
        }
        let directories: Vec<_> = root.ancestors().map(directory).collect::<Result<_>>()?;
        if physical(directories[0].key) != header.intent.root_identity {
            return Err(invalid(
                "conflict baseline descriptive root does not match actual key",
            ));
        }
        let base_path = root.join(".sync-tmp");
        let marker = directory(&root.join(".sync-extend"))?;
        let marker_file = GuardedReadFile::open(&root.join(".sync-extend/space-id"))?;
        let base = match fs::symlink_metadata(&base_path) {
            Ok(_) => Some(directory(&base_path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut originals = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for entry in header.intent.baseline.entries.values() {
            let path = root.join(entry.path.as_str());
            let held = LockedFile::open(&path)?;
            let key = held.key()?;
            if key.volume != directories[0].key.volume || !keys.insert((key.volume, key.id)) {
                return Err(invalid(
                    "conflict baseline original key volume or alias differs",
                ));
            }
            originals.insert(
                entry.path.clone(),
                Original {
                    entry: entry.clone(),
                    path,
                    key,
                    held,
                },
            );
        }
        for (_, content) in pins(&header)?.keys() {
            self.require_cas_access(content)?;
        }
        let mut selected = ConflictNativeBaseline {
            header,
            layout,
            directories,
            marker,
            marker_file,
            base,
            originals,
            _cas: cas,
            bound: false,
        };
        selected.verify_native()?;
        if let Some(binding) = super::native_binding::stored(&self.connection, &selected.header)? {
            if binding != selected.binding()? {
                return Err(invalid(
                    "conflict baseline original persisted fullkeys changed",
                ));
            }
            selected.bound = true;
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&selected.header.intent.baseline.space_id, bounds)?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid(
                "conflict baseline read changed actual Journal snapshot",
            ));
        }
        tx.commit()?;
        Ok(selected)
    }
    /// Persist only the Journal-opened original baseline keys. This reserves no
    /// future effects and grants no creator, Ready, Final or cleanup authority.
    pub fn bind_conflict_native_baseline(
        &self,
        mut selected: ConflictNativeBaseline,
    ) -> Result<ConflictNativeBaseline> {
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "conflict baseline binding refuses caller transaction",
            ));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let space = &selected.header.intent.baseline.space_id;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(space, bounds)?;
        let plan = selected.header.plan()?;
        bind(&self.connection, &selected.header, &plan)?;
        selected.verify_native()?;
        let binding = selected.binding()?;
        binding.validate(&selected.header)?;
        let mut expected = row_map(&before.rows);
        if let Some(stored) = super::native_binding::stored(&self.connection, &selected.header)? {
            if stored != binding {
                return Err(invalid("conflict baseline binding exact retry differs"));
            }
        } else {
            let json = serde_json::to_string(&binding)?;
            if json.len() > crate::MAX_OPERATION_BYTES {
                return Err(invalid("conflict baseline binding encoded budget"));
            }
            let values = vec![
                Value::Text(binding.transaction_id.to_string()),
                Value::Text(binding.parent_hash.to_string()),
                Value::Text(hash(&binding)?.to_string()),
                Value::Text(json),
            ];
            let (row, columns) = value_columns("native_bindings", &values)?;
            if expected.insert(row, columns).is_some() {
                return Err(invalid("conflict baseline binding row collision"));
            }
            let bytes: u64 = values
                .iter()
                .map(|v| match v {
                    Value::Text(s) => s.len() as u64,
                    _ => 8,
                })
                .sum();
            let total = before.report.accounted_total();
            if total
                .rows
                .checked_add(1)
                .is_none_or(|n| n > bounds.max_rows)
                || total
                    .logical_bytes
                    .checked_add(bytes)
                    .is_none_or(|n| n > bounds.max_logical_bytes)
            {
                return Err(invalid("conflict baseline binding prewrite exact capacity"));
            }
            let mut issued = vec![Value::Text("native_bindings".into())];
            issued.extend(values.clone());
            let _permit = self.conflict_resolution_issuance.permit(Some(issued))?;
            tx.execute(
                "INSERT INTO main.conflict_resolution_native_bindings VALUES(?1,?2,?3,?4)",
                rusqlite::params_from_iter(values),
            )?;
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(space, bounds)?;
        if row_map(&after.rows) != expected || !after.report.within_accounted_limits() {
            return Err(invalid(
                "conflict baseline binding exact allvalue receipt differs",
            ));
        }
        selected.verify_native()?;
        tx.commit()?;
        selected.bound = true;
        Ok(selected)
    }
}
