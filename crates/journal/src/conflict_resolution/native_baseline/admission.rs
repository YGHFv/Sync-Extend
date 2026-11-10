//! Private child of native_baseline: complete held future admission, no effects.
use super::super::native_ledger::{NativeHeader, Residue, ResidueDirectory, ResidueFile};
use super::super::native_ledger_storage;
use super::*;
mod cleanup;
mod creators;
mod disposition;
mod equivalent_history;
mod final_commit;
mod forward;
mod handoff;
pub use creators::{ConflictNativeCreation, ConflictNativeReadiness};
pub use forward::{ConflictNativeExecution, ConflictNativeObservation};

struct RetainedResidue {
    description: Residue,
    directories: Vec<Directory>,
    files: Vec<(ResidueFile, GuardedReadFile)>,
}

fn descriptive(key: FileKey) -> super::super::native_binding::Key {
    super::super::native_binding::Key {
        volume: format!("{:016x}", key.volume),
        id: format!("{:032x}", key.id),
    }
}

impl RetainedResidue {
    fn reopen(
        selected: &ConflictNativeBaseline,
        description: Residue,
        owned_base: Option<FileKey>,
        owner: Option<&Path>,
    ) -> Result<Self> {
        let directories = description
            .directories
            .iter()
            .map(|row| directory(Path::new(&row.path)))
            .collect::<Result<_>>()?;
        let files = description
            .files
            .iter()
            .map(|row| Ok((row.clone(), GuardedReadFile::open(Path::new(&row.path))?)))
            .collect::<Result<_>>()?;
        let retained = Self {
            description,
            directories,
            files,
        };
        retained.verify_scope(selected, owned_base, owner)?;
        Ok(retained)
    }
    fn open(selected: &ConflictNativeBaseline, maximum: usize) -> Result<Self> {
        if maximum == 0 || maximum > sync_extend_core_model::limits::MAX_ENTRIES {
            return Err(invalid("conflict future residue traversal limit"));
        }
        let mut description = Residue {
            directories: Vec::new(),
            files: Vec::new(),
            bytes: 0,
        };
        let mut directories = Vec::new();
        let mut files = Vec::new();
        if let Some(base) = &selected.base {
            let binding = selected.binding()?;
            let mut keys: BTreeSet<_> = binding
                .ancestors
                .iter()
                .map(|row| row.key.clone())
                .chain(binding.existing_base.iter().cloned())
                .chain(std::iter::once(binding.marker_directory))
                .chain(std::iter::once(binding.marker_file))
                .chain(binding.originals.into_values())
                .collect();
            let mut pending = vec![(base.path.clone(), 0usize)];
            while let Some((path, depth)) = pending.pop() {
                if depth > 128 {
                    return Err(invalid("conflict future borrowed residue depth limit"));
                }
                for child in fs::read_dir(path)? {
                    if description
                        .files
                        .len()
                        .saturating_add(description.directories.len())
                        >= maximum
                    {
                        return Err(invalid("conflict future borrowed residue entry limit"));
                    }
                    let child = child?;
                    let path = child.path();
                    let name = child
                        .file_name()
                        .to_str()
                        .ok_or(invalid("conflict future residue component UTF8"))?
                        .to_string();
                    if name.is_empty() || name.contains(['/', '\\']) {
                        return Err(invalid("conflict future residue component scope"));
                    }
                    let metadata = fs::symlink_metadata(&path)?;
                    if metadata.is_dir() {
                        let held = directory(&path)?;
                        let row = ResidueDirectory {
                            path: path
                                .to_str()
                                .ok_or(invalid("conflict future residue path UTF8"))?
                                .into(),
                            key: descriptive(held.key),
                        };
                        if row.key.volume != descriptive(base.key).volume
                            || !keys.insert(row.key.clone())
                        {
                            return Err(invalid("conflict future residue directory native alias"));
                        }
                        pending.push((path, depth + 1));
                        description.directories.push(row);
                        directories.push(held);
                    } else if metadata.is_file() {
                        let held = GuardedReadFile::open(&path)?;
                        let row = ResidueFile {
                            path: path
                                .to_str()
                                .ok_or(invalid("conflict future residue file path UTF8"))?
                                .into(),
                            key: descriptive(held.key()?),
                            length: held.reader().metadata()?.len(),
                        };
                        if row.key.volume != descriptive(base.key).volume
                            || !keys.insert(row.key.clone())
                            || row.length != metadata.len()
                        {
                            return Err(invalid("conflict future residue file alias or length"));
                        }
                        description.bytes = description
                            .bytes
                            .checked_add(row.length)
                            .ok_or(invalid("conflict future residue byte overflow"))?;
                        description.files.push(row.clone());
                        files.push((row, held));
                    } else {
                        return Err(invalid(
                            "conflict future unsupported borrowed residue member",
                        ));
                    }
                }
            }
        }
        description.directories.sort_by(|a, b| a.path.cmp(&b.path));
        description.files.sort_by(|a, b| a.path.cmp(&b.path));
        let retained = Self {
            description,
            directories,
            files,
        };
        retained.verify(selected)?;
        Ok(retained)
    }
    fn verify(&self, selected: &ConflictNativeBaseline) -> Result<()> {
        self.verify_scope(selected, None, None)
    }
    fn verify_scope(
        &self,
        selected: &ConflictNativeBaseline,
        owned_base: Option<FileKey>,
        owner: Option<&Path>,
    ) -> Result<()> {
        selected.verify_native_scope(owned_base)?;
        self.verify_borrowed_scope(selected, owned_base, owner)
    }
    fn verify_borrowed_scope(
        &self,
        selected: &ConflictNativeBaseline,
        owned_base: Option<FileKey>,
        owner: Option<&Path>,
    ) -> Result<()> {
        let mut expected: BTreeMap<PathBuf, BTreeSet<PathBuf>> = BTreeMap::new();
        if let Some(base) = &selected.base {
            expected.insert(base.path.clone(), BTreeSet::new());
        }
        if owned_base.is_some() {
            expected
                .entry(selected.directories[0].path.join(".sync-tmp"))
                .or_default();
        }
        for directory in &self.directories {
            let observed = super::directory(&directory.path)?;
            if observed.key != directory.key || directory.held.key()? != directory.key {
                return Err(invalid(
                    "conflict future original borrowed directory changed",
                ));
            }
            expected.insert(directory.path.clone(), BTreeSet::new());
        }
        for path in self
            .directories
            .iter()
            .map(|row| row.path.clone())
            .chain(self.files.iter().map(|(row, _)| PathBuf::from(&row.path)))
        {
            expected
                .get_mut(path.parent().ok_or(invalid("conflict residue parent"))?)
                .ok_or(invalid("conflict future residue parent guard missing"))?
                .insert(path);
        }
        if let Some(owner) = owner {
            expected
                .get_mut(
                    owner
                        .parent()
                        .ok_or(invalid("conflict owned scope parent"))?,
                )
                .ok_or(invalid("conflict owned original base guard missing"))?
                .insert(owner.to_path_buf());
        }
        for (parent, children) in expected {
            let mut actual = BTreeSet::new();
            for child in fs::read_dir(parent)? {
                if actual.len() >= children.len() {
                    return Err(invalid("conflict bounded exact residue membership grew"));
                }
                actual.insert(child?.path());
            }
            if actual != children {
                return Err(invalid(
                    "conflict future exact borrowed residue membership changed",
                ));
            }
        }
        for (row, held) in &self.files {
            held.verify_single_link()?;
            let named = GuardedReadFile::open(Path::new(&row.path))?;
            if descriptive(named.key()?) != row.key
                || descriptive(held.key()?) != row.key
                || held.reader().metadata()?.len() != row.length
            {
                return Err(invalid(
                    "conflict future original borrowed residue file changed",
                ));
            }
        }
        Ok(())
    }
}

/// Private retained capability. Description/hash and report cannot mint it.
pub struct ConflictNativeAdmission {
    selected: ConflictNativeBaseline,
    header: NativeHeader,
    residue: RetainedResidue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConflictNativeAdmissionReport {
    pub transaction_id: EntryId,
    pub generation: EntryId,
    pub header_hash: ContentId,
    pub complete_future_templates: usize,
    pub reserved: sync_extend_core_model::tree_storage_capacity::TreeStorageCharge,
    pub residue_bytes: u64,
    pub native_peak_bytes: u64,
    pub original_keys_persisted: bool,
    pub native_admission_persisted: bool,
    pub execution_authorized: bool,
    pub worktree_materialized: bool,
    pub release_available: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConflictNativeAdmissionLimits {
    pub max_residue_entries: usize,
    pub max_internal_bytes: u64,
    pub max_rows: u64,
    pub max_logical_bytes: u64,
}
impl Default for ConflictNativeAdmissionLimits {
    fn default() -> Self {
        Self {
            max_residue_entries: sync_extend_core_model::limits::MAX_ENTRIES,
            max_internal_bytes: 10 * 1024 * 1024 * 1024,
            max_rows: sync_extend_core_model::limits::MAX_ENTRIES as u64,
            max_logical_bytes: sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024,
        }
    }
}
impl ConflictNativeAdmissionLimits {
    fn validate(self) -> Result<()> {
        if self.max_residue_entries == 0
            || self.max_residue_entries > sync_extend_core_model::limits::MAX_ENTRIES
            || self.max_internal_bytes == 0
            || self.max_rows == 0
            || self.max_logical_bytes == 0
            || self.max_rows > sync_extend_core_model::limits::MAX_ENTRIES as u64
            || self.max_logical_bytes > sync_extend_core_model::limits::MAX_ENTRIES as u64 * 1024
        {
            return Err(invalid("conflict future admission limits"));
        }
        Ok(())
    }
}

impl ConflictNativeAdmission {
    pub fn report(&self) -> Result<ConflictNativeAdmissionReport> {
        self.residue.verify(&self.selected)?;
        let ledger = self
            .header
            .validate(&self.selected.header, &self.selected.binding()?)?;
        Ok(ConflictNativeAdmissionReport {
            transaction_id: self.header.transaction_id.clone(),
            generation: self.header.generation.clone(),
            header_hash: hash(&self.header)?,
            complete_future_templates: ledger.templates.len(),
            reserved: ledger.reserved,
            residue_bytes: self.residue.description.bytes,
            native_peak_bytes: self.header.native_peak,
            original_keys_persisted: true,
            native_admission_persisted: true,
            execution_authorized: false,
            worktree_materialized: false,
            release_available: false,
        })
    }
}

impl Journal {
    pub fn admit_conflict_native_baseline(
        &self,
        selected: ConflictNativeBaseline,
        limits: ConflictNativeAdmissionLimits,
    ) -> Result<ConflictNativeAdmission> {
        limits.validate()?;
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "conflict future caller transaction or native limit",
            ));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let space = &selected.header.intent.baseline.space_id;
        let mut bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        bounds.max_rows = bounds.max_rows.min(limits.max_rows);
        bounds.max_logical_bytes = bounds.max_logical_bytes.min(limits.max_logical_bytes);
        let before = self
            .read_view()
            .audit_local_commit_capacity(space, bounds)?;
        let plan = selected.header.plan()?;
        bind(&self.connection, &selected.header, &plan)?;
        selected.verify_native()?;
        let binding = selected.binding()?;
        if !selected.bound
            || super::super::native_binding::stored(&self.connection, &selected.header)?
                != Some(binding.clone())
        {
            return Err(invalid(
                "conflict future exact durable original keys required",
            ));
        }
        let residue = RetainedResidue::open(&selected, limits.max_residue_entries)?;
        let header = if let Some(stored) =
            native_ledger_storage::stored(&self.connection, &selected.header)?
        {
            if stored.residue != residue.description {
                return Err(invalid(
                    "conflict future exact original residue retry differs",
                ));
            }
            stored
        } else {
            let history = super::super::native_history_templates::HistorySelection::from_actual(
                &selected.header,
                &before.rows,
            )?;
            NativeHeader::build(
                &selected.header,
                &binding,
                EntryId::random()?,
                history,
                residue.description.clone(),
            )?
            .0
        };
        if header.native_peak > limits.max_internal_bytes
            || !before.report.within_accounted_limits()
        {
            return Err(invalid(
                "conflict future preeffect complete native/Journal capacity",
            ));
        }
        let ledger = header.validate(&selected.header, &binding)?;
        native_ledger_storage::require_fresh_generation(&header, &before.rows, &self.connection)?;
        let mut expected = row_map(&before.rows);
        let candidate = native_ledger_storage::values(&header, &ledger)?;
        let exists = expected.contains_key(&(
            "conflict_resolution_native_headers".into(),
            vec![header.transaction_id.to_string()],
        ));
        if !exists {
            let mut added_rows = 0u64;
            let mut added_bytes = 0u64;
            for (suffix, values) in &candidate {
                let (key, columns) = value_columns(suffix, values)?;
                if expected.insert(key, columns).is_some() {
                    return Err(invalid("conflict future original actual row collision"));
                }
                added_rows = added_rows
                    .checked_add(1)
                    .ok_or(invalid("conflict future admission row overflow"))?;
                for value in values {
                    added_bytes = added_bytes
                        .checked_add(match value {
                            Value::Text(s) => s.len() as u64,
                            Value::Integer(_) => 8,
                            _ => return Err(invalid("conflict future admission value type")),
                        })
                        .ok_or(invalid("conflict future admission byte overflow"))?;
                }
            }
            let prior = before.report.accounted_total();
            if prior
                .rows
                .checked_add(added_rows)
                .and_then(|n| n.checked_add(ledger.reserved.rows))
                .is_none_or(|n| n > bounds.max_rows)
                || prior
                    .logical_bytes
                    .checked_add(added_bytes)
                    .and_then(|n| n.checked_add(ledger.reserved.logical_bytes))
                    .is_none_or(|n| n > bounds.max_logical_bytes)
            {
                return Err(invalid(
                    "conflict future complete prewrite allmain liability limit",
                ));
            }
            for (suffix, values) in candidate {
                let mut issued = vec![Value::Text(suffix.into())];
                issued.extend(values.clone());
                let _permit = self.conflict_resolution_issuance.permit(Some(issued))?;
                let parameters = (1..=values.len())
                    .map(|number| format!("?{number}"))
                    .collect::<Vec<_>>()
                    .join(",");
                tx.execute(
                    &format!("INSERT INTO main.conflict_resolution_{suffix} VALUES({parameters})"),
                    rusqlite::params_from_iter(values),
                )?;
            }
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(space, bounds)?;
        if row_map(&after.rows) != expected || !after.report.within_accounted_limits() {
            return Err(invalid(
                "conflict future complete exact allvalue receipt differs",
            ));
        }
        residue.verify(&selected)?;
        tx.commit()?;
        Ok(ConflictNativeAdmission {
            selected,
            header,
            residue,
        })
    }
}
