//! Whole original forward-only execution; no materialization or release.
use super::super::super::native_effects;
use super::creators::{base_key, base_path, owner_path, physical_key};
use super::*;

pub struct ConflictNativeExecution {
    pub(super) held: ConflictNativeReadiness,
    pub(super) binding: super::super::super::native_binding::Binding,
    pub(super) recovery_state: BTreeSet<String>,
}
pub struct ConflictNativeObservation {
    pub(super) held: ConflictNativeExecution,
}

pub(super) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn location(file: &LockedFile, candidates: &BTreeSet<PathBuf>) -> Result<PathBuf> {
    let mut found = None;
    for path in candidates {
        if exists(path)? && file.matches_path(path)? && found.replace(path.clone()).is_some() {
            return Err(invalid("conflict forward original key aliases two slots"));
        }
    }
    found.ok_or(invalid(
        "conflict forward original key missing every admitted slot",
    ))
}

fn member_set(path: &Path, expected: &BTreeSet<PathBuf>) -> Result<()> {
    let mut actual = BTreeSet::new();
    for child in fs::read_dir(path)? {
        if actual.len() >= expected.len() {
            return Err(invalid("conflict forward bounded namespace grew"));
        }
        actual.insert(child?.path());
    }
    if actual != *expected {
        return Err(invalid("conflict forward complete namespace differs"));
    }
    Ok(())
}

fn original_candidates(
    admission: &ConflictNativeAdmission,
    action: &sync_extend_core_model::conflict_native_layout::ConflictNativeAction,
    fulfilled: &BTreeSet<String>,
) -> Result<BTreeSet<PathBuf>> {
    let entry = action
        .baseline
        .as_ref()
        .ok_or(invalid("conflict forward baseline absent"))?;
    let root = &admission.selected.directories[0].path;
    let quarantine = format!("quarantine/{}/", action.entry_id);
    let publish = format!("publish/{}/", action.entry_id);
    let reused = action.payload_component.is_none()
        && admission
            .selected
            .layout
            .publication_order
            .contains(&action.entry_id);
    let displaced = || {
        action
            .original_component
            .as_ref()
            .map(|c| owner_path(admission).join(c))
            .ok_or(invalid("conflict forward original stage absent"))
    };
    let target = || {
        action
            .target
            .as_ref()
            .map(|e| root.join(e.path.as_str()))
            .ok_or(invalid("conflict forward target absent"))
    };
    let mut candidates = BTreeSet::new();
    if reused && fulfilled.contains(&(publish.clone() + "observed")) {
        candidates.insert(target()?);
    } else if reused && fulfilled.contains(&(publish + "executing")) {
        candidates.insert(displaced()?);
        candidates.insert(target()?);
    } else if fulfilled.contains(&(quarantine.clone() + "observed")) {
        candidates.insert(displaced()?);
    } else {
        candidates.insert(root.join(entry.path.as_str()));
        if fulfilled.contains(&(quarantine + "executing")) {
            candidates.insert(displaced()?);
        }
    }
    Ok(candidates)
}
fn payload_candidates(
    admission: &ConflictNativeAdmission,
    action: &sync_extend_core_model::conflict_native_layout::ConflictNativeAction,
    fulfilled: &BTreeSet<String>,
) -> Result<BTreeSet<PathBuf>> {
    let publish = format!("publish/{}/", action.entry_id);
    let entry = action
        .target
        .as_ref()
        .ok_or(invalid("conflict forward target absent"))?;
    let target = admission.selected.directories[0]
        .path
        .join(entry.path.as_str());
    let mut candidates = BTreeSet::new();
    if fulfilled.contains(&(publish.clone() + "observed")) {
        candidates.insert(target);
    } else {
        candidates.insert(
            owner_path(admission).join(
                action
                    .payload_component
                    .as_ref()
                    .ok_or(invalid("conflict forward payload component absent"))?,
            ),
        );
        if fulfilled.contains(&(publish + "executing")) {
            candidates.insert(target);
        }
    }
    Ok(candidates)
}
fn reopen_original(
    expected: &super::super::super::native_binding::Key,
    candidates: &BTreeSet<PathBuf>,
) -> Result<LockedFile> {
    let mut found = None;
    for path in candidates {
        if !exists(path)? {
            continue;
        }
        let file = LockedFile::open(path)?;
        if descriptive(file.key()?) != *expected {
            continue;
        }
        if found.replace(file).is_some() {
            return Err(invalid("conflict forward reopen original alias"));
        }
    }
    found.ok_or(invalid("conflict forward original receipt key absent"))
}

impl ConflictNativeExecution {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    fn directory_absent(
        &self,
        path: &Path,
        held: &Option<LockedDirectory>,
        key: &super::super::super::native_binding::Key,
        fulfilled: &BTreeSet<String>,
    ) -> Result<bool> {
        let component = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(invalid("conflict directory component UTF8"))?;
        let intended = fulfilled.contains(&format!("dispose/{component}/intended"));
        let terminal = fulfilled.contains(&format!("dispose/{component}/absent"))
            || fulfilled.contains(&format!("dispose/{component}/terminal"));
        if exists(path)? {
            if terminal
                || descriptive(directory(path)?.key) != *key
                || held
                    .as_ref()
                    .is_some_and(|h| h.key().map(descriptive).ok().as_ref() != Some(key))
            {
                return Err(invalid(
                    "conflict cleanup directory fullkey or terminal differs",
                ));
            }
            if held.is_none() && !intended {
                return Err(invalid("conflict directory guard absent before intended"));
            }
            Ok(false)
        } else if intended && held.is_none() {
            Ok(true)
        } else {
            Err(invalid("conflict directory absent before exact intended"))
        }
    }
    pub(super) fn verify(&self, fulfilled: &BTreeSet<String>) -> Result<()> {
        let ready = &self.held;
        let admission = &ready.admission;
        let selected = &admission.selected;
        let root = &selected.directories[0].path;
        selected.verify_retained_ancestors()?;
        let owner_slot = owner_path(admission);
        let owner_absent =
            self.directory_absent(&owner_slot, &ready.owner, &ready.keys[&1], fulfilled)?;
        let base_slot = base_path(admission);
        let base_absent = if self.binding.existing_base.is_none() {
            self.directory_absent(
                &base_slot,
                &ready.base,
                &base_key(admission, &ready.keys)?,
                fulfilled,
            )?
        } else {
            if descriptive(
                ready
                    .base
                    .as_ref()
                    .ok_or(invalid("conflict borrowed base guard absent"))?
                    .key()?,
            ) != base_key(admission, &ready.keys)?
                || descriptive(directory(&base_slot)?.key) != base_key(admission, &ready.keys)?
            {
                return Err(invalid("conflict borrowed base fullkey changed"));
            }
            false
        };
        admission.residue.verify_borrowed_scope(
            selected,
            if base_absent {
                None
            } else {
                ready.keys.get(&0).map(physical_key).transpose()?
            },
            if owner_absent {
                None
            } else {
                Some(owner_slot.as_path())
            },
        )?;
        let mut live = BTreeSet::from([root.join(".sync-extend")]);
        if !base_absent {
            live.insert(root.join(".sync-tmp"));
        }
        let mut owned = BTreeSet::new();
        let mut payload_step = 2;
        for action in &selected.layout.actions {
            if let Some(entry) = &action.baseline {
                if let Some(component) = &action.original_component {
                    let disposed = fulfilled.contains(&format!("dispose/{component}/absent"))
                        || fulfilled.contains(&format!("dispose/{component}/terminal"));
                    let path = owner_path(admission).join(component);
                    let intended_absence = fulfilled
                        .contains(&format!("dispose/{component}/intended"))
                        && !exists(&path)?;
                    if disposed || intended_absence {
                        if exists(&path)? {
                            return Err(invalid("conflict disposed original slot reappeared"));
                        }
                        if action.target.is_none() {
                            continue;
                        }
                    } else {
                        let original = selected
                            .originals
                            .get(&entry.path)
                            .ok_or(invalid("conflict disposition remaining original absent"))?;
                        if descriptive(original.held.key()?)
                            != self.binding.originals[&entry.entry_id]
                        {
                            return Err(invalid(
                                "conflict disposition retained original key differs",
                            ));
                        }
                        let at = location(
                            &original.held,
                            &original_candidates(admission, action, fulfilled)?,
                        )?;
                        super::super::verify_content(original.held.reader(), entry)?;
                        if at.parent() == Some(root.as_path()) {
                            live.insert(at);
                        } else {
                            owned.insert(at);
                        }
                    }
                } else {
                    let original = selected
                        .originals
                        .get(&entry.path)
                        .ok_or(invalid("conflict disposition unchanged original absent"))?;
                    if descriptive(original.held.key()?) != self.binding.originals[&entry.entry_id]
                    {
                        return Err(invalid(
                            "conflict disposition unchanged original key differs",
                        ));
                    }
                    let at = location(
                        &original.held,
                        &original_candidates(admission, action, fulfilled)?,
                    )?;
                    super::super::verify_content(original.held.reader(), entry)?;
                    live.insert(at);
                }
            }
            if action.payload_component.is_some() {
                let entry = action
                    .target
                    .as_ref()
                    .ok_or(invalid("conflict forward payload target absent"))?;
                let file = ready
                    .payloads
                    .get(&action.entry_id)
                    .ok_or(invalid("conflict forward retained payload absent"))?;
                if descriptive(file.key()?) != ready.keys[&payload_step] {
                    return Err(invalid("conflict forward payload key differs"));
                }
                let candidates = payload_candidates(admission, action, fulfilled)?;
                let at = location(file, &candidates)?;
                super::super::verify_content(file.reader(), entry)?;
                if at.parent() == Some(root.as_path()) {
                    live.insert(at);
                } else {
                    owned.insert(at);
                }
                payload_step += 1;
            }
        }
        member_set(root, &live)?;
        if owner_absent {
            if !owned.is_empty() {
                return Err(invalid("conflict absent owner still owns original files"));
            }
            Ok(())
        } else {
            member_set(&owner_path(admission), &owned)
        }
    }
}

impl ConflictNativeObservation {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    pub fn manifest(&self) -> &Manifest {
        &self.held.held.admission.selected.header.target
    }
    pub fn verify_content(&self) -> Result<()> {
        let admission = &self.held.held.admission;
        let ledger = admission
            .header
            .validate(&admission.selected.header, &self.held.binding)?;
        let mut completed: BTreeSet<String> = ledger
            .templates
            .iter()
            .take_while(|t| !t.name.starts_with("history/"))
            .map(|t| t.name.clone())
            .collect();
        completed.extend(self.held.recovery_state.iter().cloned());
        self.held.verify(&completed)
    }
    /// Borrowed exact target observation; never exposes a reader or writable handle.
    pub fn observe_file(&self, path: &Path) -> Result<Option<NativePublicationFileObservation>> {
        self.verify_content()?;
        let ready = &self.held.held;
        let selected = &ready.admission.selected;
        let root = &selected.directories[0].path;
        let canonical = fs::canonicalize(path).ok();
        let Some(action) = selected.layout.actions.iter().find(|action| {
            action.target.as_ref().is_some_and(|entry| {
                let target = root.join(entry.path.as_str());
                target == path || canonical.as_deref() == Some(target.as_path())
            })
        }) else {
            return Ok(None);
        };
        let entry = action
            .target
            .as_ref()
            .ok_or(invalid("conflict whole target view entry absent"))?;
        let file = if action.payload_component.is_some() {
            ready
                .payloads
                .get(&action.entry_id)
                .ok_or(invalid("conflict whole target view payload absent"))?
        } else {
            let baseline = action
                .baseline
                .as_ref()
                .ok_or(invalid("conflict whole target view original absent"))?;
            &selected
                .originals
                .get(&baseline.path)
                .ok_or(invalid("conflict whole target view original missing"))?
                .held
        };
        if !file.matches_path(path)? {
            return Err(invalid("conflict whole target view fullkey slot differs"));
        }
        Ok(Some(NativePublicationFileObservation {
            metadata: file.reader().metadata()?,
            physical_identity: super::super::physical(file.key()?),
            content: entry.content.clone(),
        }))
    }
}

impl Journal {
    pub fn reopen_conflict_native_execution(
        &mut self,
        transaction: &EntryId,
    ) -> Result<ConflictNativeExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict forward reopen caller transaction"));
        }
        let cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let json: String = self.connection.query_row(
            "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
            [transaction.as_str()],
            |r| r.get(0),
        )?;
        let header: Header = serde_json::from_str(&json)?;
        bind(&self.connection, &header, &header.plan()?)?;
        let before = self.read_view().audit_local_commit_capacity(
            &header.target.space_id,
            storage_policy::capacity_limits(self.max_storage_entries)?,
        )?;
        if !before.report.within_accounted_limits() {
            return Err(invalid("conflict forward reopen capacity"));
        }
        let binding = super::super::super::native_binding::stored(&self.connection, &header)?
            .ok_or(invalid("conflict forward original binding absent"))?;
        let native = native_ledger_storage::stored(&self.connection, &header)?
            .ok_or(invalid("conflict forward native header absent"))?;
        let ledger = native.validate(&header, &binding)?;
        let effects = native_effects::audit(&native, &binding, &ledger, &before.rows)?;
        if !effects.fulfilled.contains("phase/ready") {
            return Err(invalid("conflict forward reopen missing whole Ready"));
        }
        let root = Path::new(&header.intent.worktree);
        let directories = root
            .ancestors()
            .map(directory)
            .collect::<Result<Vec<_>>>()?;
        let marker = directory(&root.join(".sync-extend"))?;
        let marker_file = GuardedReadFile::open(&root.join(".sync-extend/space-id"))?;
        let base = if binding.existing_base.is_some() {
            Some(directory(&root.join(".sync-tmp"))?)
        } else {
            None
        };
        let layout = plan_conflict_native_layout(
            &header.intent.baseline,
            &header.target,
            Default::default(),
        )?;
        // Persisted original paths stay unchanged even after their handles move.
        let selected = ConflictNativeBaseline {
            header,
            layout,
            directories,
            marker,
            marker_file,
            base,
            originals: BTreeMap::new(),
            _cas: cas,
            bound: true,
        };
        let residue = RetainedResidue {
            description: native.residue.clone(),
            directories: native
                .residue
                .directories
                .iter()
                .map(|r| directory(Path::new(&r.path)))
                .collect::<Result<_>>()?,
            files: native
                .residue
                .files
                .iter()
                .map(|r| Ok((r.clone(), GuardedReadFile::open(Path::new(&r.path))?)))
                .collect::<Result<_>>()?,
        };
        let mut admission = ConflictNativeAdmission {
            selected,
            header: native,
            residue,
        };
        for action in &admission.selected.layout.actions {
            let Some(entry) = &action.baseline else {
                continue;
            };
            if let Some(component) = &action.original_component {
                let path = owner_path(&admission).join(component);
                if effects
                    .fulfilled
                    .contains(&format!("dispose/{component}/intended"))
                    && !exists(&path)?
                {
                    continue;
                }
            }
            let key = &binding.originals[&entry.entry_id];
            let file = reopen_original(
                key,
                &original_candidates(&admission, action, &effects.fulfilled)?,
            )?;
            let original = super::super::Original {
                entry: entry.clone(),
                path: admission.selected.directories[0]
                    .path
                    .join(entry.path.as_str()),
                key: file.key()?,
                held: file,
            };
            admission
                .selected
                .originals
                .insert(entry.path.clone(), original);
        }
        let mut actual_binding = admission.selected.binding()?;
        for (entry, key) in &binding.originals {
            actual_binding
                .originals
                .entry(entry.clone())
                .or_insert_with(|| key.clone());
        }
        if actual_binding != binding {
            return Err(invalid(
                "conflict forward reopened original binding differs",
            ));
        }
        let reopen_directory = |path: PathBuf| -> Result<Option<LockedDirectory>> {
            let component = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(invalid("conflict cleanup directory UTF8"))?;
            if !exists(&path)?
                && effects
                    .fulfilled
                    .contains(&format!("dispose/{component}/intended"))
            {
                Ok(None)
            } else {
                Ok(Some(directory(&path)?.held))
            }
        };
        let base = reopen_directory(base_path(&admission))?;
        let owner = reopen_directory(owner_path(&admission))?;
        let mut payloads = BTreeMap::new();
        let mut step = 2;
        for action in &admission.selected.layout.actions {
            if action.payload_component.is_some() {
                let key = effects
                    .creators
                    .get(&step)
                    .ok_or(invalid("conflict forward original payload receipt absent"))?;
                let file = reopen_original(
                    key,
                    &payload_candidates(&admission, action, &effects.fulfilled)?,
                )?;
                payloads.insert(action.entry_id.clone(), file);
                step += 1;
            }
        }
        let held = ConflictNativeExecution {
            binding,
            recovery_state: effects.fulfilled,
            held: ConflictNativeReadiness {
                admission,
                base,
                owner,
                keys: effects.creators,
                payloads,
            },
        };
        self.conflict_forward_state(&held)?;
        tx.commit()?;
        Ok(held)
    }
    pub(super) fn conflict_forward_state(
        &self,
        held: &ConflictNativeExecution,
    ) -> Result<BTreeSet<String>> {
        let admission = &held.held.admission;
        let parent = &admission.selected.header;
        bind(&self.connection, parent, &parent.plan()?)?;
        let before = self.read_view().audit_local_commit_capacity(
            &parent.target.space_id,
            storage_policy::capacity_limits(self.max_storage_entries)?,
        )?;
        if !before.report.within_accounted_limits()
            || native_ledger_storage::stored(&self.connection, parent)?.as_ref()
                != Some(&admission.header)
        {
            return Err(invalid("conflict forward admission or capacity differs"));
        }
        let binding = &held.binding;
        let ledger = admission.header.validate(parent, binding)?;
        let effects = native_effects::audit(&admission.header, binding, &ledger, &before.rows)?;
        if !effects.fulfilled.contains("phase/ready") {
            return Err(invalid("conflict forward whole Ready absent"));
        }
        held.verify(&effects.fulfilled)?;
        self.verify_conflict_creator_cas(admission)?;
        Ok(effects.fulfilled)
    }
    pub fn start_conflict_native_execution(
        &mut self,
        ready: ConflictNativeReadiness,
    ) -> Result<ConflictNativeExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict forward caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        ready.verify_content()?;
        let binding = ready.admission.selected.binding()?;
        let held = ConflictNativeExecution {
            held: ready,
            binding,
            recovery_state: BTreeSet::new(),
        };
        self.conflict_forward_state(&held)?;
        tx.commit()?;
        Ok(held)
    }
    fn conflict_forward_template(
        &mut self,
        held: &ConflictNativeExecution,
        name: &str,
    ) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict forward receipt caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut state = self.conflict_forward_state(held)?;
        state.insert(name.into());
        held.verify(&state)?;
        tx.commit()?;
        self.fulfill_conflict_creator(&held.held.admission, name, &held.held.keys, || {
            held.verify(&state)
        })
    }
    fn conflict_forward_move(
        &mut self,
        held: &ConflictNativeExecution,
        entry: &EntryId,
        action: &str,
    ) -> Result<()> {
        let executing = format!("{action}/{entry}/executing");
        let observed = format!("{action}/{entry}/observed");
        self.conflict_forward_template(held, &executing)?;
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict forward effect caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let state = self.conflict_forward_state(held)?;
        let admission = &held.held.admission;
        let selected = &admission.selected;
        let item = selected
            .layout
            .actions
            .iter()
            .find(|a| &a.entry_id == entry)
            .ok_or(invalid("conflict forward action absent"))?;
        let root = &selected.directories[0].path;
        let (file, from, to) = if action == "quarantine" {
            let original = item
                .baseline
                .as_ref()
                .ok_or(invalid("conflict forward baseline absent"))?;
            (
                &selected.originals[&original.path].held,
                root.join(original.path.as_str()),
                owner_path(admission).join(
                    item.original_component
                        .as_ref()
                        .ok_or(invalid("conflict forward quarantine component absent"))?,
                ),
            )
        } else {
            let target = item
                .target
                .as_ref()
                .ok_or(invalid("conflict forward target absent"))?;
            let (file, from) = if let Some(component) = &item.payload_component {
                (
                    &held.held.payloads[entry],
                    owner_path(admission).join(component),
                )
            } else {
                let original = item
                    .baseline
                    .as_ref()
                    .ok_or(invalid("conflict forward reuse original absent"))?;
                (
                    &selected.originals[&original.path].held,
                    owner_path(admission).join(
                        item.original_component
                            .as_ref()
                            .ok_or(invalid("conflict forward reuse component absent"))?,
                    ),
                )
            };
            (file, from, root.join(target.path.as_str()))
        };
        if !state.contains(&observed) {
            if exists(&from)? && file.matches_path(&from)? {
                if exists(&to)? {
                    return Err(invalid("conflict forward destination occupied"));
                }
                file.rename_no_replace(&to)?;
            }
            if !exists(&to)? || !file.matches_path(&to)? || exists(&from)? {
                return Err(invalid("conflict forward exact moved slots differ"));
            }
            self.conflict_forward_state(held)?;
        }
        tx.commit()?;
        self.conflict_forward_template(held, &observed)
    }
    pub fn execute_conflict_native(
        &mut self,
        held: ConflictNativeExecution,
    ) -> Result<ConflictNativeObservation> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict replay caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let complete = self
            .conflict_forward_state(&held)?
            .contains("phase/observed");
        tx.commit()?;
        if complete {
            return Ok(ConflictNativeObservation { held });
        }
        let held = self.quarantine_conflict_native(held)?;
        self.publish_conflict_native(held)
    }
    pub fn quarantine_conflict_native(
        &mut self,
        held: ConflictNativeExecution,
    ) -> Result<ConflictNativeExecution> {
        for entry in held.held.admission.selected.layout.quarantine_order.clone() {
            self.conflict_forward_move(&held, &entry, "quarantine")?;
        }
        self.conflict_forward_template(&held, "phase/quarantined")?;
        Ok(held)
    }
    pub fn publish_conflict_native(
        &mut self,
        held: ConflictNativeExecution,
    ) -> Result<ConflictNativeObservation> {
        for entry in held
            .held
            .admission
            .selected
            .layout
            .publication_order
            .clone()
        {
            self.conflict_forward_move(&held, &entry, "publish")?;
        }
        self.conflict_forward_template(&held, "phase/observed")?;
        Ok(ConflictNativeObservation { held })
    }
}
