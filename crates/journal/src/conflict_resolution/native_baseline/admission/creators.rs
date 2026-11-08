//! Original whole-plan creator handles; no quarantine or publication endpoint.
use super::super::super::{native_binding::Key, native_effects, native_templates::Cell};
use super::*;
use sync_extend_platform_fs::OwnedFileCreation;

pub struct ConflictNativeCreation {
    admission: ConflictNativeAdmission,
    base: LockedDirectory,
    owner: LockedDirectory,
    keys: BTreeMap<u64, Key>,
    payloads: BTreeMap<EntryId, (u64, OwnedFileCreation)>,
}
pub struct ConflictNativeReadiness {
    admission: ConflictNativeAdmission,
    base: LockedDirectory,
    owner: LockedDirectory,
    keys: BTreeMap<u64, Key>,
    payloads: BTreeMap<EntryId, LockedFile>,
}

fn physical_key(key: &Key) -> Result<FileKey> {
    Ok(FileKey {
        volume: u64::from_str_radix(&key.volume, 16)
            .map_err(|_| invalid("conflict original creator volume"))?,
        id: u128::from_str_radix(&key.id, 16)
            .map_err(|_| invalid("conflict original creator full ID"))?,
    })
}
fn base_path(admission: &ConflictNativeAdmission) -> PathBuf {
    admission.selected.directories[0].path.join(".sync-tmp")
}
fn owner_path(admission: &ConflictNativeAdmission) -> PathBuf {
    base_path(admission).join(format!("conflict-{}", admission.header.generation))
}
fn original_scope(admission: &ConflictNativeAdmission, keys: &BTreeMap<u64, Key>) -> Result<()> {
    let own_base = keys.get(&0).map(physical_key).transpose()?;
    let owner = keys.contains_key(&1).then(|| owner_path(admission));
    admission
        .residue
        .verify_scope(&admission.selected, own_base, owner.as_deref())?;
    for (step, path) in [(0, base_path(admission)), (1, owner_path(admission))] {
        if let Some(expected) = keys.get(&step) {
            if descriptive(directory(&path)?.key) != *expected {
                return Err(invalid("conflict original created directory slot changed"));
            }
        }
    }
    Ok(())
}
fn base_key(admission: &ConflictNativeAdmission, keys: &BTreeMap<u64, Key>) -> Result<Key> {
    admission
        .selected
        .binding()?
        .existing_base
        .or_else(|| keys.get(&0).cloned())
        .ok_or(invalid("conflict original base receipt missing"))
}
fn owner_membership(admission: &ConflictNativeAdmission) -> Result<BTreeSet<PathBuf>> {
    let maximum = admission.selected.layout.actions.len();
    let mut actual = BTreeSet::new();
    for child in fs::read_dir(owner_path(admission))? {
        if actual.len() >= maximum {
            return Err(invalid("conflict bounded original owner membership"));
        }
        actual.insert(child?.path());
    }
    Ok(actual)
}

impl ConflictNativeCreation {
    pub fn transaction_id(&self) -> &EntryId {
        &self.admission.header.transaction_id
    }
    pub fn payload_entries(&self) -> Vec<EntryId> {
        self.payloads.keys().cloned().collect()
    }
    pub fn payload_writer(&mut self, entry: &EntryId) -> Result<&mut fs::File> {
        self.verify()?;
        let target = self
            .admission
            .selected
            .layout
            .actions
            .iter()
            .find(|action| &action.entry_id == entry)
            .and_then(|action| action.target.as_ref())
            .and_then(|target| target.content.as_ref())
            .ok_or(invalid("conflict original payload target absent"))?;
        let (_, file) = self
            .payloads
            .get_mut(entry)
            .ok_or(invalid("conflict original payload entry not created"))?;
        if file.reader().metadata()?.len() > target.length {
            return Err(invalid("conflict original payload exceeds admitted extent"));
        }
        Ok(file.writer())
    }
    fn verify(&self) -> Result<()> {
        original_scope(&self.admission, &self.keys)?;
        if descriptive(self.owner.key()?) != self.keys[&1]
            || descriptive(self.base.key()?) != base_key(&self.admission, &self.keys)?
        {
            return Err(invalid(
                "conflict retained whole creator directories differ",
            ));
        }
        let expected = self
            .payloads
            .values()
            .map(|(_, payload)| {
                Ok(owner_path(&self.admission)
                    .join(payload.original_creation()?.created_component()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if owner_membership(&self.admission)? != expected {
            return Err(invalid("conflict whole creator owner membership differs"));
        }
        for (step, file) in self.payloads.values() {
            let original = file.original_creation()?;
            original.verify()?;
            if descriptive(original.key()?) != self.keys[step]
                || descriptive(original.parent_key()?) != self.keys[&1]
            {
                return Err(invalid(
                    "conflict retained original payload lineage differs",
                ));
            }
        }
        let actual = self
            .payloads
            .iter()
            .try_fold(0u64, |total, (entry, (_, file))| {
                let target = self
                    .admission
                    .selected
                    .header
                    .target
                    .entries
                    .get(entry)
                    .and_then(|target| target.content.as_ref())
                    .ok_or(invalid("conflict created target content absent"))?;
                let bytes = file.reader().metadata()?.len();
                if bytes > target.length {
                    return Err(invalid("conflict created payload exceeds admitted extent"));
                }
                total
                    .checked_add(bytes)
                    .ok_or(invalid("conflict created aggregate byte overflow"))
            })?;
        if actual > self.admission.selected.layout.payload_bytes {
            return Err(invalid(
                "conflict created payloads exceed whole reservation",
            ));
        }
        Ok(())
    }
}

impl Journal {
    /// Reopen only complete exact original receipts as reads; never issue writers.
    pub fn reopen_conflict_native_readiness(
        &mut self,
        transaction: &EntryId,
    ) -> Result<ConflictNativeReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict Ready reopen refuses caller transaction"));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let json: String = self.connection.query_row(
            "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
            [transaction.as_str()],
            |r| r.get(0),
        )?;
        let parent: Header = serde_json::from_str(&json)?;
        let before = self.read_view().audit_local_commit_capacity(
            &parent.target.space_id,
            storage_policy::capacity_limits(self.max_storage_entries)?,
        )?;
        if !before.report.within_accounted_limits() {
            return Err(invalid("conflict Ready reopen lowered exact capacity"));
        }
        let binding = super::super::super::native_binding::stored(&self.connection, &parent)?
            .ok_or(invalid("conflict Ready original baseline binding absent"))?;
        let header = native_ledger_storage::stored(&self.connection, &parent)?
            .ok_or(invalid("conflict Ready original native header absent"))?;
        let ledger = header.validate(&parent, &binding)?;
        let effects = native_effects::audit(&header, &binding, &ledger, &before.rows)?;
        if ledger
            .templates
            .iter()
            .filter(|t| t.table == "conflict_resolution_native_creators")
            .any(|t| !effects.fulfilled.contains(&t.name))
        {
            return Err(invalid(
                "conflict Ready incomplete one-shot creators cannot be adopted",
            ));
        }
        let keys = effects.creators;
        tx.commit()?;
        let selected = self.hold_conflict_baseline_scope(
            transaction,
            sync_extend_core_model::conflict_native_layout::ConflictNativeLayoutLimits::default(),
            Some(&binding),
            keys.get(&0).map(physical_key).transpose()?,
        )?;
        let owner_path = selected.directories[0]
            .path
            .join(".sync-tmp")
            .join(format!("conflict-{}", header.generation));
        let residue = RetainedResidue::reopen(
            &selected,
            header.residue.clone(),
            keys.get(&0).map(physical_key).transpose()?,
            Some(&owner_path),
        )?;
        let admission = ConflictNativeAdmission {
            selected,
            header,
            residue,
        };
        let base = directory(&base_path(&admission))?.held;
        let owner = directory(&owner_path)?.held;
        let mut payloads = BTreeMap::new();
        for action in &admission.selected.layout.actions {
            if let Some(component) = &action.payload_component {
                payloads.insert(
                    action.entry_id.clone(),
                    LockedFile::open(&owner_path.join(component))?,
                );
            }
        }
        let ready = ConflictNativeReadiness {
            admission,
            base,
            owner,
            keys,
            payloads,
        };
        ready.verify_content()?;
        self.fulfill_conflict_creator(&ready.admission, "phase/ready", &ready.keys, || {
            ready.verify_content()
        })?;
        Ok(ready)
    }
    fn verify_conflict_creator_cas(&self, admission: &ConflictNativeAdmission) -> Result<()> {
        let parent = self
            .database_path
            .parent()
            .ok_or(invalid("conflict CAS parent missing"))?;
        for ((_, content), expected_length) in pins(&admission.selected.header)? {
            self.require_cas_access(&content)?;
            let path = parent
                .join("cas/objects")
                .join(&content.as_str()[..2])
                .join(content.as_str());
            let held = GuardedReadFile::open(&path)?;
            held.verify_single_link()?;
            if held.reader().metadata()?.len() != u64::from(expected_length) {
                return Err(invalid("conflict original CAS chunk length differs"));
            }
            let mut reader = held.reader();
            let mut hash = blake3::Hasher::new();
            let mut buffer = [0u8; 65536];
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            if ContentId::from_hasher(&hash) != content {
                return Err(invalid("conflict original CAS chunk bytes differ"));
            }
        }
        Ok(())
    }
    fn fulfill_conflict_creator(
        &mut self,
        admission: &ConflictNativeAdmission,
        name: &str,
        keys: &BTreeMap<u64, Key>,
        verify: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict creator refuses caller transaction"));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let parent = &admission.selected.header;
        let binding = admission.selected.binding()?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        bind(&self.connection, parent, &parent.plan()?)?;
        self.verify_conflict_creator_cas(admission)?;
        if native_ledger_storage::stored(&self.connection, parent)?.as_ref()
            != Some(&admission.header)
            || !before.report.within_accounted_limits()
        {
            return Err(invalid(
                "conflict creator exact admission or capacity differs",
            ));
        }
        let ledger = admission.header.validate(parent, &binding)?;
        let effects = native_effects::audit(&admission.header, &binding, &ledger, &before.rows)?;
        let template = ledger
            .templates
            .iter()
            .find(|template| template.name == name)
            .ok_or(invalid("conflict creator named future template missing"))?;
        if !matches!(
            template.table.as_str(),
            "conflict_resolution_native_activations" | "conflict_resolution_native_creators"
        ) && template.name != "phase/ready"
        {
            return Err(invalid("conflict unsupported native effect endpoint"));
        }
        if template
            .dependencies
            .iter()
            .any(|name| !effects.fulfilled.contains(name))
        {
            return Err(invalid("conflict creator exact prior dependency missing"));
        }
        let values = native_effects::resolve(
            template
                .future
                .as_ref()
                .ok_or(invalid("conflict creator future values missing"))?,
            keys,
        )?;
        let suffix = template
            .table
            .strip_prefix("conflict_resolution_")
            .ok_or(invalid("conflict creator exact physical namespace"))?;
        let (key, columns) = value_columns(suffix, &values)?;
        let mut expected = row_map(&before.rows);
        if let Some(stored) = expected.get(&key) {
            if stored != &columns {
                return Err(invalid("conflict original creator exact retry differs"));
            }
        } else {
            expected.insert(key, columns);
            let mut issued = vec![Value::Text(suffix.into())];
            issued.extend(values.clone());
            let _permit = self.conflict_resolution_issuance.permit(Some(issued))?;
            let parameters = (1..=values.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(",");
            tx.execute(
                &format!("INSERT INTO main.{} VALUES({parameters})", template.table),
                rusqlite::params_from_iter(values),
            )?;
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        if row_map(&after.rows) != expected
            || !after.report.within_accounted_limits()
            || before.report.accounted_total() != after.report.accounted_total()
        {
            return Err(invalid("conflict creator exact allmain conversion differs"));
        }
        verify()?;
        tx.commit()?;
        Ok(())
    }

    fn create_conflict_directory(
        &mut self,
        admission: &ConflictNativeAdmission,
        step: u64,
        parent: &LockedDirectory,
        keys: &mut BTreeMap<u64, Key>,
    ) -> Result<()> {
        let ledger = admission
            .header
            .validate(&admission.selected.header, &admission.selected.binding()?)?;
        let activation = format!("activate/{step}");
        let template = ledger
            .templates
            .iter()
            .find(|t| t.name == activation)
            .ok_or(invalid("conflict original directory activation absent"))?;
        let Some(Cell::Text(component)) = template.future.as_ref().and_then(|v| v.get(4)) else {
            return Err(invalid("conflict original creator directory component"));
        };
        let exists: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.conflict_resolution_native_activations WHERE transaction_id=?1 AND step=?2)",
            params![admission.header.transaction_id.as_str(), step as i64], |r| r.get(0),
        )?;
        if exists {
            return Err(invalid(
                "conflict original directory CREATE cannot retry or adopt",
            ));
        }
        self.fulfill_conflict_creator(admission, &activation, keys, || {
            original_scope(admission, keys)
        })?;
        original_scope(admission, keys)?;
        let created = if step == 0 {
            parent.create_new_staging_directory()?
        } else {
            parent.create_new_child(component)?
        };
        let original = created.original_creation()?;
        let key = descriptive(original.key()?);
        keys.insert(step, key.clone());
        self.fulfill_conflict_creator(admission, &format!("creator/{step}"), keys, || {
            original.verify()?;
            if descriptive(original.key()?) != key
                || original.parent_key()? != parent.key()?
                || original.created_component() != component
            {
                return Err(invalid(
                    "conflict original directory CREATE lineage changed",
                ));
            }
            admission.residue.verify_scope(
                &admission.selected,
                keys.get(&0).map(physical_key).transpose()?,
                keys.contains_key(&1)
                    .then(|| owner_path(admission))
                    .as_deref(),
            )
        })?;
        drop(created);
        original_scope(admission, keys)
    }

    pub fn create_conflict_native_payloads(
        &mut self,
        admission: ConflictNativeAdmission,
    ) -> Result<ConflictNativeCreation> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict whole CREATE refuses caller transaction"));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.read_view().audit_local_commit_capacity(
            &admission.selected.header.target.space_id,
            storage_policy::capacity_limits(self.max_storage_entries)?,
        )?;
        if before.rows.iter().any(|row| {
            matches!(
                row.table(),
                "conflict_resolution_native_activations"
                    | "conflict_resolution_native_creators"
                    | "conflict_resolution_native_phases"
            )
        }) {
            return Err(invalid(
                "conflict whole CREATE is one-shot; no writer reopen",
            ));
        }
        admission.residue.verify(&admission.selected)?;
        self.verify_conflict_creator_cas(&admission)?;
        tx.commit()?;
        let mut keys = BTreeMap::new();
        if admission.selected.base.is_none() {
            self.create_conflict_directory(
                &admission,
                0,
                &admission.selected.directories[0].held,
                &mut keys,
            )?;
        }
        let base = directory(&base_path(&admission))?.held;
        self.create_conflict_directory(&admission, 1, &base, &mut keys)?;
        let owner = directory(&owner_path(&admission))?.held;
        let mut payloads = BTreeMap::new();
        for action in &admission.selected.layout.actions {
            let Some(component) = &action.payload_component else {
                continue;
            };
            let step = 2 + payloads.len() as u64;
            self.fulfill_conflict_creator(&admission, &format!("activate/{step}"), &keys, || {
                original_scope(&admission, &keys)
            })?;
            original_scope(&admission, &keys)?;
            let payload = owner.create_new_file(component)?;
            let original = payload.original_creation()?;
            let key = descriptive(original.key()?);
            keys.insert(step, key.clone());
            self.fulfill_conflict_creator(&admission, &format!("creator/{step}"), &keys, || {
                original.verify()?;
                if descriptive(original.key()?) != key
                    || descriptive(original.parent_key()?) != keys[&1]
                    || original.created_component() != component
                {
                    return Err(invalid("conflict original payload creator lineage differs"));
                }
                original_scope(&admission, &keys)
            })?;
            payloads.insert(action.entry_id.clone(), (step, payload));
        }
        let creation = ConflictNativeCreation {
            admission,
            base,
            owner,
            keys,
            payloads,
        };
        creation.verify()?;
        Ok(creation)
    }

    pub fn seal_conflict_native_payloads(
        &mut self,
        creation: ConflictNativeCreation,
    ) -> Result<ConflictNativeReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict whole seal refuses caller transaction"));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.read_view().audit_local_commit_capacity(
            &creation.admission.selected.header.target.space_id,
            storage_policy::capacity_limits(self.max_storage_entries)?,
        )?;
        if !before.report.within_accounted_limits() {
            return Err(invalid("conflict whole seal lowered exact capacity"));
        }
        self.verify_conflict_creator_cas(&creation.admission)?;
        creation.verify()?;
        for (_, payload) in creation.payloads.values() {
            payload.reader().sync_all()?;
        }
        let ConflictNativeCreation {
            admission,
            base,
            owner,
            keys,
            payloads,
        } = creation;
        // Close ALL original writers before even the first payload read is opened.
        drop(payloads);
        let mut payloads = BTreeMap::new();
        for action in &admission.selected.layout.actions {
            if let Some(component) = &action.payload_component {
                let file = LockedFile::open(&owner_path(&admission).join(component))?;
                let step = 2 + payloads.len() as u64;
                if descriptive(file.key()?) != keys[&step] {
                    return Err(invalid("conflict original sealed payload fullkey differs"));
                }
                payloads.insert(action.entry_id.clone(), file);
            }
        }
        let readiness = ConflictNativeReadiness {
            admission,
            base,
            owner,
            keys,
            payloads,
        };
        readiness.verify_content()?;
        let after = self.read_view().audit_local_commit_capacity(
            &readiness.admission.selected.header.target.space_id,
            before.report.limits(),
        )?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid("conflict whole seal changed exact Journal values"));
        }
        tx.commit()?;
        self.fulfill_conflict_creator(
            &readiness.admission,
            "phase/ready",
            &readiness.keys,
            || readiness.verify_content(),
        )?;
        Ok(readiness)
    }
}

impl ConflictNativeReadiness {
    pub fn transaction_id(&self) -> &EntryId {
        &self.admission.header.transaction_id
    }
    pub fn verify_content(&self) -> Result<()> {
        original_scope(&self.admission, &self.keys)?;
        if descriptive(self.owner.key()?) != self.keys[&1]
            || descriptive(self.base.key()?) != base_key(&self.admission, &self.keys)?
        {
            return Err(invalid("conflict whole Ready retained directories differ"));
        }
        let expected: BTreeSet<_> = self
            .admission
            .selected
            .layout
            .actions
            .iter()
            .filter_map(|action| action.payload_component.as_ref())
            .map(|component| owner_path(&self.admission).join(component))
            .collect();
        if owner_membership(&self.admission)? != expected || expected.len() != self.payloads.len() {
            return Err(invalid(
                "conflict whole Ready exact payload membership differs",
            ));
        }
        let mut payload_step = 2;
        for action in &self.admission.selected.layout.actions {
            if let Some(component) = &action.payload_component {
                let entry = action
                    .target
                    .as_ref()
                    .ok_or(invalid("conflict whole Ready target entry absent"))?;
                let file = self
                    .payloads
                    .get(&action.entry_id)
                    .ok_or(invalid("conflict whole Ready payload absent"))?;
                let path = owner_path(&self.admission).join(component);
                if !file.matches_path(&path)?
                    || descriptive(file.key()?) != self.keys[&payload_step]
                {
                    return Err(invalid(
                        "conflict whole Ready original payload slot differs",
                    ));
                }
                sync_extend_platform_fs::verify_regular_file(file.reader())?;
                super::super::verify_content(file.reader(), entry)?;
                payload_step += 1;
            }
        }
        Ok(())
    }
}
