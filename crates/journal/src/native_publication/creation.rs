//! The Journal directly performs each selected CREATE after durable activation.
use super::{issuance, peak, physical, steps, Ancestor, Header, Key};
use crate::{
    storage_capacity::CapacitySnapshot,
    storage_inventory::reader::{hash, invalid},
    storage_policy, CasAccessGuard, Journal, JournalStorageColumn, JournalStorageColumnValue,
    PublicationState, Result,
};
use rusqlite::{params_from_iter, types::Value, Transaction, TransactionBehavior};
use std::{collections::BTreeMap, fs::File, path::PathBuf};
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, EntryId};
use sync_extend_platform_fs::{
    FileKey, LockedDirectory, LockedDirectoryMutation, OriginalDirectoryCreation,
    OriginalFileCreation, OwnedFileCreation,
};

enum Original<'a> {
    Directory(OriginalDirectoryCreation<'a>),
    File(OriginalFileCreation<'a>),
}
impl Original<'_> {
    fn verify(&self) -> Result<()> {
        match self {
            Self::Directory(proof) => proof.verify()?,
            Self::File(proof) => proof.verify()?,
        }
        Ok(())
    }
    fn key(&self) -> Result<FileKey> {
        Ok(match self {
            Self::Directory(p) => p.key()?,
            Self::File(p) => p.key()?,
        })
    }
    fn parent(&self) -> Result<FileKey> {
        Ok(match self {
            Self::Directory(p) => p.parent_key()?,
            Self::File(p) => p.parent_key()?,
        })
    }
    fn component(&self) -> &str {
        match self {
            Self::Directory(p) => p.created_component(),
            Self::File(p) => p.created_component(),
        }
    }
}
pub(super) enum Base {
    Existing(LockedDirectory),
    Created(LockedDirectoryMutation),
}
impl Base {
    pub(super) fn require_case_insensitive(&self) -> Result<()> {
        match self {
            Self::Existing(held) => held.require_case_insensitive()?,
            Self::Created(held) => held.require_case_insensitive()?,
        }
        Ok(())
    }
    pub(super) fn key(&self) -> Result<FileKey> {
        Ok(match self {
            Self::Existing(h) => h.key()?,
            Self::Created(h) => h.key()?,
        })
    }
    fn create(&self, name: &str) -> Result<LockedDirectoryMutation> {
        Ok(match self {
            Self::Existing(h) => h.create_new_child(name)?,
            Self::Created(h) => h.create_new_child(name)?,
        })
    }
}
/// Live original creator set only. No path-open constructor, Clone or durable
/// publication grant. Content/Ready/publishing/recovery remain separate stages.
pub struct NativePublicationCreation {
    pub(super) _ancestors: Vec<LockedDirectory>,
    pub(super) _parent: LockedDirectory,
    pub(super) _base: Base,
    pub(super) _owner: LockedDirectoryMutation,
    pub(super) marker: OwnedFileCreation,
    pub(super) payload: OwnedFileCreation,
    pub(super) _cas: CasAccessGuard,
    pub(super) transaction: EntryId,
    pub(super) header: Header,
}
impl NativePublicationCreation {
    pub fn transaction_id(&self) -> &EntryId {
        &self.transaction
    }
    pub fn marker_writer(&mut self) -> &mut File {
        self.marker.writer()
    }
    pub fn payload_writer(&mut self) -> &mut File {
        self.payload.writer()
    }
    pub fn payload_reader(&self) -> &File {
        self.payload.reader()
    }
    pub fn verify_originals(&self) -> Result<()> {
        self._owner.original_creation()?.verify()?;
        self.marker.original_creation()?.verify()?;
        self.payload.original_creation()?.verify()?;
        Ok(())
    }
}
pub(super) fn key(key: FileKey) -> Key {
    Key {
        volume: format!("{:016x}", key.volume),
        id: format!("{:032x}", key.id),
    }
}
fn values_text(value: &str) -> Value {
    Value::Text(value.into())
}
fn column(name: &str, value: &Value) -> Result<JournalStorageColumn> {
    let value = match value {
        Value::Text(s) => JournalStorageColumnValue::Text(s.clone()),
        Value::Integer(n) => JournalStorageColumnValue::Integer(
            u64::try_from(*n).map_err(|_| invalid("native SQL signed integer"))?,
        ),
        _ => return Err(invalid("native SQL value type")),
    };
    Ok(JournalStorageColumn {
        name: name.into(),
        value,
    })
}
type Rows = BTreeMap<(String, Vec<String>), Vec<JournalStorageColumn>>;
fn rows(snapshot: &CapacitySnapshot) -> Rows {
    snapshot
        .rows
        .iter()
        .map(|r| {
            (
                (r.table().into(), r.primary_key().to_vec()),
                r.columns().to_vec(),
            )
        })
        .collect()
}
fn charge(values: &[Value]) -> Result<TreeStorageCharge> {
    let bytes = values.iter().try_fold(0u64, |sum, value| {
        let n = match value {
            Value::Text(s) => s.len() as u64,
            Value::Integer(_) => 8,
            _ => return Err(invalid("native admission value")),
        };
        sum.checked_add(n)
            .ok_or(invalid("native admission overflow"))
    })?;
    Ok(TreeStorageCharge {
        rows: 1,
        logical_bytes: bytes,
    })
}
impl Journal {
    pub(super) fn native_insert(
        &mut self,
        header: &Header,
        table: &'static str,
        values: Vec<Value>,
        reserve: bool,
        before_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&header.intent.space_id, bounds)?;
        let current = self.publication(&header.intent.transaction_id)?;
        if current.intent != header.intent
            || current.state != PublicationState::Preparing
            || current.cleaned
        {
            return Err(invalid("native owner changed before original effect"));
        }
        storage_policy::receive::tree_gate(&before)?;
        if self
            .current(&header.intent.space_id)?
            .map(|m| m.root())
            .transpose()?
            .as_ref()
            != Some(&header.intent.baseline_root)
        {
            return Err(invalid("native creator baseline changed"));
        }
        for id in header
            .intent
            .completion
            .as_ref()
            .ok_or(invalid("native history plan missing"))?
            .protected_objects
            .keys()
        {
            self.require_cas_access(id)?;
        }
        let mut expected = rows(&before);
        let spec = super::schema::TABLES
            .iter()
            .find(|s| s.name == table)
            .ok_or(invalid("native insert table"))?;
        if spec.columns.len() != values.len() {
            return Err(invalid("native insert width"));
        }
        let columns = spec
            .columns
            .iter()
            .zip(&values)
            .map(|(s, v)| column(s.name, v))
            .collect::<Result<Vec<_>>>()?;
        let pk: Vec<_> = spec
            .columns
            .iter()
            .zip(&values)
            .filter(|(s, _)| s.primary_key != 0)
            .map(|(_, v)| match v {
                Value::Text(s) => Ok(s.clone()),
                Value::Integer(n) => Ok(n.to_string()),
                _ => Err(invalid("native insert PK")),
            })
            .collect::<Result<_>>()?;
        if expected.insert((table.into(), pk), columns).is_some() {
            return Err(invalid("one-shot native CREATE already activated"));
        }
        if reserve {
            let added = charge(&values)?;
            let prior = before.report.accounted_total();
            if prior
                .rows
                .checked_add(added.rows)
                .and_then(|n| n.checked_add(header.native_peak.rows))
                .is_none_or(|n| n > bounds.max_rows)
                || prior
                    .logical_bytes
                    .checked_add(added.logical_bytes)
                    .and_then(|n| n.checked_add(header.native_peak.logical_bytes))
                    .is_none_or(|n| n > bounds.max_logical_bytes)
            {
                return Err(invalid(
                    "native full continuation exceeds pre-effect capacity",
                ));
            }
        } else if !before.report.within_accounted_limits() {
            return Err(invalid("native continuation policy lowered"));
        }
        let kind = table
            .strip_prefix("native_publication_")
            .ok_or(invalid("native insert namespace"))?;
        let mut authorized = vec![values_text(kind)];
        authorized.extend(values.clone());
        let _permit = issuance::permit(&self.native_issuance, authorized)?;
        let names = spec
            .columns
            .iter()
            .map(|s| s.name)
            .collect::<Vec<_>>()
            .join(",");
        let params = (1..=values.len())
            .map(|n| format!("?{n}"))
            .collect::<Vec<_>>()
            .join(",");
        if tx.execute(
            &format!("INSERT INTO main.{table}({names}) VALUES({params})"),
            params_from_iter(&values),
        )? != 1
        {
            return Err(invalid("native private INSERT missing"));
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&header.intent.space_id, bounds)?;
        if rows(&after) != expected || !after.report.within_accounted_limits() {
            return Err(invalid("native exact all-value receipt drift or capacity"));
        }
        if !reserve && before.report.accounted_total() != after.report.accounted_total() {
            return Err(invalid("native reservation consumed incorrectly"));
        }
        before_commit()?;
        tx.commit()?;
        Ok(())
    }
    fn native_activate(&mut self, header: &Header, index: u64, parent: &Key) -> Result<Vec<Value>> {
        let planned = steps(header);
        let step = planned
            .get(index as usize)
            .ok_or(invalid("native selected step"))?;
        let values = vec![
            values_text(header.intent.transaction_id.as_str()),
            values_text(header.generation.as_str()),
            Value::Integer(index as i64),
            values_text(hash(header)?.as_str()),
            values_text(&step.component),
            values_text(step.kind),
            values_text(&parent.volume),
            values_text(&parent.id),
        ];
        self.native_insert(
            header,
            "native_publication_activations",
            values.clone(),
            false,
            || Ok(()),
        )?;
        Ok(values)
    }
    fn native_original(
        &mut self,
        header: &Header,
        activation: Vec<Value>,
        proof: Original<'_>,
    ) -> Result<()> {
        proof.verify()?;
        let parent = key(proof.parent()?);
        if activation[4] != values_text(proof.component())
            || activation[6] != values_text(&parent.volume)
            || activation[7] != values_text(&parent.id)
        {
            return Err(invalid(
                "original descriptor does not match private activation",
            ));
        }
        let original = key(proof.key()?);
        let mut values = activation;
        values.extend([values_text(&original.volume), values_text(&original.id)]);
        self.native_insert(header, "native_publication_creators", values, false, || {
            proof.verify()
        })
    }

    /// Opt-in creator protocol over an admitted Preparing publication. Reserve
    /// every owner/marker/payload/phase and all 17 payload attempts BEFORE CREATE.
    /// This does not publish, complete history or adopt a prior native attempt.
    pub fn begin_native_publication_creation(
        &mut self,
        id: &EntryId,
        available_internal_bytes: u64,
    ) -> Result<NativePublicationCreation> {
        if !self.connection.is_autocommit() {
            return Err(invalid("native CREATE refuses caller-owned transaction"));
        }
        let publication = self.publication(id)?;
        let intent = publication.intent;
        if publication.state != PublicationState::Preparing
            || publication.cleaned
            || intent.attempt != 0
            || intent.completion.is_none()
        {
            return Err(invalid(
                "native creator requires initial admitted publication",
            ));
        }
        super::legacy_gate(&self.connection, id)?;
        let root_path = PathBuf::from(
            self.state("worktree")?
                .ok_or(invalid("native root missing"))?,
        );
        if !root_path.is_absolute() {
            return Err(invalid("native root must be absolute"));
        }
        let parent_path = intent
            .target_path
            .parent()
            .map_or(root_path.clone(), |p| root_path.join(p.as_str()));
        let mut ancestors = Vec::new();
        let mut lineage = Vec::new();
        for path in parent_path.ancestors() {
            let held = LockedDirectory::open(path)?;
            held.require_local_ntfs(path)?;
            held.require_case_insensitive()?;
            lineage.push(Ancestor {
                path: path
                    .to_str()
                    .ok_or(invalid("native non-UTF8 ancestor"))?
                    .into(),
                key: key(held.key()?),
            });
            ancestors.push(held);
        }
        let parent = LockedDirectory::open(&parent_path)?;
        let root = LockedDirectory::open(&root_path)?;
        if intent.root_identity.as_ref() != Some(&physical(&key(root.key()?))?)
            || intent.parent_identity.as_ref() != Some(&physical(&key(parent.key()?))?)
        {
            return Err(invalid(
                "native retained root/parent differs from publication",
            ));
        }
        let base_path = parent_path.join(".sync-tmp");
        if base_path.join(id.as_str()).try_exists()? {
            return Err(invalid(
                "legacy staging evidence exists; native protocol cannot adopt",
            ));
        }
        let existing = if base_path.try_exists()? {
            let held = LockedDirectory::open(&base_path)?;
            held.require_local_ntfs(&base_path)?;
            held.require_case_insensitive()?;
            Some(held)
        } else {
            None
        };
        let mut header = Header {
            format: 1,
            intent,
            generation: EntryId::random()?,
            root: key(root.key()?),
            parent: key(parent.key()?),
            ancestors: lineage,
            existing_base: existing.as_ref().map(|h| h.key().map(key)).transpose()?,
            native_peak: TreeStorageCharge::default(),
            worktree_peak_bytes: 0,
        };
        header.worktree_peak_bytes = header
            .intent
            .content
            .length
            .checked_mul(17)
            .and_then(|n| n.checked_add(32))
            .ok_or(invalid("native worktree reservation overflow"))?;
        if header.worktree_peak_bytes > available_internal_bytes {
            return Err(invalid(
                "native worktree peak exceeds available internal budget",
            ));
        }
        header.native_peak = peak(&header)?;
        let cas = self.acquire_cas_coordination()?;
        let json = serde_json::to_string(&header)?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(invalid("native header bytes exceeded"));
        }
        self.native_insert(
            &header,
            "native_publication_headers",
            vec![
                values_text(id.as_str()),
                values_text(header.intent.space_id.as_str()),
                values_text(header.generation.as_str()),
                values_text(hash(&header)?.as_str()),
                Value::Integer(header.native_peak.rows as i64),
                Value::Integer(header.native_peak.logical_bytes as i64),
                values_text(&json),
            ],
            true,
            || Ok(()),
        )?;
        let base = match existing {
            Some(base) => Base::Existing(base),
            None => {
                let activated = self.native_activate(&header, 0, &key(parent.key()?))?;
                let created = parent.create_new_staging_directory()?;
                let proof = created.original_creation()?;
                proof.verify()?;
                self.native_original(&header, activated, Original::Directory(proof))?;
                Base::Created(created)
            }
        };
        let activated = self.native_activate(&header, 1, &key(base.key()?))?;
        let owner = base.create(&format!("native-{}", header.generation))?;
        let proof = owner.original_creation()?;
        proof.verify()?;
        self.native_original(&header, activated, Original::Directory(proof))?;
        let marker = self.native_create_file(&header, &owner, 2, "owner")?;
        let payload = self.native_create_file(&header, &owner, 3, "payload-0")?;
        let created = NativePublicationCreation {
            _ancestors: ancestors,
            _parent: parent,
            _base: base,
            _owner: owner,
            marker,
            payload,
            _cas: cas,
            transaction: id.clone(),
            header,
        };
        created.verify_originals()?;
        Ok(created)
    }
    fn native_create_file(
        &mut self,
        header: &Header,
        parent: &LockedDirectoryMutation,
        index: u64,
        name: &str,
    ) -> Result<OwnedFileCreation> {
        let activated = self.native_activate(header, index, &key(parent.key()?))?;
        let created = parent.create_new_file(name)?;
        let proof = created.original_creation()?;
        proof.verify()?;
        self.native_original(header, activated, Original::File(proof))?;
        Ok(created)
    }
}
