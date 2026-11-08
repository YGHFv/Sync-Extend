//! immutable whole future ledger. Effects remain deliberately unavailable.
use super::*;
use super::{
    native_binding::Binding,
    native_history_templates::{history_partition, HistorySelection},
    native_templates::{cleanup_partition, native_partition, Ledger},
};
use sync_extend_core_model::tree_storage_capacity::TreeStorageCharge;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResidueDirectory {
    pub path: String,
    pub key: super::native_binding::Key,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResidueFile {
    pub path: String,
    pub key: super::native_binding::Key,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Residue {
    pub directories: Vec<ResidueDirectory>,
    pub files: Vec<ResidueFile>,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeHeader {
    pub format: u32,
    pub transaction_id: EntryId,
    pub parent_hash: ContentId,
    pub binding_hash: ContentId,
    pub generation: EntryId,
    pub layout_hash: ContentId,
    pub history: HistorySelection,
    pub residue: Residue,
    pub native_peak: u64,
    pub ledger_hash: ContentId,
    pub reserved: TreeStorageCharge,
}

fn layout(
    header: &Header,
) -> Result<sync_extend_core_model::conflict_native_layout::ConflictNativeLayout> {
    use sync_extend_core_model::conflict_native_layout::{
        plan_conflict_native_layout, ConflictNativeLayoutLimits,
    };
    Ok(plan_conflict_native_layout(
        &header.intent.baseline,
        &header.target,
        ConflictNativeLayoutLimits::default(),
    )?)
}

impl Residue {
    fn validate(&self, parent: &Header, binding: &Binding, generation: &EntryId) -> Result<()> {
        use std::path::{Component, Path};
        let base = Path::new(&parent.intent.worktree).join(".sync-tmp");
        let owner = base.join(format!("conflict-{generation}"));
        if self.directories.len().saturating_add(self.files.len())
            > sync_extend_core_model::limits::MAX_ENTRIES
            || self
                .directories
                .windows(2)
                .any(|rows| rows[0].path >= rows[1].path)
            || self
                .files
                .windows(2)
                .any(|rows| rows[0].path >= rows[1].path)
            || (binding.existing_base.is_none()
                && (!self.directories.is_empty() || !self.files.is_empty() || self.bytes != 0))
        {
            return Err(invalid("conflict future bounded actual residue"));
        }
        let mut keys = BTreeSet::new();
        for key in binding
            .ancestors
            .iter()
            .map(|a| &a.key)
            .chain(binding.existing_base.iter())
            .chain(std::iter::once(&binding.marker_directory))
            .chain(std::iter::once(&binding.marker_file))
            .chain(binding.originals.values())
        {
            keys.insert(key.clone());
        }
        let mut paths = BTreeSet::new();
        paths.insert(base.clone());
        for (path, key) in self
            .directories
            .iter()
            .map(|row| (&row.path, &row.key))
            .chain(self.files.iter().map(|row| (&row.path, &row.key)))
        {
            let path = Path::new(path);
            let relative = path
                .strip_prefix(&base)
                .map_err(|_| invalid("conflict future residue outside borrowed base"))?;
            if relative.components().count() == 0
                || relative.components().count() > 128
                || relative
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || path.starts_with(&owner)
                || !paths.insert(path.to_path_buf())
                || key.volume != binding.ancestors[0].key.volume
                || !keys.insert(key.clone())
            {
                return Err(invalid(
                    "conflict future residue alias, scope or owner collision",
                ));
            }
            if [(&key.volume, 16), (&key.id, 32)]
                .into_iter()
                .any(|(value, width)| {
                    value.len() != width
                        || !value
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
            {
                return Err(invalid("conflict future residue full native key width"));
            }
        }
        let directory_paths: BTreeSet<_> = std::iter::once(base.clone())
            .chain(
                self.directories
                    .iter()
                    .map(|r| Path::new(&r.path).to_path_buf()),
            )
            .collect();
        for path in paths {
            if path != base && path.parent().is_some_and(|p| !directory_paths.contains(p)) {
                return Err(invalid("conflict future residue parent not held"));
            }
        }
        let bytes = self.files.iter().try_fold(0u64, |sum, file| {
            sum.checked_add(file.length)
                .ok_or(invalid("conflict future actual residue byte overflow"))
        })?;
        if bytes != self.bytes {
            return Err(invalid("conflict future actual residue sum differs"));
        }
        Ok(())
    }
}

impl NativeHeader {
    fn scope_hash(&self) -> Result<ContentId> {
        hash(&(
            "SyncExtend original whole conflict future scope v1",
            self.format,
            &self.transaction_id,
            &self.parent_hash,
            &self.binding_hash,
            &self.generation,
            &self.layout_hash,
            &self.history,
            &self.residue,
            self.native_peak,
        ))
    }
    #[cfg(windows)]
    pub(super) fn build(
        parent: &Header,
        binding: &Binding,
        generation: EntryId,
        history: HistorySelection,
        residue: Residue,
    ) -> Result<(Self, Ledger)> {
        binding.validate(parent)?;
        residue.validate(parent, binding, &generation)?;
        let layout = layout(parent)?;
        let mut header = Self {
            format: 1,
            transaction_id: parent.transaction_id.clone(),
            parent_hash: hash(parent)?,
            binding_hash: hash(binding)?,
            generation,
            layout_hash: layout.fingerprint()?,
            history,
            native_peak: layout
                .internal_peak_bytes
                .checked_add(residue.bytes)
                .ok_or(invalid("conflict future whole native peak overflow"))?,
            residue,
            ledger_hash: ContentId::hash(b"unbuilt future ledger"),
            reserved: TreeStorageCharge::default(),
        };
        let ledger = header.ledger(parent, binding)?;
        super::native_template_schema::validate(&ledger)?;
        header.ledger_hash = hash(&ledger)?;
        header.reserved = ledger.reserved;
        if serde_json::to_vec(&header)?.len() > crate::MAX_OPERATION_BYTES {
            return Err(invalid("conflict future immutable header encoded budget"));
        }
        Ok((header, ledger))
    }
    pub(super) fn ledger(&self, parent: &Header, binding: &Binding) -> Result<Ledger> {
        let scope = self.scope_hash()?;
        let native = native_partition(parent, binding, &self.generation, &scope)?;
        let (builder, dependencies) =
            history_partition(native, parent, &self.generation, &self.history)?;
        cleanup_partition(
            builder,
            parent,
            binding,
            &self.generation,
            &scope,
            dependencies,
            &self.history.branch_owners,
        )
    }
    pub(super) fn validate(&self, parent: &Header, binding: &Binding) -> Result<Ledger> {
        binding.validate(parent)?;
        self.residue.validate(parent, binding, &self.generation)?;
        let layout = layout(parent)?;
        if self.format != 1
            || self.transaction_id != parent.transaction_id
            || self.generation == self.transaction_id
            || parent
                .intent
                .baseline
                .entries
                .contains_key(&self.generation)
            || parent.target.entries.contains_key(&self.generation)
            || parent
                .intent
                .baseline
                .tombstones
                .contains_key(&self.generation)
            || parent.target.tombstones.contains_key(&self.generation)
            || self.parent_hash != hash(parent)?
            || self.binding_hash != hash(binding)?
            || self.layout_hash != layout.fingerprint()?
            || self.native_peak
                != layout
                    .internal_peak_bytes
                    .checked_add(self.residue.bytes)
                    .ok_or(invalid("conflict future native peak overflow"))?
        {
            return Err(invalid("conflict future immutable native scope differs"));
        }
        let ledger = self.ledger(parent, binding)?;
        super::native_template_schema::validate(&ledger)?;
        if self.ledger_hash != hash(&ledger)? || self.reserved != ledger.reserved {
            return Err(invalid("conflict future complete exact ledger differs"));
        }
        Ok(ledger)
    }
}
