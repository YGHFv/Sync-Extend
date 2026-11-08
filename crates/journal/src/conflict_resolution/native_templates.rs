//! exact future metadata templates; no execution, SQL or native issuance.
use super::*;
use sync_extend_core_model::tree_storage_capacity::TreeStorageCharge;

const MAX_TEMPLATES: usize = 250_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Cell {
    Text(String),
    Integer(u64),
    CreatorVolume(u64),
    CreatorId(u64),
}
impl Cell {
    fn width(&self) -> Result<u64> {
        match self {
            Self::Text(value) => Ok(value.len() as u64),
            Self::Integer(value) if *value <= i64::MAX as u64 => Ok(8),
            Self::CreatorVolume(_) => Ok(16),
            Self::CreatorId(_) => Ok(32),
            _ => Err(invalid("conflict future SQLite integer width")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Dml {
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Template {
    pub name: String,
    pub table: String,
    pub dml: Dml,
    pub prior: Option<Vec<Cell>>,
    pub future: Option<Vec<Cell>>,
    pub dependencies: Vec<String>,
    pub charge: TreeStorageCharge,
    pub ordinary_credit: TreeStorageCharge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub templates: Vec<Template>,
    pub reserved: TreeStorageCharge,
}

fn text(value: impl ToString) -> Cell {
    Cell::Text(value.to_string())
}
fn width(values: &[Cell]) -> Result<u64> {
    values.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(value.width()?)
            .ok_or(invalid("conflict future row width overflow"))
    })
}
fn plus(a: TreeStorageCharge, b: TreeStorageCharge) -> Result<TreeStorageCharge> {
    Ok(TreeStorageCharge {
        rows: a
            .rows
            .checked_add(b.rows)
            .ok_or(invalid("conflict future row charge overflow"))?,
        logical_bytes: a
            .logical_bytes
            .checked_add(b.logical_bytes)
            .ok_or(invalid("conflict future byte charge overflow"))?,
    })
}

pub(super) struct Builder {
    templates: Vec<Template>,
    names: BTreeSet<String>,
    reserved: TreeStorageCharge,
}
impl Builder {
    pub fn new() -> Self {
        Self {
            templates: Vec::new(),
            names: BTreeSet::new(),
            reserved: TreeStorageCharge::default(),
        }
    }
    fn push(
        &mut self,
        name: String,
        table: &str,
        prior: Option<Vec<Cell>>,
        future: Option<Vec<Cell>>,
        dependencies: Vec<String>,
        ordinary_credit: TreeStorageCharge,
    ) -> Result<()> {
        if self.templates.len() >= MAX_TEMPLATES
            || name.is_empty()
            || name.len() > 256
            || !name.is_ascii()
            || self.names.contains(&name)
            || dependencies
                .iter()
                .any(|dependency| !self.names.contains(dependency))
            || dependencies.iter().collect::<BTreeSet<_>>().len() != dependencies.len()
        {
            return Err(invalid("conflict future identity or dependency graph"));
        }
        let (dml, raw) = match (&prior, &future) {
            (None, Some(values)) => (
                Dml::Insert,
                TreeStorageCharge {
                    rows: 1,
                    logical_bytes: width(values)?,
                },
            ),
            (Some(old), Some(new)) => (
                Dml::Update,
                TreeStorageCharge {
                    rows: 0,
                    // Admission never borrows bytes freed by a counterfactual update.
                    logical_bytes: width(new)?.saturating_sub(width(old)?),
                },
            ),
            (Some(_), None) => (Dml::Delete, TreeStorageCharge::default()),
            _ => return Err(invalid("conflict future missing DML values")),
        };
        if ordinary_credit.rows > raw.rows
            || ordinary_credit.logical_bytes > raw.logical_bytes
            || (ordinary_credit != TreeStorageCharge::default()
                && (table != "operations"
                    || dml != Dml::Update
                    || ordinary_credit.rows != 0
                    || ordinary_credit.logical_bytes != 4))
        {
            return Err(invalid(
                "conflict future unrelated ordinary liability credit",
            ));
        }
        let charge = TreeStorageCharge {
            rows: raw.rows - ordinary_credit.rows,
            logical_bytes: raw.logical_bytes - ordinary_credit.logical_bytes,
        };
        self.reserved = plus(self.reserved, charge)?;
        self.names.insert(name.clone());
        self.templates.push(Template {
            name,
            table: table.into(),
            dml,
            prior,
            future,
            dependencies,
            charge,
            ordinary_credit,
        });
        Ok(())
    }
    pub fn insert(
        &mut self,
        name: String,
        table: &str,
        values: Vec<Cell>,
        dependencies: Vec<String>,
    ) -> Result<()> {
        self.push(
            name,
            table,
            None,
            Some(values),
            dependencies,
            TreeStorageCharge::default(),
        )
    }
    pub fn update(
        &mut self,
        name: String,
        table: &str,
        prior: Vec<Cell>,
        future: Vec<Cell>,
        dependencies: Vec<String>,
        credit: TreeStorageCharge,
    ) -> Result<()> {
        self.push(name, table, Some(prior), Some(future), dependencies, credit)
    }
    pub fn delete(
        &mut self,
        name: String,
        table: &str,
        prior: Vec<Cell>,
        dependencies: Vec<String>,
    ) -> Result<()> {
        self.push(
            name,
            table,
            Some(prior),
            None,
            dependencies,
            TreeStorageCharge::default(),
        )
    }
    pub fn finish(self) -> Ledger {
        Ledger {
            templates: self.templates,
            reserved: self.reserved,
        }
    }
}

struct Scope<'a> {
    transaction: &'a EntryId,
    generation: &'a EntryId,
    digest: &'a ContentId,
    root: &'a SnapshotId,
}
impl Scope<'_> {
    fn creator(
        &self,
        builder: &mut Builder,
        step: u64,
        component: &str,
        parent: (Cell, Cell),
        kind: &str,
        dependencies: Vec<String>,
    ) -> Result<String> {
        let activation = format!("activate/{step}");
        let receipt = format!("creator/{step}");
        let values = vec![
            text(self.transaction),
            text(self.generation),
            Cell::Integer(step),
            text(self.digest),
            text(component),
            text(kind),
            parent.0,
            parent.1,
        ];
        builder.insert(
            activation.clone(),
            "conflict_resolution_native_activations",
            values.clone(),
            dependencies,
        )?;
        let mut created = values;
        created.extend([Cell::CreatorVolume(step), Cell::CreatorId(step)]);
        builder.insert(
            receipt.clone(),
            "conflict_resolution_native_creators",
            created,
            vec![activation],
        )?;
        Ok(receipt)
    }

    fn phase(
        &self,
        builder: &mut Builder,
        phase: &str,
        dependencies: Vec<String>,
    ) -> Result<String> {
        let name = format!("phase/{phase}");
        builder.insert(
            name.clone(),
            "conflict_resolution_native_phases",
            vec![
                text(self.transaction),
                text(self.generation),
                text(self.digest),
                text(phase),
                text(self.root),
            ],
            dependencies,
        )?;
        Ok(name)
    }

    fn step(
        &self,
        builder: &mut Builder,
        entry: &EntryId,
        action: &str,
        key: (Cell, Cell),
        dependency: String,
    ) -> Result<String> {
        let executing = format!("{action}/{entry}/executing");
        let observed = format!("{action}/{entry}/observed");
        for (phase, name, depends) in [
            ("executing", executing.clone(), dependency),
            ("observed", observed.clone(), executing),
        ] {
            builder.insert(
                name,
                "conflict_resolution_native_steps",
                vec![
                    text(self.transaction),
                    text(self.generation),
                    text(self.digest),
                    text(entry),
                    text(action),
                    text(phase),
                    key.0.clone(),
                    key.1.clone(),
                ],
                vec![depends],
            )?;
        }
        Ok(observed)
    }

    fn disposition(
        &self,
        builder: &mut Builder,
        component: &str,
        key: (Cell, Cell),
        mut dependency: String,
    ) -> Result<String> {
        for stage in ["intended", "absent", "terminal"] {
            let name = format!("dispose/{component}/{stage}");
            builder.insert(
                name.clone(),
                "conflict_resolution_native_dispositions",
                vec![
                    text(self.transaction),
                    text(self.generation),
                    text(self.digest),
                    text(component),
                    text(stage),
                    key.0.clone(),
                    key.1.clone(),
                ],
                vec![dependency],
            )?;
            dependency = name;
        }
        Ok(dependency)
    }
}

pub(super) struct NativePartition {
    pub builder: Builder,
    pub observed: String,
}

pub(super) fn native_partition(
    parent: &Header,
    binding: &super::native_binding::Binding,
    generation: &EntryId,
    scope_digest: &ContentId,
) -> Result<NativePartition> {
    use sync_extend_core_model::conflict_native_layout::{
        plan_conflict_native_layout, ConflictNativeLayoutLimits,
    };
    binding.validate(parent)?;
    let layout = plan_conflict_native_layout(
        &parent.intent.baseline,
        &parent.target,
        ConflictNativeLayoutLimits::default(),
    )?;
    let id = &parent.transaction_id;
    let root = parent.target.root()?;
    let scope = Scope {
        transaction: id,
        generation,
        digest: scope_digest,
        root: &root,
    };
    let mut builder = Builder::new();
    let base_dependency;
    let base_key = if let Some(base) = &binding.existing_base {
        base_dependency = Vec::new();
        (text(&base.volume), text(&base.id))
    } else {
        base_dependency = vec![scope.creator(
            &mut builder,
            0,
            ".sync-tmp",
            (
                text(&binding.ancestors[0].key.volume),
                text(&binding.ancestors[0].key.id),
            ),
            "directory",
            Vec::new(),
        )?];
        (Cell::CreatorVolume(0), Cell::CreatorId(0))
    };
    let owner = scope.creator(
        &mut builder,
        1,
        &format!("conflict-{generation}"),
        base_key,
        "directory",
        base_dependency,
    )?;
    let mut payload_steps = BTreeMap::new();
    let mut creators = vec![owner.clone()];
    for action in &layout.actions {
        if let Some(component) = &action.payload_component {
            let number = 2 + payload_steps.len() as u64;
            creators.push(scope.creator(
                &mut builder,
                number,
                component,
                (Cell::CreatorVolume(1), Cell::CreatorId(1)),
                "file",
                vec![owner.clone()],
            )?);
            payload_steps.insert(action.entry_id.clone(), number);
        }
    }
    let mut prior = scope.phase(&mut builder, "ready", creators)?;
    for entry in &layout.quarantine_order {
        let key = binding
            .originals
            .get(entry)
            .ok_or(invalid("conflict future complete original key missing"))?;
        prior = scope.step(
            &mut builder,
            entry,
            "quarantine",
            (text(&key.volume), text(&key.id)),
            prior,
        )?;
    }
    prior = scope.phase(&mut builder, "quarantined", vec![prior])?;
    for entry in &layout.publication_order {
        let key = if let Some(step) = payload_steps.get(entry) {
            (Cell::CreatorVolume(*step), Cell::CreatorId(*step))
        } else {
            let key = binding
                .originals
                .get(entry)
                .ok_or(invalid("conflict future original publication key missing"))?;
            (text(&key.volume), text(&key.id))
        };
        prior = scope.step(&mut builder, entry, "publish", key, prior)?;
    }
    let observed = scope.phase(&mut builder, "observed", vec![prior])?;
    Ok(NativePartition { builder, observed })
}

pub(super) fn cleanup_partition(
    mut builder: Builder,
    parent: &Header,
    binding: &super::native_binding::Binding,
    generation: &EntryId,
    scope_digest: &ContentId,
    final_dependencies: Vec<String>,
    branch_owners: &[super::native_history_templates::BranchOwner],
) -> Result<Ledger> {
    use sync_extend_core_model::conflict_native_layout::{
        plan_conflict_native_layout, ConflictNativeActionKind, ConflictNativeLayoutLimits,
    };
    let layout = plan_conflict_native_layout(
        &parent.intent.baseline,
        &parent.target,
        ConflictNativeLayoutLimits::default(),
    )?;
    let id = &parent.transaction_id;
    let root = parent.target.root()?;
    let scope = Scope {
        transaction: id,
        generation,
        digest: scope_digest,
        root: &root,
    };
    let final_phase = scope.phase(&mut builder, "final", final_dependencies)?;
    let handoff = scope.phase(&mut builder, "history_handoff", vec![final_phase.clone()])?;
    let mut terminal = vec![handoff.clone()];
    for ((role, content), length) in pins(parent)? {
        let name = format!("release/c3/{role}/{content}");
        builder.delete(
            name.clone(),
            "conflict_resolution_objects",
            vec![
                text(id),
                text(role),
                text(content),
                Cell::Integer(u64::from(length)),
            ],
            vec![handoff.clone()],
        )?;
        terminal.push(name);
    }
    for owner in branch_owners {
        for content in &owner.objects {
            let name = format!("release/branch/{}/{content}", owner.owner_id);
            builder.delete(
                name.clone(),
                "reference_reservation_objects",
                vec![text(&owner.owner_id), text(content)],
                vec![handoff.clone()],
            )?;
            terminal.push(name);
        }
    }
    for action in &layout.actions {
        if matches!(
            action.kind,
            ConflictNativeActionKind::QuarantineOriginal
                | ConflictNativeActionKind::ReplaceOriginal
        ) {
            let key = binding
                .originals
                .get(&action.entry_id)
                .ok_or(invalid("conflict future cleanup original key missing"))?;
            terminal.push(scope.disposition(
                &mut builder,
                action.original_component.as_deref().ok_or(invalid(
                    "conflict future cleanup original component missing",
                ))?,
                (text(&key.volume), text(&key.id)),
                handoff.clone(),
            )?);
        }
    }
    let files_cleaned = scope.phase(&mut builder, "files_cleaned", terminal)?;
    let owner_terminal = scope.disposition(
        &mut builder,
        &format!("conflict-{generation}"),
        (Cell::CreatorVolume(1), Cell::CreatorId(1)),
        files_cleaned,
    )?;
    let last = if binding.existing_base.is_none() {
        scope.disposition(
            &mut builder,
            ".sync-tmp",
            (Cell::CreatorVolume(0), Cell::CreatorId(0)),
            owner_terminal,
        )?
    } else {
        owner_terminal
    };
    scope.phase(&mut builder, "cleanup", vec![last])?;
    Ok(builder.finish())
}
