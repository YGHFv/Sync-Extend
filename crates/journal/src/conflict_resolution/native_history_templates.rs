//! counterfactual full original history, never a materialization grant.
use super::native_templates::{Builder, Cell, NativePartition};
use super::*;
use crate::JournalStorageColumnValue;
use sync_extend_core_model::tree_storage_capacity::TreeStorageCharge;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExistingRow {
    pub table: String,
    pub primary_key: Vec<String>,
    pub columns: Vec<Cell>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HistorySelection {
    pub format: u32,
    pub existing: Vec<ExistingRow>,
    pub branch_owners: Vec<BranchOwner>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BranchOwner {
    pub owner_id: EntryId,
    pub intent: crate::ReferenceReservationIntent,
    pub objects: Vec<ContentId>,
}

#[derive(Serialize)]
struct Record<'a> {
    format: u32,
    transaction_id: &'a EntryId,
    generation: &'a EntryId,
    parent_hash: ContentId,
    original: &'a Header,
    plan: &'a FileResolutionPlan,
    all_branch_objects: Vec<(String, ContentId, u32)>,
    branch_owners: &'a [BranchOwner],
}

fn text(value: impl ToString) -> Cell {
    Cell::Text(value.to_string())
}
fn encoded(value: &impl Serialize) -> Result<String> {
    let json = serde_json::to_string(value)?;
    if json.len() > crate::MAX_OPERATION_BYTES {
        return Err(invalid("conflict future history encoded budget"));
    }
    Ok(json)
}
fn actual(row: &JournalStoredRow) -> Result<ExistingRow> {
    Ok(ExistingRow {
        table: row.table().into(),
        primary_key: row.primary_key().to_vec(),
        columns: row
            .columns()
            .iter()
            .map(|column| match &column.value {
                JournalStorageColumnValue::Text(s) => Ok(Cell::Text(s.clone())),
                JournalStorageColumnValue::Integer(n) => Ok(Cell::Integer(*n)),
                _ => Err(invalid("conflict future unsupported history null")),
            })
            .collect::<Result<_>>()?,
    })
}

impl HistorySelection {
    pub(super) fn from_actual(header: &Header, rows: &[JournalStoredRow]) -> Result<Self> {
        let root = header.target.root()?;
        let space = header.target.space_id.as_str();
        let mut existing = Vec::new();
        for row in rows {
            let included = match row.table() {
                "snapshots" => row.primary_key() == [root.as_str()],
                "snapshot_objects" => {
                    row.primary_key().first().map(String::as_str) == Some(root.as_str())
                }
                "current_manifests" | "rename_observations" => row.primary_key() == [space],
                _ => false,
            };
            if included {
                existing.push(actual(row)?);
            }
        }
        existing.sort_by(|a, b| (&a.table, &a.primary_key).cmp(&(&b.table, &b.primary_key)));
        let selected = Self {
            format: 1,
            existing,
            branch_owners: BranchOwner::from_actual(header, rows)?,
        };
        selected.validate(header)?;
        Ok(selected)
    }
    fn row(&self, table: &str, primary: &[&str]) -> Option<&[Cell]> {
        self.existing
            .iter()
            .find(|row| {
                row.table == table
                    && row
                        .primary_key
                        .iter()
                        .map(String::as_str)
                        .eq(primary.iter().copied())
            })
            .map(|row| row.columns.as_slice())
    }
    fn validate(&self, header: &Header) -> Result<()> {
        let root = header.target.root()?;
        let space = header.target.space_id.as_str();
        if self.format != 1
            || self.existing.windows(2).any(|rows| {
                (&rows[0].table, &rows[0].primary_key) >= (&rows[1].table, &rows[1].primary_key)
            })
            || self.row("current_manifests", &[space])
                != Some([text(space), text(header.intent.baseline.root()?)].as_slice())
        {
            return Err(invalid(
                "conflict future complete history selection differs",
            ));
        }
        if self.branch_owners.len() > 1 {
            return Err(invalid("conflict future ambiguous canonical branch owner"));
        }
        for owner in &self.branch_owners {
            owner.validate(header)?;
        }
        let objects: BTreeSet<_> = header
            .target
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .flat_map(|f| f.chunks.iter().map(|c| c.content_id.as_str()))
            .collect();
        let snapshot = self.row("snapshots", &[root.as_str()]);
        for row in &self.existing {
            match row.table.as_str() {
                "current_manifests" if row.primary_key == [space] => {}
                "rename_observations" if row.primary_key == [space] => {
                    if row.columns.len() != 4
                        || row.columns[0] != text(space)
                        || row.columns[1] != text(header.intent.baseline.root()?)
                    {
                        return Err(invalid("conflict future old rename inference scope"));
                    }
                    let (Cell::Text(json), Cell::Text(digest)) = (&row.columns[2], &row.columns[3])
                    else {
                        return Err(invalid("conflict future old rename inference columns"));
                    };
                    let map: sync_extend_core_model::persisted_rename::RenameObservationMap =
                        serde_json::from_str(json)?;
                    map.validate(
                        &header.intent.baseline,
                        sync_extend_core_model::limits::MAX_ENTRIES,
                    )?;
                    if encoded(&map)? != *json
                        || ContentId::hash(json.as_bytes()).as_str() != digest
                    {
                        return Err(invalid("conflict future old rename inference integrity"));
                    }
                }
                "snapshots" if row.primary_key == [root.as_str()] => {
                    if row.columns.len() != 6
                        || row.columns[0] != text(&root)
                        || row.columns[1] != text(space)
                        || row.columns[2] != text(encoded(&header.target)?)
                        || !matches!(&row.columns[3], Cell::Integer(n) if *n <= i64::MAX as u64)
                        || !matches!(&row.columns[4], Cell::Text(s)
                            if matches!(s.as_str(), "metadata_only" | "content_closed" | "materialized"))
                        || !matches!(&row.columns[5], Cell::Integer(0 | 1))
                    {
                        return Err(invalid("conflict future existing target snapshot differs"));
                    }
                }
                "snapshot_objects"
                    if row.primary_key.len() == 2
                        && row.primary_key[0] == root.as_str()
                        && objects.contains(row.primary_key[1].as_str())
                        && snapshot.is_some()
                        && row.columns == [text(&root), text(&row.primary_key[1])] => {}
                _ => return Err(invalid("conflict future foreign history selection row")),
            }
        }
        Ok(())
    }
}

impl BranchOwner {
    fn canonical(header: &Header) -> Result<crate::ReferenceReservationIntent> {
        use sync_extend_core_model::reference_owner::{ReferenceOwnerKind, ReferenceOwnerScope};
        let plan = header.plan()?;
        let fingerprint = plan.fingerprint()?;
        let owner_id: EntryId = ContentId::hash(
            format!("SyncExtend canonical conflict branch owner v1:{fingerprint}").as_bytes(),
        )
        .as_str()[..32]
            .parse()?;
        let mut files = BTreeMap::new();
        for file in &plan.files {
            let content = file
                .entry
                .content
                .as_ref()
                .ok_or(invalid("conflict future canonical branch content absent"))?;
            files
                .entry(serde_json::to_vec(content)?)
                .or_insert_with(|| content.clone());
        }
        Ok(crate::ReferenceReservationIntent {
            owner_id,
            scope: ReferenceOwnerScope {
                format_version: sync_extend_core_model::FORMAT_VERSION,
                space_id: header.target.space_id.clone(),
                kind: ReferenceOwnerKind::Conflict,
                target_device: None,
                files: files.into_values().collect(),
            },
            created_at_ms: 0,
        })
    }
    fn objects(intent: &crate::ReferenceReservationIntent) -> Vec<ContentId> {
        intent
            .scope
            .files
            .iter()
            .flat_map(|file| file.chunks.iter().map(|chunk| chunk.content_id.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    fn validate(&self, header: &Header) -> Result<()> {
        let canonical = Self::canonical(header)?;
        if self.owner_id != canonical.owner_id
            || self.intent != canonical
            || self.objects != Self::objects(&canonical)
        {
            return Err(invalid("conflict future canonical branch handoff differs"));
        }
        Ok(())
    }
    fn from_actual(header: &Header, rows: &[JournalStoredRow]) -> Result<Vec<Self>> {
        let canonical = Self::canonical(header)?;
        let matching: Vec<_> = rows
            .iter()
            .filter(|row| {
                row.table() == "reference_reservations"
                    && row.primary_key() == [canonical.owner_id.as_str()]
            })
            .collect();
        if matching.is_empty() {
            return Ok(Vec::new());
        }
        if matching.len() != 1 {
            return Err(invalid("conflict future canonical branch owner ambiguous"));
        }
        let owner = matching[0];
        let column = |name: &str| -> Result<&crate::JournalStorageColumnValue> {
            owner
                .columns()
                .iter()
                .find(|column| column.name == name)
                .map(|column| &column.value)
                .ok_or(invalid(
                    "conflict future canonical branch owner column absent",
                ))
        };
        if column("intent")? != &crate::JournalStorageColumnValue::Text(encoded(&canonical)?)
            || column("intent_hash")?
                != &crate::JournalStorageColumnValue::Text(
                    ContentId::hash(encoded(&canonical)?.as_bytes()).to_string(),
                )
            || rows.iter().any(|row| {
                row.table() == "reference_snapshot_handoffs"
                    && row.primary_key() == [canonical.owner_id.as_str()]
            })
        {
            return Err(invalid(
                "conflict future original canonical branch owner changed",
            ));
        }
        let objects = Self::objects(&canonical);
        let actual: BTreeSet<_> = rows
            .iter()
            .filter(|row| {
                row.table() == "reference_reservation_objects"
                    && row.primary_key().first().map(String::as_str)
                        == Some(canonical.owner_id.as_str())
            })
            .map(|row| row.primary_key()[1].clone())
            .collect();
        if actual != objects.iter().map(ToString::to_string).collect() {
            return Err(invalid(
                "conflict future canonical branch owner pins differ",
            ));
        }
        Ok(vec![Self {
            owner_id: canonical.owner_id.clone(),
            intent: canonical,
            objects,
        }])
    }
}

pub(super) fn history_partition(
    native: NativePartition,
    header: &Header,
    generation: &EntryId,
    selection: &HistorySelection,
) -> Result<(Builder, Vec<String>)> {
    selection.validate(header)?;
    let NativePartition {
        mut builder,
        observed,
    } = native;
    let id = &header.transaction_id;
    let space = header.target.space_id.as_str();
    let root = header.target.root()?;
    let p = &header.intent.proof.payload;
    let plan = header.plan()?;
    let mut final_dependencies = vec![observed.clone()];
    for original in &p.originals {
        let op = &original.operation;
        if header
            .original_states
            .get(op.op_id.as_str())
            .map(String::as_str)
            == Some("received")
        {
            let name = format!("history/materialize/{}", op.op_id);
            let mut prior = vec![
                text(&op.op_id),
                text(space),
                text(&op.payload.origin_device_id),
                Cell::Integer(op.payload.origin_seq),
                text(encoded(op)?),
                text("received"),
            ];
            let mut future = prior.clone();
            future[5] = text("materialized");
            builder.update(
                name.clone(),
                "operations",
                std::mem::take(&mut prior),
                future,
                vec![observed.clone()],
                TreeStorageCharge {
                    rows: 0,
                    logical_bytes: 4,
                },
            )?;
            final_dependencies.push(name);
        }
    }
    let mut prior = observed.clone();
    for (index, signed) in p.resolving.iter().enumerate() {
        let op = &signed.operation;
        let name = format!("history/resolve/{}", op.op_id);
        let values = vec![
            text(&op.op_id),
            text(space),
            text(&op.payload.origin_device_id),
            Cell::Integer(op.payload.origin_seq),
            text(encoded(op)?),
            text("materialized"),
        ];
        if header
            .foreign
            .as_ref()
            .is_some_and(|scope| index < scope.received_resolving_operations)
        {
            let mut old = values.clone();
            old[5] = text("received");
            builder.update(
                name.clone(),
                "operations",
                old,
                values,
                vec![prior],
                TreeStorageCharge {
                    rows: 0,
                    logical_bytes: 4,
                },
            )?;
        } else {
            builder.insert(name.clone(), "operations", values, vec![prior])?;
        }
        prior = name;
    }
    let cursor = format!("history/cursor/{}", p.resolver_device);
    let before_cursor = header
        .foreign
        .as_ref()
        .map_or(plan.received_vector.get(&p.resolver_device), |scope| {
            scope.received_vector.get(&p.resolver_device)
        });
    let values = vec![
        text(space),
        text(&p.resolver_device),
        Cell::Integer(header.target.version_vector.get(&p.resolver_device)),
    ];
    if header.foreign.is_some() && before_cursor == 0 {
        builder.insert(cursor.clone(), "receive_cursors", values, vec![prior])?;
    } else {
        builder.update(
            cursor.clone(),
            "receive_cursors",
            vec![
                text(space),
                text(&p.resolver_device),
                Cell::Integer(before_cursor),
            ],
            values,
            vec![prior],
            TreeStorageCharge::default(),
        )?;
    }
    final_dependencies.push(cursor);
    let snapshot = format!("history/snapshot/{root}");
    if let Some(existing) = selection.row("snapshots", &[root.as_str()]) {
        let mut values = existing.to_vec();
        values[4] = text("materialized");
        builder.update(
            snapshot.clone(),
            "snapshots",
            existing.to_vec(),
            values,
            vec![observed.clone()],
            TreeStorageCharge::default(),
        )?;
    } else {
        builder.insert(
            snapshot.clone(),
            "snapshots",
            vec![
                text(&root),
                text(space),
                text(encoded(&header.target)?),
                Cell::Integer(p.created_at_ms),
                text("materialized"),
                Cell::Integer(0),
            ],
            vec![observed.clone()],
        )?;
    }
    final_dependencies.push(snapshot.clone());
    let objects: BTreeSet<_> = header
        .target
        .entries
        .values()
        .filter_map(|e| e.content.as_ref())
        .flat_map(|f| f.chunks.iter().map(|c| c.content_id.clone()))
        .collect();
    for content in objects {
        if selection
            .row("snapshot_objects", &[root.as_str(), content.as_str()])
            .is_none()
        {
            let name = format!("history/snapshot-pin/{content}");
            builder.insert(
                name.clone(),
                "snapshot_objects",
                vec![text(&root), text(&content)],
                vec![snapshot.clone()],
            )?;
            final_dependencies.push(name);
        }
    }
    let current = format!("history/current/{space}");
    builder.update(
        current.clone(),
        "current_manifests",
        selection
            .row("current_manifests", &[space])
            .ok_or(invalid("conflict future current pointer missing"))?
            .to_vec(),
        vec![text(space), text(&root)],
        vec![snapshot],
        TreeStorageCharge::default(),
    )?;
    final_dependencies.push(current.clone());
    if let Some(columns) = selection.row("rename_observations", &[space]) {
        let name = format!("history/invalidate-rename/{space}");
        builder.delete(
            name.clone(),
            "rename_observations",
            columns.to_vec(),
            vec![current],
        )?;
        final_dependencies.push(name);
    }
    let record = encoded(&Record {
        format: 1,
        transaction_id: id,
        generation,
        parent_hash: hash(header)?,
        original: header,
        plan: &plan,
        all_branch_objects: pins(header)?
            .into_iter()
            .map(|((role, content), length)| (role, content, length))
            .collect(),
        branch_owners: &selection.branch_owners,
    })?;
    let history = "history/complete".to_string();
    builder.insert(
        history.clone(),
        "conflict_resolution_native_history",
        vec![
            text(id),
            text(generation),
            text(hash(header)?),
            text(&root),
            text(ContentId::hash(record.as_bytes())),
            text(record),
        ],
        vec![observed],
    )?;
    final_dependencies.push(history.clone());
    for (number, event) in plan.events.iter().enumerate() {
        let record = encoded(event)?;
        let name = format!("history/event/{number}");
        builder.insert(
            name.clone(),
            "conflict_resolution_native_events",
            vec![
                text(id),
                text(generation),
                Cell::Integer(number as u64),
                text(ContentId::hash(record.as_bytes())),
                text(record),
            ],
            vec![history.clone()],
        )?;
        final_dependencies.push(name);
    }
    for ((role, content), length) in pins(header)? {
        let name = format!("history/branch-pin/{role}/{content}");
        builder.insert(
            name.clone(),
            "conflict_resolution_native_history_objects",
            vec![
                text(id),
                text(role),
                text(content),
                Cell::Integer(u64::from(length)),
            ],
            vec![history.clone()],
        )?;
        final_dependencies.push(name);
    }
    for owner in &selection.branch_owners {
        let name = format!("history/branch-handoff/{}", owner.owner_id);
        builder.insert(
            name.clone(),
            "conflict_resolution_native_branch_handoffs",
            vec![
                text(id),
                text(&owner.owner_id),
                text(ContentId::hash(encoded(&owner.intent)?.as_bytes())),
                text(hash(&(
                    "SyncExtend complete original conflict branch history v1",
                    header,
                    &plan,
                    &selection.branch_owners,
                ))?),
            ],
            final_dependencies.clone(),
        )?;
        final_dependencies.push(name);
    }
    Ok((builder, final_dependencies))
}
