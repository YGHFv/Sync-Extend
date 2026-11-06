//! Uncompiled private ordinary-history projection draft; no native authority.
use crate::{
    storage_capacity::CapacitySnapshot, JournalError, JournalStorageColumn,
    JournalStorageColumnValue as Value, Result,
};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    tree_storage_capacity::TreeStorageCharge, ContentId, Manifest, Operation, SnapshotId,
    VersionVector,
};

type Key = (String, Vec<String>);
type Rows = BTreeMap<Key, Vec<JournalStorageColumn>>;

fn text<'a>(columns: &'a [JournalStorageColumn], name: &str) -> Result<&'a str> {
    match columns.iter().find(|c| c.name == name).map(|c| &c.value) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant("local commit expected text")),
    }
}

fn integer(columns: &[JournalStorageColumn], name: &str) -> Result<u64> {
    match columns.iter().find(|c| c.name == name).map(|c| &c.value) {
        Some(Value::Integer(value)) => Ok(*value),
        _ => Err(JournalError::Invariant("local commit expected integer")),
    }
}

fn string(name: &str, value: &str) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: Value::Text(value.into()),
    }
}

fn number(name: &str, value: u64) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: Value::Integer(value),
    }
}

fn bytes(columns: &[JournalStorageColumn]) -> Result<u64> {
    columns.iter().try_fold(0u64, |sum, column| {
        let size = match &column.value {
            Value::Null => 0,
            Value::Integer(_) => 8,
            Value::Text(value) => value.len() as u64,
        };
        sum.checked_add(size)
            .ok_or(JournalError::Invariant("local commit byte overflow"))
    })
}

fn add(charge: &mut TreeStorageCharge, rows: u64, bytes: u64) -> Result<()> {
    charge.rows = charge
        .rows
        .checked_add(rows)
        .ok_or(JournalError::Invariant("local commit row overflow"))?;
    charge.logical_bytes = charge
        .logical_bytes
        .checked_add(bytes)
        .ok_or(JournalError::Invariant("local commit charge overflow"))?;
    Ok(())
}

fn subtract(charge: &mut TreeStorageCharge, rows: u64, bytes: u64) -> Result<()> {
    charge.rows = charge
        .rows
        .checked_sub(rows)
        .ok_or(JournalError::Invariant("local commit row underflow"))?;
    charge.logical_bytes = charge
        .logical_bytes
        .checked_sub(bytes)
        .ok_or(JournalError::Invariant("local commit charge underflow"))?;
    Ok(())
}

fn key(table: &str, components: &[&str]) -> Key {
    (
        table.into(),
        components.iter().map(|value| (*value).into()).collect(),
    )
}

fn insert(rows: &mut Rows, key: Key, columns: Vec<JournalStorageColumn>) -> Result<()> {
    if rows.insert(key, columns).is_some() {
        return Err(JournalError::Invariant(
            "local commit projected row collision",
        ));
    }
    Ok(())
}

pub(crate) struct Projection {
    rows: Rows,
    charge: TreeStorageCharge,
}

pub(crate) struct Input<'a> {
    pub(crate) expected_root: Option<&'a SnapshotId>,
    pub(crate) manifest: &'a Manifest,
    pub(crate) operations: &'a [Operation],
    pub(crate) operation_json: &'a [String],
    pub(crate) snapshot_json: &'a str,
    pub(crate) timestamp: u64,
    pub(crate) observation_json: Option<&'a str>,
}

pub(crate) fn project(before: &CapacitySnapshot, input: Input<'_>) -> Result<Projection> {
    project_inner(before, input, None)
}

pub(crate) fn project_publication(
    before: &CapacitySnapshot,
    input: Input<'_>,
    publication: &crate::PublicationIntent,
) -> Result<Projection> {
    project_inner(before, input, Some(publication))
}

fn project_inner(
    before: &CapacitySnapshot,
    input: Input<'_>,
    publication: Option<&crate::PublicationIntent>,
) -> Result<Projection> {
    let Input {
        expected_root,
        manifest,
        operations,
        operation_json,
        snapshot_json,
        timestamp,
        observation_json,
    } = input;
    crate::storage_policy::receive::tree_gate(before)?;
    if publication.is_none() {
        crate::storage_policy::receive::completion_gate(before)?;
    } else if before.rows.iter().any(|row| {
        (row.table() == "mutations"
            && !matches!(text(row.columns(), "state"), Ok("cancelled" | "committed")))
            || (row.table() == "publications"
                && row.primary_key().first().map(String::as_str)
                    != publication.map(|intent| intent.transaction_id.as_str())
                && !matches!(integer(row.columns(), "cleaned"), Ok(1)))
    }) {
        return Err(JournalError::Invariant(
            "publication completion has another writer",
        ));
    }
    let mut rows: Rows = before
        .rows
        .iter()
        .map(|row| {
            (
                (row.table().into(), row.primary_key().to_vec()),
                row.columns().to_vec(),
            )
        })
        .collect();
    if rows.iter().any(|((table, _), columns)| {
        table == "publications"
            && !matches!(integer(columns, "cleaned"), Ok(1))
            && publication.is_none_or(|intent| {
                text(columns, "transaction_id").ok() != Some(intent.transaction_id.as_str())
            })
    }) {
        return Err(JournalError::Invariant(
            "outstanding publication must be recovered first",
        ));
    }
    let space = manifest.space_id.as_str();
    let root = manifest.root()?;
    let current_key = key("current_manifests", &[space]);
    let current_root = rows
        .get(&current_key)
        .map(|columns| text(columns, "snapshot_id"))
        .transpose()?;
    if current_root != expected_root.map(SnapshotId::as_str) {
        return Err(JournalError::Invariant("manifest baseline changed"));
    }
    let mut vector = match current_root {
        Some(current) => {
            let prior = rows
                .get(&key("snapshots", &[current]))
                .ok_or(JournalError::Invariant(
                    "local commit baseline snapshot missing",
                ))?;
            serde_json::from_str::<Manifest>(text(prior, "manifest")?)?.version_vector
        }
        None => VersionVector::default(),
    };
    if rows.contains_key(&key("snapshot_prunings", &[root.as_str()])) {
        return Err(JournalError::Invariant("local commit target was pruned"));
    }
    let mut cursors = BTreeMap::new();
    let mut pending_origins = BTreeSet::new();
    let mut origin_sequences = BTreeSet::new();
    for ((table, _), columns) in &rows {
        if table == "receive_cursors" {
            cursors.insert(
                text(columns, "device_id")?.to_string(),
                integer(columns, "contiguous_seq")?,
            );
        } else if table == "operations" {
            let device = text(columns, "origin_device_id")?.to_string();
            origin_sequences.insert((device.clone(), integer(columns, "origin_seq")?));
            if text(columns, "state")? == "pending" {
                pending_origins.insert(device);
            }
        }
    }
    let mut charge = before.report.accounted_total();
    let mut handed_off_pin_bytes = 0;
    let mut handed_off_pin_rows = 0;
    if let Some(intent) = publication {
        let completion = intent
            .completion
            .as_ref()
            .ok_or(JournalError::Invariant("publication reservation missing"))?;
        let held = completion.charge()?;
        subtract(&mut charge, held.rows, held.logical_bytes + 64)?;
        let columns = rows
            .get_mut(&key("publications", &[intent.transaction_id.as_str()]))
            .ok_or(JournalError::Invariant(
                "publication projected owner missing",
            ))?;
        if text(columns, "state")? != "published" {
            return Err(JournalError::Invariant(
                "publication projection requires published",
            ));
        }
        columns
            .iter_mut()
            .find(|column| column.name == "state")
            .unwrap()
            .value = Value::Text("committed".into());
        columns
            .iter_mut()
            .find(|column| column.name == "committed_snapshot")
            .unwrap()
            .value = Value::Text(root.to_string());
        add(&mut charge, 0, 64)?;
        let pins: Vec<_> = rows
            .keys()
            .filter(|(table, components)| {
                table == "publication_objects"
                    && components.first().map(String::as_str)
                        == Some(intent.transaction_id.as_str())
            })
            .cloned()
            .collect();
        // Pin handoff happens after snapshot pin insertion. Keep these charges
        // in the admission peak until the final projection below.
        for pin in pins {
            let columns = rows.remove(&pin).unwrap();
            handed_off_pin_bytes += bytes(&columns)?;
            handed_off_pin_rows += 1;
        }
    }
    if operations.len() != operation_json.len() {
        return Err(JournalError::Invariant(
            "local commit canonical operation count mismatch",
        ));
    }
    for (op, json) in operations.iter().zip(operation_json) {
        let payload = &op.payload;
        let device = payload.origin_device_id.as_str();
        let previous = cursors.get(device).copied().unwrap_or(0);
        if payload.space_id != manifest.space_id
            || payload.causal != vector
            || previous.checked_add(1) != Some(payload.origin_seq)
            || payload
                .causal
                .0
                .iter()
                .any(|(origin, seq)| cursors.get(origin.as_str()).copied().unwrap_or(0) < *seq)
            || !origin_sequences.insert((device.into(), payload.origin_seq))
        {
            return Err(JournalError::Invariant("local sequence discontinuity"));
        }
        insert(
            &mut rows,
            key("operations", &[op.op_id.as_str()]),
            vec![
                string("op_id", op.op_id.as_str()),
                string("space_id", space),
                string("origin_device_id", device),
                number("origin_seq", payload.origin_seq),
                string("payload", json),
                string("state", "materialized"),
            ],
        )?;
        add(&mut charge, 1, json.len() as u64 + 180)?;
        let cursor_key = key("receive_cursors", &[space, device]);
        if !rows.contains_key(&cursor_key) {
            add(&mut charge, 1, 104)?;
            if pending_origins.remove(device) {
                subtract(&mut charge, 1, 104)?;
            }
        }
        rows.insert(
            cursor_key,
            vec![
                string("space_id", space),
                string("device_id", device),
                number("contiguous_seq", payload.origin_seq),
            ],
        );
        cursors.insert(device.to_string(), payload.origin_seq);
        vector.observe(payload.origin_device_id.clone(), payload.origin_seq);
    }
    if vector != manifest.version_vector {
        return Err(JournalError::Invariant(
            "manifest vector does not match committed operations",
        ));
    }
    let snapshot_key = key("snapshots", &[root.as_str()]);
    if let Some(stored) = rows.get(&snapshot_key) {
        if text(stored, "space_id")? != space
            || text(stored, "manifest")? != snapshot_json
            || text(stored, "state")? != "materialized"
        {
            return Err(JournalError::Invariant(
                "existing snapshot differs from local commit",
            ));
        }
    } else {
        insert(
            &mut rows,
            snapshot_key,
            vec![
                string("snapshot_id", root.as_str()),
                string("space_id", space),
                string("manifest", snapshot_json),
                number("created_at_ms", timestamp),
                string("state", "materialized"),
                number("locked", 0),
            ],
        )?;
        add(&mut charge, 1, snapshot_json.len() as u64 + 124)?;
    }
    if !rows.contains_key(&current_key) {
        add(&mut charge, 1, 96)?;
    }
    rows.insert(
        current_key,
        vec![
            string("space_id", space),
            string("snapshot_id", root.as_str()),
        ],
    );
    let peak_before_map_release = charge;
    if let Some(old) = rows.remove(&key("rename_observations", &[space])) {
        subtract(&mut charge, 1, bytes(&old)?)?;
    }
    let contents: BTreeSet<_> = manifest
        .entries
        .values()
        .filter_map(|entry| entry.content.as_ref())
        .flat_map(|content| content.chunks.iter().map(|chunk| chunk.content_id.as_str()))
        .collect();
    for content in &contents {
        let pin_key = key("snapshot_objects", &[root.as_str(), content]);
        if !rows.contains_key(&pin_key) {
            insert(
                &mut rows,
                pin_key,
                vec![
                    string("snapshot_id", root.as_str()),
                    string("content_id", content),
                ],
            )?;
            add(&mut charge, 1, 128)?;
        }
    }
    let marks: Vec<_> = rows
        .iter()
        .filter(|((table, _), _)| table == "gc_marks")
        .filter_map(|(_, columns)| {
            let content = text(columns, "content_id");
            match content {
                Ok(content) if contents.contains(content) => {
                    Some(text(columns, "mark_id").map(str::to_string))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect::<Result<_>>()?;
    for mark in marks {
        let invalidation_key = key("gc_invalidations", &[&mark]);
        if !rows.contains_key(&key("gc_cancellations", &[&mark]))
            && !rows.contains_key(&invalidation_key)
        {
            if !before
                .report
                .ordinary_obligations()
                .iter()
                .any(|obligation| {
                    obligation.family == "gc_invalidation"
                        && obligation.owner_key == [mark.clone()]
                        && obligation.charge
                            == (TreeStorageCharge {
                                rows: 1,
                                logical_bytes: 32,
                            })
                })
            {
                return Err(JournalError::Invariant("local commit GC liability missing"));
            }
            insert(&mut rows, invalidation_key, vec![string("mark_id", &mark)])?;
            // The row consumes this exact mark's held terminal liability.
        }
    }
    if let Some(json) = observation_json {
        insert(
            &mut rows,
            key("rename_observations", &[space]),
            vec![
                string("space_id", space),
                string("snapshot_id", root.as_str()),
                string("observation", json),
                string(
                    "observation_hash",
                    ContentId::hash(json.as_bytes()).as_str(),
                ),
            ],
        )?;
        add(&mut charge, 1, json.len() as u64 + 160)?;
    }
    let limits = before.report.limits();
    for stage in [peak_before_map_release, charge] {
        if stage.rows > limits.max_rows || stage.logical_bytes > limits.max_logical_bytes {
            return Err(JournalError::Invariant(
                "journal configured local commit capacity exceeded",
            ));
        }
    }
    subtract(&mut charge, handed_off_pin_rows, handed_off_pin_bytes)?;
    Ok(Projection { rows, charge })
}

impl Projection {
    pub(crate) fn receipt(&self, after: &CapacitySnapshot) -> Result<()> {
        let actual: Rows = after
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().into(), row.primary_key().to_vec()),
                    row.columns().to_vec(),
                )
            })
            .collect();
        if actual != self.rows
            || after.report.accounted_total() != self.charge
            || !after.report.within_accounted_limits()
        {
            return Err(JournalError::Invariant(
                "local commit exact history/capacity receipt mismatch",
            ));
        }
        Ok(())
    }
}
