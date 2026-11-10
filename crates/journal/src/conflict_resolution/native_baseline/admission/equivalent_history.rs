//! Exact no-native-delta history commit requires a retained whole live observation.
use super::super::super::equivalent::{self, EquivalentConflictHistory, Record};
use super::super::super::native_templates::Cell;
use super::final_commit::row;
use super::*;
use sync_extend_core_model::conflict_resolution::verify_file_resolution_projection;

struct Change {
    table: &'static str,
    old: Option<Vec<Value>>,
    new: Option<Vec<Value>>,
}
fn text(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}
fn integer(value: u64) -> Result<Value> {
    Ok(Value::Integer(i64::try_from(value).map_err(|_| {
        invalid("equivalent history SQLite integer")
    })?))
}
fn identity(table: &str, values: &[Value]) -> Result<(RowKey, RowValue)> {
    let cells = values
        .iter()
        .map(|v| match v {
            Value::Text(s) => Ok(Cell::Text(s.clone())),
            Value::Integer(n) if *n >= 0 => Ok(Cell::Integer(*n as u64)),
            _ => Err(invalid("equivalent history exact row type")),
        })
        .collect::<Result<Vec<_>>>()?;
    row(table, &cells)
}
fn values(columns: &[crate::JournalStorageColumn]) -> Result<Vec<Value>> {
    columns
        .iter()
        .map(|c| match &c.value {
            crate::JournalStorageColumnValue::Text(s) => Ok(text(s)),
            crate::JournalStorageColumnValue::Integer(n) => integer(*n),
            _ => Err(invalid("equivalent history existing row type")),
        })
        .collect()
}
fn stage(
    table: &'static str,
    new: Vec<Value>,
    expected: &mut RowMap,
    changes: &mut Vec<Change>,
) -> Result<()> {
    let (key, columns) = identity(table, &new)?;
    if expected.get(&key) == Some(&columns) {
        return Ok(());
    }
    let old = expected.get(&key).map(|c| values(c)).transpose()?;
    expected.insert(key, columns);
    changes.push(Change {
        table,
        old,
        new: Some(new),
    });
    Ok(())
}
fn width(rows: &RowMap) -> Result<u64> {
    rows.values().flatten().try_fold(0u64, |n, c| {
        n.checked_add(match &c.value {
            crate::JournalStorageColumnValue::Text(s) => s.len() as u64,
            crate::JournalStorageColumnValue::Integer(_) => 8,
            crate::JournalStorageColumnValue::Null => 0,
        })
        .ok_or(invalid("equivalent history exact logical width overflow"))
    })
}

impl Journal {
    /// Accept an independently signed equivalent resolver with no file effects.
    /// Phase labels alone cannot mint this authority: the original live tree is held.
    pub fn finalize_equivalent_conflict_history(
        &mut self,
        observed: ConflictNativeObservation,
        proof: &ConflictResolutionProof,
        approved_keys: &[ConflictResolutionKey],
    ) -> Result<EquivalentConflictHistory> {
        if !self.connection.is_autocommit() {
            return Err(invalid("equivalent history caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let admission = &observed.held.held.admission;
        let parent = &admission.selected.header;
        if !self
            .conflict_forward_state(&observed.held)?
            .contains("phase/cleanup")
            || !super::super::super::native_cleanup_state::complete(&self.connection, parent)?
        {
            return Err(invalid(
                "equivalent history requires exact original terminal",
            ));
        }
        observed.verify_content()?;
        self.verify_conflict_creator_cas(admission)?;
        super::super::super::native_final_state::exact_history(&self.connection, parent)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        let prior = row_map(&before.rows);
        let records = equivalent::records(&before.rows)?;
        let id = equivalent::identity(parent, proof)?;
        if let Some(record) = records.iter().find(|r| r.transaction_id == id) {
            if record.proof != *proof || record.approved_keys != approved_keys {
                return Err(invalid("equivalent history exact retry differs"));
            }
            observed.verify_content()?;
            tx.commit()?;
            return record.receipt();
        }
        if records.len() >= 32 {
            return Err(invalid("equivalent history complete record bound"));
        }
        let plan = parent.plan()?;
        if proof.payload.originals != parent.intent.proof.payload.originals
            || proof.payload.resolver_device == *parent.receiver_device()
            || proof.verify(approved_keys, ResolutionLimits::default())? != plan
        {
            return Err(invalid(
                "equivalent history exact approved original plan differs",
            ));
        }
        let current = self
            .read_view()
            .current(&parent.target.space_id)?
            .ok_or(invalid("equivalent history applied baseline absent"))?;
        if current.entries != parent.target.entries
            || current.tombstones != parent.target.tombstones
        {
            return Err(invalid("equivalent history live applied tree differs"));
        }
        let mut complete = BTreeMap::new();
        for signed in parent
            .intent
            .proof
            .payload
            .originals
            .iter()
            .chain(&parent.intent.proof.payload.resolving)
            .chain(
                records
                    .iter()
                    .flat_map(|r| r.proof.payload.resolving.iter()),
            )
        {
            if complete
                .insert(signed.operation.op_id.clone(), signed.operation.clone())
                .is_some_and(|old| old != signed.operation)
            {
                return Err(invalid(
                    "equivalent history prior signed operation collision",
                ));
            }
        }
        let incoming: BTreeMap<_, _> = proof
            .payload
            .resolving
            .iter()
            .map(|s| (s.operation.op_id.clone(), s.operation.clone()))
            .collect();
        let mut old_vector = VersionVector::default();
        let mut missing = false;
        for signed in &proof.payload.resolving {
            let key = (
                "operations".into(),
                vec![signed.operation.op_id.to_string()],
            );
            let exists = prior.contains_key(&key);
            if exists && missing {
                return Err(invalid("equivalent history received prefix skips"));
            }
            if !exists {
                missing = true;
            }
        }
        let mut accepted_originals = BTreeSet::new();
        for row in before.rows.iter().filter(|r| r.table() == "operations") {
            let cells = values(row.columns())?;
            let Value::Text(json) = &cells[4] else {
                return Err(invalid("equivalent operation JSON type"));
            };
            let op: Operation = serde_json::from_str(json)?;
            let expected_state = if complete.contains_key(&op.op_id) {
                "materialized"
            } else {
                "received"
            };
            if complete.get(&op.op_id).or_else(|| incoming.get(&op.op_id)) != Some(&op)
                || cells
                    != vec![
                        text(&op.op_id),
                        text(&op.payload.space_id),
                        text(&op.payload.origin_device_id),
                        integer(op.payload.origin_seq)?,
                        text(serde_json::to_string(&op)?),
                        text(expected_state),
                    ]
            {
                return Err(invalid(
                    "equivalent history unsupported or differing complete receipt",
                ));
            }
            if complete.contains_key(&op.op_id) {
                accepted_originals.insert(op.op_id.clone());
            }
            old_vector.observe(op.payload.origin_device_id.clone(), op.payload.origin_seq);
        }
        if accepted_originals.len() != complete.len() {
            return Err(invalid(
                "equivalent history prior materialized operation missing",
            ));
        }
        let mut cursor = VersionVector::default();
        for row in before
            .rows
            .iter()
            .filter(|r| r.table() == "receive_cursors")
        {
            let cells = values(row.columns())?;
            let (Value::Text(space), Value::Text(device), Value::Integer(seq)) =
                (&cells[0], &cells[1], &cells[2])
            else {
                return Err(invalid("equivalent history cursor types"));
            };
            let device = device.parse()?;
            if space != parent.target.space_id.as_str() || *seq <= 0 || cursor.get(&device) != 0 {
                return Err(invalid("equivalent history cursor scope"));
            }
            cursor.observe(device, *seq as u64);
        }
        if cursor != old_vector {
            return Err(invalid(
                "equivalent history complete received cursor differs",
            ));
        }
        let prior_operations = complete.values().cloned().collect::<Vec<_>>();
        let prior_reduced = reduce_operations(&parent.target.space_id, &prior_operations, 10_000)?;
        if prior_reduced.received_vector != current.version_vector {
            return Err(invalid(
                "equivalent history complete applied vector differs",
            ));
        }
        for operation in incoming.into_values() {
            if complete
                .insert(operation.op_id.clone(), operation.clone())
                .is_some_and(|old| old != operation)
            {
                return Err(invalid("equivalent history signed identity collision"));
            }
        }
        let originals = parent
            .intent
            .proof
            .payload
            .originals
            .iter()
            .map(|s| s.operation.clone())
            .collect::<Vec<_>>();
        let original_ids = originals
            .iter()
            .map(|op| op.op_id.clone())
            .collect::<BTreeSet<_>>();
        let resolving = complete
            .values()
            .filter(|op| !original_ids.contains(&op.op_id))
            .cloned()
            .collect::<Vec<_>>();
        verify_file_resolution_projection(
            &plan,
            &originals,
            &resolving,
            ResolutionLimits::default(),
        )?;
        let combined = reduce_operations(
            &parent.target.space_id,
            &complete.values().cloned().collect::<Vec<_>>(),
            10_000,
        )?;
        let mut target = plan.projected.clone();
        target.version_vector = combined.received_vector;
        if target.version_vector.get(parent.receiver_device())
            != current.version_vector.get(parent.receiver_device())
        {
            return Err(invalid(
                "equivalent history receiver sequence must remain unchanged",
            ));
        }
        let record = Record {
            format: 1,
            transaction_id: id,
            base_transaction_id: parent.transaction_id.clone(),
            receiver_device: parent.receiver_device().clone(),
            proof: proof.clone(),
            approved_keys: approved_keys.to_vec(),
            prior_equivalents: records.iter().map(|r| r.proof.clone()).collect(),
            target,
        };
        record.validate(parent)?;
        let mut expected = prior.clone();
        let mut changes = Vec::new();
        for signed in &proof.payload.resolving {
            let op = &signed.operation;
            stage(
                "operations",
                vec![
                    text(&op.op_id),
                    text(&op.payload.space_id),
                    text(&op.payload.origin_device_id),
                    integer(op.payload.origin_seq)?,
                    text(serde_json::to_string(op)?),
                    text("materialized"),
                ],
                &mut expected,
                &mut changes,
            )?;
        }
        for (device, seq) in &record.target.version_vector.0 {
            stage(
                "receive_cursors",
                vec![text(&record.target.space_id), text(device), integer(*seq)?],
                &mut expected,
                &mut changes,
            )?;
        }
        let root = record.target.root()?;
        let snapshot_key = ("snapshots".into(), vec![root.to_string()]);
        let snapshot = vec![
            text(&root),
            text(&record.target.space_id),
            text(serde_json::to_string(&record.target)?),
            integer(proof.payload.created_at_ms)?,
            text("materialized"),
            integer(0)?,
        ];
        if let Some(old) = expected.get(&snapshot_key) {
            let cells = values(old)?;
            if cells[..3] != snapshot[..3] || cells[4] != text("materialized") {
                return Err(invalid("equivalent history target snapshot collision"));
            }
        } else {
            stage("snapshots", snapshot, &mut expected, &mut changes)?;
        }
        for content in record
            .target
            .entries
            .values()
            .filter_map(|e| e.content.as_ref())
            .flat_map(|f| f.chunks.iter().map(|c| c.content_id.clone()))
            .collect::<BTreeSet<_>>()
        {
            stage(
                "snapshot_objects",
                vec![text(&root), text(content)],
                &mut expected,
                &mut changes,
            )?;
        }
        stage(
            "current_manifests",
            vec![text(&record.target.space_id), text(&root)],
            &mut expected,
            &mut changes,
        )?;
        let rename = (
            "rename_observations".into(),
            vec![record.target.space_id.to_string()],
        );
        if let Some(columns) = expected.remove(&rename) {
            changes.push(Change {
                table: "rename_observations",
                old: Some(values(&columns)?),
                new: None,
            });
        }
        for (suffix, values) in record.values()? {
            let table = match suffix {
                "equivalent_histories" => "conflict_resolution_equivalent_histories",
                "equivalent_signatures" => "conflict_resolution_equivalent_signatures",
                _ => return Err(invalid("equivalent record table scope")),
            };
            let (key, _) = identity(table, &values)?;
            if expected.contains_key(&key) {
                return Err(invalid("equivalent record identity already used"));
            }
            stage(table, values, &mut expected, &mut changes)?;
        }
        let mut added_rows = 0u64;
        let mut added_bytes = 0u64;
        for change in &changes {
            if let Some(new) = &change.new {
                added_rows = added_rows
                    .checked_add(u64::from(change.old.is_none()))
                    .ok_or(invalid("equivalent history row peak overflow"))?;
                let (_, columns) = identity(change.table, new)?;
                let future = width(&BTreeMap::from([(("peak".into(), Vec::new()), columns)]))?;
                let old = change
                    .old
                    .as_ref()
                    .map(|old| {
                        let (_, columns) = identity(change.table, old)?;
                        width(&BTreeMap::from([(("peak".into(), Vec::new()), columns)]))
                    })
                    .transpose()?
                    .unwrap_or(0);
                added_bytes = added_bytes
                    .checked_add(future.saturating_sub(old))
                    .ok_or(invalid("equivalent history byte peak overflow"))?;
            }
        }
        let accounted = before.report.accounted_total();
        if accounted
            .rows
            .checked_add(added_rows)
            .is_none_or(|n| n > bounds.max_rows)
            || accounted
                .logical_bytes
                .checked_add(added_bytes)
                .is_none_or(|n| n > bounds.max_logical_bytes)
        {
            return Err(invalid(
                "equivalent history preeffect peak capacity exceeded",
            ));
        }
        observed.verify_content()?;
        for change in &changes {
            let old = change.old.as_deref().unwrap_or_default();
            let new = change.new.as_deref().unwrap_or_default();
            let _permit = if let Some(suffix) = change.table.strip_prefix("conflict_resolution_") {
                let mut issued = vec![text(suffix)];
                issued.extend_from_slice(new);
                self.conflict_resolution_issuance.permit(Some(issued))?
            } else {
                let kind = if change.old.is_none() {
                    "insert"
                } else if change.new.is_none() {
                    "delete"
                } else {
                    "update"
                };
                let mut issued = vec![text(change.table), text(kind)];
                issued.extend_from_slice(old);
                issued.extend_from_slice(new);
                let mut permits = vec![issued];
                if change.table == "current_manifests" {
                    for cascade in changes
                        .iter()
                        .filter(|c| c.table == "rename_observations" && c.new.is_none())
                    {
                        let mut issued = vec![text("rename_observations"), text("delete")];
                        issued.extend_from_slice(cascade.old.as_deref().unwrap_or_default());
                        permits.push(issued);
                    }
                }
                self.conflict_resolution_issuance.final_permit(permits)?
            };
            let spec = crate::storage_inventory::tables()
                .into_iter()
                .find(|s| s.name == change.table)
                .ok_or(invalid("equivalent exact DML schema absent"))?;
            let (sql, values) = if change.old.is_none() {
                (
                    format!(
                        "INSERT INTO main.{} VALUES({})",
                        change.table,
                        (1..=new.len())
                            .map(|n| format!("?{n}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                    new.to_vec(),
                )
            } else {
                let mut values = new.to_vec();
                let offset = values.len();
                let predicate = spec
                    .columns
                    .iter()
                    .enumerate()
                    .map(|(i, c)| format!("{}=?{}", c.name, offset + i + 1))
                    .collect::<Vec<_>>()
                    .join(" AND ");
                let sql = if change.new.is_some() {
                    format!(
                        "UPDATE main.{} SET {} WHERE {predicate}",
                        change.table,
                        spec.columns
                            .iter()
                            .enumerate()
                            .map(|(i, c)| format!("{}=?{}", c.name, i + 1))
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                } else {
                    format!("DELETE FROM main.{} WHERE {predicate}", change.table)
                };
                values.extend_from_slice(old);
                (sql, values)
            };
            let changed = tx.execute(&sql, rusqlite::params_from_iter(values))?;
            if changed != 1
                && !(change.table == "rename_observations"
                    && change.new.is_none()
                    && !tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM main.rename_observations WHERE space_id=?1)",
                        [record.target.space_id.as_str()],
                        |r| r.get::<_, bool>(0),
                    )?)
            {
                return Err(invalid("equivalent history exact DML count"));
            }
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        if row_map(&after.rows) != expected || !after.report.within_accounted_limits() {
            return Err(invalid(
                "equivalent history changed unrelated allmain rows or exceeded capacity",
            ));
        }
        observed.verify_content()?;
        self.verify_conflict_creator_cas(admission)?;
        tx.commit()?;
        record.receipt()
    }
}
