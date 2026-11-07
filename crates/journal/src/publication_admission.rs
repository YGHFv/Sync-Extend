//! Persisted exact history admission before native effects; no creator authority.
use crate::{
    storage_capacity::CapacitySnapshot, storage_policy, Completion, Journal, JournalError,
    JournalStorageColumn, JournalStorageColumnValue as Value, PublicationIntent, PublicationState,
    Result,
};
use rusqlite::{params, Transaction, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::*;

type Rows = BTreeMap<(String, Vec<String>), Vec<JournalStorageColumn>>;

fn rows(snapshot: &CapacitySnapshot) -> Rows {
    snapshot
        .rows
        .iter()
        .map(|row| {
            (
                (row.table().into(), row.primary_key().to_vec()),
                row.columns().to_vec(),
            )
        })
        .collect()
}

fn text(name: &str, value: &str) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: Value::Text(value.into()),
    }
}

fn field<'a>(columns: &'a [JournalStorageColumn], name: &str) -> Result<&'a str> {
    match columns
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant(
            "publication admission expected text",
        )),
    }
}

fn update(columns: &mut [JournalStorageColumn], name: &str, value: &str) -> Result<()> {
    columns
        .iter_mut()
        .find(|column| column.name == name)
        .ok_or(JournalError::Invariant(
            "publication admission column missing",
        ))?
        .value = Value::Text(value.into());
    Ok(())
}

fn verify(expected: &Rows, after: &CapacitySnapshot) -> Result<()> {
    if *expected != rows(after) || !after.report.within_accounted_limits() {
        return Err(JournalError::Invariant(
            "publication admission exact receipt or capacity",
        ));
    }
    Ok(())
}

fn replacement_capacity(
    before: &CapacitySnapshot,
    old: &PublicationIntent,
    json: &str,
    completion: &crate::PublicationCompletion,
    new_pins: u64,
) -> Result<()> {
    let prior = before.report.accounted_total();
    let held = old
        .completion
        .as_ref()
        .ok_or(JournalError::Invariant("publication reservation missing"))?
        .charge()?;
    let next = completion.charge()?;
    let old_json = before
        .rows
        .iter()
        .find(|row| {
            row.table() == "publications" && row.primary_key() == [old.transaction_id.to_string()]
        })
        .map(|row| field(row.columns(), "intent"))
        .transpose()?
        .ok_or(JournalError::Invariant(
            "publication replacement owner missing",
        ))?;
    let row_charge = prior
        .rows
        .checked_sub(held.rows)
        .and_then(|n| n.checked_add(next.rows))
        .and_then(|n| n.checked_add(new_pins));
    let byte_charge = prior
        .logical_bytes
        .checked_sub(held.logical_bytes)
        .and_then(|n| n.checked_sub(old_json.len() as u64))
        .and_then(|n| n.checked_add(next.logical_bytes))
        .and_then(|n| n.checked_add(json.len() as u64))
        .and_then(|n| {
            new_pins
                .checked_mul(96)
                .and_then(|pins| n.checked_add(pins))
        });
    let limits = before.report.limits();
    if row_charge.is_none_or(|n| n > limits.max_rows)
        || byte_charge.is_none_or(|n| n > limits.max_logical_bytes)
    {
        return Err(JournalError::Invariant(
            "publication replacement pre-effect capacity exceeded",
        ));
    }
    Ok(())
}

fn history_context(before: &CapacitySnapshot, intent: &PublicationIntent) -> Result<()> {
    let plan = intent
        .completion
        .as_ref()
        .ok_or(JournalError::Invariant("publication history plan missing"))?;
    let device = &plan
        .operations
        .last()
        .ok_or(JournalError::Invariant(
            "publication history operation missing",
        ))?
        .payload
        .origin_device_id;
    let mut cursors = BTreeMap::new();
    for row in &before.rows {
        if row.table() == "receive_cursors" {
            let sequence = row
                .columns()
                .iter()
                .find(|column| column.name == "contiguous_seq")
                .and_then(|column| match column.value {
                    Value::Integer(value) => Some(value),
                    _ => None,
                })
                .ok_or(JournalError::Invariant("publication cursor value missing"))?;
            cursors.insert(field(row.columns(), "device_id")?, sequence);
        }
        if row.table() == "operations"
            && field(row.columns(), "origin_device_id")? == device.as_str()
            && field(row.columns(), "state")? == "pending"
        {
            return Err(JournalError::Invariant(
                "publication local origin has pending history",
            ));
        }
    }
    if cursors.get(device.as_str()).copied().unwrap_or(0)
        != plan.baseline.version_vector.get(device)
        || plan
            .baseline
            .version_vector
            .0
            .iter()
            .any(|(origin, sequence)| {
                cursors.get(origin.as_str()).copied().unwrap_or(0) < *sequence
            })
    {
        return Err(JournalError::Invariant(
            "publication local history context discontinuity",
        ));
    }
    Ok(())
}

impl Journal {
    pub(crate) fn clean_admitted_publication(&mut self, id: &EntryId) -> Result<()> {
        crate::native_publication::legacy_gate(&self.connection, id)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        if publication.state != PublicationState::Committed
            || publication.intent.completion.is_none()
        {
            return Err(JournalError::Invariant(
                "cannot clean pending admitted publication",
            ));
        }
        let before = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        let mut expected = rows(&before);
        let columns = expected
            .get_mut(&("publications".into(), vec![id.to_string()]))
            .ok_or(JournalError::Invariant("publication cleanup owner missing"))?;
        columns
            .iter_mut()
            .find(|column| column.name == "cleaned")
            .ok_or(JournalError::Invariant(
                "publication cleaned column missing",
            ))?
            .value = Value::Integer(1);
        tx.execute(
            "UPDATE publications SET cleaned=1 WHERE transaction_id=?1 AND state='committed'",
            [id.as_str()],
        )?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        // Exact fixed-width cleanup consumes no new capacity and is permitted
        // after limits tighten; unrelated value changes must still roll back.
        if rows(&after) != expected
            || after.report.accounted_total() != before.report.accounted_total()
        {
            return Err(JournalError::Invariant(
                "publication cleanup exact receipt mismatch",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn begin_admitted_publication(&mut self, intent: &PublicationIntent) -> Result<()> {
        intent.validate()?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        if !before.report.within_accounted_limits() {
            return Err(JournalError::Invariant(
                "publication admission existing capacity exceeded",
            ));
        }
        storage_policy::receive::tree_gate(&before)?;
        storage_policy::receive::completion_gate(&before)?;
        history_context(&before, intent)?;
        let completion = intent
            .completion
            .as_ref()
            .ok_or(JournalError::Invariant("publication completion required"))?;
        let operation = completion.operations.last().ok_or(JournalError::Invariant(
            "publication completion operation missing",
        ))?;
        if crate::PublicationCompletion::new(
            &completion.baseline,
            &operation.payload.origin_device_id,
            completion.manifest.entries[&intent.entry_id].clone(),
            intent.created_at_ms,
        )? != *completion
        {
            return Err(JournalError::Invariant(
                "initial publication contains unobserved changes",
            ));
        }
        if intent.root_identity.is_none() || intent.parent_identity.is_none() {
            return Err(JournalError::Invariant(
                "admitted publication requires physical parent scope",
            ));
        }
        if self.state("device_id")?.as_deref() != Some(operation.payload.origin_device_id.as_str())
            || self
                .current(&intent.space_id)?
                .as_ref()
                .map(Manifest::root)
                .transpose()?
                != Some(intent.baseline_root.clone())
            || intent.requested_baseline.is_some() && intent.target_path == intent.requested_path
        {
            return Err(JournalError::Invariant(
                "publication admitted baseline or origin changed",
            ));
        }
        let json = serde_json::to_string(intent)?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant(
                "publication admitted intent byte limit",
            ));
        }
        let id = intent.transaction_id.as_str();
        let chunks: BTreeSet<_> = completion
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| content.chunks.iter().map(|chunk| chunk.content_id.as_str()))
            .collect();
        let held = completion.charge()?;
        let prior = before.report.accounted_total();
        let added_rows = 1 + chunks.len() as u64 + held.rows;
        let added_bytes =
            json.len() as u64 + 145 + chunks.len() as u64 * 96 + 64 + held.logical_bytes;
        if prior
            .rows
            .checked_add(added_rows)
            .is_none_or(|n| n > bounds.max_rows)
            || prior
                .logical_bytes
                .checked_add(added_bytes)
                .is_none_or(|n| n > bounds.max_logical_bytes)
        {
            return Err(JournalError::Invariant(
                "publication pre-effect history capacity exceeded",
            ));
        }
        let mut expected = rows(&before);
        if expected
            .insert(
                ("publications".into(), vec![id.into()]),
                vec![
                    text("transaction_id", id),
                    text("space_id", intent.space_id.as_str()),
                    text("intent", &json),
                    text("intent_hash", ContentId::hash(json.as_bytes()).as_str()),
                    text("state", "preparing"),
                    JournalStorageColumn {
                        name: "committed_snapshot".into(),
                        value: Value::Null,
                    },
                    JournalStorageColumn {
                        name: "cleaned".into(),
                        value: Value::Integer(0),
                    },
                ],
            )
            .is_some()
        {
            return Err(JournalError::Invariant("publication admitted owner reused"));
        }
        let invalidations: Vec<_> = before
            .rows
            .iter()
            .filter(|row| row.table() == "gc_marks")
            .filter_map(|row| match field(row.columns(), "content_id") {
                Ok(content) if chunks.contains(content) => {
                    Some(field(row.columns(), "mark_id").map(str::to_string))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<_>>()?;
        for mark in invalidations {
            if !expected.contains_key(&("gc_cancellations".into(), vec![mark.clone()])) {
                expected
                    .entry(("gc_invalidations".into(), vec![mark.clone()]))
                    .or_insert_with(|| vec![text("mark_id", &mark)]);
            }
        }
        tx.execute(
            "INSERT INTO publications VALUES (?1,?2,?3,?4,'preparing',NULL,0)",
            params![
                id,
                intent.space_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str()
            ],
        )?;
        for chunk in chunks {
            expected.insert(
                ("publication_objects".into(), vec![id.into(), chunk.into()]),
                vec![text("transaction_id", id), text("content_id", chunk)],
            );
            tx.execute(
                "INSERT INTO publication_objects VALUES (?1,?2)",
                params![id, chunk],
            )?;
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        verify(&expected, &after)?;
        if after.report.accounted_total()
            != (tree_storage_capacity::TreeStorageCharge {
                rows: prior.rows + added_rows,
                logical_bytes: prior.logical_bytes + added_bytes,
            })
        {
            return Err(JournalError::Invariant(
                "publication admitted liability mismatch",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn advance_admitted_publication(
        &mut self,
        id: &EntryId,
        expected_state: PublicationState,
        next: PublicationState,
    ) -> Result<()> {
        crate::native_publication::legacy_gate(&self.connection, id)?;
        if !matches!(
            (expected_state, next),
            (PublicationState::Preparing, PublicationState::Ready)
                | (PublicationState::Ready, PublicationState::Published)
        ) {
            return Err(JournalError::Invariant(
                "illegal admitted publication transition",
            ));
        }
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        if publication.state != expected_state || publication.intent.completion.is_none() {
            return Err(JournalError::Invariant("admitted publication changed"));
        }
        let before = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        let mut expected = rows(&before);
        update(
            expected
                .get_mut(&("publications".into(), vec![id.to_string()]))
                .unwrap(),
            "state",
            next.as_str(),
        )?;
        tx.execute(
            "UPDATE publications SET state=?1 WHERE transaction_id=?2 AND state=?3",
            params![next.as_str(), id.as_str(), expected_state.as_str()],
        )?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        verify(&expected, &after)?;
        if after.report.accounted_total() != before.report.accounted_total() {
            return Err(JournalError::Invariant(
                "publication phase changed reservation",
            ));
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn retarget_admitted_publication(
        &mut self,
        id: &EntryId,
        path: PortablePath,
    ) -> Result<()> {
        crate::native_publication::legacy_gate(&self.connection, id)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        if publication.state == PublicationState::Committed
            || path == publication.intent.target_path
            || path == publication.intent.requested_path
        {
            return Err(JournalError::Invariant(
                "invalid admitted publication retarget",
            ));
        }
        let before = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        let mut intent = publication.intent.clone();
        let baseline = self.snapshot(&intent.space_id, &intent.baseline_root)?;
        let device = intent
            .completion
            .as_ref()
            .unwrap()
            .operations
            .last()
            .unwrap()
            .payload
            .origin_device_id
            .clone();
        intent.target_path = path;
        intent.attempt = intent
            .attempt
            .checked_add(1)
            .ok_or(JournalError::Invariant("publication attempt overflow"))?;
        let protected = intent
            .completion
            .as_ref()
            .unwrap()
            .protected_objects
            .clone();
        let mut observed = intent.completion.as_ref().unwrap().manifest.entries.clone();
        observed.remove(&intent.entry_id);
        intent.completion = Some(crate::publication::PublicationCompletion::from_observed(
            &baseline,
            &device,
            observed,
            Entry {
                entry_id: intent.entry_id.clone(),
                path: intent.target_path.clone(),
                kind: EntryKind::File,
                content: Some(intent.content.clone()),
            },
            intent.created_at_ms,
        )?);
        intent.completion.as_mut().unwrap().protected_objects = protected;
        intent.validate()?;
        let json = serde_json::to_string(&intent)?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant("publication retarget byte limit"));
        }
        replacement_capacity(
            &before,
            &publication.intent,
            &json,
            intent.completion.as_ref().unwrap(),
            0,
        )?;
        let mut expected = rows(&before);
        let columns = expected
            .get_mut(&("publications".into(), vec![id.to_string()]))
            .unwrap();
        update(columns, "intent", &json)?;
        update(
            columns,
            "intent_hash",
            ContentId::hash(json.as_bytes()).as_str(),
        )?;
        update(columns, "state", "preparing")?;
        tx.execute("UPDATE publications SET intent=?1,intent_hash=?2,state='preparing' WHERE transaction_id=?3",
            params![json, ContentId::hash(json.as_bytes()).as_str(), id.as_str()])?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        verify(&expected, &after)?;
        tx.commit()?;
        Ok(())
    }

    /// Replace only this owner's future history, after a fresh native scan.
    /// This admits observations but grants no filesystem mutation authority.
    pub fn refresh_publication_completion(
        &mut self,
        expected_intent: &PublicationIntent,
        completion: &crate::PublicationCompletion,
    ) -> Result<()> {
        crate::native_publication::legacy_gate(&self.connection, &expected_intent.transaction_id)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(&expected_intent.transaction_id)?;
        if publication.state == PublicationState::Committed
            || publication.intent != *expected_intent
            || expected_intent.completion.is_none()
            || expected_intent
                .completion
                .as_ref()
                .unwrap()
                .protected_objects
                .iter()
                .any(|(id, length)| completion.protected_objects.get(id) != Some(length))
            || completion
                .operations
                .last()
                .map(|op| &op.payload.origin_device_id)
                != expected_intent
                    .completion
                    .as_ref()
                    .unwrap()
                    .operations
                    .last()
                    .map(|op| &op.payload.origin_device_id)
        {
            return Err(JournalError::Invariant(
                "publication observation owner changed",
            ));
        }
        let before = self
            .read_view()
            .audit_local_commit_capacity(&expected_intent.space_id, bounds)?;
        if !before.report.within_accounted_limits() {
            return Err(JournalError::Invariant(
                "publication observation existing capacity exceeded",
            ));
        }
        let mut intent = expected_intent.clone();
        history_context(&before, expected_intent)?;
        if self.state("device_id")?.as_deref()
            != completion
                .operations
                .last()
                .map(|op| op.payload.origin_device_id.as_str())
        {
            return Err(JournalError::Invariant(
                "publication observation local origin changed",
            ));
        }
        intent.completion = Some(completion.clone());
        intent.validate()?;
        let mut expected_protection = expected_intent
            .completion
            .as_ref()
            .unwrap()
            .protected_objects
            .clone();
        for content in completion
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            for chunk in &content.chunks {
                if expected_protection
                    .insert(chunk.content_id.clone(), chunk.length)
                    .is_some_and(|length| length != chunk.length)
                {
                    return Err(JournalError::Invariant(
                        "publication observation conflicting lengths",
                    ));
                }
            }
        }
        if expected_protection != completion.protected_objects {
            return Err(JournalError::Invariant(
                "publication observation unrelated protection",
            ));
        }
        if self
            .current(&intent.space_id)?
            .as_ref()
            .map(Manifest::root)
            .transpose()?
            != Some(intent.baseline_root.clone())
        {
            return Err(JournalError::Invariant(
                "publication observation baseline changed",
            ));
        }
        let json = serde_json::to_string(&intent)?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(JournalError::Invariant(
                "publication observation intent byte limit",
            ));
        }
        let mut expected = rows(&before);
        let id = intent.transaction_id.as_str();
        let chunks: BTreeSet<_> = completion
            .protected_objects
            .keys()
            .map(ContentId::as_str)
            .collect();
        let new_pins = chunks
            .iter()
            .filter(|chunk| {
                !expected.contains_key(&(
                    "publication_objects".into(),
                    vec![id.into(), (**chunk).into()],
                ))
            })
            .count() as u64;
        replacement_capacity(&before, expected_intent, &json, completion, new_pins)?;
        let columns = expected
            .get_mut(&("publications".into(), vec![id.into()]))
            .ok_or(JournalError::Invariant(
                "publication observation owner missing",
            ))?;
        update(columns, "intent", &json)?;
        update(
            columns,
            "intent_hash",
            ContentId::hash(json.as_bytes()).as_str(),
        )?;
        tx.execute(
            "UPDATE publications SET intent=?1,intent_hash=?2 WHERE transaction_id=?3",
            params![json, ContentId::hash(json.as_bytes()).as_str(), id],
        )?;
        // Retain previous observation pins as well until atomic snapshot handoff.
        for chunk in &chunks {
            let key = (
                "publication_objects".into(),
                vec![id.into(), (*chunk).into()],
            );
            if let std::collections::btree_map::Entry::Vacant(entry) = expected.entry(key) {
                entry.insert(vec![text("transaction_id", id), text("content_id", chunk)]);
                tx.execute(
                    "INSERT INTO publication_objects VALUES (?1,?2)",
                    params![id, chunk],
                )?;
            }
        }
        for row in before.rows.iter().filter(|row| row.table() == "gc_marks") {
            if chunks.contains(field(row.columns(), "content_id")?) {
                let mark = field(row.columns(), "mark_id")?.to_string();
                if !expected.contains_key(&("gc_cancellations".into(), vec![mark.clone()])) {
                    expected
                        .entry(("gc_invalidations".into(), vec![mark.clone()]))
                        .or_insert_with(|| vec![text("mark_id", &mark)]);
                }
            }
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        verify(&expected, &after)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn commit_admitted_publication(
        &mut self,
        id: &EntryId,
        expected_root: &SnapshotId,
        manifest: &Manifest,
        operations: &[Operation],
        timestamp: u64,
    ) -> Result<SnapshotId> {
        crate::native_publication::legacy_gate(&self.connection, id)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        let intent = &publication.intent;
        let completion = intent.completion.as_ref().ok_or(JournalError::Invariant(
            "publication history reservation missing",
        ))?;
        if publication.state != PublicationState::Published
            || expected_root != &intent.baseline_root
            || manifest != &completion.manifest
            || operations != completion.operations
            || timestamp != completion.timestamp_ms
        {
            return Err(JournalError::Invariant(
                "publication completion differs from admitted plan",
            ));
        }
        let before = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        let snapshot_json = serde_json::to_string(manifest)?;
        let operation_json = completion
            .operations
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let projection = storage_policy::local_commit::project_publication(
            &before,
            storage_policy::local_commit::Input {
                expected_root: Some(expected_root),
                manifest,
                operations,
                operation_json: &operation_json,
                snapshot_json: &snapshot_json,
                timestamp,
                observation_json: None,
            },
            intent,
        )?;
        let root = self.commit_history_sql(
            &tx,
            Some(expected_root),
            manifest,
            operations,
            timestamp,
            Completion::Publication(id),
        )?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&intent.space_id, bounds)?;
        projection.receipt(&after)?;
        tx.commit()?;
        Ok(root)
    }
}
