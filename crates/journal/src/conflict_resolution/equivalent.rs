//! Independently signed logical equivalence; never a replacement native issuer.
use super::*;
use sync_extend_core_model::conflict_resolution::verify_file_resolution_projection;

const MAX_EQUIVALENT_HISTORIES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub format: u32,
    pub transaction_id: EntryId,
    pub base_transaction_id: EntryId,
    pub receiver_device: sync_extend_core_model::DeviceId,
    pub proof: ConflictResolutionProof,
    pub approved_keys: Vec<ConflictResolutionKey>,
    pub prior_equivalents: Vec<ConflictResolutionProof>,
    pub target: Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EquivalentConflictHistory {
    pub transaction_id: EntryId,
    pub base_transaction_id: EntryId,
    pub receiver_device: sync_extend_core_model::DeviceId,
    pub resolver_device: sync_extend_core_model::DeviceId,
    pub target_root: SnapshotId,
    pub receiver_sequence_reserved: bool,
    pub native_delta: bool,
    pub original_signatures_retained: bool,
}

pub(super) fn identity(parent: &Header, proof: &ConflictResolutionProof) -> Result<EntryId> {
    Ok(hash(&(
        "SyncExtend equivalent conflict history v1",
        &parent.transaction_id,
        parent.receiver_device(),
        proof,
    ))?
    .as_str()[..32]
        .parse()?)
}

fn text(value: impl ToString) -> Value {
    Value::Text(value.to_string())
}

impl Record {
    pub(super) fn validate(&self, parent: &Header) -> Result<FileResolutionPlan> {
        let plan = parent.plan()?;
        if self.format != 1
            || self.base_transaction_id != parent.transaction_id
            || self.receiver_device != *parent.receiver_device()
            || self.proof.payload.resolver_device == self.receiver_device
            || self.proof.payload.originals != parent.intent.proof.payload.originals
            || self.transaction_id != identity(parent, &self.proof)?
            || self
                .approved_keys
                .windows(2)
                .any(|p| p[0].device_id >= p[1].device_id)
            || self
                .proof
                .verify(&self.approved_keys, ResolutionLimits::default())?
                != plan
        {
            return Err(invalid(
                "equivalent conflict exact approved original bundle differs",
            ));
        }
        let original: Vec<_> = parent
            .intent
            .proof
            .payload
            .originals
            .iter()
            .map(|s| s.operation.clone())
            .collect();
        if self.prior_equivalents.len() > MAX_EQUIVALENT_HISTORIES {
            return Err(invalid("equivalent conflict prior envelope count"));
        }
        let mut bytes = serde_json::to_vec(&self.proof)?.len();
        for proof in &self.prior_equivalents {
            bytes = bytes
                .checked_add(serde_json::to_vec(proof)?.len())
                .filter(|n| *n <= sync_extend_core_model::conflict_resolution::MAX_RESOLUTION_BYTES)
                .ok_or(invalid("equivalent conflict signed aggregate bytes"))?;
            if proof.payload.originals != parent.intent.proof.payload.originals
                || proof.verify(&self.approved_keys, ResolutionLimits::default())? != plan
            {
                return Err(invalid(
                    "equivalent conflict prior signed canonical bundle differs",
                ));
            }
        }
        let resolving: Vec<_> = parent
            .intent
            .proof
            .payload
            .resolving
            .iter()
            .chain(&self.proof.payload.resolving)
            .chain(
                self.prior_equivalents
                    .iter()
                    .flat_map(|p| p.payload.resolving.iter()),
            )
            .map(|s| s.operation.clone())
            .collect();
        verify_file_resolution_projection(
            &plan,
            &original,
            &resolving,
            ResolutionLimits::default(),
        )?;
        let mut combined = original;
        combined.extend(resolving);
        let reduced = reduce_operations(&parent.target.space_id, &combined, 10_000)?;
        if self.target.entries != plan.projected.entries
            || self.target.tombstones != plan.projected.tombstones
            || self.target.space_id != parent.target.space_id
            || !self
                .target
                .version_vector
                .dominates(&parent.target.version_vector)
            || self.target.version_vector != reduced.received_vector
        {
            return Err(invalid("equivalent conflict logical target differs"));
        }
        self.target.validate()?;
        Ok(plan)
    }

    pub(super) fn values(&self) -> Result<Vec<(&'static str, Vec<Value>)>> {
        let json = serde_json::to_string(self)?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(invalid("equivalent conflict record byte budget"));
        }
        let mut values = vec![(
            "equivalent_histories",
            vec![
                text(&self.transaction_id),
                text(&self.base_transaction_id),
                text(&self.receiver_device),
                text(&self.proof.payload.resolver_device),
                text(self.target.root()?),
                text(ContentId::hash(json.as_bytes())),
                text(json),
            ],
        )];
        for signed in &self.proof.payload.resolving {
            values.push((
                "equivalent_signatures",
                vec![
                    text(&self.transaction_id),
                    text(&signed.operation.op_id),
                    text(serde_json::to_string(signed)?),
                ],
            ));
        }
        Ok(values)
    }

    #[cfg(windows)]
    pub(super) fn receipt(&self) -> Result<EquivalentConflictHistory> {
        Ok(EquivalentConflictHistory {
            transaction_id: self.transaction_id.clone(),
            base_transaction_id: self.base_transaction_id.clone(),
            receiver_device: self.receiver_device.clone(),
            resolver_device: self.proof.payload.resolver_device.clone(),
            target_root: self.target.root()?,
            receiver_sequence_reserved: false,
            native_delta: false,
            original_signatures_retained: true,
        })
    }
}

pub(super) fn records(rows: &[JournalStoredRow]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    let mut bytes = 0usize;
    for row in rows
        .iter()
        .filter(|r| r.table() == "conflict_resolution_equivalent_histories")
    {
        if records.len() >= MAX_EQUIVALENT_HISTORIES {
            return Err(invalid("equivalent conflict record count"));
        }
        let column = row
            .columns()
            .iter()
            .find(|c| c.name == "record")
            .ok_or(invalid("equivalent conflict record column absent"))?;
        let crate::JournalStorageColumnValue::Text(json) = &column.value else {
            return Err(invalid("equivalent conflict record type"));
        };
        bytes = bytes
            .checked_add(json.len())
            .filter(|n| *n <= sync_extend_core_model::conflict_resolution::MAX_RESOLUTION_BYTES)
            .ok_or(invalid("equivalent conflict aggregate record bytes"))?;
        records.push(serde_json::from_str(json)?);
    }
    Ok(records)
}

pub(super) fn audit(rows: &[JournalStoredRow], connection: &Connection) -> Result<()> {
    let mut expected = RowMap::new();
    for record in records(rows)? {
        let json: String = connection.query_row(
            "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
            [record.base_transaction_id.as_str()],
            |r| r.get(0),
        )?;
        let parent: Header = serde_json::from_str(&json)?;
        record.validate(&parent)?;
        if !native_cleanup_state::complete(connection, &parent)? {
            return Err(invalid("equivalent conflict original terminal absent"));
        }
        for (name, value) in [
            ("space_id", record.target.space_id.as_str()),
            ("device_id", record.receiver_device.as_str()),
            ("worktree", parent.intent.worktree.as_str()),
        ] {
            let actual: String = connection.query_row(
                "SELECT value FROM main.local_state WHERE key=?1",
                [name],
                |r| r.get(0),
            )?;
            if actual != value {
                return Err(invalid("equivalent conflict receiver root differs"));
            }
        }
        for signed in &record.proof.payload.resolving {
            let op = &signed.operation;
            let actual: (String,String,i64,String,String) = connection.query_row(
                "SELECT space_id,origin_device_id,origin_seq,payload,state FROM main.operations WHERE op_id=?1",
                [op.op_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
            )?;
            if actual
                != (
                    op.payload.space_id.to_string(),
                    op.payload.origin_device_id.to_string(),
                    op.payload.origin_seq as i64,
                    serde_json::to_string(op)?,
                    "materialized".into(),
                )
            {
                return Err(invalid(
                    "equivalent conflict signed materialized row differs",
                ));
            }
        }
        let snapshot: String = connection.query_row(
            "SELECT manifest FROM main.snapshots WHERE snapshot_id=?1",
            [record.target.root()?.as_str()],
            |r| r.get(0),
        )?;
        if snapshot != serde_json::to_string(&record.target)? {
            return Err(invalid(
                "equivalent conflict immutable target snapshot differs",
            ));
        }
        for (suffix, values) in record.values()? {
            let (key, columns) = value_columns(suffix, &values)?;
            if expected.insert(key, columns).is_some() {
                return Err(invalid("equivalent conflict duplicate record"));
            }
        }
    }
    let actual = row_map(
        &rows
            .iter()
            .filter(|r| r.table().starts_with("conflict_resolution_equivalent_"))
            .cloned()
            .collect::<Vec<_>>(),
    );
    if expected != actual {
        return Err(invalid(
            "equivalent conflict complete record/signature receipt differs",
        ));
    }
    Ok(())
}
