//! Exact foreign prefix receipt; never consumes the receiver's signing sequence.
use super::*;
use rusqlite::OptionalExtension;
use sync_extend_core_model::DeviceId;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ForeignScope {
    pub receiver_device: DeviceId,
    pub received_resolving_operations: usize,
    pub received_vector: VersionVector,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ForeignConflictResolutionAdmission {
    pub transaction_id: EntryId,
    pub receiver_device: DeviceId,
    pub resolver_device: DeviceId,
    pub received_resolving_operations: usize,
    pub missing_resolving_operations: usize,
    pub protected_chunks: Vec<ChunkRef>,
    pub original_signatures_retained: bool,
    pub receiver_sequence_reserved: bool,
    pub worktree_materialized: bool,
}

pub(super) fn transaction_id(
    proof: &ConflictResolutionProof,
    receiver: &DeviceId,
) -> Result<EntryId> {
    Ok(
        hash(&("SyncExtend foreign conflict admission v1", receiver, proof))?.as_str()[..32]
            .parse()?,
    )
}

fn received(connection: &Connection, space: &SpaceId) -> Result<(Vec<Operation>, VersionVector)> {
    let count: i64 =
        connection.query_row("SELECT count(*) FROM main.operations", [], |r| r.get(0))?;
    if !(0..=10_000).contains(&count) {
        return Err(invalid("foreign conflict complete operation count"));
    }
    let mut operations = Vec::new();
    let mut bytes = 0usize;
    let mut statement = connection.prepare(
        "SELECT op_id,space_id,origin_device_id,origin_seq,payload,state FROM main.operations ORDER BY op_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let json: String = row.get(4)?;
        bytes = bytes
            .checked_add(json.len())
            .filter(|n| *n <= sync_extend_core_model::conflict_resolution::MAX_RESOLUTION_BYTES)
            .ok_or(invalid("foreign conflict aggregate operation byte budget"))?;
        if json.len() > crate::MAX_OPERATION_BYTES {
            return Err(invalid("foreign conflict operation byte budget"));
        }
        let operation: Operation = serde_json::from_str(&json)?;
        let state: String = row.get(5)?;
        if row.get::<_, String>(0)? != operation.op_id.as_str()
            || row.get::<_, String>(1)? != space.as_str()
            || row.get::<_, String>(2)? != operation.payload.origin_device_id.as_str()
            || row.get::<_, i64>(3)? != operation.payload.origin_seq as i64
            || serde_json::to_string(&operation)? != json
            || !matches!(state.as_str(), "received" | "materialized")
        {
            return Err(invalid("foreign conflict exact operation row differs"));
        }
        operation.validate()?;
        operations.push(operation);
    }
    let mut vector = VersionVector::default();
    let mut statement =
        connection.prepare("SELECT space_id,device_id,contiguous_seq FROM main.receive_cursors")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let device: DeviceId = row.get::<_, String>(1)?.parse()?;
        let sequence = u64::try_from(row.get::<_, i64>(2)?)
            .map_err(|_| invalid("foreign conflict negative cursor"))?;
        if row.get::<_, String>(0)? != space.as_str()
            || sequence == 0
            || vector.get(&device) != 0
            || vector.0.len() >= 1024
        {
            return Err(invalid("foreign conflict cursor scope differs"));
        }
        vector.observe(device, sequence);
    }
    Ok((operations, vector))
}

impl ForeignScope {
    pub(super) fn capture(
        connection: &Connection,
        intent: &ConflictResolutionAdmissionIntent,
        plan: &FileResolutionPlan,
    ) -> Result<Self> {
        let receiver: DeviceId = connection
            .query_row(
                "SELECT value FROM main.local_state WHERE key='device_id'",
                [],
                |r| r.get::<_, String>(0),
            )?
            .parse()?;
        if receiver == intent.proof.payload.resolver_device {
            return Err(invalid(
                "foreign conflict requires distinct receiver identity",
            ));
        }
        let id = transaction_id(&intent.proof, &receiver)?;
        let stored: Option<String> = connection
            .query_row(
                "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(json) = stored {
            let parent: Header = serde_json::from_str(&json)?;
            if parent.intent != *intent {
                return Err(invalid("foreign conflict retry intent differs"));
            }
            parent.plan()?;
            return parent
                .foreign
                .ok_or(invalid("foreign conflict retry provenance absent"));
        }
        let (rows, vector) = received(connection, &intent.proof.payload.space_id)?;
        let expected: BTreeMap<_, _> = intent
            .proof
            .payload
            .originals
            .iter()
            .map(|signed| (&signed.operation.op_id, &signed.operation))
            .collect();
        let mut rest: BTreeMap<_, _> = rows.iter().map(|op| (&op.op_id, op)).collect();
        for (id, operation) in expected {
            if rest.remove(id) != Some(operation) {
                return Err(invalid("foreign conflict original signed bundle differs"));
            }
        }
        let mut prefix = 0;
        let mut missing = false;
        for signed in &intent.proof.payload.resolving {
            match rest.remove(&signed.operation.op_id) {
                Some(actual) if !missing && actual == &signed.operation => prefix += 1,
                None => missing = true,
                _ => return Err(invalid("foreign conflict prefix differs or skips")),
            }
        }
        if !rest.is_empty() {
            return Err(invalid("foreign conflict unsupported unrelated history"));
        }
        let scope = Self {
            receiver_device: receiver,
            received_resolving_operations: prefix,
            received_vector: vector,
        };
        if reduce_operations(&intent.proof.payload.space_id, &rows, 10_000)?.received_vector
            != scope.received_vector
        {
            return Err(invalid("foreign conflict complete received cursor differs"));
        }
        let mut expected_vector = plan.received_vector.clone();
        for signed in intent.proof.payload.resolving.iter().take(prefix) {
            expected_vector.observe(
                signed.operation.payload.origin_device_id.clone(),
                signed.operation.payload.origin_seq,
            );
        }
        if scope.received_vector != expected_vector {
            return Err(invalid("foreign conflict exact prefix vector differs"));
        }
        Ok(scope)
    }

    pub(super) fn validate(&self, header: &Header, plan: &FileResolutionPlan) -> Result<()> {
        let payload = &header.intent.proof.payload;
        if self.receiver_device == payload.resolver_device
            || self.received_resolving_operations > payload.resolving.len()
        {
            return Err(invalid(
                "foreign conflict immutable receiver or prefix differs",
            ));
        }
        let mut expected = plan.received_vector.clone();
        for signed in payload
            .resolving
            .iter()
            .take(self.received_resolving_operations)
        {
            expected.observe(
                payload.resolver_device.clone(),
                signed.operation.payload.origin_seq,
            );
        }
        if expected != self.received_vector {
            return Err(invalid("foreign conflict immutable prefix cursor differs"));
        }
        Ok(())
    }

    pub(super) fn bind(
        &self,
        connection: &Connection,
        header: &Header,
        plan: &FileResolutionPlan,
    ) -> Result<()> {
        self.validate(header, plan)?;
        let payload = &header.intent.proof.payload;
        let (rows, vector) = received(connection, &payload.space_id)?;
        let expected: BTreeMap<_, _> = payload
            .originals
            .iter()
            .chain(
                payload
                    .resolving
                    .iter()
                    .take(self.received_resolving_operations),
            )
            .map(|signed| (&signed.operation.op_id, &signed.operation))
            .collect();
        if rows.len() != expected.len() || vector != self.received_vector {
            return Err(invalid(
                "foreign conflict immutable complete receipt differs",
            ));
        }
        for operation in rows {
            if expected.get(&operation.op_id).copied() != Some(&operation) {
                return Err(invalid(
                    "foreign conflict immutable signed operation differs",
                ));
            }
            let state: String = connection.query_row(
                "SELECT state FROM main.operations WHERE op_id=?1",
                [operation.op_id.as_str()],
                |r| r.get(0),
            )?;
            let expected_state = header
                .original_states
                .get(operation.op_id.as_str())
                .map_or("received", String::as_str);
            if state != expected_state {
                return Err(invalid("foreign conflict received/applied prefix differs"));
            }
        }
        let pruned: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.snapshot_prunings WHERE snapshot_id=?1 OR snapshot_id=?2)",
            params![header.intent.baseline.root()?.as_str(),header.target.root()?.as_str()], |r| r.get(0),
        )?;
        if pruned {
            return Err(invalid("foreign conflict baseline or target pruned"));
        }
        Ok(())
    }
}

impl Journal {
    /// Dedicated authenticated foreign admission. No local signing or sequence reservation.
    pub fn with_foreign_conflict_resolution_admission<T, E>(
        &self,
        intent: &ConflictResolutionAdmissionIntent,
        inspect: impl FnOnce(&ForeignConflictResolutionAdmission) -> std::result::Result<T, E>,
    ) -> std::result::Result<(CasAccessGuard, T, ForeignConflictResolutionAdmission), E>
    where
        E: From<crate::JournalError>,
    {
        let mut receipt = None;
        let (guard, held, _) = self.with_conflict_admission_scope(
            intent,
            true,
            |admission| -> std::result::Result<T, E> {
                let json: String = self.connection.query_row(
                "SELECT header FROM main.conflict_resolution_admissions WHERE transaction_id=?1",
                [admission.transaction_id.as_str()], |r| r.get(0),
            ).map_err(crate::JournalError::from)?;
                let header: Header =
                    serde_json::from_str(&json).map_err(crate::JournalError::from)?;
                let scope = header
                    .foreign
                    .ok_or(invalid("foreign admission receipt provenance absent"))?;
                let result = ForeignConflictResolutionAdmission {
                    transaction_id: admission.transaction_id.clone(),
                    receiver_device: scope.receiver_device,
                    resolver_device: intent.proof.payload.resolver_device.clone(),
                    received_resolving_operations: scope.received_resolving_operations,
                    missing_resolving_operations: intent.proof.payload.resolving.len()
                        - scope.received_resolving_operations,
                    protected_chunks: admission.protected_chunks.clone(),
                    original_signatures_retained: true,
                    receiver_sequence_reserved: false,
                    worktree_materialized: false,
                };
                let held = inspect(&result)?;
                receipt = Some(result);
                Ok(held)
            },
        )?;
        Ok((
            guard,
            held,
            receipt.ok_or(invalid("foreign admission receipt absent"))?,
        ))
    }
}
