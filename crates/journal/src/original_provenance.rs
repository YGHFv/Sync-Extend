//! Exact durable individual signature provenance, not operation reception or apply.
use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    Journal, JournalError, RemotePublicationProof, Result,
};
use rusqlite::{
    params,
    types::{Value, ValueRef},
    Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use sync_extend_core_model::{ContentId, DeviceId, SpaceId};

const fn c(name: &'static str, kind: ColumnKind, pk: usize) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key: pk,
        not_null: true,
        default: None,
    }
}
pub(crate) const TABLES: &[TableSpec] = &[TableSpec {
    name: "original_operation_provenance",
    columns: &[
        c("space_id", ColumnKind::Text(32), 1),
        c("origin_device_id", ColumnKind::Text(64), 2),
        c("origin_seq", ColumnKind::Integer, 3),
        c("op_id", ColumnKind::Text(64), 0),
        c("proof_hash", ColumnKind::Text(64), 0),
        c("proof", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
    ],
}];

#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<Option<Vec<Value>>>>);
pub(crate) struct Permit(Gate);
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0 .0.lock() {
            *held = None;
        }
    }
}
impl Gate {
    pub(crate) fn register(connection: &Connection) -> Result<Self> {
        let gate = Self::default();
        for name in [
            "sync_original_operation_issue",
            "sync_original_page_issue",
            "sync_forwarded_page_issue",
            "sync_storage_handoff_issue",
        ] {
            let state = gate.clone();
            connection.create_scalar_function(
                name,
                -1,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |ctx| {
                    let Ok(mut held) = state.0.lock() else {
                        return Ok(false);
                    };
                    let Some(values) = held.as_ref() else {
                        return Ok(false);
                    };
                    let matches = values.len() == ctx.len()
                        && values
                            .iter()
                            .enumerate()
                            .all(|(i, v)| match (v, ctx.get_raw(i)) {
                                (Value::Text(a), ValueRef::Text(b)) => a.as_bytes() == b,
                                (Value::Integer(a), ValueRef::Integer(b)) => *a == b,
                                _ => false,
                            });
                    if matches {
                        *held = None;
                    }
                    Ok(matches)
                },
            )?;
        }
        Ok(gate)
    }
    pub(crate) fn permit(&self, values: Vec<Value>) -> Result<Permit> {
        let mut held = self
            .0
            .lock()
            .map_err(|_| JournalError::Invariant("original issuer poisoned"))?;
        if held.is_some() {
            return Err(JournalError::Invariant("original issuer already active"));
        }
        *held = Some(values);
        Ok(Permit(self.clone()))
    }
}

fn columns(proof: &RemotePublicationProof) -> Result<Vec<Value>> {
    proof.verify()?;
    let bytes = serde_json::to_string(proof)?;
    if bytes.len() > crate::MAX_OPERATION_BYTES {
        return Err(JournalError::Invariant("original provenance byte bound"));
    }
    Ok(vec![
        Value::Text(proof.operation.payload.space_id.to_string()),
        Value::Text(proof.operation.payload.origin_device_id.to_string()),
        Value::Integer(crate::sql_integer(proof.operation.payload.origin_seq)?),
        Value::Text(proof.operation.op_id.to_string()),
        Value::Text(ContentId::hash(bytes.as_bytes()).to_string()),
        Value::Text(bytes),
    ])
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    type Object = (String, String, String, Option<String>);
    fn objects(connection: &Connection) -> Result<Vec<Object>> {
        Ok(connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema
                 WHERE instr(name,'original_operation_provenance')=1
                    OR tbl_name='original_operation_provenance'
                 ORDER BY type,name",
            )?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE instr(name,'original_operation_provenance')=1
            OR tbl_name='original_operation_provenance')",
        [],
        |row| row.get(0),
    )?;
    if shadow {
        return Err(JournalError::Invariant(
            "original provenance TEMP shadow or trigger",
        ));
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(include_str!("migration-049.sql"))?;
    if objects(connection)? != objects(&expected)? {
        return Err(JournalError::Invariant(
            "original provenance exact table/trigger/index differs",
        ));
    }
    Ok(())
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<RemotePublicationProof>> {
    validate_schema(connection)?;
    crate::storage_inventory::reader::preflight(
        connection,
        TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let mut statement=connection.prepare("SELECT space_id,origin_device_id,origin_seq,op_id,proof_hash,proof FROM main.original_operation_provenance ORDER BY space_id,origin_device_id,origin_seq")?;
    let rows = statement
        .query_map([], |row| {
            (0..6)
                .map(|i| row.get::<_, Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut proofs = Vec::new();
    for row in rows {
        let Value::Text(json) = &row[5] else {
            return Err(JournalError::Invariant("original provenance record type"));
        };
        let proof: RemotePublicationProof = serde_json::from_str(json)?;
        if columns(&proof)? != row {
            return Err(JournalError::Invariant("original provenance exact row"));
        }
        proofs.push(proof);
    }
    Ok(proofs)
}

impl Journal {
    /// Bounded complete ordinary history for a separately authenticated conflict
    /// bundle. No row is filtered by origin, applied status or native eligibility.
    pub fn original_conflict_operations(
        &self,
        space: &SpaceId,
        max_operations: usize,
        max_bytes: usize,
    ) -> Result<Vec<sync_extend_core_model::Operation>> {
        if max_operations == 0
            || max_operations > sync_extend_core_model::causal::MAX_CAUSAL_OPERATIONS
            || max_bytes == 0
            || max_bytes > sync_extend_core_model::conflict_resolution::MAX_RESOLUTION_BYTES
        {
            return Err(JournalError::Invariant("original conflict listing bounds"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        if self.state("space_id")?.as_ref() != Some(&space.to_string()) {
            return Err(JournalError::Invariant("original conflict listing space"));
        }
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let (count, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(CAST(payload AS BLOB))),0)
             FROM main.operations WHERE space_id=?1",
            [space.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count < 0
            || bytes < 0
            || count as u64 > max_operations as u64
            || bytes as u64 > max_bytes as u64
        {
            return Err(JournalError::Invariant(
                "original conflict listing capacity",
            ));
        }
        let operations = self.operations(space)?;
        if operations.len() != count as usize {
            return Err(JournalError::Invariant("original conflict listing changed"));
        }
        tx.commit()?;
        Ok(operations)
    }

    /// Caller supplies a separately approved source key, never a wire key as approval.
    pub fn retain_original_provenance(
        &self,
        proof: &RemotePublicationProof,
        approved: &[u8; 32],
    ) -> Result<bool> {
        if &proof.public_key != approved {
            return Err(JournalError::Invariant(
                "original approved source key differs",
            ));
        }
        let values = columns(proof)?;
        let space = &proof.operation.payload.space_id;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if self.state("space_id")?.as_ref() != Some(&space.to_string())
            || self.state("device_id")?.as_ref()
                == Some(&proof.operation.payload.origin_device_id.to_string())
        {
            return Err(JournalError::Invariant(
                "original receiver independent identity",
            ));
        }
        let before = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let existing:Option<String>=tx.query_row(
            "SELECT proof FROM main.original_operation_provenance WHERE space_id=?1 AND origin_device_id=?2 AND origin_seq=?3",
            params![space.as_str(),proof.operation.payload.origin_device_id.as_str(),crate::sql_integer(proof.operation.payload.origin_seq)?],
            |row|row.get(0)).optional()?;
        if let Some(old) = existing {
            let Value::Text(new) = &values[5] else {
                unreachable!()
            };
            if &old != new {
                return Err(JournalError::Invariant("original provenance equivocation"));
            }
            tx.commit()?;
            return Ok(false);
        }
        if !before.report.within_accounted_limits() {
            return Err(JournalError::Invariant(
                "original current capacity exceeded",
            ));
        }
        let bytes: u64 = values
            .iter()
            .map(|v| match v {
                Value::Text(s) => s.len() as u64,
                Value::Integer(_) => 8,
                _ => 0,
            })
            .sum();
        let prior = before.report.accounted_total();
        if prior
            .rows
            .checked_add(1)
            .is_none_or(|n| n > bounds.max_rows)
            || prior
                .logical_bytes
                .checked_add(bytes)
                .is_none_or(|n| n > bounds.max_logical_bytes)
        {
            return Err(JournalError::Invariant(
                "original prospective capacity exceeded",
            ));
        }
        let _permit = self.original_operation_issuance.permit(values.clone())?;
        if tx.execute(
            "INSERT INTO main.original_operation_provenance VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params_from_iter(&values),
        )? != 1
        {
            return Err(JournalError::Invariant(
                "original provenance insert differs",
            ));
        }
        let after = self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let old: BTreeMap<_, _> = before
            .rows
            .iter()
            .map(|r| {
                (
                    (r.table().to_owned(), r.primary_key().to_vec()),
                    r.fingerprint(),
                )
            })
            .collect();
        let mut next: BTreeMap<_, _> = after
            .rows
            .iter()
            .map(|r| {
                (
                    (r.table().to_owned(), r.primary_key().to_vec()),
                    r.fingerprint(),
                )
            })
            .collect();
        let key = (
            "original_operation_provenance".to_owned(),
            vec![
                space.to_string(),
                proof.operation.payload.origin_device_id.to_string(),
                proof.operation.payload.origin_seq.to_string(),
            ],
        );
        if next.remove(&key).is_none()
            || next != old
            || after.report.accounted_total().rows != prior.rows + 1
            || after.report.accounted_total().logical_bytes != prior.logical_bytes + bytes
            || !after.report.within_accounted_limits()
        {
            return Err(JournalError::Invariant(
                "original exact all-table postwrite receipt",
            ));
        }
        tx.commit()?;
        Ok(true)
    }

    pub fn original_provenance(
        &self,
        space: &SpaceId,
        origin: &DeviceId,
        sequence: u64,
    ) -> Result<Option<RemotePublicationProof>> {
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let result = audit(&self.connection)?.into_iter().find(|p| {
            p.operation.payload.space_id == *space
                && p.operation.payload.origin_device_id == *origin
                && p.operation.payload.origin_seq == sequence
        });
        tx.commit()?;
        Ok(result)
    }
}
