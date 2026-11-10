//! Immutable signed page restart provenance, never received or native authority.
use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    Journal, JournalError, RemotePublicationProof, Result,
};
use rusqlite::{
    params, types::Value, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{ContentId, SpaceId};
use sync_extend_transport::{PeerIdentity, SignedOriginalOperationPage, MAX_ORIGINAL_PAGE_BYTES};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalPageEnvelope {
    pub source: PeerIdentity,
    pub receiver: PeerIdentity,
    pub signed_page: SignedOriginalOperationPage,
}

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
    name: "original_page_inbox",
    columns: &[
        c("request_id", ColumnKind::Text(64), 1),
        c("space_id", ColumnKind::Text(32), 0),
        c("origin_device_id", ColumnKind::Text(64), 0),
        c("receiver_device_id", ColumnKind::Text(64), 0),
        c("after_sequence", ColumnKind::Integer, 0),
        c("last_sequence", ColumnKind::Integer, 0),
        c("tip_sequence", ColumnKind::Integer, 0),
        c("envelope_hash", ColumnKind::Text(64), 0),
        c("envelope", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
    ],
}];

fn invalid() -> JournalError {
    JournalError::Invariant("original signed page inbox identity/signature/provenance")
}

fn values(envelope: &OriginalPageEnvelope) -> Result<Vec<Value>> {
    let signed = &envelope.signed_page;
    let page = &signed.page;
    signed
        .verify(
            &envelope.source,
            &envelope.receiver,
            &page.channel_binding,
            page.after_sequence,
        )
        .map_err(|_| invalid())?;
    if page.operations.is_empty() {
        return Err(invalid());
    }
    let bytes = serde_json::to_string(envelope)?;
    if bytes.len() > MAX_ORIGINAL_PAGE_BYTES + 128 * 1024 {
        return Err(JournalError::Invariant(
            "original page inbox envelope byte bound",
        ));
    }
    let last = page.operations.last().ok_or_else(invalid)?;
    Ok(vec![
        Value::Text(page.request_id().map_err(|_| invalid())?.to_string()),
        Value::Text(page.space_id.to_string()),
        Value::Text(page.origin_device.to_string()),
        Value::Text(page.receiver_device.to_string()),
        Value::Integer(crate::sql_integer(page.after_sequence)?),
        Value::Integer(crate::sql_integer(last.operation.payload.origin_seq)?),
        Value::Integer(crate::sql_integer(page.tip_sequence)?),
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
                 WHERE instr(name,'original_page_inbox')=1 OR tbl_name='original_page_inbox'
                 ORDER BY type,name",
            )?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<_>>()?)
    }
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE instr(name,'original_page_inbox')=1 OR tbl_name='original_page_inbox')",
        [],
        |row| row.get(0),
    )?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(include_str!("migration-050.sql"))?;
    if shadow || objects(connection)? != objects(&expected)? {
        return Err(JournalError::Invariant(
            "original page inbox schema/trigger/index/TEMP",
        ));
    }
    Ok(())
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<OriginalPageEnvelope>> {
    validate_schema(connection)?;
    crate::storage_inventory::reader::preflight(
        connection,
        TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let proofs = crate::original_provenance::audit(connection)?;
    let mut statement = connection.prepare(
        "SELECT request_id,space_id,origin_device_id,receiver_device_id,after_sequence,
         last_sequence,tip_sequence,envelope_hash,envelope FROM main.original_page_inbox
         ORDER BY request_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            (0..9)
                .map(|i| row.get::<_, Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for row in rows {
        let Value::Text(json) = &row[8] else {
            return Err(invalid());
        };
        let envelope: OriginalPageEnvelope = serde_json::from_str(json)?;
        if values(&envelope)? != row {
            return Err(invalid());
        }
        for signed in &envelope.signed_page.page.operations {
            let original = RemotePublicationProof {
                public_key: envelope.source.public_key,
                operation: signed.operation.clone(),
                signature: signed.signature.clone(),
            };
            if !proofs.contains(&original) {
                return Err(invalid());
            }
        }
        result.push(envelope);
    }
    Ok(result)
}

impl Journal {
    /// Current approval is supplied independently; persisted wire keys never approve themselves.
    pub fn retain_original_page(
        &self,
        envelope: &OriginalPageEnvelope,
        approved: &[u8; 32],
    ) -> Result<bool> {
        if &envelope.source.public_key != approved {
            return Err(invalid());
        }
        let values = values(envelope)?;
        let page = &envelope.signed_page.page;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if self.state("space_id")?.as_deref() != Some(page.space_id.as_str())
            || self.state("device_id")?.as_deref() != Some(page.receiver_device.as_str())
        {
            return Err(invalid());
        }
        let before = self.read_view().audit_original_provenance_capacity(
            &page.space_id,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let retained = crate::original_provenance::audit(&self.connection)?;
        for signed in &page.operations {
            if !retained.contains(&RemotePublicationProof {
                public_key: *approved,
                operation: signed.operation.clone(),
                signature: signed.signature.clone(),
            }) {
                return Err(invalid());
            }
        }
        let existing: Option<String> = tx
            .query_row(
                "SELECT envelope FROM main.original_page_inbox WHERE request_id=?1",
                [page.request_id().map_err(|_| invalid())?.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        let Value::Text(json) = &values[8] else {
            return Err(invalid());
        };
        if let Some(old) = existing {
            if &old != json {
                return Err(invalid());
            }
            tx.commit()?;
            return Ok(false);
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
        if !before.report.within_accounted_limits()
            || prior
                .rows
                .checked_add(1)
                .is_none_or(|n| n > bounds.max_rows)
            || prior
                .logical_bytes
                .checked_add(bytes)
                .is_none_or(|n| n > bounds.max_logical_bytes)
        {
            return Err(JournalError::Invariant(
                "original inbox preeffect current/peak capacity",
            ));
        }
        let _permit = self.original_operation_issuance.permit(values.clone())?;
        if tx.execute(
            "INSERT INTO main.original_page_inbox VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params_from_iter(&values),
        )? != 1
        {
            return Err(invalid());
        }
        let after = self.read_view().audit_original_provenance_capacity(
            &page.space_id,
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
            "original_page_inbox".to_owned(),
            vec![page.request_id().map_err(|_| invalid())?.to_string()],
        );
        if next.remove(&key).is_none()
            || next != old
            || after.report.accounted_total().rows != prior.rows + 1
            || after.report.accounted_total().logical_bytes != prior.logical_bytes + bytes
            || !after.report.within_accounted_limits()
        {
            return Err(JournalError::Invariant(
                "original inbox exact allmain postwrite",
            ));
        }
        tx.commit()?;
        Ok(true)
    }

    /// Read only a bounded page set. Callers must recheck approval and native state before retry.
    pub fn original_pages(&self, space: &SpaceId, max: usize) -> Result<Vec<OriginalPageEnvelope>> {
        if max == 0 || max > crate::limits::MAX_ENTRIES {
            return Err(JournalError::Invariant("original inbox list bound"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        self.read_view().audit_original_provenance_capacity(
            space,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM main.original_page_inbox
             WHERE space_id=?1 LIMIT ?2)",
            params![space.as_str(), max as i64 + 1],
            |row| row.get(0),
        )?;
        if count > max as i64 {
            return Err(JournalError::Invariant(
                "original inbox listing requires backpressure",
            ));
        }
        let receiver = self.state("device_id")?.ok_or_else(invalid)?;
        let result = audit(&self.connection)?;
        if result.iter().any(|e| {
            e.signed_page.page.space_id != *space || e.receiver.device_id.as_str() != receiver
        }) {
            return Err(invalid());
        }
        tx.commit()?;
        Ok(result)
    }
}
