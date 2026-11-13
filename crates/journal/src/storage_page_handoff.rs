//! Storage-only atomic exact owner handoff; never CAS disposition or a native claim.
use crate::{
    storage_inventory::reader::{ColumnKind, ColumnSpec, TableSpec},
    Journal, JournalError, ReferenceReservationIntent, Result,
};
use rusqlite::{
    params, types::Value, Connection, OptionalExtension, Transaction, TransactionBehavior,
};
use sync_extend_core_model::{reference_owner::ReferenceOwnerKind, Change, ContentId, EntryId};
use sync_extend_transport::{StoragePageDeliveryRecord, VerifiedStoragePageDelivery};

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
    name: "storage_page_handoffs",
    columns: &[
        c("owner_id", ColumnKind::Text(32), 1),
        c("space_id", ColumnKind::Text(32), 0),
        c("storage_id", ColumnKind::Text(64), 0),
        c("record_hash", ColumnKind::Text(64), 0),
        c("handed_off_at_ms", ColumnKind::Integer, 0),
        c("record", ColumnKind::Text(crate::MAX_OPERATION_BYTES), 0),
    ],
}];

fn invalid() -> JournalError {
    JournalError::Invariant("storage exact original page delivery handoff")
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<()> {
    type SchemaObject = (String, String, String, Option<String>);
    fn objects(connection: &Connection) -> Result<Vec<SchemaObject>> {
        Ok(connection
            .prepare(
                "SELECT type,name,tbl_name,sql FROM main.sqlite_schema
             WHERE instr(name,'storage_page_handoffs')=1 OR tbl_name='storage_page_handoffs'
             OR name='storage_handoff_no_pin'
             OR name='reference_reservation_pin_no_delete' ORDER BY type,name",
            )?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?)
    }
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(
        "CREATE TABLE reference_reservation_objects(owner_id TEXT,content_id TEXT);
         CREATE TRIGGER reference_reservation_pin_no_delete BEFORE DELETE
         ON reference_reservation_objects BEGIN SELECT 1; END;",
    )?;
    expected.execute_batch(include_str!("migration-057.sql"))?;
    let shadow: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE instr(name,'storage_page_handoffs')=1 OR tbl_name='storage_page_handoffs'
         OR name='storage_handoff_no_pin'
         OR name='reference_reservation_pin_no_delete')",
        [],
        |r| r.get(0),
    )?;
    if shadow || objects(connection)? != objects(&expected)? {
        return Err(invalid());
    }
    Ok(())
}

fn values(record: &StoragePageDeliveryRecord) -> Result<Vec<Value>> {
    record.validate().map_err(|_| invalid())?;
    let page = &record.retained.signed_page.page;
    let id = page.storage_id().map_err(|_| invalid())?;
    let json = serde_json::to_string(record)?;
    if json.len() > crate::MAX_OPERATION_BYTES {
        return Err(invalid());
    }
    Ok(vec![
        Value::Text(id.as_str()[..32].to_owned()),
        Value::Text(page.space_id.to_string()),
        Value::Text(id.to_string()),
        Value::Text(ContentId::hash(json.as_bytes()).to_string()),
        Value::Integer(crate::sql_integer(record.handed_off_at_ms)?),
        Value::Text(json),
    ])
}

fn owner_matches(
    intent: &ReferenceReservationIntent,
    record: &StoragePageDeliveryRecord,
) -> Result<()> {
    let page = &record.retained.signed_page.page;
    let id = page.storage_id().map_err(|_| invalid())?;
    let files = page
        .operations
        .iter()
        .filter_map(|signed| {
            if let Change::Put { entry } = &signed.operation.payload.change {
                entry.content.clone()
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if intent.owner_id.as_str() != &id.as_str()[..32]
        || intent.scope.space_id != page.space_id
        || intent.scope.kind != ReferenceOwnerKind::Download
        || intent.scope.target_device.is_some()
        || intent.scope.files != files
        || intent.created_at_ms
            != page
                .operations
                .first()
                .map_or(0, |s| s.operation.payload.created_at_ms)
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<StoragePageDeliveryRecord>> {
    validate_schema(connection)?;
    crate::storage_inventory::reader::preflight(
        connection,
        TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let mut statement = connection.prepare(
        "SELECT owner_id,space_id,storage_id,record_hash,handed_off_at_ms,record
         FROM main.storage_page_handoffs ORDER BY owner_id",
    )?;
    let rows = statement
        .query_map([], |r| {
            (0..6)
                .map(|i| r.get::<_, Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for row in rows {
        let Value::Text(json) = &row[5] else {
            return Err(invalid());
        };
        let record: StoragePageDeliveryRecord = serde_json::from_str(json)?;
        if values(&record)? != row {
            return Err(invalid());
        }
        let owner = &row[0];
        let intent: String = connection.query_row(
            "SELECT intent FROM main.reference_reservations WHERE owner_id=?1",
            [owner],
            |r| r.get(0),
        )?;
        owner_matches(&serde_json::from_str(&intent)?, &record)?;
        for signed in &record.retained.signed_page.page.operations {
            let json: String = connection.query_row(
                "SELECT proof FROM main.original_operation_provenance
                 WHERE space_id=?1 AND origin_device_id=?2 AND origin_seq=?3",
                params![
                    signed.operation.payload.space_id.as_str(),
                    signed.operation.payload.origin_device_id.as_str(),
                    crate::sql_integer(signed.operation.payload.origin_seq)?,
                ],
                |r| r.get(0),
            )?;
            let proof: crate::RemotePublicationProof = serde_json::from_str(&json)?;
            proof.verify()?;
            if proof.operation != signed.operation
                || proof.signature != signed.signature
                || proof.public_key != record.retained.origin.public_key
            {
                return Err(invalid());
            }
        }
        result.push(record);
    }
    Ok(result)
}

pub(crate) fn reference_terminal(
    connection: &Connection,
    intent: &ReferenceReservationIntent,
) -> Result<bool> {
    validate_schema(connection)?;
    let stored: Option<Vec<Value>> = connection
        .query_row(
            "SELECT owner_id,space_id,storage_id,record_hash,handed_off_at_ms,
         CASE WHEN length(CAST(record AS BLOB))<=16777216
         THEN record ELSE '' END FROM main.storage_page_handoffs WHERE owner_id=?1",
            [intent.owner_id.as_str()],
            |r| (0..6).map(|i| r.get(i)).collect(),
        )
        .optional()?;
    if let Some(stored) = stored {
        let Value::Text(json) = &stored[5] else {
            return Err(invalid());
        };
        let record: StoragePageDeliveryRecord = serde_json::from_str(json)?;
        if values(&record)? != stored {
            return Err(invalid());
        }
        owner_matches(intent, &record)?;
        return Ok(true);
    }
    Ok(false)
}

impl Journal {
    /// Caller obtains a verified delivery from independently current keys. CAS
    /// coordination precedes SQLite; exact terminal and pin removal commit together.
    pub fn handoff_storage_page(&self, verified: &VerifiedStoragePageDelivery) -> Result<bool> {
        let record = verified.record();
        let issued = values(record)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid())?
            .as_millis();
        if record.handed_off_at_ms as u128 > now {
            return Err(invalid());
        }
        let id: EntryId = record.policy.storage_id.as_str()[..32].parse()?;
        if self.state("storage_role")?.as_deref() != Some("storage-v1")
            || self.state("worktree")?.is_some()
            || self.state("space_id")?.as_deref() != Some(record.policy.space_id.as_str())
            || self.state("device_id")?.as_deref() != Some(record.policy.storage_device.as_str())
        {
            return Err(invalid());
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let bounds = self.writer_capacity_limits(self.max_storage_entries)?;
        let before = self.read_view().audit_original_provenance_capacity(
            &record.policy.space_id,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let prior: Option<String> = tx
            .query_row(
                "SELECT record FROM main.storage_page_handoffs WHERE owner_id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            let old: StoragePageDeliveryRecord = serde_json::from_str(&prior)?;
            if old.policy != record.policy
                || old.retained.signed_page.page.operations
                    != record.retained.signed_page.page.operations
            {
                return Err(invalid());
            }
            tx.commit()?;
            return Ok(false);
        }
        let owner = self
            .reference_reservations(&record.policy.space_id, self.max_storage_entries)?
            .into_iter()
            .find(|o| o.intent.owner_id == id)
            .ok_or_else(invalid)?;
        owner_matches(&owner.intent, record)?;
        if owner.state != "reserved" {
            return Err(invalid());
        }
        let additional = issued
            .iter()
            .map(|v| match v {
                Value::Text(text) => text.len() as u64,
                Value::Integer(_) => 8,
                _ => 0,
            })
            .sum::<u64>();
        let prior = before.report.accounted_total();
        if !before.report.within_accounted_limits()
            || prior
                .rows
                .checked_add(1)
                .is_none_or(|n| n > bounds.max_rows)
            || prior
                .logical_bytes
                .checked_add(additional)
                .is_none_or(|n| n > bounds.max_logical_bytes)
        {
            return Err(JournalError::Invariant(
                "storage handoff peak exact capacity",
            ));
        }
        {
            let _permit = self.original_operation_issuance.permit(issued.clone())?;
            if tx.execute(
                "INSERT INTO main.storage_page_handoffs VALUES(?1,?2,?3,?4,?5,?6)",
                rusqlite::params_from_iter(&issued),
            )? != 1
            {
                return Err(invalid());
            }
        }
        let pins = tx.prepare(
            "SELECT content_id FROM main.reference_reservation_objects WHERE owner_id=?1 ORDER BY content_id",
        )?.query_map([id.as_str()], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let removed = pins
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        for content in pins {
            let _permit = self.original_operation_issuance.permit(vec![
                Value::Text("reference_reservation_objects:delete".to_owned()),
                Value::Text(id.to_string()),
                Value::Text(content.clone()),
            ])?;
            if tx.execute(
                "DELETE FROM main.reference_reservation_objects WHERE owner_id=?1 AND content_id=?2",
                params![id.as_str(), content],
            )? != 1 {
                return Err(invalid());
            }
        }
        let after = self.read_view().audit_original_provenance_capacity(
            &record.policy.space_id,
            crate::limits::MAX_ENTRIES,
            bounds,
        )?;
        let mut expected = before
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint().clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        for content in &removed {
            if expected
                .remove(&(
                    "reference_reservation_objects".to_owned(),
                    vec![id.to_string(), content.clone()],
                ))
                .is_none()
            {
                return Err(invalid());
            }
        }
        let mut actual = after
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint().clone(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        if actual
            .remove(&("storage_page_handoffs".to_owned(), vec![id.to_string()]))
            .is_none()
            || actual != expected
            || !after.report.within_accounted_limits()
        {
            return Err(invalid());
        }
        self.audit_gc_owners(&record.policy.space_id, self.max_storage_entries)?;
        tx.commit()?;
        Ok(true)
    }
}
