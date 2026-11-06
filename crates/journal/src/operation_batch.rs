use crate::{cursor, Journal, JournalError, Result};
use rusqlite::params;
use sync_extend_core_model::{
    operation_batch::{OperationBatch, MAX_OPERATION_BATCH, MAX_OPERATION_BATCH_BYTES},
    DeviceId, Operation, SpaceId, PROTOCOL_VERSION,
};

impl Journal {
    /// Own-origin export only. Never forge a forwarded origin's signature.
    /// Bound SQL rows and encoded payload before deserialization.
    pub fn own_operation_batch(
        &self,
        space: &SpaceId,
        device: &DeviceId,
        after_sequence: u64,
    ) -> Result<OperationBatch> {
        if after_sequence > i64::MAX as u64 || !self.connection.is_autocommit() {
            return Err(JournalError::Invariant(
                "operation export caller transaction or sequence",
            ));
        }
        self.connection.execute_batch("BEGIN DEFERRED")?;
        let result = (|| {
            if self.state("space_id")?.as_deref() != Some(space.as_str())
                || self.state("device_id")?.as_deref() != Some(device.as_str())
            {
                return Err(JournalError::Invariant("own operation export identity"));
            }
            let tip = cursor(&self.connection, space, device)?;
            if after_sequence > tip {
                return Err(JournalError::Invariant(
                    "operation export cursor beyond tip",
                ));
            }
            let mut statement = self.connection.prepare(
                "SELECT origin_seq,
                    CASE WHEN length(CAST(payload AS BLOB))<=1048576 THEN payload ELSE '' END,
                    state FROM operations
                 WHERE space_id=?1 AND origin_device_id=?2 AND origin_seq>?3
                 ORDER BY origin_seq LIMIT ?4",
            )?;
            let mut rows = statement.query(params![
                space.as_str(),
                device.as_str(),
                after_sequence as i64,
                MAX_OPERATION_BATCH as i64,
            ])?;
            let mut batch = OperationBatch {
                protocol_version: PROTOCOL_VERSION,
                space_id: space.clone(),
                origin_device: device.clone(),
                after_sequence,
                tip_sequence: tip,
                operations: Vec::new(),
            };
            while let Some(row) = rows.next()? {
                let sequence: i64 = row.get(0)?;
                let json: String = row.get(1)?;
                let state: String = row.get(2)?;
                let expected = after_sequence + batch.operations.len() as u64 + 1;
                if sequence <= 0 || sequence as u64 != expected || state != "materialized" {
                    return Err(JournalError::Invariant(
                        "own operation export discontinuity",
                    ));
                }
                if json.is_empty() {
                    return Err(JournalError::Invariant("own operation exceeds page limit"));
                }
                let operation: Operation = serde_json::from_str(&json)?;
                operation.validate()?;
                batch.operations.push(operation);
                if serde_json::to_vec(&batch)?.len() > MAX_OPERATION_BATCH_BYTES {
                    batch.operations.pop();
                    if batch.operations.is_empty() {
                        return Err(JournalError::Invariant("own operation exceeds page limit"));
                    }
                    break;
                }
            }
            batch.validate()?;
            Ok(batch)
        })();
        // Read-only export cannot leave a transaction behind on failure.
        self.connection.execute_batch("ROLLBACK")?;
        result
    }
}
