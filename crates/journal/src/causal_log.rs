use crate::{Journal, JournalError, Result};
use sync_extend_core_model::{
    causal::{reduce_operations, CausalReduction, MAX_CAUSAL_OPERATIONS},
    Operation, SpaceId,
};

impl Journal {
    /// Read-only diagnostic frontier. Pending operations are excluded; missing
    /// ancestry refuses rather than treating a received cursor as materialized.
    pub fn causal_frontiers(&self, space: &SpaceId) -> Result<CausalReduction> {
        if !self.connection.is_autocommit() {
            return Err(JournalError::Invariant(
                "causal diagnostic caller transaction",
            ));
        }
        self.connection.execute_batch("BEGIN DEFERRED")?;
        let result = (|| {
            if self.state("space_id")?.as_deref() != Some(space.as_str()) {
                return Err(JournalError::Invariant("causal diagnostic space mismatch"));
            }
            let mut statement = self.connection.prepare(
                "SELECT CASE WHEN length(CAST(payload AS BLOB))<=16777216
                             THEN payload ELSE '' END
                 FROM operations
                 WHERE space_id=?1 AND state IN ('received','materialized')
                 ORDER BY origin_device_id,origin_seq LIMIT ?2",
            )?;
            let mut rows = statement.query(rusqlite::params![
                space.as_str(),
                (MAX_CAUSAL_OPERATIONS + 1) as i64
            ])?;
            let mut operations = Vec::new();
            let mut bytes = 0usize;
            while let Some(row) = rows.next()? {
                if operations.len() == MAX_CAUSAL_OPERATIONS {
                    return Err(JournalError::Invariant(
                        "causal diagnostic operation budget",
                    ));
                }
                let json: String = row.get(0)?;
                bytes = bytes
                    .checked_add(json.len())
                    .filter(|bytes| *bytes <= 64 * 1024 * 1024)
                    .ok_or(JournalError::Invariant("causal diagnostic byte budget"))?;
                if json.is_empty() {
                    return Err(JournalError::Invariant(
                        "causal diagnostic oversized payload",
                    ));
                }
                operations.push(serde_json::from_str::<Operation>(&json)?);
            }
            Ok(reduce_operations(
                space,
                &operations,
                MAX_CAUSAL_OPERATIONS,
            )?)
        })();
        self.connection.execute_batch("ROLLBACK")?;
        result
    }
}
