//! Connection-local, one-row archived retention projection. Never a live issuer.
use crate::backup_image::native_history_persistence::{
    NativeHistoryFreshWriter, NativeHistoryFreshWriterState,
};
use crate::{JournalError, JournalStorageColumnValue, JournalStoredRow, Result};
use rusqlite::{
    Connection, params,
    types::{Value, ValueRef},
};
use std::sync::{Arc, Mutex};

struct ExactRow {
    // The private issuance binds these to the current admitted writer before SQL.
    binding: (String, String, String, String, String),
    values: Vec<Value>,
}
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<Option<ExactRow>>>);
pub(crate) struct Permit(Gate);
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0.0.lock() {
            *held = None;
        }
    }
}
impl Permit {
    pub(crate) fn finish(self) -> Result<()> {
        if self
            .0
            .0
            .lock()
            .map_err(|_| JournalError::Invariant("archived retention issuer poisoned"))?
            .is_some()
        {
            return Err(JournalError::Invariant(
                "archived retention row permit unconsumed",
            ));
        }
        Ok(())
    }
}
impl Gate {
    pub(crate) fn register(connection: &Connection) -> Result<Self> {
        let gate = Self::default();
        let state = gate.clone();
        connection.create_scalar_function(
            "sync_deletion_retention_archive",
            -1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
            move |ctx| {
                let mut held = state.0.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                // Every attempt consumes the exact permit, including a mismatch.
                let Some(row) = held.take() else {
                    return Ok(false);
                };
                let _binding = &row.binding;
                Ok(row.values.len() == ctx.len()
                    && row
                        .values
                        .iter()
                        .enumerate()
                        .all(|(i, v)| match (v, ctx.get_raw(i)) {
                            (Value::Text(a), ValueRef::Text(b)) => a.as_bytes() == b,
                            (Value::Integer(a), ValueRef::Integer(b)) => *a == b,
                            _ => false,
                        }))
            },
        )?;
        Ok(gate)
    }

    /// Caller has re-audited the immutable source in the same create operation.
    /// No caller-selected cells, cross-table permit or SQL boolean is accepted.
    pub(crate) fn permit(
        &self,
        connection: &Connection,
        audited: &crate::backup_image::native_history_persistence::AuditedArchivedProjection<'_>,
        writer: &NativeHistoryFreshWriter,
        row: &JournalStoredRow,
    ) -> Result<Permit> {
        let source = audited.source();
        let spec = super::schema::TABLES
            .iter()
            .find(|t| t.name == row.table())
            .ok_or(JournalError::Invariant("archived retention table"))?;
        let source_device = source
            .rows()
            .iter()
            .find(|r| r.table() == "local_state" && r.primary_key() == ["device_id"])
            .and_then(|r| r.columns().iter().find(|c| c.name == "value"))
            .map(|c| &c.value);
        if writer.state() != NativeHistoryFreshWriterState::Admitted
            || writer.source_digest() != source.source_digest()
            || writer.projection_digest() != source.projection().digest()
            || writer.image_digest() != source.source_image_digest()
            || writer.space() != source.space()
            || source_device
                != Some(&JournalStorageColumnValue::Text(
                    writer.device().to_string(),
                ))
            || !source
                .projection()
                .portable_rows()
                .iter()
                .any(|k| k.table() == row.table() && k.primary_key() == row.primary_key())
            || !source.rows().iter().any(|r| std::ptr::eq(r, row))
            || row.columns().len() != spec.columns.len()
            || row
                .columns()
                .iter()
                .zip(spec.columns)
                .any(|(c, s)| c.name != s.name)
        {
            return Err(JournalError::Invariant(
                "archived retention exact source writer row",
            ));
        }
        let admitted:bool=connection.query_row("SELECT EXISTS(SELECT 1 FROM main.native_history_fresh_writers WHERE writer_id=?1 AND source_digest=?2 AND projection_digest=?3 AND image_digest=?4 AND space_id=?5 AND device_id=?6 AND state='admitted' AND created_snapshot IS NULL AND replaced_snapshot IS NULL)",params![writer.writer_id().as_str(),source.source_digest().as_str(),source.projection().digest().as_str(),source.source_image_digest().as_str(),writer.space().as_str(),writer.device().as_str()],|r|r.get(0))?;
        if !admitted {
            return Err(JournalError::Invariant(
                "archived retention admitted writer binding",
            ));
        }
        let mut values = vec![Value::Text(row.table().to_owned())];
        for column in row.columns() {
            values.push(match &column.value {
                JournalStorageColumnValue::Text(v) => Value::Text(v.clone()),
                JournalStorageColumnValue::Integer(v) => Value::Integer(crate::sql_integer(*v)?),
                _ => {
                    return Err(JournalError::Invariant(
                        "archived retention exact typed cells",
                    ));
                }
            });
        }
        let mut held = self
            .0
            .lock()
            .map_err(|_| JournalError::Invariant("archived retention issuer poisoned"))?;
        if held.is_some() {
            return Err(JournalError::Invariant("archived retention nested issuer"));
        }
        *held = Some(ExactRow {
            binding: (
                writer.writer_id().to_string(),
                source.source_digest().to_string(),
                source.projection().digest().to_string(),
                writer.space().to_string(),
                writer.device().to_string(),
            ),
            values,
        });
        Ok(Permit(self.clone()))
    }
}
