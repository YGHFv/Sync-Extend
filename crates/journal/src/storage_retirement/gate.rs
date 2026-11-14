use crate::{JournalError, Result};
use rusqlite::{functions::FunctionFlags, Connection};
use std::sync::{Arc, Mutex};

/// Exact one-shot issuance, never an SQL caller supplied boolean.
pub(crate) struct Gate(Arc<Mutex<Option<(String, u64)>>>);

impl Gate {
    pub(crate) fn register(connection: &Connection, function: &str) -> Result<Self> {
        let value = Arc::new(Mutex::new(None));
        let held = value.clone();
        connection.create_scalar_function(
            function,
            2,
            FunctionFlags::SQLITE_UTF8,
            move |context| {
                let actual = (
                    context.get::<String>(0)?,
                    crate::sql_nonnegative(context.get::<i64>(1)?, 1)?,
                );
                let mut gate = held.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                if gate.as_ref() == Some(&actual) {
                    *gate = None;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
        )?;
        Ok(Self(value))
    }

    pub(crate) fn issue<T>(
        &self,
        fingerprint: String,
        time: u64,
        action: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        {
            let mut gate = self
                .0
                .lock()
                .map_err(|_| JournalError::Invariant("storage retirement issuance lock"))?;
            if gate.is_some() {
                return Err(JournalError::Invariant(
                    "storage retirement issuance nested",
                ));
            }
            *gate = Some((fingerprint, time));
        }
        let result = action();
        let mut gate = self
            .0
            .lock()
            .map_err(|_| JournalError::Invariant("storage retirement issuance lock"))?;
        let consumed = gate.take().is_none();
        if result.is_ok() && !consumed {
            return Err(JournalError::Invariant(
                "storage retirement issuance unconsumed",
            ));
        }
        result
    }
}
