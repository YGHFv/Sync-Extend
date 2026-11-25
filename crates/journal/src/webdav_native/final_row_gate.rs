//! One exact original causal Final row statement; no transaction-wide bypass.
use crate::{JournalError, JournalStorageColumnValue, Result};
use rusqlite::{Connection, functions::FunctionFlags};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Eq, PartialEq)]
struct Row {
    table: String,
    action: String,
    prior: Option<Vec<JournalStorageColumnValue>>,
    future: Option<Vec<JournalStorageColumnValue>>,
}
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<Option<Row>>>);
#[cfg(windows)]
struct Reset(Gate);
#[cfg(windows)]
impl Drop for Reset {
    fn drop(&mut self) {
        if let Ok(mut held) = self.0.0.lock() {
            *held = None;
        }
    }
}
fn invalid() -> JournalError {
    JournalError::Invariant("exact original DAV causal Final row statement")
}
fn parse(json: Option<String>) -> Result<Option<Vec<JournalStorageColumnValue>>> {
    let Some(json) = json else {
        return Ok(None);
    };
    let values: Vec<serde_json::Value> = serde_json::from_str(&json)?;
    let mut output = Vec::new();
    for value in values {
        output.push(match value {
            serde_json::Value::Null => JournalStorageColumnValue::Null,
            serde_json::Value::String(value) => JournalStorageColumnValue::Text(value),
            serde_json::Value::Number(value) => JournalStorageColumnValue::Integer(
                value
                    .as_u64()
                    .filter(|value| *value <= i64::MAX as u64)
                    .ok_or_else(invalid)?,
            ),
            _ => return Err(invalid()),
        });
    }
    Ok(Some(output))
}
impl Gate {
    pub(crate) fn register(connection: &Connection) -> Result<Self> {
        let gate = Self::default();
        let state = gate.clone();
        connection.create_scalar_function(
            "sync_webdav_original_final_row_issue",
            4,
            FunctionFlags::SQLITE_UTF8,
            move |context| {
                let table = context.get::<String>(0)?;
                let action = context.get::<String>(1)?;
                let prior = parse(context.get::<Option<String>>(2)?);
                let future = parse(context.get::<Option<String>>(3)?);
                let (Ok(prior), Ok(future)) = (prior, future) else {
                    return Ok(false);
                };
                let Ok(mut held) = state.0.lock() else {
                    return Ok(false);
                };
                let candidate = Row {
                    table,
                    action,
                    prior,
                    future,
                };
                if held.as_ref() != Some(&candidate) {
                    return Ok(false);
                }
                *held = None;
                Ok(true)
            },
        )?;
        Ok(gate)
    }
    #[cfg(windows)]
    pub(crate) fn issue<T>(
        &self,
        table: &str,
        prior: Option<Vec<JournalStorageColumnValue>>,
        future: Option<Vec<JournalStorageColumnValue>>,
        write: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let action = match (&prior, &future) {
            (None, Some(_)) => "insert",
            (Some(_), Some(_)) => "update",
            (Some(_), None) => "delete",
            _ => return Err(invalid()),
        };
        {
            let mut held = self.0.lock().map_err(|_| invalid())?;
            if held.is_some() {
                return Err(invalid());
            }
            *held = Some(Row {
                table: table.into(),
                action: action.into(),
                prior,
                future,
            });
        }
        let _reset = Reset(self.clone());
        let result = write()?;
        if self.0.lock().map_err(|_| invalid())?.is_some() {
            return Err(invalid());
        }
        Ok(result)
    }
}
