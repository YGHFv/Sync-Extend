//! Connection-local exact-value issuance; not protection from hostile SQL/unsafe.
use crate::{JournalError, Result};
use rusqlite::{
    functions::FunctionFlags,
    types::{Value, ValueRef},
    Connection,
};
use std::sync::{Arc, Mutex};

pub(crate) type Gate = Arc<Mutex<Option<Permit>>>;
pub(crate) struct Permit {
    values: Vec<Value>,
    consumed: bool,
}
pub(crate) struct Issuance(Gate);
impl Drop for Issuance {
    fn drop(&mut self) {
        if let Ok(mut gate) = self.0.lock() {
            *gate = None;
        }
    }
}
pub(crate) fn register(connection: &Connection) -> Result<Gate> {
    let gate: Gate = Arc::new(Mutex::new(None));
    let held = gate.clone();
    connection.create_scalar_function(
        "sync_native_publication_issue",
        -1,
        FunctionFlags::SQLITE_UTF8,
        move |context| {
            let Ok(mut gate) = held.lock() else {
                return Ok(false);
            };
            let Some(permit) = gate.as_mut() else {
                return Ok(false);
            };
            if permit.consumed || permit.values.len() != context.len() {
                return Ok(false);
            }
            for (index, value) in permit.values.iter().enumerate() {
                let matches = match (context.get_raw(index), value) {
                    (ValueRef::Text(actual), Value::Text(expected)) => {
                        actual == expected.as_bytes()
                    }
                    (ValueRef::Integer(actual), Value::Integer(expected)) => actual == *expected,
                    _ => false,
                };
                if !matches {
                    return Ok(false);
                }
            }
            permit.consumed = true;
            Ok(true)
        },
    )?;
    Ok(gate)
}
pub(crate) fn permit(gate: &Gate, values: Vec<Value>) -> Result<Issuance> {
    let mut current = gate
        .lock()
        .map_err(|_| JournalError::Invariant("native issuer poisoned"))?;
    if current.is_some() {
        return Err(JournalError::Invariant("native issuer already active"));
    }
    *current = Some(Permit {
        values,
        consumed: false,
    });
    Ok(Issuance(gate.clone()))
}
