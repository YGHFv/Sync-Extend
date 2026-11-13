//! Exact connection-local owner issuance. Untrusted SQL receives no permits.
#[cfg(windows)]
use crate::JournalError;
use crate::Result;
use rusqlite::{
    functions::FunctionFlags,
    types::{Value, ValueRef},
    Connection,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<Option<Vec<Vec<Value>>>>>);

#[cfg(windows)]
pub(super) struct Permit(Gate);

#[cfg(windows)]
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0 .0.lock() {
            *state = None;
        }
    }
}

impl Gate {
    pub(crate) fn register(connection: &Connection) -> Result<Self> {
        let gate = Self::default();
        let held = gate.clone();
        connection.create_scalar_function(
            "sync_tree_native_issue",
            -1,
            FunctionFlags::SQLITE_UTF8,
            move |context| {
                let Ok(mut state) = held.0.lock() else {
                    return Ok(false);
                };
                let Some(permits) = &mut *state else {
                    return Ok(false);
                };
                let index = permits.iter().position(|values| {
                    values.len() == context.len()
                        && values.iter().enumerate().all(|(index, value)| {
                            match (context.get_raw(index), value) {
                                (ValueRef::Text(actual), Value::Text(expected)) => {
                                    actual == expected.as_bytes()
                                }
                                (ValueRef::Integer(actual), Value::Integer(expected)) => {
                                    actual == *expected
                                }
                                (ValueRef::Null, Value::Null) => true,
                                _ => false,
                            }
                        })
                });
                let Some(index) = index else {
                    return Ok(false);
                };
                permits.remove(index);
                Ok(true)
            },
        )?;
        Ok(gate)
    }

    #[cfg(windows)]
    pub(super) fn permit(&self, values: Vec<Vec<Value>>) -> Result<Permit> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| JournalError::Invariant("tree native issuer poisoned"))?;
        if state.is_some() || values.is_empty() {
            return Err(JournalError::Invariant(
                "tree native issuer active or empty",
            ));
        }
        *state = Some(values);
        Ok(Permit(self.clone()))
    }
}

#[cfg(windows)]
impl Permit {
    pub(super) fn require_consumed(&self) -> Result<()> {
        let state = self
            .0
             .0
            .lock()
            .map_err(|_| JournalError::Invariant("tree native issuer poisoned"))?;
        if state.as_ref().is_none_or(|values| !values.is_empty()) {
            return Err(JournalError::Invariant(
                "tree native exact permit unconsumed",
            ));
        }
        Ok(())
    }
}
