//! Connection-local exact issuance, not a defense against hostile same-process SQL.
#[cfg(windows)]
use crate::JournalError;
use crate::Result;
use rusqlite::{
    functions::FunctionFlags,
    types::{Value, ValueRef},
    Connection,
};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    exact: Option<Vec<Value>>,
    consumed: bool,
    write: Option<&'static str>,
}
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<Mutex<State>>);
#[cfg(windows)]
pub(super) struct Permit(Gate);
#[cfg(windows)]
impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0 .0.lock() {
            *state = State::default();
        }
    }
}
impl Gate {
    pub(crate) fn register(connection: &Connection) -> Result<Self> {
        let gate = Self::default();
        let held = gate.clone();
        connection.create_scalar_function(
            "sync_remote_delete_issue",
            -1,
            FunctionFlags::SQLITE_UTF8,
            move |ctx| {
                let Ok(mut state) = held.0.lock() else {
                    return Ok(false);
                };
                let Some(values) = &state.exact else {
                    return Ok(false);
                };
                if state.consumed || values.len() != ctx.len() {
                    return Ok(false);
                }
                for (index, value) in values.iter().enumerate() {
                    if !match (ctx.get_raw(index), value) {
                        (ValueRef::Text(a), Value::Text(b)) => a == b.as_bytes(),
                        (ValueRef::Integer(a), Value::Integer(b)) => a == *b,
                        _ => false,
                    } {
                        return Ok(false);
                    }
                }
                state.consumed = true;
                Ok(true)
            },
        )?;
        let held = gate.clone();
        connection.create_scalar_function("sync_remote_delete_write", 1, FunctionFlags::SQLITE_UTF8, move |ctx| {
            Ok(held.0.lock().ok().is_some_and(|state|
                state.write.is_some_and(|scope| matches!(ctx.get_raw(0), ValueRef::Text(value) if value == scope.as_bytes()))))
        })?;
        Ok(gate)
    }
    #[cfg(windows)]
    pub(super) fn permit(
        &self,
        exact: Option<Vec<Value>>,
        write: Option<&'static str>,
    ) -> Result<Permit> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| JournalError::Invariant("remote Delete issuer poisoned"))?;
        if state.exact.is_some() || state.write.is_some() {
            return Err(JournalError::Invariant(
                "remote Delete issuer already active",
            ));
        }
        *state = State {
            exact,
            consumed: false,
            write,
        };
        Ok(Permit(self.clone()))
    }
}
