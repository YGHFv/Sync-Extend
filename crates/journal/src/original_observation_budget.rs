//! One complete observation borrows the installed original SQLite budget.
//! The previous instruction balance and deadline survive the temporary scope.
use crate::{JournalError, NodeInspectionBounds, Result};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const PROGRESS_OPS: u64 = 1_000;

#[derive(Clone)]
pub(crate) struct OriginalObservationBudget {
    state: Arc<Mutex<BudgetState>>,
    max_vm_instructions: u64,
    max_query_time: Duration,
}

struct QueryBudget {
    started: Instant,
    remaining: u64,
    interrupted: bool,
}

struct BudgetState {
    current: QueryBudget,
    observing: bool,
}

pub(crate) struct OriginalObservationScope {
    budget: OriginalObservationBudget,
    previous: Option<QueryBudget>,
}

impl OriginalObservationBudget {
    pub(crate) fn new(bounds: NodeInspectionBounds) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState {
                current: QueryBudget {
                    started: Instant::now(),
                    remaining: bounds.max_vm_instructions,
                    interrupted: false,
                },
                observing: false,
            })),
            max_vm_instructions: bounds.max_vm_instructions,
            max_query_time: bounds.max_query_time,
        }
    }

    pub(crate) fn interrupt(&self) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return true;
        };
        let current = &mut state.current;
        if current.interrupted
            || current.remaining < PROGRESS_OPS
            || current.started.elapsed() >= self.max_query_time
        {
            current.interrupted = true;
            return true;
        }
        current.remaining -= PROGRESS_OPS;
        false
    }

    pub(crate) fn begin(&self) -> Result<OriginalObservationScope> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JournalError::Invariant("original observation budget was poisoned"))?;
        if state.observing {
            return Err(JournalError::Invariant(
                "original observation cannot nest or reset its operation budget",
            ));
        }
        let previous = std::mem::replace(
            &mut state.current,
            QueryBudget {
                started: Instant::now(),
                remaining: self.max_vm_instructions,
                interrupted: false,
            },
        );
        state.observing = true;
        Ok(OriginalObservationScope {
            budget: self.clone(),
            previous: Some(previous),
        })
    }
}

impl OriginalObservationScope {
    pub(crate) fn finish(mut self) -> Result<()> {
        // A short query below SQLite's callback granularity still cannot
        // return success after the complete operation deadline has elapsed.
        let result = self
            .budget
            .state
            .lock()
            .map_err(|_| JournalError::Invariant("original observation budget was poisoned"))
            .and_then(|state| {
                if !state.observing
                    || state.current.interrupted
                    || state.current.started.elapsed() >= self.budget.max_query_time
                {
                    Err(JournalError::Invariant(
                        "original observation budget exhausted",
                    ))
                } else {
                    Ok(())
                }
            });
        let restored = self.restore();
        result.and(restored)
    }

    fn restore(&mut self) -> Result<()> {
        let Some(mut previous) = self.previous.take() else {
            return Ok(());
        };
        match self.budget.state.lock() {
            Ok(mut state) => {
                state.current = previous;
                state.observing = false;
                Ok(())
            }
            Err(poisoned) => {
                // Retain the previous balance/deadline, but a poisoned
                // callback state must never grant another successful query.
                previous.interrupted = true;
                let mut state = poisoned.into_inner();
                state.current = previous;
                state.observing = false;
                Err(JournalError::Invariant(
                    "original observation budget was poisoned",
                ))
            }
        }
    }
}

impl Drop for OriginalObservationScope {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
