//! Per-operation SQL budget, installed before any untrusted catalog query.
use rusqlite::{limits::Limit, Connection};
use std::time::{Duration, Instant};
use sync_extend_journal::{JournalError, Result};

#[derive(Clone, Copy)]
pub struct LedgerBounds {
    pub max_records: u64,
    pub max_intents: usize,
    pub max_record_bytes: u64,
    pub max_database_bytes: u64,
    pub max_content_bytes: u64,
    pub max_vm_instructions: u64,
    pub max_query_time: Duration,
}

impl LedgerBounds {
    /// Validate the bounded restore-ledger policy before protected runtime
    /// acquisition. The check is pure and has no filesystem side effects.
    pub fn validate(self) -> Result<()> {
        if !(1..=100_000).contains(&self.max_records)
            || self.max_intents == 0
            || self.max_intents as u64 > self.max_records
            || !(1..=64 * 1024 * 1024).contains(&self.max_record_bytes)
            || !(4096..=128 * 1024 * 1024).contains(&self.max_database_bytes)
            || self.max_record_bytes > self.max_database_bytes
            || self.max_content_bytes == 0
            || self.max_content_bytes > 1024 * 1024 * 1024
            || !(1_000..=250_000_000).contains(&self.max_vm_instructions)
            || self.max_query_time.is_zero()
            || self.max_query_time > Duration::from_secs(300)
        {
            return Err(JournalError::Invariant(
                "explicit bounded restore ledger limits",
            ));
        }
        Ok(())
    }
}

pub(in super::super) fn configure(connection: &mut Connection, bounds: LedgerBounds) -> Result<()> {
    bounds.validate()?;
    for (category, limit) in [
        (Limit::SQLITE_LIMIT_LENGTH, 1024 * 1024),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 65_536),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        (Limit::SQLITE_LIMIT_COLUMN, 32),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 8),
    ] {
        connection.set_limit(category, limit)?;
        if connection.limit(category)? > limit {
            return Err(JournalError::Invariant(
                "restore ledger SQL limit not applied",
            ));
        }
    }
    let started = Instant::now();
    let mut remaining = bounds.max_vm_instructions;
    connection.progress_handler(
        1_000,
        Some(move || {
            if remaining < 1_000 || started.elapsed() >= bounds.max_query_time {
                return true;
            }
            remaining -= 1_000;
            false
        }),
    )?;
    connection.busy_timeout(Duration::ZERO)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    connection.pragma_update(None, "cache_size", -2_048i32)?;
    Ok(())
}

pub(in super::super) fn validate(bounds: LedgerBounds) -> Result<()> {
    bounds.validate()
}
