use super::{
    budget_error, now_ms, Attempt, Direction, FrameClass, FrameContext, ProducerKind,
    ProducerUsage, Reservation, SignedTransportAttemptPolicy, TransportAttemptStatus,
    MAX_RECORD_BYTES,
};
use crate::Result;
use rusqlite::{limits::Limit, params, Connection, TransactionBehavior};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use sync_extend_core_model::{ContentId, EntryId};

const SCHEMA: &str = include_str!("schema.sql");
type Catalog = Vec<(String, String, String)>;
type Issue = (u64, String, String);
type QueryBudget = Arc<Mutex<(Instant, u64)>>;
#[cfg(any(target_os = "linux", target_os = "android"))]
type LedgerConnection = sync_extend_platform_fs::UnixSqliteLedgerConnection;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
type LedgerConnection = Connection;

#[derive(Default)]
struct Usage {
    bytes: u64,
    entries: u64,
    clock: u64,
    producers: BTreeMap<ProducerKind, (u64, u64)>,
}

/// Created, used and destroyed only on the private issuer worker.
pub(crate) struct Ledger {
    connection: LedgerConnection,
    #[cfg(windows)]
    files: std::cell::RefCell<super::guard::WindowsFiles>,
    gate: Arc<Mutex<Option<Issue>>>,
    signed: SignedTransportAttemptPolicy,
    policy_json: String,
    fingerprint: ContentId,
    catalog: Catalog,
    read_only: bool,
    query_budget: QueryBudget,
}

fn sql_integer(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| budget_error("application budget SQL integer overflow"))
}

fn catalog(connection: &Connection) -> Result<Catalog> {
    let mut query = connection
        .prepare("SELECT type,name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name LIMIT 17")
        .map_err(budget_error)?;
    let rows = query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(budget_error)?
        .collect::<rusqlite::Result<_>>()
        .map_err(budget_error)?;
    Ok(rows)
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn disable_close_checkpoint(connection: &Connection) -> Result<()> {
    use rusqlite::config::DbConfig;

    // A rejected retained policy must not cause a final WAL checkpoint when
    // the guarded connection closes. Configure this before its first read.
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .map_err(budget_error)?;
    if !connection
        .db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE)
        .map_err(budget_error)?
    {
        return Err(budget_error(
            "application budget SQLite close checkpoint guard did not apply",
        ));
    }
    Ok(())
}

#[cfg(any(windows, target_os = "linux", target_os = "android"))]
fn restore_writer_close_checkpoint(connection: &Connection) -> Result<()> {
    use rusqlite::config::DbConfig;

    match connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, false)
        .and_then(|_| connection.db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE))
    {
        Ok(false) => Ok(()),
        Ok(true) => Err(budget_error(
            "application budget SQLite writer close checkpoint did not apply",
        )),
        Err(error) => {
            // A failed admission must retain the same non-writing close guard.
            disable_close_checkpoint(connection)?;
            Err(budget_error(error))
        }
    }
}

impl Ledger {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn open_unix(
        signed: SignedTransportAttemptPolicy,
        vfs: sync_extend_platform_fs::UnixSqliteLedger,
        initialize: Option<u64>,
        read_only: bool,
    ) -> Result<Self> {
        let connection = vfs.open_connection().map_err(budget_error)?;
        disable_close_checkpoint(&connection)?;
        Self::configure(signed, connection, initialize, read_only)
    }

    #[cfg(windows)]
    pub(crate) fn open_windows(
        signed: SignedTransportAttemptPolicy,
        roots: super::guard::WindowsRoots,
        initialize: Option<u64>,
    ) -> Result<Self> {
        let files = super::guard::WindowsFiles::open(roots, &signed, initialize.is_some())?;
        let connection = Connection::open_with_flags(
            &signed.policy.ledger_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(budget_error)?;
        // Authenticate the actual SQLite main HANDLE before any mutating
        // pragma. A pathname QA handle is not enough for writable authority.
        files.verify_main(&connection)?;
        disable_close_checkpoint(&connection)?;
        // Even connection-only cache pragmas can load the schema and open WAL.
        // Establish the heap-index mode before that first read; changing it
        // after SQLite has created SHM cannot revoke that sidecar authority.
        connection
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .map_err(budget_error)?;
        Self::configure(signed, connection, initialize, false, files)
    }

    fn configure(
        signed: SignedTransportAttemptPolicy,
        mut connection: LedgerConnection,
        initialize: Option<u64>,
        read_only: bool,
        #[cfg(windows)] files: super::guard::WindowsFiles,
    ) -> Result<Self> {
        let policy = &signed.policy;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(budget_error)?;
        for (category, maximum) in [
            (Limit::SQLITE_LIMIT_LENGTH, 131_072),
            (Limit::SQLITE_LIMIT_SQL_LENGTH, 65_536),
            (Limit::SQLITE_LIMIT_ATTACHED, 0),
            (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        ] {
            connection
                .set_limit(category, maximum)
                .map_err(budget_error)?;
            if connection.limit(category).map_err(budget_error)? > maximum {
                return Err(budget_error(
                    "application budget SQLite limit did not apply",
                ));
            }
        }
        let instructions = Self::instruction_limit(policy.max_attempt_entries)?;
        let query_budget = Arc::new(Mutex::new((Instant::now(), instructions)));
        let observed = query_budget.clone();
        connection
            .progress_handler(
                1000,
                Some(move || {
                    let Ok(mut budget) = observed.lock() else {
                        return true;
                    };
                    if budget.1 < 1000 || budget.0.elapsed() >= Duration::from_secs(10) {
                        return true;
                    }
                    budget.1 -= 1000;
                    false
                }),
            )
            .map_err(budget_error)?;
        connection
            .pragma_update(None, "trusted_schema", false)
            .map_err(budget_error)?;
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(budget_error)?;
        connection
            .pragma_update(None, "cache_size", -4096i32)
            .map_err(budget_error)?;
        connection
            .pragma_update(None, "mmap_size", 0i64)
            .map_err(budget_error)?;
        #[cfg(windows)]
        {
            // The connection already entered exclusive mode before any pragma.
            // A bounded schema read opens an existing WAL under that mode;
            // verify its actual SQLite HANDLE before any writable pragma/DDL.
            connection
                .query_row(
                    "SELECT count(*) FROM (SELECT name FROM sqlite_schema LIMIT 17)",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .map_err(budget_error)?;
            let mut files = files;
            files.verify(&connection)?;
            return Self::configure_after_native(
                signed,
                connection,
                initialize,
                read_only,
                files,
                query_budget,
            );
        }
        #[cfg(not(windows))]
        Self::configure_after_native(signed, connection, initialize, read_only, query_budget)
    }

    fn configure_after_native(
        signed: SignedTransportAttemptPolicy,
        connection: LedgerConnection,
        initialize: Option<u64>,
        read_only: bool,
        #[cfg(windows)] files: super::guard::WindowsFiles,
        query_budget: QueryBudget,
    ) -> Result<Self> {
        if connection
            .query_row("PRAGMA page_size", [], |row| row.get::<_, u32>(0))
            .map_err(budget_error)?
            != 4096
        {
            return Err(budget_error(
                "application ledger requires its exact bounded 4096-byte page layout",
            ));
        }
        if read_only {
            connection
                .pragma_update(None, "query_only", true)
                .map_err(budget_error)?;
        }
        let gate = Arc::new(Mutex::new(None::<Issue>));
        let issuer = gate.clone();
        connection
            .create_scalar_function(
                "sync_application_frame_attempt_issue",
                3,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8
                    | rusqlite::functions::FunctionFlags::SQLITE_INNOCUOUS,
                move |context| {
                    let actual = (
                        u64::try_from(context.get::<i64>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        context.get::<String>(1)?,
                        context.get::<String>(2)?,
                    );
                    let mut issue = issuer.lock().map_err(|_| rusqlite::Error::InvalidQuery)?;
                    if issue.as_ref() == Some(&actual) {
                        *issue = None;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                },
            )
            .map_err(budget_error)?;
        let policy_json = serde_json::to_string(&signed)?;
        if policy_json.len() > super::MAX_SIGNED_POLICY_BYTES {
            return Err(budget_error("signed application policy encoding bound"));
        }
        let fingerprint = signed.fingerprint()?;
        let expected = Connection::open_in_memory().map_err(budget_error)?;
        expected.execute_batch(SCHEMA).map_err(budget_error)?;
        let result = Self {
            connection,
            #[cfg(windows)]
            files: std::cell::RefCell::new(files),
            gate,
            signed,
            policy_json,
            fingerprint,
            catalog: catalog(&expected)?,
            read_only,
            query_budget,
        };
        if let Some(at) = initialize {
            result.configure_writable()?;
            let transaction = rusqlite::Transaction::new_unchecked(
                &result.connection,
                TransactionBehavior::Immediate,
            )
            .map_err(budget_error)?;
            #[cfg(any(target_os = "linux", target_os = "android"))]
            result.connection.verify().map_err(budget_error)?;
            #[cfg(windows)]
            result.files.borrow_mut().verify(&result.connection)?;
            transaction.execute_batch(SCHEMA).map_err(budget_error)?;
            transaction
                .execute(
                    "INSERT INTO owner VALUES(1,?1,?2,?3)",
                    params![
                        &result.policy_json,
                        result.fingerprint.as_str(),
                        sql_integer(at)?
                    ],
                )
                .map_err(budget_error)?;
            transaction.commit().map_err(budget_error)?;
        } else {
            // Audit existing catalog, exact owner and every canonical attempt
            // while SQL writes remain disabled. Capacity/journal configuration
            // must not repair or alter a rejected retained database first.
            result
                .connection
                .pragma_update(None, "query_only", true)
                .map_err(budget_error)?;
            result.audit()?;
            if !read_only {
                result
                    .connection
                    .pragma_update(None, "query_only", false)
                    .map_err(budget_error)?;
                result.configure_writable()?;
            }
        }
        result.audit()?;
        #[cfg(any(windows, target_os = "linux", target_os = "android"))]
        if !read_only {
            // Full native/catalog/owner/attempt admission has succeeded.
            // Legal writers must close with the normal checkpoint behavior,
            // so a later Unix status reader can require empty sidecars.
            restore_writer_close_checkpoint(&result.connection)?;
        }
        Ok(result)
    }

    fn configure_writable(&self) -> Result<()> {
        let maximum_pages = sql_integer(self.signed.policy.max_file_bytes()? / 4096)?;
        self.connection
            .pragma_update(None, "max_page_count", maximum_pages)
            .map_err(budget_error)?;
        if self
            .connection
            .query_row("PRAGMA max_page_count", [], |row| row.get::<_, i64>(0))
            .map_err(budget_error)?
            != maximum_pages
        {
            return Err(budget_error(
                "application ledger future page capacity did not apply",
            ));
        }
        // Both native substrates use exclusive WAL without physical SHM.
        // The independent control-directory contract has no SHM authority.
        self.connection
            .pragma_update(None, "locking_mode", "EXCLUSIVE")
            .map_err(budget_error)?;
        self.connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(budget_error)?;
        self.connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(budget_error)?;
        self.connection
            .pragma_update(None, "wal_autocheckpoint", 1i32)
            .map_err(budget_error)?;
        self.connection
            .pragma_update(None, "journal_size_limit", 1024 * 1024i64)
            .map_err(budget_error)?;
        Ok(())
    }

    fn instruction_limit(entries: u64) -> Result<u64> {
        entries
            .checked_mul(2500)
            .and_then(|value| value.checked_add(1_000_000))
            .ok_or_else(|| budget_error("application budget instruction bound overflow"))
    }

    fn audit(&self) -> Result<Usage> {
        *self
            .query_budget
            .lock()
            .map_err(|_| budget_error("application query gate poisoned"))? = (
            Instant::now(),
            Self::instruction_limit(self.signed.policy.max_attempt_entries)?,
        );
        #[cfg(any(target_os = "linux", target_os = "android"))]
        self.connection.verify().map_err(budget_error)?;
        #[cfg(windows)]
        self.files.borrow_mut().verify(&self.connection)?;
        if catalog(&self.connection)? != self.catalog
            || self
                .connection
                .query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .map_err(budget_error)?
                != 1
        {
            return Err(budget_error(
                "application budget complete immutable catalog differs",
            ));
        }
        let policy = &self.signed.policy;
        let mut owner_query = self
            .connection
            .prepare("SELECT slot,policy,fingerprint,initialized_at_ms FROM owner LIMIT 2")
            .map_err(budget_error)?;
        let owners = owner_query
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(budget_error)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(budget_error)?;
        let [(1, canonical, fingerprint, initialized)] = owners.as_slice() else {
            return Err(budget_error("application budget singleton owner differs"));
        };
        if canonical != &self.policy_json
            || fingerprint != self.fingerprint.as_str()
            || *initialized < 0
            || u64::try_from(*initialized).map_err(budget_error)? >= policy.period_end_ms
        {
            return Err(budget_error(
                "application budget immutable signed policy/clock differs",
            ));
        }
        let mut usage = Usage {
            clock: u64::try_from(*initialized).map_err(budget_error)?,
            ..Usage::default()
        };
        let limit = policy
            .max_attempt_entries
            .checked_add(1)
            .ok_or_else(|| budget_error("application row bound overflow"))?;
        let mut query = self
            .connection
            .prepare("SELECT sequence,attempt_id,record FROM attempts ORDER BY sequence LIMIT ?1")
            .map_err(budget_error)?;
        let mut rows = query.query([sql_integer(limit)?]).map_err(budget_error)?;
        while let Some(row) = rows.next().map_err(budget_error)? {
            usage.entries = usage
                .entries
                .checked_add(1)
                .ok_or_else(|| budget_error("application attempt count overflow"))?;
            let sequence: i64 = row.get(0).map_err(budget_error)?;
            let id: String = row.get(1).map_err(budget_error)?;
            let _: EntryId = id.parse()?;
            let record: String = row.get(2).map_err(budget_error)?;
            if sequence != sql_integer(usage.entries)?
                || usage.entries > policy.max_attempt_entries
                || record.len() > MAX_RECORD_BYTES
            {
                return Err(budget_error("application record/count bound differs"));
            }
            let attempt: Attempt = serde_json::from_str(&record)?;
            let source = if attempt.frame.direction == Direction::Send {
                &policy.owner
            } else {
                &policy.approved_peer
            };
            let cap = policy.producer_limit(attempt.frame.producer)?;
            let is_block = attempt.frame.producer.frame_class() == FrameClass::Block;
            if serde_json::to_string(&attempt)? != record
                || attempt.policy != self.fingerprint
                || attempt.owner != policy.owner.device_id
                || attempt.peer != policy.approved_peer.device_id
                || attempt.peer_public_key != policy.approved_peer.public_key
                || attempt.peer_certificate != policy.approved_peer.certificate_fingerprint()
                || attempt.source != source.device_id
                || attempt.source_public_key != source.public_key
                || attempt.source_certificate != source.certificate_fingerprint()
                || attempt.frame.reserved_bytes == 0
                || attempt.frame.reserved_bytes > cap.max_frame_bytes
                || is_block != attempt.frame.content_id.is_some()
                || !is_block && attempt.frame.reserved_bytes != cap.max_frame_bytes
                || is_block && attempt.frame.reserved_bytes < 6
                || attempt.at_ms < usage.clock
                || attempt.at_ms < policy.period_start_ms
                || attempt.at_ms >= policy.period_end_ms
            {
                return Err(budget_error(
                    "application record policy/source/kind/clock differs",
                ));
            }
            usage.clock = attempt.at_ms;
            usage.bytes = usage
                .bytes
                .checked_add(attempt.frame.reserved_bytes)
                .ok_or_else(|| budget_error("application reserved byte sum overflow"))?;
            let used = usage.producers.entry(attempt.frame.producer).or_default();
            used.0 = used
                .0
                .checked_add(attempt.frame.reserved_bytes)
                .ok_or_else(|| budget_error("producer reserved byte sum overflow"))?;
            used.1 = used
                .1
                .checked_add(1)
                .ok_or_else(|| budget_error("producer attempt sum overflow"))?;
            if usage.bytes > policy.max_reserved_frame_bytes
                || used.0 > cap.max_reserved_bytes
                || used.1 > cap.max_attempt_entries
            {
                return Err(budget_error(
                    "persistent application global/producer quota exceeded",
                ));
            }
        }
        Ok(usage)
    }

    pub(crate) fn reserve(&self, frame: FrameContext) -> Result<Reservation> {
        if self.read_only {
            return Err(budget_error(
                "read-only application ledger cannot issue permits",
            ));
        }
        let policy = &self.signed.policy;
        let cap = policy.producer_limit(frame.producer)?;
        if frame.reserved_bytes == 0
            || frame.reserved_bytes > cap.max_frame_bytes
            || (frame.producer.frame_class() == FrameClass::Block) != frame.content_id.is_some()
            || frame.producer.frame_class() != FrameClass::Block
                && frame.reserved_bytes != cap.max_frame_bytes
        {
            return Err(budget_error("typed application reservation shape differs"));
        }
        let at = now_ms()?;
        if at < policy.period_start_ms || at >= policy.period_end_ms {
            return Err(budget_error(
                "application reservation outside its explicit window",
            ));
        }
        let transaction =
            rusqlite::Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(budget_error)?;
        let before = self.audit()?;
        let next = before
            .entries
            .checked_add(1)
            .ok_or_else(|| budget_error("attempt sequence overflow"))?;
        let sum = before
            .bytes
            .checked_add(frame.reserved_bytes)
            .ok_or_else(|| budget_error("application quota addition overflow"))?;
        let producer_before = before
            .producers
            .get(&frame.producer)
            .copied()
            .unwrap_or_default();
        let producer_sum = producer_before
            .0
            .checked_add(frame.reserved_bytes)
            .ok_or_else(|| budget_error("producer quota addition overflow"))?;
        let producer_entries = producer_before
            .1
            .checked_add(1)
            .ok_or_else(|| budget_error("producer entry addition overflow"))?;
        if at < before.clock
            || next > policy.max_attempt_entries
            || sum > policy.max_reserved_frame_bytes
            || producer_sum > cap.max_reserved_bytes
            || producer_entries > cap.max_attempt_entries
        {
            return Err(budget_error(
                "application clock/global/producer quota rejected",
            ));
        }
        let id = EntryId::random()?;
        let source = if frame.direction == Direction::Send {
            &policy.owner
        } else {
            &policy.approved_peer
        };
        let record = serde_json::to_string(&Attempt {
            policy: self.fingerprint.clone(),
            owner: policy.owner.device_id.clone(),
            peer: policy.approved_peer.device_id.clone(),
            peer_public_key: policy.approved_peer.public_key,
            peer_certificate: policy.approved_peer.certificate_fingerprint(),
            source: source.device_id.clone(),
            source_public_key: source.public_key,
            source_certificate: source.certificate_fingerprint(),
            frame: frame.clone(),
            at_ms: at,
        })?;
        if record.len() > MAX_RECORD_BYTES {
            return Err(budget_error("application attempt encoded bound"));
        }
        *self
            .gate
            .lock()
            .map_err(|_| budget_error("application issue gate poisoned"))? =
            Some((next, id.to_string(), record.clone()));
        let inserted = transaction.execute(
            "INSERT INTO attempts VALUES(?1,?2,?3)",
            params![sql_integer(next)?, id.as_str(), record],
        );
        *self
            .gate
            .lock()
            .map_err(|_| budget_error("application issue gate poisoned"))? = None;
        if inserted.map_err(budget_error)? != 1 {
            return Err(budget_error("application attempt insertion differs"));
        }
        let after = self.audit()?;
        if after.bytes != sum
            || after.entries != next
            || after.clock != at
            || after.producers.get(&frame.producer).copied()
                != Some((producer_sum, producer_entries))
        {
            return Err(budget_error(
                "application durable reservation postcondition differs",
            ));
        }
        transaction.commit().map_err(budget_error)?;
        // No refund on unused permit, failed send/receive, timeout or process death.
        Ok(Reservation {
            sequence: next,
            attempt_id: id,
            frame,
            at_ms: at,
        })
    }

    pub(crate) fn check_use(&self, reservation: &Reservation) -> Result<()> {
        let usage = self.audit()?;
        let at = now_ms()?;
        let policy = &self.signed.policy;
        if at < usage.clock
            || at < reservation.at_ms
            || at < policy.period_start_ms
            || at >= policy.period_end_ms
        {
            return Err(budget_error("application permit clock/window rejected"));
        }
        let record: String = self
            .connection
            .query_row(
                "SELECT record FROM attempts WHERE sequence=?1 AND attempt_id=?2",
                params![
                    sql_integer(reservation.sequence)?,
                    reservation.attempt_id.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(budget_error)?;
        let attempt: Attempt = serde_json::from_str(&record)?;
        if attempt.frame != reservation.frame
            || attempt.at_ms != reservation.at_ms
            || attempt.policy != self.fingerprint
        {
            return Err(budget_error(
                "application permit does not match its retained record",
            ));
        }
        Ok(())
    }

    pub(crate) fn status(&self) -> Result<TransportAttemptStatus> {
        let usage = self.audit()?;
        let policy = &self.signed.policy;
        let producers = policy
            .producer_limits
            .iter()
            .map(|cap| {
                let (bytes, entries) = usage
                    .producers
                    .get(&cap.producer)
                    .copied()
                    .unwrap_or_default();
                ProducerUsage {
                    producer: cap.producer,
                    max_frame_bytes: cap.max_frame_bytes,
                    max_reserved_bytes: cap.max_reserved_bytes,
                    reserved_bytes: bytes,
                    remaining_bytes: cap.max_reserved_bytes - bytes,
                    max_attempt_entries: cap.max_attempt_entries,
                    attempt_entries: entries,
                    remaining_attempt_entries: cap.max_attempt_entries - entries,
                }
            })
            .collect();
        Ok(TransportAttemptStatus {
            budget_id: policy.budget_id.clone(),
            policy_fingerprint: self.fingerprint.clone(),
            owner: policy.owner.device_id.clone(),
            approved_peer: policy.approved_peer.device_id.clone(),
            data_root: policy.data_root.clone(),
            control_root: policy.control_root.clone(),
            meter_unit: policy.meter_unit.clone(),
            route_scope: policy.route_scope.clone(),
            period_start_ms: policy.period_start_ms,
            period_end_ms: policy.period_end_ms,
            reserved_frame_bytes: usage.bytes,
            remaining_frame_bytes: policy.max_reserved_frame_bytes - usage.bytes,
            attempt_entries: usage.entries,
            remaining_attempt_entries: policy.max_attempt_entries - usage.entries,
            clock_high_water_ms: usage.clock,
            producers,
            actual_wire_bytes: None,
            automatic_rollover: false,
            failed_reservations_refunded: false,
            logical_dedup_affects_attempts: false,
        })
    }
}
