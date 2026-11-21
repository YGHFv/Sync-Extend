//! Explicit conservative application-frame attempts, independent of logical or
//! outer-wire billing. The trusted SQLite issuer never leaves its worker thread.
mod guard;
mod ledger;
mod policy;
pub use policy::{ProducerLimit, SignedTransportAttemptPolicy, TransportAttemptPolicy};

use crate::{
    PeerIdentity, Result, TransportError, TransportIdentity, MAX_BLOCK_BYTES, MAX_CONTROL_BYTES,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use sync_extend_core_model::{ContentId, DeviceId, EntryId};

const MAX_ENTRIES: u64 = 100_000;
const MAX_POLICY_BYTES: usize = 65_536;
const MAX_SIGNED_POLICY_BYTES: usize = MAX_POLICY_BYTES + 4096;
const MAX_RECORD_BYTES: usize = 2048;
const WORKER_WAIT: Duration = Duration::from_secs(15);

pub(crate) fn budget_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Budget(error.to_string())
}

pub(crate) fn now_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| budget_error("application budget clock precedes epoch"))?;
    let at = u64::try_from(elapsed.as_millis()).map_err(budget_error)?;
    if at > i64::MAX as u64 {
        return Err(budget_error("application budget clock overflows SQL range"));
    }
    Ok(at)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameClass {
    Control,
    Block,
    Probe,
}

/// Closed production registry. Policies must list all kinds in exactly this order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerKind {
    AuthenticationControl,
    DirectFileControl,
    DirectFileBlock,
    OperationMetadataControl,
    MetadataCycleControl,
    OriginalPageControl,
    OriginalContentControl,
    OriginalContentBlock,
    OriginalOutcomeControl,
    OriginalCycleControl,
    ConflictOfferControl,
    ConflictContentControl,
    ConflictContentBlock,
    ConflictReceiptControl,
    StoragePageControl,
    StorageSnapshotControl,
    StorageChunkControl,
    StoragePageBlock,
    StorageSnapshotBlock,
    StorageFinishControl,
    StorageDispatchControl,
    EndOfSessionProbe,
}

impl ProducerKind {
    pub const ALL: [Self; 22] = [
        Self::AuthenticationControl,
        Self::DirectFileControl,
        Self::DirectFileBlock,
        Self::OperationMetadataControl,
        Self::MetadataCycleControl,
        Self::OriginalPageControl,
        Self::OriginalContentControl,
        Self::OriginalContentBlock,
        Self::OriginalOutcomeControl,
        Self::OriginalCycleControl,
        Self::ConflictOfferControl,
        Self::ConflictContentControl,
        Self::ConflictContentBlock,
        Self::ConflictReceiptControl,
        Self::StoragePageControl,
        Self::StorageSnapshotControl,
        Self::StorageChunkControl,
        Self::StoragePageBlock,
        Self::StorageSnapshotBlock,
        Self::StorageFinishControl,
        Self::StorageDispatchControl,
        Self::EndOfSessionProbe,
    ];

    pub(crate) fn frame_class(self) -> FrameClass {
        match self {
            Self::DirectFileBlock
            | Self::OriginalContentBlock
            | Self::ConflictContentBlock
            | Self::StoragePageBlock
            | Self::StorageSnapshotBlock => FrameClass::Block,
            Self::EndOfSessionProbe => FrameClass::Probe,
            _ => FrameClass::Control,
        }
    }

    pub fn maximum_frame_bytes(self) -> u64 {
        match self.frame_class() {
            FrameClass::Control => MAX_CONTROL_BYTES as u64 + 5,
            FrameClass::Block => MAX_BLOCK_BYTES as u64 + 5,
            FrameClass::Probe => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Direction {
    Send,
    Receive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrameContext {
    pub connection: EntryId,
    pub channel: ContentId,
    pub producer: ProducerKind,
    pub direction: Direction,
    pub reserved_bytes: u64,
    pub content_id: Option<ContentId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    policy: ContentId,
    owner: DeviceId,
    peer: DeviceId,
    peer_public_key: [u8; 32],
    peer_certificate: ContentId,
    source: DeviceId,
    source_public_key: [u8; 32],
    source_certificate: ContentId,
    frame: FrameContext,
    at_ms: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct Reservation {
    sequence: u64,
    attempt_id: EntryId,
    pub frame: FrameContext,
    at_ms: u64,
}

/// An opaque, non-cloneable attempt. Dropping it never refunds its reservation.
/// Only its originating connection can use it, once, for its typed frame.
pub struct FramePermit {
    pub(crate) producer: Option<ProducerKind>,
    pub(crate) class: FrameClass,
    pub(crate) direction: Direction,
    pub(crate) connection: EntryId,
    pub(crate) channel: ContentId,
    pub(crate) reserved_bytes: u64,
    pub(crate) content_id: Option<ContentId>,
    pub(crate) reservation: Option<Reservation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProducerUsage {
    pub producer: ProducerKind,
    pub max_frame_bytes: u64,
    pub max_reserved_bytes: u64,
    pub reserved_bytes: u64,
    pub remaining_bytes: u64,
    pub max_attempt_entries: u64,
    pub attempt_entries: u64,
    pub remaining_attempt_entries: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct TransportAttemptStatus {
    pub budget_id: EntryId,
    pub policy_fingerprint: ContentId,
    pub owner: DeviceId,
    pub approved_peer: DeviceId,
    pub data_root: PathBuf,
    pub control_root: PathBuf,
    pub meter_unit: String,
    pub route_scope: String,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub reserved_frame_bytes: u64,
    pub remaining_frame_bytes: u64,
    pub attempt_entries: u64,
    pub remaining_attempt_entries: u64,
    pub clock_high_water_ms: u64,
    pub producers: Vec<ProducerUsage>,
    pub actual_wire_bytes: Option<u64>,
    pub automatic_rollover: bool,
    pub failed_reservations_refunded: bool,
    pub logical_dedup_affects_attempts: bool,
}

enum WorkerRequest {
    Reserve(FrameContext),
    Check(Reservation),
    Status,
    Stop,
}
enum WorkerResponse {
    Reserved(Reservation),
    Checked,
    Status(TransportAttemptStatus),
}
struct Envelope {
    request: WorkerRequest,
    reply: Option<mpsc::SyncSender<Result<WorkerResponse>>>,
}

/// Arc/thread-safe handle, not a public callback issuer. Raw SQLite/VFS pointers
/// live, operate and close only in the single bounded private worker.
pub struct ApplicationBudget {
    policy: TransportAttemptPolicy,
    fingerprint: ContentId,
    sender: mpsc::SyncSender<Envelope>,
    closed: Mutex<mpsc::Receiver<()>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl ApplicationBudget {
    pub fn require_readonly_platform() -> Result<()> {
        guard::require_readonly_platform()
    }

    pub fn require_unselected_ledger_absent(control_root: &Path) -> Result<()> {
        guard::require_legacy_absent(control_root)
    }

    /// Startup validation without a worker, VFS, SQLite connection or CREATE.
    /// Actual roots are retained and revalidated again by the eventual worker.
    pub fn validate_roots(
        signed: &SignedTransportAttemptPolicy,
        data_root: &Path,
        control_root: &Path,
    ) -> Result<()> {
        guard::require_platform()?;
        signed.verify(data_root, control_root)?;
        signed.policy.max_file_bytes()?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let _roots = sync_extend_platform_fs::UnixSqliteLedger::hold_transport_attempt_roots(
            data_root,
            control_root,
        )
        .map_err(budget_error)?;
        #[cfg(windows)]
        let _roots = guard::WindowsRoots::hold(data_root, control_root)?;
        Ok(())
    }

    /// Explicit fresh creation only. Existing state is never reset or replaced.
    pub fn init(
        signed: SignedTransportAttemptPolicy,
        data_root: &Path,
        control_root: &Path,
    ) -> Result<Arc<Self>> {
        Self::start(signed, data_root, control_root, Some(now_ms()?), false)
    }

    pub fn open(
        signed: SignedTransportAttemptPolicy,
        data_root: &Path,
        control_root: &Path,
    ) -> Result<Arc<Self>> {
        Self::start(signed, data_root, control_root, None, false)
    }

    /// Unsupported platforms refuse before inspecting any policy, root or file.
    pub fn read_status(
        signed: SignedTransportAttemptPolicy,
        data_root: &Path,
        control_root: &Path,
    ) -> Result<TransportAttemptStatus> {
        guard::require_readonly_platform()?;
        Self::start(signed, data_root, control_root, None, true)?.status()
    }

    fn start(
        signed: SignedTransportAttemptPolicy,
        data_root: &Path,
        control_root: &Path,
        initialize: Option<u64>,
        read_only: bool,
    ) -> Result<Arc<Self>> {
        guard::require_platform()?;
        signed.verify(data_root, control_root)?;
        signed.policy.max_file_bytes()?;
        if initialize.is_some_and(|at| at >= signed.policy.period_end_ms) {
            return Err(budget_error(
                "cannot initialize an already expired application window",
            ));
        }
        let fingerprint = signed.fingerprint()?;
        let policy = signed.policy.clone();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            // Only directory guards move to the worker. No VFS exists yet.
            // Marker/identity/private/local roots and all file liabilities are
            // checked before this point and before the worker thread is spawned.
            let roots = sync_extend_platform_fs::UnixSqliteLedger::hold_transport_attempt_roots(
                data_root,
                control_root,
            )
            .map_err(budget_error)?;
            let maximum = policy.max_file_bytes()?;
            Self::spawn_worker(policy, fingerprint, move || {
                let vfs = sync_extend_platform_fs::UnixSqliteLedger::open_transport_attempt(
                    roots,
                    maximum,
                    initialize.is_some(),
                    read_only,
                )
                .map_err(budget_error)?;
                ledger::Ledger::open_unix(signed, vfs, initialize, read_only)
            })
        }
        #[cfg(windows)]
        {
            if read_only {
                return Err(budget_error(
                    "read-only application-frame status is Unsupported",
                ));
            }
            let roots = guard::WindowsRoots::hold(data_root, control_root)?;
            Self::spawn_worker(policy, fingerprint, move || {
                ledger::Ledger::open_windows(signed, roots, initialize)
            })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        {
            let _ = (fingerprint, policy, initialize, read_only);
            Err(budget_error("application-frame ledger is Unsupported"))
        }
    }

    fn spawn_worker<F>(
        policy: TransportAttemptPolicy,
        fingerprint: ContentId,
        create: F,
    ) -> Result<Arc<Self>>
    where
        F: FnOnce() -> Result<ledger::Ledger> + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel::<Envelope>(32);
        let (ready, startup) = mpsc::sync_channel(1);
        let (stopped, closed) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("sync-frame-budget".to_owned())
            .spawn(move || {
                let ledger = match create() {
                    Ok(ledger) => ledger,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        let _ = stopped.send(());
                        return;
                    }
                };
                let status = ledger.status();
                let success = status.is_ok();
                if ready.send(status).is_err() || !success {
                    drop(ledger);
                    let _ = stopped.send(());
                    return;
                }
                while let Ok(envelope) = receiver.recv() {
                    let result = match envelope.request {
                        WorkerRequest::Reserve(frame) => {
                            ledger.reserve(frame).map(WorkerResponse::Reserved)
                        }
                        WorkerRequest::Check(reservation) => ledger
                            .check_use(&reservation)
                            .map(|()| WorkerResponse::Checked),
                        WorkerRequest::Status => ledger.status().map(WorkerResponse::Status),
                        WorkerRequest::Stop => break,
                    };
                    if let Some(reply) = envelope.reply {
                        // A lost/timeout reply can follow a durable commit. Keep it.
                        let _ = reply.send(result);
                    }
                }
                drop(ledger);
                let _ = stopped.send(());
            })
            .map_err(budget_error)?;
        let status = startup.recv_timeout(WORKER_WAIT).map_err(budget_error)?;
        if let Err(error) = status {
            drop(sender);
            drop(worker);
            return Err(error);
        }
        Ok(Arc::new(Self {
            policy,
            fingerprint,
            sender,
            closed: Mutex::new(closed),
            worker: Mutex::new(Some(worker)),
        }))
    }

    fn invoke(&self, request: WorkerRequest) -> Result<WorkerResponse> {
        let (reply, result) = mpsc::sync_channel(1);
        self.sender
            .try_send(Envelope {
                request,
                reply: Some(reply),
            })
            .map_err(budget_error)?;
        result.recv_timeout(WORKER_WAIT).map_err(budget_error)?
    }

    pub(crate) fn verify_connection(
        &self,
        identity: &TransportIdentity,
        peer: &PeerIdentity,
    ) -> Result<()> {
        if identity.peer_identity() != &self.policy.owner || peer != &self.policy.approved_peer {
            return Err(budget_error(
                "selected budget requires its one exact pinned owner/peer",
            ));
        }
        Ok(())
    }

    pub(crate) fn frame_bound(&self, producer: ProducerKind) -> Result<u64> {
        Ok(self.policy.producer_limit(producer)?.max_frame_bytes)
    }

    pub(crate) fn reserve(&self, frame: FrameContext) -> Result<Reservation> {
        match self.invoke(WorkerRequest::Reserve(frame))? {
            WorkerResponse::Reserved(reservation) => {
                // Check after the durable reply, before the producer prepares
                // or reads content. Failure keeps the already committed charge.
                self.check_use(&reservation)?;
                Ok(reservation)
            }
            _ => Err(budget_error("private application issuer response differs")),
        }
    }

    pub(crate) fn check_use(&self, reservation: &Reservation) -> Result<()> {
        match self.invoke(WorkerRequest::Check(reservation.clone()))? {
            WorkerResponse::Checked => Ok(()),
            _ => Err(budget_error("private application use check differs")),
        }
    }

    pub(crate) fn bounded_wait(&self, requested: Duration) -> Result<Duration> {
        let remaining = self
            .policy
            .period_end_ms
            .checked_sub(now_ms()?)
            .filter(|value| *value > 0)
            .ok_or_else(|| budget_error("application frame window has ended"))?;
        Ok(requested.min(Duration::from_millis(remaining)))
    }

    pub fn status(&self) -> Result<TransportAttemptStatus> {
        match self.invoke(WorkerRequest::Status)? {
            WorkerResponse::Status(status) if status.policy_fingerprint == self.fingerprint => {
                Ok(status)
            }
            _ => Err(budget_error("private application status policy differs")),
        }
    }
}

impl Drop for ApplicationBudget {
    fn drop(&mut self) {
        let _ = self.sender.try_send(Envelope {
            request: WorkerRequest::Stop,
            reply: None,
        });
        let finished = self
            .closed
            .get_mut()
            .ok()
            .is_some_and(|closed| closed.recv_timeout(WORKER_WAIT).is_ok());
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                if finished {
                    let _ = worker.join();
                }
                // A stalled worker can still hold a committed charge. It gets
                // no further requests; never detach authority to another issuer.
            }
        }
    }
}
