use clap::{Parser, Subcommand};
use std::{io::Read, path::PathBuf, process::ExitCode, time::Duration};
use sync_extend_core_model::{
    config::{Config, HistoryPolicy},
    PortablePath,
};
use sync_extend_reconcile::LocalSpace;

#[derive(Parser)]
#[command(
    name = "syncd",
    version,
    about = "SyncExtend offline local core prototype; network and WebDAV are not yet available"
)]
struct Cli {
    /// Apply a local limits JSON file to this invocation (not a retention/GC policy).
    #[arg(long, global = true)]
    limits: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a local space. Data must be outside the existing worktree.
    Init {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        root: PathBuf,
    },
    /// Reconcile a stable full scan into immutable content and journal.
    Scan {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Show truthful local capability and index state.
    Status {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Audit one bounded metadata snapshot; report implementation and certification gaps.
    Diagnostics {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Audit local storage and references without importing, recovering or deleting.
    StorageReport {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Reserve immutable expected content locally; no import, release or worker.
    ReserveContent {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        intent: PathBuf,
    },
    /// Audit durable worker content reservations without reading CAS or releasing pins.
    ReferenceReservations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Transfer download/restore pins to an exact retained local snapshot; no remote receipt.
    HandoffContent {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        snapshot: String,
    },
    /// Verify and ingest one exact reserved chunk; no snapshot/worker/remote completion.
    IngestReservedChunk {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        chunk: String,
        #[arg(long)]
        source: PathBuf,
    },
    /// Persist one verified unreferenced CAS observation; never authorize deletion.
    MarkGcObject {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        object: String,
        #[arg(long, default_value_t=86400, value_parser=clap::value_parser!(u64).range(1..=604800))]
        grace_secs: u64,
    },
    /// Audit persistent GC marks without touching content or advancing time.
    GcMarks {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Cancel only one GC mark; preserve every file and reference.
    CancelGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
    },
    /// Recheck a GC observation after grace; the result never authorizes deletion.
    RevalidateGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
    },
    /// Inspect one mark under transient database/file guards; never authorize deletion.
    PreflightGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
    },
    /// Persist one guarded GC intent for a future executor; never delete.
    AuthorizeGcMark {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        mark: String,
        #[arg(long, default_value_t=300, value_parser=clap::value_parser!(u64).range(1..=3600))]
        ttl_secs: u64,
    },
    /// Audit GC authorization intents at the durable clock watermark.
    GcAuthorizations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Consume one explicit GC intent into a durable reference fence; never move/delete.
    AdmitGcExecution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        authorization: String,
    },
    /// Audit durable single-use execution admissions and independent terminal states.
    GcExecutions {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Explicitly quarantine one admitted CAS object; preserve bytes, never sweep.
    QuarantineGcExecution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Audit bounded durable GC quarantine plans without physical recovery.
    GcQuarantines {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Persist one single-use pre-disposition record; never request deletion.
    PrepareGcDisposal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Explicitly dispose one prepared quarantine; pending readers retain its fence.
    ExecuteGcDisposal {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Audit disposal preparation/restoration/deletion without executing physical recovery.
    GcDisposals {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Restore only the exact admitted quarantine object, without overwrite.
    RestoreGcQuarantine {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Abort a non-displacing execution fence; never restore/delete or reuse its intent.
    AbortGcExecution {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        execution: String,
    },
    /// Permanently revoke one GC intent without changing any file or pin.
    RevokeGcAuthorization {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        authorization: String,
    },
    /// Recheck a durable GC intent under transient guards; no deletion.
    CheckGcAuthorization {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        authorization: String,
    },
    /// List immutable snapshot audit metadata, including explicitly pruned non-restorable history.
    SnapshotAudit {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Explicitly retire one old snapshot's own pins, preserving audit metadata and all CAS files.
    PruneSnapshot {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        baseline: String,
    },
    /// Protect a retained materialized snapshot after validating its references and content.
    LockSnapshot {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
    },
    /// Remove only the explicit user lock, never history or object pins.
    UnlockSnapshot {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
    },
    /// Preview count/budget retention and blockers; never prune history or run GC.
    RetentionReport {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = HistoryPolicy::default().history_snapshots)]
        history_snapshots: u32,
        #[arg(long, default_value_t = HistoryPolicy::default().history_budget_bytes)]
        history_budget_bytes: u64,
    },
    /// Persist exact retained-file read pins; does not release overdue leases.
    AcquireReadLease {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        path: String,
        #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=86400))]
        ttl_secs: u64,
    },
    /// Audit all read lease states without implicitly expiring their pins.
    ReadLeases {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Extend an active, unexpired lease without changing its fixed version.
    RenewReadLease {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        lease: String,
        #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=86400))]
        ttl_secs: u64,
    },
    /// Release only this lease's pins; never delete content or history.
    ReleaseReadLease {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        lease: String,
    },
    /// Explicitly expire overdue read lease pins; never delete content.
    RecoverReadLeases {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Export the lease's fixed historical file outside worktree/data, never overwrite.
    ExportLeased {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        lease: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Prepare exact committed Move marker cleanup without authorizing deletion.
    PrepareCleanup {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// List persistent marker cleanup plans and authorization/completion states.
    CleanupPlans {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Cancel a prepared marker cleanup; no file or history is removed.
    CancelCleanup {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Explicitly remove only the protected owner marker of a committed Move.
    ExecuteCleanup {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Resume authorized marker cleanups only; never authorize preparations.
    RecoverCleanups {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Print the immutable current manifest (contains local filenames).
    Manifest {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Print local operations (contains local filenames).
    Ops {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Check SQLite, snapshot roots and all retained file versions.
    Verify {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Export a verified current file outside the worktree; never overwrite.
    Export {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        path: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Publish a single local file without overwriting an existing destination.
    Publish {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        path: String,
    },
    /// Restore one retained file as a new local change; occupied paths keep a conflict copy.
    Restore {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        path: String,
    },
    /// Resume authorized mutations/publications without rolling back newer writes.
    Recover {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// List retained snapshot IDs for single-file restore.
    Snapshots {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Persist a file mutation baseline only. No file is replaced, removed or moved.
    PrepareMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        path: String,
        #[command(subcommand)]
        action: PrepareAction,
    },
    /// List local mutation preparations and cancellations (contains filenames).
    Mutations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Revalidate a preparation without executing any worktree mutation.
    CheckMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Cancel an unexecuted preparation, releasing only its journal references.
    CancelMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Explicitly execute a prepared Windows local NTFS single-file Delete, Move or Replace.
    ExecuteMutation {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        transaction: String,
    },
    /// Resume authorized file mutations, never automatically authorize preparations.
    RecoverMutations {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// Validate configuration without starting any listener.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Run local polling reconciliation only; no network listener is started.
    Run {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        scan_interval_secs: u64,
    },
}

#[derive(Subcommand)]
enum PrepareAction {
    Replace {
        #[arg(long)]
        source: PathBuf,
    },
    Delete,
    Move {
        #[arg(long)]
        destination: String,
    },
}

fn print(value: &impl serde::Serialize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("syncd: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let limits: sync_extend_core_model::limits::LocalLimits = if let Some(path) = cli.limits {
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err("limits configuration exceeds 64 KiB".into());
        }
        serde_json::from_slice(&bytes)?
    } else {
        Default::default()
    };
    limits.validate()?;
    let open = |data: &std::path::Path| LocalSpace::open(data)?.with_limits(limits.clone());
    match cli.command {
        Command::Init { data_dir, root } => {
            let local = LocalSpace::initialize_with_limits(&data_dir, &root, limits.clone())?;
            print(&local.status()?)?;
        }
        Command::Scan { data_dir } => {
            print(&open(&data_dir)?.scan()?)?;
        }
        Command::Status { data_dir } => {
            print(&open(&data_dir)?.status()?)?;
        }
        Command::Diagnostics { data_dir } => {
            print(&open(&data_dir)?.diagnostics()?)?;
        }
        Command::StorageReport { data_dir } => {
            print(&open(&data_dir)?.storage_report()?)?;
        }
        Command::ReserveContent { data_dir, intent } => {
            let mut bytes = Vec::new();
            std::fs::File::open(intent)?
                .take(16 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err("reservation intent exceeds 16 MiB".into());
            }
            let intent: sync_extend_reconcile::ReferenceReservationIntent =
                serde_json::from_slice(&bytes)?;
            print(&open(&data_dir)?.reserve_content(&intent)?)?;
        }
        Command::ReferenceReservations { data_dir } => {
            print(&open(&data_dir)?.reference_reservations()?)?;
        }
        Command::HandoffContent {
            data_dir,
            owner,
            snapshot,
        } => {
            print(&open(&data_dir)?.handoff_content(&owner.parse()?, &snapshot.parse()?)?)?;
        }
        Command::IngestReservedChunk {
            data_dir,
            owner,
            chunk,
            source,
        } => {
            print(&open(&data_dir)?.ingest_reserved_chunk(
                &owner.parse()?,
                &chunk.parse()?,
                &source,
            )?)?;
        }
        Command::MarkGcObject {
            data_dir,
            object,
            grace_secs,
        } => {
            print(&open(&data_dir)?.mark_gc_object(&object.parse()?, grace_secs)?)?;
        }
        Command::GcMarks { data_dir } => print(&open(&data_dir)?.gc_marks()?)?,
        Command::CancelGcMark { data_dir, mark } => {
            print(&open(&data_dir)?.cancel_gc_mark(&mark.parse()?)?)?;
        }
        Command::RevalidateGcMark { data_dir, mark } => {
            print(&open(&data_dir)?.revalidate_gc_mark(&mark.parse()?)?)?;
        }
        Command::PreflightGcMark { data_dir, mark } => {
            print(&open(&data_dir)?.preflight_gc_mark(&mark.parse()?)?)?;
        }
        Command::AuthorizeGcMark {
            data_dir,
            mark,
            ttl_secs,
        } => {
            print(&open(&data_dir)?.authorize_gc_mark(&mark.parse()?, ttl_secs)?)?;
        }
        Command::GcAuthorizations { data_dir } => print(&open(&data_dir)?.gc_authorizations()?)?,
        Command::AdmitGcExecution {
            data_dir,
            authorization,
        } => print(&open(&data_dir)?.admit_gc_execution(&authorization.parse()?)?)?,
        Command::GcExecutions { data_dir } => print(&open(&data_dir)?.gc_executions()?)?,
        Command::QuarantineGcExecution {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.quarantine_gc_execution(&execution.parse()?)?)?,
        Command::GcQuarantines { data_dir } => print(&open(&data_dir)?.gc_quarantines()?)?,
        Command::PrepareGcDisposal {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.prepare_gc_disposal(&execution.parse()?)?)?,
        Command::GcDisposals { data_dir } => print(&open(&data_dir)?.gc_disposals()?)?,
        Command::ExecuteGcDisposal {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.execute_gc_disposal(&execution.parse()?)?)?,
        Command::RestoreGcQuarantine {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.restore_gc_quarantine(&execution.parse()?)?)?,
        Command::AbortGcExecution {
            data_dir,
            execution,
        } => print(&open(&data_dir)?.abort_gc_execution(&execution.parse()?)?)?,
        Command::RevokeGcAuthorization {
            data_dir,
            authorization,
        } => {
            print(&open(&data_dir)?.revoke_gc_authorization(&authorization.parse()?)?)?;
        }
        Command::CheckGcAuthorization {
            data_dir,
            authorization,
        } => {
            print(&open(&data_dir)?.check_gc_authorization(&authorization.parse()?)?)?;
        }
        Command::SnapshotAudit { data_dir } => print(&open(&data_dir)?.snapshot_audit()?)?,
        Command::PruneSnapshot {
            data_dir,
            snapshot,
            baseline,
        } => {
            print(&open(&data_dir)?.prune_snapshot(&snapshot.parse()?, &baseline.parse()?)?)?;
        }
        Command::LockSnapshot { data_dir, snapshot } => {
            print(&open(&data_dir)?.lock_snapshot(&snapshot.parse()?)?)?;
        }
        Command::UnlockSnapshot { data_dir, snapshot } => {
            print(&open(&data_dir)?.unlock_snapshot(&snapshot.parse()?)?)?;
        }
        Command::RetentionReport {
            data_dir,
            history_snapshots,
            history_budget_bytes,
        } => {
            let policy = HistoryPolicy {
                history_snapshots,
                history_budget_bytes,
                ..Default::default()
            };
            print(&open(&data_dir)?.retention_report(policy)?)?;
        }
        Command::AcquireReadLease {
            data_dir,
            snapshot,
            path,
            ttl_secs,
        } => {
            print(&open(&data_dir)?.acquire_read_lease(
                &snapshot.parse()?,
                &PortablePath::new(path)?,
                ttl_secs,
            )?)?;
        }
        Command::ReadLeases { data_dir } => print(&open(&data_dir)?.read_leases()?)?,
        Command::RenewReadLease {
            data_dir,
            lease,
            ttl_secs,
        } => {
            print(&open(&data_dir)?.renew_read_lease(&lease.parse()?, ttl_secs)?)?;
        }
        Command::ReleaseReadLease { data_dir, lease } => {
            print(&open(&data_dir)?.release_read_lease(&lease.parse()?)?)?;
        }
        Command::RecoverReadLeases { data_dir } => print(&open(&data_dir)?.recover_read_leases()?)?,
        Command::ExportLeased {
            data_dir,
            lease,
            output,
        } => {
            print(&open(&data_dir)?.export_leased(&lease.parse()?, &output)?)?;
        }
        Command::PrepareCleanup {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.prepare_cleanup(&transaction.parse()?)?)?;
        }
        Command::CleanupPlans { data_dir } => print(&open(&data_dir)?.cleanup_plans()?)?,
        Command::CancelCleanup {
            data_dir,
            transaction,
        } => {
            open(&data_dir)?.cancel_cleanup(&transaction.parse()?)?;
            print(&serde_json::json!({"cancelled": true, "worktree_modified": false}))?;
        }
        Command::ExecuteCleanup {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.execute_cleanup(&transaction.parse()?)?)?;
        }
        Command::RecoverCleanups { data_dir } => print(&open(&data_dir)?.recover_cleanups()?)?,
        Command::Manifest { data_dir } => {
            print(&open(&data_dir)?.manifest()?)?;
        }
        Command::Ops { data_dir } => {
            print(&open(&data_dir)?.operations()?)?;
        }
        Command::Verify { data_dir } => {
            let files = open(&data_dir)?.verify()?;
            print(&serde_json::json!({"verified_file_versions": files, "sqlite_integrity": "ok"}))?;
        }
        Command::Export {
            data_dir,
            path,
            output,
        } => {
            open(&data_dir)?.export_file(&PortablePath::new(path)?, &output)?;
            print(&serde_json::json!({"exported": true, "remote_backup_complete": false}))?;
        }
        Command::CheckConfig { config } => {
            let file = std::fs::File::open(config)?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > 1024 * 1024 {
                return Err("configuration exceeds 1 MiB".into());
            }
            let config: Config = serde_json::from_slice(&bytes)?;
            config.validate()?;
            print(&serde_json::json!({"valid": true, "listener_started": false}))?;
        }
        Command::Publish {
            data_dir,
            source,
            path,
        } => {
            print(&open(&data_dir)?.publish_file(&source, PortablePath::new(path)?)?)?;
        }
        Command::Restore {
            data_dir,
            snapshot,
            path,
        } => {
            print(&open(&data_dir)?.restore_file(&snapshot.parse()?, PortablePath::new(path)?)?)?;
        }
        Command::Recover { data_dir } => {
            print(&open(&data_dir)?.recover()?)?;
        }
        Command::Snapshots { data_dir } => {
            print(&open(&data_dir)?.snapshots()?)?;
        }
        Command::PrepareMutation {
            data_dir,
            snapshot,
            path,
            action,
        } => {
            let mut local = open(&data_dir)?;
            let snapshot = snapshot.parse()?;
            let path = PortablePath::new(path)?;
            let executor_available = cfg!(windows);
            let mutation = match action {
                PrepareAction::Replace { source } => {
                    local.prepare_replace(&snapshot, &path, &source)?
                }
                PrepareAction::Delete => local.prepare_delete(&snapshot, &path)?,
                PrepareAction::Move { destination } => {
                    local.prepare_move(&snapshot, &path, &PortablePath::new(destination)?)?
                }
            };
            print(&serde_json::json!({
                "mutation": mutation, "executor_available": executor_available,
                "worktree_modified": false, "remote_backup_complete": false,
            }))?;
        }
        Command::Mutations { data_dir } => print(&open(&data_dir)?.mutations()?)?,
        Command::CheckMutation {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.check_mutation(&transaction.parse()?)?)?;
        }
        Command::CancelMutation {
            data_dir,
            transaction,
        } => {
            open(&data_dir)?.cancel_mutation(&transaction.parse()?)?;
            print(&serde_json::json!({"cancelled": true, "worktree_modified": false}))?;
        }
        Command::ExecuteMutation {
            data_dir,
            transaction,
        } => {
            print(&open(&data_dir)?.execute_mutation(&transaction.parse()?)?)?;
        }
        Command::RecoverMutations { data_dir } => print(&open(&data_dir)?.recover_mutations()?)?,
        Command::Run {
            data_dir,
            scan_interval_secs,
        } => {
            let mut local = open(&data_dir)?;
            let mut timer = tokio::time::interval(Duration::from_secs(scan_interval_secs));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let shutdown = tokio::signal::ctrl_c();
            tokio::pin!(shutdown);
            loop {
                tokio::select! {
                    result = &mut shutdown => { result?; break; }
                    _ = timer.tick() => {
                        local = tokio::task::spawn_blocking(move || {
                            match local.scan() {
                                Ok(result) => { println!("{}", serde_json::to_string(&result).unwrap_or_default()); }
                                Err(error) => { eprintln!("syncd: reconciliation deferred: {error}"); }
                            }
                            local
                        }).await?;
                    }
                }
            }
        }
    }
    Ok(())
}
