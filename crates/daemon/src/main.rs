use clap::{Parser, Subcommand};
use std::{io::Read, path::PathBuf, process::ExitCode, time::Duration};
use sync_extend_core_model::{config::Config, PortablePath};
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
    /// Audit local storage and references without importing, recovering or deleting.
    StorageReport {
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
        Command::StorageReport { data_dir } => {
            print(&open(&data_dir)?.storage_report()?)?;
        }
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
