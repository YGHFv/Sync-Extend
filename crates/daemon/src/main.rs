use clap::{Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode, time::Duration};
use sync_extend_core_model::{config::Config, PortablePath};
use sync_extend_reconcile::LocalSpace;

#[derive(Parser)]
#[command(
    name = "syncd",
    version,
    about = "SyncExtend offline local core prototype; network and WebDAV are not yet available"
)]
struct Cli {
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
    match cli.command {
        Command::Init { data_dir, root } => {
            let local = LocalSpace::initialize(&data_dir, &root)?;
            print(&local.status()?)?;
        }
        Command::Scan { data_dir } => {
            print(&LocalSpace::open(&data_dir)?.scan()?)?;
        }
        Command::Status { data_dir } => {
            print(&LocalSpace::open(&data_dir)?.status()?)?;
        }
        Command::Manifest { data_dir } => {
            print(&LocalSpace::open(&data_dir)?.manifest()?)?;
        }
        Command::Ops { data_dir } => {
            print(&LocalSpace::open(&data_dir)?.operations()?)?;
        }
        Command::Verify { data_dir } => {
            let files = LocalSpace::open(&data_dir)?.verify()?;
            print(&serde_json::json!({"verified_file_versions": files, "sqlite_integrity": "ok"}))?;
        }
        Command::Export {
            data_dir,
            path,
            output,
        } => {
            LocalSpace::open(&data_dir)?.export_file(&PortablePath::new(path)?, &output)?;
            print(&serde_json::json!({"exported": true, "remote_backup_complete": false}))?;
        }
        Command::CheckConfig { config } => {
            let metadata = std::fs::metadata(&config)?;
            if metadata.len() > 1024 * 1024 {
                return Err("configuration exceeds 1 MiB".into());
            }
            let config: Config = serde_json::from_reader(std::fs::File::open(config)?)?;
            config.validate()?;
            print(&serde_json::json!({"valid": true, "listener_started": false}))?;
        }
        Command::Run {
            data_dir,
            scan_interval_secs,
        } => {
            let mut local = LocalSpace::open(&data_dir)?;
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
