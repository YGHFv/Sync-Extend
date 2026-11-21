//! Acquire Linux owner before threads; prepare Publish helpers after its full plan.
use super::{Cli, Command};
use serde::Deserialize;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};
use sync_extend_core_model::{limits::LocalLimits, ContentId};
use sync_extend_platform_fs::{
    LinuxMetadataBudget, LinuxMetadataLimits, LinuxNamespaceCapability, LinuxPublicationEpoch,
    OriginalPairTerminalRelease, OutsideHelperProgram, OutsideHelperSession, PinnedProgram,
};
use sync_extend_reconcile::LocalSpace;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataLimits {
    main: u64,
    wal: u64,
    shm: u64,
    rollback_journal: u64,
    owner_record: u64,
    total_physical: u64,
}

impl From<MetadataLimits> for LinuxMetadataLimits {
    fn from(value: MetadataLimits) -> Self {
        Self {
            main: value.main,
            wal: value.wal,
            shm: value.shm,
            rollback_journal: value.rollback_journal,
            owner_record: value.owner_record,
            total_physical: value.total_physical,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    format_version: u32,
    backing_image: PathBuf,
    mount_root: PathBuf,
    worktree_directory: String,
    metadata_root: PathBuf,
    metadata_limits: MetadataLimits,
    helper_program: PathBuf,
    accepted_helper_content_id: ContentId,
    terminal_receipt_output: Option<PathBuf>,
}

#[derive(Default)]
struct PreparedHelperEvidence {
    process_ids: Vec<u32>,
    startup_bytes: Vec<Vec<u8>>,
    process_births: Vec<serde_json::Value>,
}

#[derive(Clone, Copy)]
enum PublisherPhase {
    Ready,
    Publishing,
    Blocked,
}

struct PublisherActor {
    initial_epoch: Option<LinuxPublicationEpoch>,
    publisher: Option<sync_extend_reconcile::LinuxNativePublisher>,
    phase: PublisherPhase,
    completed_epochs: u64,
    last_terminal_diagnostic: Option<serde_json::Value>,
}

pub struct LinuxDaemonOwner {
    pub owner: Arc<LinuxNamespaceCapability>,
    pub budget: Arc<LinuxMetadataBudget>,
    pub helpers: Mutex<Option<OutsideHelperSession>>,
    metadata_root: PathBuf,
    worktree: PathBuf,
    terminal: Mutex<Option<OriginalPairTerminalRelease>>,
    publisher_actor: Mutex<PublisherActor>,
    terminal_receipt_output: Option<PathBuf>,
    prepared: Mutex<PreparedHelperEvidence>,
    delayed_helper_program: Option<OutsideHelperProgram>,
}

pub struct LinuxWebDavCommitFailure {
    pub error: Box<sync_extend_reconcile::ReconcileError>,
    pub committed: Option<sync_extend_reconcile::WebDavCommit>,
}

impl From<sync_extend_reconcile::ReconcileError> for LinuxWebDavCommitFailure {
    fn from(error: sync_extend_reconcile::ReconcileError) -> Self {
        Self {
            error: Box::new(error),
            committed: None,
        }
    }
}

fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("Linux owner paths must be normalized absolute paths".into());
    }
    Ok(())
}

pub fn prepare(cli: &Cli) -> Result<Option<LinuxDaemonOwner>> {
    let Some(config_path) = &cli.linux_namespace_config else {
        return Ok(None);
    };
    let bytes = super::config_file::read(config_path, 65_536)?;
    let config: Config = serde_json::from_slice(&bytes)?;
    if config.format_version != 1
        || config.worktree_directory.is_empty()
        || config.worktree_directory.starts_with('.')
        || config.worktree_directory.len() > 220
        || Path::new(&config.worktree_directory).components().count() != 1
        || !matches!(
            Path::new(&config.worktree_directory).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err("Linux owner configuration has an invalid worktree component".into());
    }
    for path in [
        &config.backing_image,
        &config.mount_root,
        &config.metadata_root,
        &config.helper_program,
    ] {
        absolute(path)?;
    }
    if let Some(path) = &config.terminal_receipt_output {
        absolute(path)?;
        if path.starts_with(&config.mount_root) || path.try_exists()? {
            return Err("fresh terminal receipt must remain outside the acquired worktree".into());
        }
    }
    let webdav_gateway = match &cli.command {
        Command::WebdavServe { config, .. } => Some(config.clone()),
        Command::DeploymentRun { config } => match super::deployment::load(config)?.role {
            sync_extend_core_model::deployment::DeploymentRole::WebdavClient {
                gateway_config,
                ..
            } => Some(gateway_config),
            _ => None,
        },
        _ => None,
    };
    let (data_dir, initialize) = if let Some(gateway) = &webdav_gateway {
        let runtime = super::webdav::load(gateway)?;
        let exported = runtime.listener.exports.iter().any(|export| {
            runtime
                .spaces
                .get(&export.space_id)
                .is_some_and(|path| path == &config.metadata_root)
        });
        if !exported {
            return Err("Linux owner metadata root is not a configured DAV export".into());
        }
        (&config.metadata_root, false)
    } else {
        match &cli.command {
            Command::Init { data_dir, root } => {
                if root != &config.mount_root.join(&config.worktree_directory) {
                    return Err("init root differs from the explicit Linux owner worktree".into());
                }
                (data_dir, true)
            }
            Command::Scan { data_dir }
            | Command::Status { data_dir }
            | Command::Run { data_dir, .. }
            | Command::Publish { data_dir, .. }
            | Command::LinuxNativeFinals { data_dir }
            | Command::CleanupLinuxNative { data_dir, .. }
            | Command::Manifest { data_dir }
            | Command::Ops { data_dir }
            | Command::Verify { data_dir }
            | Command::Snapshots { data_dir }
            | Command::SnapshotAudit { data_dir } => (data_dir, false),
            _ => return Err("this command does not use the explicit Linux local owner".into()),
        }
    };
    if data_dir != &config.metadata_root {
        return Err("command metadata root differs from the explicit Linux owner".into());
    }
    let pinned = PinnedProgram::open(&config.helper_program, 64 * 1024 * 1024)?;
    let mut accepted = Vec::new();
    pinned
        .reader()
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut accepted)?;
    if accepted.is_empty()
        || accepted.len() > 64 * 1024 * 1024
        || ContentId::hash(&accepted) != config.accepted_helper_content_id
        || !accepted.starts_with(b"\x7fELF")
    {
        return Err("helper image differs from the explicitly accepted content identity".into());
    }
    let helper = OutsideHelperProgram::from_accepted_image(&pinned, &accepted)?;
    let owner = Arc::new(LinuxNamespaceCapability::acquire_private_ext4_image(
        &config.backing_image,
        &config.mount_root,
    )?);
    // Every ordinary command prepares its namespace and metadata without
    // starting a native watchdog. Only an actual Publish/DAV transaction
    // launches the accepted helpers immediately before its native ARM.
    let delayed = matches!(&cli.command, Command::Publish { .. }) || webdav_gateway.is_some();
    let initial_epoch = owner.initial_publication_epoch()?;
    let mut helpers: Option<OutsideHelperSession> = None;
    let prepared = PreparedHelperEvidence::default();
    let metadata_limits = config.metadata_limits.into();
    let budget = if initialize {
        LinuxMetadataBudget::prepare_new(
            &owner,
            &config.metadata_root,
            "journal.sqlite",
            metadata_limits,
        )
    } else {
        LinuxMetadataBudget::reopen_existing(
            &owner,
            &config.metadata_root,
            "journal.sqlite",
            metadata_limits,
        )
    };
    let budget = match budget {
        Ok(budget) => Arc::new(budget),
        Err(error) => {
            let terminal = helpers
                .take()
                .map(OutsideHelperSession::finish_unarmed)
                .transpose()?;
            let owner =
                Arc::try_unwrap(owner).map_err(|_| "refused Linux owner remains borrowed")?;
            if let Some(terminal) = terminal {
                owner.release_mount_after_helpers(terminal)?;
            } else {
                owner.release_unarmed_mount()?;
            }
            return Err(error.into());
        }
    };
    let worktree = config.mount_root.join(&config.worktree_directory);
    let worktree_prepared = (|| -> Result<()> {
        if initialize && !worktree.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(&worktree)?;
            fs::File::open(&config.mount_root)?.sync_all()?;
        }
        owner
            .volume()
            .directory(Path::new(&config.worktree_directory))?
            .verify()?;
        Ok(())
    })();
    if let Err(error) = worktree_prepared {
        let terminal = helpers
            .take()
            .map(OutsideHelperSession::finish_unarmed)
            .transpose()?;
        let closed = budget.checkpoint_closed();
        drop(budget);
        let owner =
            Arc::try_unwrap(owner).map_err(|_| "refused Linux worktree owner remains borrowed")?;
        let release = if let Some(terminal) = terminal {
            owner.release_mount_after_helpers(terminal)
        } else {
            owner.release_unarmed_mount()
        };
        closed?;
        release?;
        return Err(error);
    }
    Ok(Some(LinuxDaemonOwner {
        owner,
        budget,
        helpers: Mutex::new(helpers),
        metadata_root: config.metadata_root,
        worktree,
        terminal: Mutex::new(None),
        publisher_actor: Mutex::new(PublisherActor {
            initial_epoch: Some(initial_epoch),
            publisher: None,
            phase: PublisherPhase::Ready,
            completed_epochs: 0,
            last_terminal_diagnostic: None,
        }),
        terminal_receipt_output: config.terminal_receipt_output,
        prepared: Mutex::new(prepared),
        delayed_helper_program: if delayed { Some(helper) } else { None },
    }))
}

// Capture exact births only while the two original PREPARED pidfds are live.
fn capture_prepared(
    owner: &LinuxNamespaceCapability,
    helpers: &OutsideHelperSession,
) -> std::io::Result<PreparedHelperEvidence> {
    helpers.verify_prepared_owner(owner)?;
    let (guardian, supervisor) = helpers.process_ids();
    let ids = [
        guardian,
        supervisor.ok_or_else(|| std::io::Error::other("prepared supervisor PID absent"))?,
    ];
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let mut births = Vec::new();
    for pid in ids {
        let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let fields = raw
            .rsplit_once(')')
            .ok_or_else(|| std::io::Error::other("prepared helper stat encoding"))?
            .1;
        let start_ticks: u64 = fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| std::io::Error::other("prepared helper start time absent"))?
            .parse()
            .map_err(std::io::Error::other)?;
        births.push(
            serde_json::json!({"pid": pid, "start_ticks": start_ticks, "boot_id": boot_id.trim()}),
        );
    }
    let (guardian, supervisor) = helpers.startup_bytes();
    let startup = vec![
        guardian.to_vec(),
        supervisor
            .ok_or_else(|| std::io::Error::other("prepared supervisor bytes absent"))?
            .to_vec(),
    ];
    helpers.verify_prepared_owner(owner)?;
    Ok(PreparedHelperEvidence {
        process_ids: ids.to_vec(),
        startup_bytes: startup,
        process_births: births,
    })
}

impl LinuxDaemonOwner {
    /// This ordinary Publish path finishes without constructing a Tokio runtime.
    /// The live LocalSpace plan remains borrowed until the same attempt commits.
    pub fn publish_before_runtime(
        &mut self,
        data: &Path,
        source: &Path,
        path: sync_extend_core_model::PortablePath,
        limits: LocalLimits,
    ) -> Result<sync_extend_reconcile::PublishResult> {
        let mut local = self.open(data, limits)?;
        let program = self
            .delayed_helper_program
            .as_ref()
            .ok_or("late helper program absent")?;
        let owner = &self.owner;
        let prepared = &self.prepared;
        let mut actor = self
            .publisher_actor
            .lock()
            .map_err(|_| "publisher actor poisoned")?;
        let PublisherActor {
            initial_epoch,
            publisher,
            phase,
            ..
        } = &mut *actor;
        if publisher.is_none() {
            *publisher = Some(local.bind_initial_linux_native_publisher(
                owner,
                &self.budget,
                initial_epoch,
            )?);
        }
        let publisher = publisher.as_ref().ok_or("publisher initial epoch absent")?;
        *phase = PublisherPhase::Publishing;
        let mut helpers = self
            .helpers
            .lock()
            .map_err(|_| "original Linux helper session lock poisoned")?;
        let mut terminal = self
            .terminal
            .lock()
            .map_err(|_| "Linux terminal token lock poisoned")?;
        let result = local.publish_original_linux_native_file(
            source,
            path,
            sync_extend_reconcile::LinuxNativePublication::borrow_original(
                owner,
                &self.budget,
                publisher,
                &mut helpers,
                &mut terminal,
            ),
            |slot| {
                *slot = Some(OutsideHelperSession::prepare(
                    owner,
                    publisher.platform_epoch()?,
                    program,
                )?);
                let evidence = capture_prepared(
                    owner,
                    slot.as_ref()
                        .ok_or(sync_extend_reconcile::ReconcileError::Invariant(
                            "original prepared helper escaped",
                        ))?,
                )?;
                *prepared.lock().map_err(|_| {
                    sync_extend_reconcile::ReconcileError::Invariant(
                        "Linux prepared helper evidence lock poisoned",
                    )
                })? = evidence;
                Ok(())
            },
        );
        *phase = PublisherPhase::Blocked;
        let result = result?;
        drop(terminal);
        drop(helpers);
        drop(local);
        Ok(result)
    }
    pub fn initialize(&self, data: &Path, root: &Path, limits: LocalLimits) -> Result<LocalSpace> {
        if data != self.metadata_root || root != self.worktree {
            return Err("Linux initializer escaped its original owner roots".into());
        }
        Ok(LocalSpace::initialize_with_linux_namespace_metadata(
            data,
            root,
            limits,
            self.owner.clone(),
            self.budget.clone(),
        )?)
    }

    pub fn open(
        &self,
        data: &Path,
        limits: LocalLimits,
    ) -> sync_extend_reconcile::Result<LocalSpace> {
        if data != self.metadata_root {
            return Err(sync_extend_reconcile::ReconcileError::Invariant(
                "Linux opener escaped its original metadata root",
            ));
        }
        LocalSpace::open_with_linux_namespace_metadata(
            data,
            limits,
            self.owner.clone(),
            self.budget.clone(),
        )
    }

    pub fn owns_metadata_root(&self, data: &Path) -> bool {
        data == self.metadata_root
    }

    pub fn commit_webdav_upload(
        &self,
        local: &mut LocalSpace,
        request: sync_extend_reconcile::LinuxNativeWebDavPut,
        source: &std::fs::File,
    ) -> std::result::Result<sync_extend_reconcile::PublishResult, LinuxWebDavCommitFailure> {
        use sync_extend_reconcile::ReconcileError::Invariant;
        let mut actor = self
            .publisher_actor
            .try_lock()
            .map_err(|_| Invariant("Linux publication actor busy or poisoned"))?;
        if !matches!(actor.phase, PublisherPhase::Ready) {
            return Err(Invariant("Linux publication actor remains blocked").into());
        }
        let PublisherActor {
            initial_epoch,
            publisher,
            phase,
            completed_epochs,
            last_terminal_diagnostic,
        } = &mut *actor;
        if publisher.is_none() {
            *publisher = Some(local.bind_initial_linux_native_publisher(
                &self.owner,
                &self.budget,
                initial_epoch,
            )?);
        }
        let publisher = publisher
            .as_mut()
            .ok_or(Invariant("Linux live publisher absent"))?;
        let mut helpers = self
            .helpers
            .lock()
            .map_err(|_| Invariant("Linux helper session lock poisoned"))?;
        let mut terminal = self
            .terminal
            .lock()
            .map_err(|_| Invariant("Linux terminal token lock poisoned"))?;
        if helpers.is_some() || terminal.is_some() {
            return Err(Invariant("Linux previous helper or terminal still retained").into());
        }
        let program = self
            .delayed_helper_program
            .as_ref()
            .ok_or(Invariant("late helper program absent"))?;
        *phase = PublisherPhase::Publishing;
        let outcome: std::result::Result<_, LinuxWebDavCommitFailure> = (|| {
            let result =
                local.commit_linux_native_webdav_put(
                    request,
                    source,
                    sync_extend_reconcile::LinuxNativePublication::borrow_original(
                        &self.owner,
                        &self.budget,
                        publisher,
                        &mut helpers,
                        &mut terminal,
                    ),
                    |slot| {
                        *slot = Some(OutsideHelperSession::prepare(
                            &self.owner,
                            publisher.platform_epoch()?,
                            program,
                        )?);
                        let evidence = capture_prepared(
                            &self.owner,
                            slot.as_ref()
                                .ok_or(Invariant("original prepared helper escaped"))?,
                        )?;
                        *self.prepared.lock().map_err(|_| {
                            Invariant("Linux prepared helper evidence lock poisoned")
                        })? = evidence;
                        Ok(())
                    },
                )?;
            *last_terminal_diagnostic = terminal.as_ref().map(terminal_diagnostic);
            let next = match local.complete_linux_native_publication_epoch(
                &self.owner,
                &self.budget,
                publisher,
                &mut terminal,
                &result.transaction_id,
            ) {
                Ok(next) => next,
                Err(error) => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "linux_publication_blocked": true,
                            "transaction_id": result.transaction_id,
                            "snapshot_id": result.snapshot_id,
                            "local_committed": true,
                            "remote_backup_complete": false,
                            "publication_ready": false,
                        })
                    );
                    return Err(LinuxWebDavCommitFailure {
                        error: Box::new(error),
                        committed: Some(sync_extend_reconcile::WebDavCommit {
                            transaction_id: result.transaction_id,
                            snapshot_id: result.snapshot_id,
                            local_committed: result.local_committed,
                            remote_backup_complete: result.remote_backup_complete,
                        }),
                    });
                }
            };
            if let Some(diagnostic) = last_terminal_diagnostic.as_mut() {
                diagnostic["consumed_by_successor"] = serde_json::json!(true);
            }
            *completed_epochs = next;
            println!(
                "{}",
                serde_json::json!({"linux_publication_successor": next,
                "transaction_id": result.transaction_id, "owner_pid": std::process::id(),
                "owner_generation": self.owner.owner_generation(),
                "namespace": {"device": self.owner.namespace_key().device, "inode": self.owner.namespace_key().inode},
                "mount": self.owner.volume().observation().runtime_mount_id,
                "image": {"device": self.owner.backing_image_key().device, "inode": self.owner.backing_image_key().inode}})
            );
            Ok(result)
        })();
        *phase = if outcome.is_ok() {
            PublisherPhase::Ready
        } else {
            PublisherPhase::Blocked
        };
        outcome
    }

    /// The synchronous gateway is one actor; polling never scans an armed,
    /// cleaning, or failed epoch, and it never opens another Journal issuer.
    pub fn publication_ready_for_scan(&self) -> bool {
        self.publisher_actor
            .try_lock()
            .is_ok_and(|actor| matches!(actor.phase, PublisherPhase::Ready))
    }

    pub fn require_publication_ready(&self) -> sync_extend_reconcile::Result<()> {
        if !self.publication_ready_for_scan() {
            return Err(sync_extend_reconcile::ReconcileError::Invariant(
                "Linux publication actor busy or blocked",
            ));
        }
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        let Self {
            owner,
            budget,
            terminal,
            terminal_receipt_output,
            helpers,
            prepared,
            publisher_actor,
            ..
        } = self;
        let actor = publisher_actor
            .into_inner()
            .map_err(|_| "Linux publisher actor poisoned")?;
        let completed_epochs = actor.completed_epochs;
        let last_terminal_diagnostic = actor.last_terminal_diagnostic;
        drop(actor.publisher);
        drop(actor.initial_epoch);
        let persistent_generation = budget.persistent_owner_generation();
        let mut terminal = terminal
            .into_inner()
            .map_err(|_| "Linux terminal token lock poisoned")?;
        let helpers = helpers
            .into_inner()
            .map_err(|_| "Linux helper session lock poisoned")?;
        let prepared = prepared
            .into_inner()
            .map_err(|_| "Linux prepared helper evidence lock poisoned")?;
        if let Some(helpers) = helpers {
            if terminal.is_some() {
                return Err("both live helper session and terminal token were retained".into());
            }
            if helpers.arm_attempted() {
                let metadata = budget.checkpoint_closed();
                let ids = helpers.process_ids();
                let refused = helpers.observe_refused_terminal_bytes()?;
                if let Some(path) = terminal_receipt_output {
                    let value = serde_json::json!({
                        "format_version": 1,
                        "native_operation_terminal": "REFUSED",
                        "owner_generation": owner.owner_generation(),
                        "process_ids": ids,
                        "before_runtime_prepared_process_ids": prepared.process_ids,
                        "before_runtime_prepared_startup_bytes": prepared.startup_bytes,
                        "before_runtime_prepared_process_births": prepared.process_births,
                        "terminal_stdout": [&refused.0, &refused.2],
                        "terminal_stderr": [&refused.1, &refused.3],
                        "original_two_helper_exits_confirmed": true,
                        "committed_release_token": false,
                        "owned_mount_released": false,
                        "owned_loop_released": false,
                        "metadata_checkpoint_error": metadata.as_ref().err().map(ToString::to_string),
                        "persistent_image_and_metadata_retained": true,
                    });
                    let mut output = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                    output.write_all(&serde_json::to_vec_pretty(&value)?)?;
                    output.write_all(b"\n")?;
                    output.sync_all()?;
                }
                return Err("original ARM attempt refused; actual helper terminals retained without committed release".into());
            }
            terminal = Some(helpers.finish_unarmed()?);
        }
        // A partial unarmed publication preparation is cancelled while its
        // original pidfds are live, before a potentially slow checkpoint.
        let metadata = budget.checkpoint_closed()?;
        let helper_terminal = terminal
            .as_ref()
            .map(terminal_diagnostic)
            .or(last_terminal_diagnostic);
        let files: Vec<_> = metadata
            .files
            .iter()
            .map(|file| {
                serde_json::json!({
                    "class": file.class,
                    "device": file.identity.device,
                    "inode": file.identity.inode,
                    "logical_bytes": file.logical_bytes,
                    "actual_file_bytes": file.actual_file_bytes,
                    "allocated_bytes": file.allocated_bytes,
                    "capacity_bytes": file.capacity_bytes,
                })
            })
            .collect();
        let owner_pid = std::process::id();
        let mount_id = owner.volume().observation().runtime_mount_id;
        let generation = owner.owner_generation();
        let namespace = owner.namespace_key();
        let image = owner.backing_image_key();
        drop(budget);
        let owner =
            Arc::try_unwrap(owner).map_err(|_| "original Linux namespace remains borrowed")?;
        if let Some(terminal) = terminal {
            owner.release_mount_after_helpers(terminal)?;
        } else {
            owner.release_unarmed_mount()?;
        }
        if let Some(path) = terminal_receipt_output {
            let value = serde_json::json!({
                "format_version": 1, "owner_generation": generation,
                "owner_pid": owner_pid, "runtime_mount_id": mount_id,
                "completed_publication_epochs": completed_epochs,
                "persistent_metadata_generation": persistent_generation,
                "namespace": {"device": namespace.device, "inode": namespace.inode},
                "backing_image": {"device": image.device, "inode": image.inode},
                "metadata_files": files,
                "total_allocated_bytes": metadata.total_allocated_bytes,
                "total_physical_budget": metadata.total_physical_budget,
                "metadata_connections_closed": true,
                "owned_mount_released": true,
                "owned_loop_released": true,
                "helper_terminal": helper_terminal,
                "prepared_helper_births_recorded": !prepared.process_births.is_empty(),
                "before_runtime_prepared_process_ids": prepared.process_ids,
                "before_runtime_prepared_startup_bytes": prepared.startup_bytes,
                "before_runtime_prepared_process_births": prepared.process_births,
                "prepared_is_not_armed_READY": true,
                "original_guardian_ARM_budget_seconds": 2,
            });
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            output.write_all(&serde_json::to_vec_pretty(&value)?)?;
            output.write_all(b"\n")?;
            output.sync_all()?;
        }
        Ok(())
    }
}

// Diagnostics are retained for the stop receipt only, never read as authority.
fn terminal_diagnostic(value: &OriginalPairTerminalRelease) -> serde_json::Value {
    let startup = value.startup_bytes();
    let finished = value.terminal_bytes();
    serde_json::json!({
        "process_ids": value.process_ids(), "startup_bytes": [startup.0, startup.1],
        "terminal_stdout": [finished.0.0, finished.1.0], "terminal_stderr": [finished.0.1, finished.1.1],
        "original_two_helper_terminal_token": true, "committed_thaw_observed": value.committed_thaw_observed(),
        "consumed_by_successor": false,
    })
}
