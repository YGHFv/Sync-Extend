//! Explicit bounded sidecar owner; no implicit network or version upgrades.
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sync_extend_core_model::{
    ContentId,
    easytier::{EasyTierConfig, compatible_version, peer_observations},
};
use sync_extend_platform_fs::{ManagedChild, ManagedRpcOwner, SidecarConfig};

mod observation;
pub(crate) use observation::{clear as clear_observations, latest as latest_observation};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn load(path: &Path) -> Result<EasyTierConfig> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > 65536 {
        return Err("EasyTier configuration limit".into());
    }
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err("EasyTier configuration limit".into());
    }
    let config: EasyTierConfig = serde_json::from_slice(&bytes)?;
    config.validate()?;
    Ok(config)
}

struct Binary {
    program: sync_extend_platform_fs::PinnedProgram,
}

impl Binary {
    fn open(path: &Path, expected: &ContentId) -> Result<Self> {
        let program = sync_extend_platform_fs::PinnedProgram::open(path, 256 * 1024 * 1024)?;
        let file = program.reader();
        if !file.metadata()?.is_file() || file.metadata()?.len() > 256 * 1024 * 1024 {
            return Err("EasyTier binary file limit".into());
        }
        let mut hasher = blake3::Hasher::new();
        let mut reader = file;
        let mut buffer = [0; 65536];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        if hasher.finalize().to_hex().as_str() != expected.as_str() {
            return Err("EasyTier pinned binary hash differs".into());
        }
        Ok(Self { program })
    }

    fn command(&self) -> Command {
        let mut command = self.program.command();
        // EasyTier CLI also consumes environment values independently of TOML parsing.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("ET_") {
                command.env_remove(key);
            }
        }
        command
    }
}

fn capture(command: &mut Command, timeout: Duration) -> Result<Vec<u8>> {
    capture_cancel(command, timeout, None)
}

fn capture_cancel(
    command: &mut Command,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<u8>> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = ManagedChild::spawn(command)?;
    let mut stdout = child.child().stdout.take().ok_or("managed stdout absent")?;
    let mut bytes = Vec::new();
    let mut buffer = [0; 65536];
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        if cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire)) {
            break Err("EasyTier command cancelled");
        }
        while let Some(count) = sync_extend_platform_fs::read_available(&mut stdout, &mut buffer)? {
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > 1024 * 1024 {
                return Err("EasyTier command output limit".into());
            }
            bytes.extend_from_slice(&buffer[..count]);
            if Instant::now() >= deadline
                || cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire))
            {
                return Err("EasyTier command timeout".into());
            }
        }
        if let Some(status) = child.child().try_wait()? {
            while let Some(count) =
                sync_extend_platform_fs::read_available(&mut stdout, &mut buffer)?
            {
                if count == 0 {
                    break;
                }
                if bytes.len().saturating_add(count) > 1024 * 1024 {
                    return Err("EasyTier command output limit".into());
                }
                bytes.extend_from_slice(&buffer[..count]);
                if Instant::now() >= deadline {
                    return Err("EasyTier command timeout".into());
                }
            }
            break if status.success() {
                Ok(())
            } else {
                Err("EasyTier command failed")
            };
        }
        if Instant::now() >= deadline {
            break Err("EasyTier command timeout");
        }
        thread::sleep(Duration::from_millis(20));
    };
    drop(child);
    outcome?;
    if bytes.len() > 1024 * 1024 {
        return Err("EasyTier command output limit".into());
    }
    Ok(bytes)
}

fn check_version(binary: &Binary, program: &str, timeout: Duration) -> Result<()> {
    check_version_cancel(binary, program, timeout, None)
}

fn check_version_cancel(
    binary: &Binary,
    program: &str,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
) -> Result<()> {
    let output = capture_cancel(binary.command().arg("--version"), timeout, cancel)?;
    if !compatible_version(std::str::from_utf8(&output)?, program) {
        return Err("EasyTier pinned version differs or has dirty build suffix".into());
    }
    Ok(())
}

pub fn check(config: &EasyTierConfig) -> Result<()> {
    config.validate()?;
    let timeout = Duration::from_secs(config.command_timeout_secs);
    let core = Binary::open(&config.core_binary, &config.core_blake3)?;
    let cli = Binary::open(&config.cli_binary, &config.cli_blake3)?;
    check_version(&core, "easytier-core", timeout)?;
    check_version(&cli, "easytier-cli", timeout)?;
    println!(
        "{}",
        serde_json::json!({
            "pinned_version":"2.6.4","binary_hashes_verified":true,
            "network_started":false,"runtime_compatibility_verified":false,
        })
    );
    Ok(())
}

pub fn observe(config: &EasyTierConfig) -> Result<()> {
    config.validate()?;
    let cli = Binary::open(&config.cli_binary, &config.cli_blake3)?;
    let timeout = Duration::from_secs(config.command_timeout_secs);
    check_version(&cli, "easytier-cli", timeout)?;
    let output = capture(
        cli.command()
            .arg("--rpc-portal")
            .arg(config.rpc_portal.to_string())
            .arg("--instance-name")
            .arg(format!("SyncExtend-{}", config.instance_id))
            .args(["--output", "json", "peer", "list"]),
        timeout,
    )?;
    let time = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let peers = peer_observations(&output, time)?;
    println!("{}", serde_json::to_string(&peers)?);
    Ok(())
}

struct Sampler {
    cancel: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    watcher: Option<thread::JoinHandle<()>>,
}

impl Sampler {
    fn start(
        config: EasyTierConfig,
        cli: Arc<Binary>,
        owner: ManagedRpcOwner,
        private: Arc<SidecarConfig>,
        config_bytes: Arc<Vec<u8>>,
        producer: observation::Producer,
    ) -> std::io::Result<Self> {
        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&cancel);
        let mut sampler = Self {
            cancel,
            thread: None,
            watcher: None,
        };
        let owner = Arc::new(owner);
        let watching = Arc::clone(&sampler.cancel);
        let process = Arc::clone(&owner);
        let observed = producer.clone();
        sampler.watcher = Some(
            thread::Builder::new()
                .name("syncd-easytier-owner".to_owned())
                .spawn(move || {
                    while !watching.load(Ordering::Acquire) {
                        if !matches!(process.wait_ended(Duration::from_millis(50)), Ok(false)) {
                            observed.invalidate();
                            super::shutdown::set_resources_ready(false);
                            watching.store(true, Ordering::Release);
                            break;
                        }
                    }
                })?,
        );
        sampler.thread = Some(
            thread::Builder::new()
                .name("syncd-easytier-observe".to_owned())
                .spawn(move || {
                    while !stopping.load(Ordering::Acquire) {
                        let result = (|| {
                            let query_started = Instant::now();
                            let timeout = Duration::from_secs(config.command_timeout_secs);
                            private
                                .verify_content(&config_bytes)
                                .map_err(|_| "configuration_pin_unavailable")?;
                            let before = owner
                                .verify_listener(config.rpc_portal)
                                .map_err(|_| "rpc_ownership_unavailable")?;
                            let remaining = timeout.saturating_sub(query_started.elapsed());
                            if remaining.is_zero() {
                                return Err("rpc_window_expired");
                            }
                            let output = capture_cancel(
                                cli.command()
                                    .arg("--rpc-portal")
                                    .arg(config.rpc_portal.to_string())
                                    .arg("--instance-name")
                                    .arg(format!("SyncExtend-{}", config.instance_id))
                                    .args(["--output", "json", "peer", "list"]),
                                remaining,
                                Some(&stopping),
                            )
                            .map_err(|_| "rpc_query_unavailable")?;
                            let after = owner
                                .verify_listener(config.rpc_portal)
                                .map_err(|_| "rpc_ownership_changed")?;
                            if before != after {
                                return Err("rpc_listener_changed");
                            }
                            private
                                .verify_content(&config_bytes)
                                .map_err(|_| "configuration_pin_changed")?;
                            if query_started.elapsed() > timeout {
                                return Err("rpc_window_expired");
                            }
                            let time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .ok()
                                .and_then(|time| u64::try_from(time.as_millis()).ok())
                                .ok_or("observation_clock_unavailable")?;
                            let peers = peer_observations(&output, time)
                                .map_err(|_| "invalid_peer_output")?;
                            if query_started.elapsed() > timeout {
                                return Err("rpc_window_expired");
                            }
                            Ok(peers)
                        })();
                        if !stopping.load(Ordering::Acquire) {
                            producer.record(result);
                        }
                        let next = Instant::now() + Duration::from_secs(2);
                        while !stopping.load(Ordering::Acquire) && Instant::now() < next {
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                })?,
        );
        Ok(sampler)
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

/// Configuration lifetime is bound to its original CREATE handle, including owner kill.
pub fn run(config: EasyTierConfig, seconds: u64, shutdown: Arc<AtomicBool>) -> Result<()> {
    config.validate()?;
    if !config.enabled || seconds == 0 || seconds > 86400 {
        return Err("EasyTier requires explicit enable and bounded runtime".into());
    }
    let config_bytes = Arc::new(config.native_config()?.into_bytes());
    let config_pin = blake3::hash(&config_bytes)
        .to_hex()
        .as_str()
        .parse::<ContentId>()?;
    let private = Arc::new(SidecarConfig::create(
        &config.state_dir,
        config.instance_id.as_str(),
        &config_bytes,
    )?);
    {
        let core = Binary::open(&config.core_binary, &config.core_blake3)?;
        let cli = Arc::new(Binary::open(&config.cli_binary, &config.cli_blake3)?);
        let timeout = Duration::from_secs(config.command_timeout_secs);
        for (binary, program) in [(&core, "easytier-core"), (&*cli, "easytier-cli")] {
            let checked = check_version_cancel(binary, program, timeout, Some(&shutdown));
            if shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            checked?;
        }
        let arguments = [
            "--disable-env-parsing".to_owned(),
            "--config-file".to_owned(),
            private.path()?.to_string_lossy().into_owned(),
            "--rpc-portal".to_owned(),
            config.rpc_portal.to_string(),
            "--rpc-portal-whitelist".to_owned(),
            if config.rpc_portal.is_ipv4() {
                "127.0.0.1/32"
            } else {
                "::1/128"
            }
            .to_owned(),
        ];
        let checked = capture_cancel(
            core.command().args(&arguments).arg("--check-config"),
            timeout,
            Some(&shutdown),
        );
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        checked?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut restart = 0;
        loop {
            if shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            private.verify_content(&config_bytes)?;
            let mut command = core.command();
            command
                .args(&arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = ManagedChild::spawn(&mut command)?;
            let generation = sync_extend_core_model::EntryId::random()?;
            let rpc_owner = child.rpc_owner(&core.program);
            let process_start = rpc_owner
                .as_ref()
                .map(|owner| owner.process_start())
                .unwrap_or_else(|_| "0000000000000000".to_owned());
            let observation = observation::Owner::new(
                &config,
                generation.clone(),
                child.child().id(),
                process_start,
                config_pin.clone(),
            );
            let sampler = match (rpc_owner, observation.as_ref()) {
                (Ok(owner), Some(observation)) => {
                    // Readiness describes retained process resources. A route
                    // or peer is available only after the separately bound RPC query.
                    super::shutdown::started(true)?;
                    match Sampler::start(
                        config.clone(),
                        Arc::clone(&cli),
                        owner,
                        Arc::clone(&private),
                        Arc::clone(&config_bytes),
                        observation.producer(),
                    ) {
                        Ok(sampler) => Some(sampler),
                        Err(_) => {
                            observation.producer().record(Err("sampler_unavailable"));
                            None
                        }
                    }
                }
                (_, Some(observation)) => {
                    observation
                        .producer()
                        .record(Err("process_owner_unavailable"));
                    super::shutdown::started(false)?;
                    None
                }
                _ => {
                    super::shutdown::started(false)?;
                    None
                }
            };
            println!(
                "{}",
                serde_json::json!({
                    "sidecar_pid":child.child().id(),"instance_id":config.instance_id,
                    "state":"started","restart":restart,"child_generation":generation,
                    "path_observed":false,
                    "sync_device_authenticated":false,
                })
            );
            let exit = loop {
                if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                    super::shutdown::set_resources_ready(false);
                    drop(observation);
                    drop(sampler);
                    return Ok(());
                }
                if let Some(status) = child.child().try_wait()? {
                    super::shutdown::set_resources_ready(false);
                    drop(observation);
                    drop(sampler);
                    break status;
                }
                thread::sleep(Duration::from_millis(50));
            };
            drop(child);
            if exit.success() || restart >= config.max_restarts {
                return Err("EasyTier sidecar stopped before requested runtime".into());
            }
            restart += 1;
            let delay = Duration::from_secs(
                config
                    .restart_delay_secs
                    .saturating_mul(1u64 << restart.min(8)),
            );
            let retry_at = Instant::now() + delay.min(Duration::from_secs(3600));
            while Instant::now() < retry_at {
                if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}
