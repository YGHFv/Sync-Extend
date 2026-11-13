//! Explicit bounded sidecar owner; no implicit network or version upgrades.
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sync_extend_core_model::{
    easytier::{compatible_version, peer_observations, EasyTierConfig},
    ContentId,
};
use sync_extend_platform_fs::ManagedChild;

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
        while let Some(count) = sync_extend_platform_fs::read_available(&mut stdout, &mut buffer)? {
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
    let output = capture(binary.command().arg("--version"), timeout)?;
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

/// Configuration lifetime is bound to its original CREATE handle, including owner kill.
pub fn run(config: EasyTierConfig, seconds: u64, shutdown: Arc<AtomicBool>) -> Result<()> {
    config.validate()?;
    if !config.enabled || seconds == 0 || seconds > 86400 {
        return Err("EasyTier requires explicit enable and bounded runtime".into());
    }
    let private = sync_extend_platform_fs::SidecarConfig::create(
        &config.state_dir,
        config.instance_id.as_str(),
        config.native_config()?.as_bytes(),
    )?;
    {
        let core = Binary::open(&config.core_binary, &config.core_blake3)?;
        let cli = Binary::open(&config.cli_binary, &config.cli_blake3)?;
        let timeout = Duration::from_secs(config.command_timeout_secs);
        check_version(&core, "easytier-core", timeout)?;
        check_version(&cli, "easytier-cli", timeout)?;
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
        capture(
            core.command().args(&arguments).arg("--check-config"),
            timeout,
        )?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut restart = 0;
        loop {
            private.path()?;
            let mut command = core.command();
            command
                .args(&arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let mut child = ManagedChild::spawn(&mut command)?;
            println!(
                "{}",
                serde_json::json!({
                    "sidecar_pid":child.child().id(),"instance_id":config.instance_id,
                    "state":"started","restart":restart,"path_observed":false,
                    "sync_device_authenticated":false,
                })
            );
            let exit = loop {
                if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return Ok(());
                }
                if let Some(status) = child.child().try_wait()? {
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
