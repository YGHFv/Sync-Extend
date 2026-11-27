//! Borrow the same verified installation through the common sidecar engine.
use super::*;
use sync_extend_reconcile::InstalledEasyTierRuntime;

pub(crate) struct ActiveRecoveredEasyTier<'installation> {
    authority: InstalledEasyTierRuntime<'installation>,
    cancel: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<std::result::Result<(), String>>>,
    terminal: Terminal,
}

pub(crate) struct RecoveredEasyTierFailure {
    pub(crate) error: &'static str,
    terminal: Terminal,
}

impl RecoveredEasyTierFailure {
    pub(crate) fn has_retained_originals(&self) -> bool {
        self.terminal.has_retained_originals()
    }
    pub(crate) fn close_remaining(self) -> Self {
        self.terminal.close_remaining();
        self
    }
    pub(crate) fn retain_until_process_exit(self) {
        self.terminal.retain_until_process_exit();
    }
}

impl<'installation> ActiveRecoveredEasyTier<'installation> {
    pub(crate) fn start(
        authority: InstalledEasyTierRuntime<'installation>,
    ) -> std::result::Result<Self, RecoveredEasyTierFailure> {
        let terminal = Terminal::default();
        let failure = |error| RecoveredEasyTierFailure {
            error,
            terminal: terminal.clone(),
        };
        authority
            .verify()
            .map_err(|_| failure("installed_easytier_authority_invalid"))?;
        observation::begin_recovered_generation()
            .map_err(|_| failure("installed_easytier_previous_generation_active"))?;
        let config = authority.configuration().clone();
        let config_bytes = Arc::new(
            config
                .native_config()
                .map_err(|_| failure("installed_easytier_configuration_invalid"))?
                .into_bytes(),
        );
        let record_open =
            |mut original: sync_extend_platform_fs::WindowsOriginalResourceOpenFailure| {
                if let Some(handles) = original.original_resources.take() {
                    let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
                    close.append_failure(handles);
                    terminal.handles(close);
                }
                failure("installed_easytier_resource_acquisition_failed")
            };
        let core = Binary::from_program(
            authority.duplicate_core().map_err(record_open)?,
            &config.core_blake3,
            terminal.clone(),
        )
        .map_err(|_| failure("installed_easytier_core_pin_invalid"))?;
        let cli = Arc::new(
            Binary::from_program(
                authority.duplicate_cli().map_err(record_open)?,
                &config.cli_blake3,
                terminal.clone(),
            )
            .map_err(|_| failure("installed_easytier_cli_pin_invalid"))?,
        );
        let private = Arc::new(PrivateConfig {
            original: Some(
                authority
                    .create_private_configuration()
                    .map_err(record_open)?,
            ),
            terminal: terminal.clone(),
        });
        authority
            .verify()
            .map_err(|_| failure("installed_easytier_authority_changed"))?;
        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&cancel);
        let ready = Arc::new(AtomicBool::new(false));
        let reported = Arc::clone(&ready);
        let start_limit = Duration::from_secs(
            config
                .command_timeout_secs
                .saturating_mul(3)
                .saturating_add(5),
        );
        let seconds = authority.seconds();
        let worker = thread::Builder::new()
            .name("syncd-recovered-easytier".into())
            .spawn(move || {
                run_resources(
                    config,
                    seconds,
                    stopping,
                    config_bytes,
                    private,
                    core,
                    cli,
                    Some(reported),
                )
                .map_err(|error| error.to_string())
            })
            .map_err(|_| failure("installed_easytier_worker_failed"))?;
        let active = Self {
            authority,
            cancel,
            worker: Some(worker),
            terminal,
        };
        let deadline = Instant::now() + start_limit;
        while !ready.load(Ordering::Acquire) {
            if active
                .worker
                .as_ref()
                .is_none_or(thread::JoinHandle::is_finished)
                || Instant::now() >= deadline
                || !active.terminal.succeeded()
            {
                let terminal = active.terminal.clone();
                let _ = active.close();
                return Err(RecoveredEasyTierFailure {
                    error: "installed_easytier_start_not_ready",
                    terminal,
                });
            }
            thread::sleep(Duration::from_millis(20));
        }
        if active.authority.verify().is_err() {
            let terminal = active.terminal.clone();
            let _ = active.close();
            return Err(RecoveredEasyTierFailure {
                error: "installed_easytier_start_authority_changed",
                terminal,
            });
        }
        Ok(active)
    }

    pub(crate) fn status(&self) -> Result<serde_json::Value> {
        self.authority.verify()?;
        if self
            .worker
            .as_ref()
            .is_none_or(thread::JoinHandle::is_finished)
            || !self.terminal.succeeded()
        {
            return Err("original EasyTier runtime ended or terminal failed".into());
        }
        Ok(serde_json::json!({
            "same_original_installation_verified": true,
            "node_free_runtime": true,
            "observation": latest_observation(),
        }))
    }

    pub(crate) fn poll(&self) -> Result<()> {
        // The installed program and parent loans prohibit replacement while
        // running. Poll only the actual worker; explicit status/stop perform
        // the expensive complete original graph audit.
        if self.worker.as_ref().is_none_or(thread::JoinHandle::is_finished)
            || !self.terminal.succeeded()
        {
            return Err("original EasyTier runtime ended or terminal failed".into());
        }
        Ok(())
    }

    pub(crate) fn close(mut self) -> std::result::Result<(), RecoveredEasyTierFailure> {
        self.cancel.store(true, Ordering::Release);
        let completed = self
            .worker
            .take()
            .is_some_and(|worker| matches!(worker.join(), Ok(Ok(()))));
        clear_observations();
        if !completed || !self.terminal.succeeded() || self.authority.verify().is_err() {
            return Err(RecoveredEasyTierFailure {
                error: "installed_easytier_terminal_failed",
                terminal: self.terminal.clone(),
            });
        }
        Ok(())
    }
}

impl Drop for ActiveRecoveredEasyTier<'_> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                self.terminal
                    .error("original recovered EasyTier worker panicked");
            }
        }
    }
}
