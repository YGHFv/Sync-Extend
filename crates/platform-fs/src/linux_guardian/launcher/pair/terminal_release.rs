//! Terminal release is issued from both exact successful helper observations.
use super::OutsidePreparationPair;
use crate::{LinuxNamespaceCapability, UnixFileKey};
use std::{
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::Duration,
};

pub struct OriginalPairTerminalRelease {
    owner_pid: u32,
    mount: UnixFileKey,
    mount_id: u64,
    namespace: UnixFileKey,
    process_ids: (u32, u32),
    startup: (Vec<u8>, Vec<u8>),
    terminal: ((Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>)),
    completion: Completion,
    original_attempt: Option<(String, u64)>,
}

enum Completion {
    PreparedCancelled,
    CommittedThawed,
}

impl OriginalPairTerminalRelease {
    pub(crate) fn verify_owner(&self, owner: &LinuxNamespaceCapability) -> io::Result<()> {
        owner.verify()?;
        let observed = owner.volume().observation();
        if self.owner_pid != std::process::id()
            || self.mount != observed.root_key
            || self.mount_id != observed.runtime_mount_id
            || self.namespace != owner.namespace_key()
        {
            return Err(super::super::super::refusal(
                "helper terminal release belongs to another owner",
            ));
        }
        Ok(())
    }
    pub fn process_ids(&self) -> (u32, u32) {
        self.process_ids
    }
    pub fn startup_bytes(&self) -> (&[u8], &[u8]) {
        (&self.startup.0, &self.startup.1)
    }
    pub fn terminal_bytes(&self) -> ((&[u8], &[u8]), (&[u8], &[u8])) {
        (
            (&self.terminal.0 .0, &self.terminal.0 .1),
            (&self.terminal.1 .0, &self.terminal.1 .1),
        )
    }
    pub fn committed_thaw_observed(&self) -> bool {
        matches!(self.completion, Completion::CommittedThawed)
    }
    pub(crate) fn verify_attempt_state(&self, admitted: Option<&(String, u64)>) -> io::Result<()> {
        if admitted != self.original_attempt.as_ref()
            || admitted.is_some() != matches!(self.completion, Completion::CommittedThawed)
        {
            return Err(super::super::super::refusal(
                "helper terminal and original attempt state differ",
            ));
        }
        Ok(())
    }
    pub fn verify_committed_owner(
        &self,
        owner: &LinuxNamespaceCapability,
        transaction: &str,
    ) -> io::Result<()> {
        self.verify_owner(owner)?;
        owner.verify_original_terminal(self)?;
        if !self.committed_thaw_observed()
            || self.original_attempt.as_ref().map(|value| value.0.as_str()) != Some(transaction)
        {
            return Err(super::super::super::refusal(
                "terminal original transaction differs",
            ));
        }
        Ok(())
    }
}

pub struct OutsideHelperSession {
    pair: OutsidePreparationPair,
    guardian_control: File,
    supervisor_control: File,
    namespace: UnixFileKey,
}

fn pipe() -> io::Result<(File, File)> {
    let mut descriptors = [-1; 2];
    // SAFETY: sized pair of writable descriptor outputs with explicit CLOEXEC.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 transferred one owner for each distinct descriptor.
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    })
}

fn original_writer(writer: &File, reader: &File) -> io::Result<()> {
    let write_key = writer.metadata()?;
    let read_key = reader.metadata()?;
    // SAFETY: pointer-free query against this original pipe endpoint.
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_WRONLY
        || write_key.dev() != read_key.dev()
        || write_key.ino() != read_key.ino()
        || write_key.mode() & libc::S_IFMT != libc::S_IFIFO
    {
        return Err(super::super::super::refusal(
            "original helper control writer differs",
        ));
    }
    Ok(())
}

fn committed_thaw(bytes: &[u8]) -> io::Result<()> {
    let line = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let prefix = b"{\"event\":\"THAWED\",\"reason\":\"committed\",\"owner_exit_before_thaw\":false,\"guardian_exit_before_thaw\":false,\"exit_verified_ns\":null,\"guardian_exit_verified_ns\":null,\"thaw_finished_ns\":";
    let suffix = b",\"actual_Rust_guardian\":true}";
    let timestamp = line
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .ok_or_else(|| super::super::super::refusal("original committed thaw row differs"))?;
    if timestamp.is_empty()
        || !timestamp.iter().all(u8::is_ascii_digit)
        || std::str::from_utf8(timestamp)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_none_or(|value| value == 0)
    {
        return Err(super::super::super::refusal(
            "original committed thaw timestamp differs",
        ));
    }
    Ok(())
}

impl OutsideHelperSession {
    pub fn prepare(
        owner: &LinuxNamespaceCapability,
        program: &super::super::OutsideHelperProgram,
    ) -> io::Result<Self> {
        owner.verify()?;
        let pid = std::process::id();
        // SAFETY: pointer-free pidfd_open against this exact original live owner.
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful pidfd_open transferred one original descriptor.
        let process = unsafe { File::from_raw_fd(descriptor) };
        let (guardian_read, guardian_control) = pipe()?;
        let (supervisor_read, supervisor_control) = pipe()?;
        owner.claim_helper_preparation()?;
        let mut pair = program.start_preparation_pair(
            owner.mount_descriptor(),
            &process,
            &guardian_read,
            pid,
        )?;
        if let Err(error) = pair.prepare_supervisor(
            program,
            owner.mount_descriptor(),
            &process,
            &supervisor_read,
            pid,
        ) {
            let observation = pair.cancel_unarmed();
            let bytes = pair.retained_terminal_bytes();
            return Err(io::Error::other(format!("original partial preparation refused: {error}; cancellation_confirmation={observation:?}; exact_terminal_streams={bytes:?}")));
        }
        if let Err(error) = owner.verify().and_then(|_| pair.verify_original_pair()) {
            let observation = pair.cancel_unarmed();
            let bytes = pair.retained_terminal_bytes();
            return Err(io::Error::other(format!("original prepared scope refused: {error}; cancellation_confirmation={observation:?}; exact_terminal_streams={bytes:?}")));
        }
        Ok(Self {
            pair,
            guardian_control,
            supervisor_control,
            namespace: owner.namespace_key(),
        })
    }
    pub fn process_ids(&self) -> (u32, Option<u32>) {
        self.pair.process_ids()
    }
    pub fn pair(&self) -> &OutsidePreparationPair {
        &self.pair
    }
    /// Both actual PREPARED lines and both live original pidfds are required.
    /// ARM and its unchanged two-second guardian deadline occur only at Final.
    pub fn verify_prepared_owner(&self, owner: &LinuxNamespaceCapability) -> io::Result<()> {
        owner.verify()?;
        self.pair.verify_original_pair()?;
        self.pair.guardian.prepared_process()?;
        self.pair
            .supervisor
            .as_ref()
            .ok_or_else(|| super::super::super::refusal("both original prepared helpers required"))?
            .prepared_process()?;
        let mount = owner.mount_descriptor().metadata()?;
        let boundary = &self.pair.guardian.boundary;
        if self.pair.single_use_attempted
            || self.namespace != owner.namespace_key()
            || boundary.owner_pid != std::process::id()
            || mount.dev() != boundary.mount_device
            || mount.ino() != boundary.mount_inode
            || super::super::retained_mount_id(owner.mount_descriptor())? != boundary.mount_id
        {
            return Err(super::super::super::refusal(
                "prepared pair belongs to another namespace owner",
            ));
        }
        Ok(())
    }
    pub fn startup_bytes(&self) -> (&[u8], Option<&[u8]>) {
        self.pair.retained_startup_bytes()
    }
    pub fn arm(&mut self, transaction: &str) -> io::Result<()> {
        if self.pair.original_transaction.is_some()
            || transaction.is_empty()
            || transaction.len() > 220
            || !transaction
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(super::super::super::refusal(
                "single exact original transaction required",
            ));
        }
        self.pair.original_transaction = Some(transaction.to_owned());
        self.pair.arm_observation()
    }
    pub fn arm_attempted(&self) -> bool {
        self.pair.single_use_attempted
    }
    /// Preserve the actual terminal streams on failure. This observation
    /// deliberately grants no committed or cancellation release capability.
    pub fn observe_refused_terminal_bytes(
        mut self,
    ) -> io::Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.pair.observe_refused_terminals()?;
        let bytes = self.pair.retained_terminal_bytes();
        let supervisor = bytes
            .1
            .ok_or_else(|| super::super::super::refusal("refused supervisor terminal absent"))?;
        Ok((
            bytes.0 .0.to_vec(),
            bytes.0 .1.to_vec(),
            supervisor.0.to_vec(),
            supervisor.1.to_vec(),
        ))
    }
    pub fn cancel_unarmed(&mut self) -> io::Result<()> {
        self.pair.cancel_unarmed()
    }
    /// Release evidence comes from both successful original cancellations,
    /// rather than a missing child or a caller-supplied completion flag.
    pub fn finish_unarmed(mut self) -> io::Result<OriginalPairTerminalRelease> {
        let result = self.finish_unarmed_inner();
        if let Err(error) = result {
            let observation = self.pair.observe_refused_terminals();
            let bytes = self.pair.retained_terminal_bytes();
            return Err(io::Error::other(format!(
                "original unarmed terminal refused: {error}; terminal_confirmation={observation:?}; exact_terminal_streams={bytes:?}"
            )));
        }
        result
    }

    fn finish_unarmed_inner(&mut self) -> io::Result<OriginalPairTerminalRelease> {
        self.pair.verify_original_pair()?;
        self.pair.guardian.prepared_process()?;
        self.pair
            .supervisor
            .as_ref()
            .ok_or_else(|| super::super::super::refusal("original supervisor is absent"))?
            .prepared_process()?;
        let boundary = &self.pair.guardian.boundary;
        let mount = UnixFileKey {
            device: boundary.mount_device,
            inode: boundary.mount_inode,
        };
        let mount_id = boundary.mount_id;
        let owner_pid = boundary.owner_pid;
        let ids = self.pair.process_ids();
        let startup = self.pair.retained_startup_bytes();
        let startup = (
            startup.0.to_vec(),
            startup
                .1
                .ok_or_else(|| super::super::super::refusal("supervisor startup is absent"))?
                .to_vec(),
        );
        self.pair.cancel_unarmed()?;
        let terminal = self.pair.retained_terminal_bytes();
        let supervisor = terminal
            .1
            .ok_or_else(|| super::super::super::refusal("supervisor cancellation bytes absent"))?;
        let cancelled = b"{\"event\":\"PREPARATION_CANCELLED\",\"actual_Rust_guardian\":true}\n";
        if terminal.0 .0 != cancelled
            || supervisor.0 != cancelled
            || !terminal.0 .1.is_empty()
            || !supervisor.1.is_empty()
        {
            return Err(super::super::super::refusal(
                "both exact original cancellation rows required",
            ));
        }
        Ok(OriginalPairTerminalRelease {
            owner_pid,
            mount,
            mount_id,
            namespace: self.namespace,
            process_ids: (
                ids.0,
                ids.1
                    .ok_or_else(|| super::super::super::refusal("supervisor pid absent"))?,
            ),
            startup,
            terminal: (
                (terminal.0 .0.to_vec(), terminal.0 .1.to_vec()),
                (supervisor.0.to_vec(), supervisor.1.to_vec()),
            ),
            completion: Completion::PreparedCancelled,
            original_attempt: None,
        })
    }
    /// No arbitrary completion string can produce this token: both exact
    /// pidfds, original control pipes, successful exits and thaw bytes agree.
    pub fn finish_committed(mut self) -> io::Result<OriginalPairTerminalRelease> {
        let result = self.finish_committed_inner();
        if let Err(error) = result {
            let observation = self.pair.observe_refused_terminals();
            let bytes = self.pair.retained_terminal_bytes();
            return Err(io::Error::other(format!(
                "original committed terminal refused: {error}; terminal_confirmation={observation:?}; exact_terminal_streams={bytes:?}"
            )));
        }
        result
    }

    fn finish_committed_inner(&mut self) -> io::Result<OriginalPairTerminalRelease> {
        let original_attempt = self.pair.original_attempt_scope()?;
        let boundary = &self.pair.guardian.boundary;
        self.pair.verify_original_mount(&boundary.mount)?;
        original_writer(&self.guardian_control, &boundary.control)?;
        let supervisor = self
            .pair
            .supervisor
            .as_ref()
            .ok_or_else(|| super::super::super::refusal("original supervisor is absent"))?;
        original_writer(&self.supervisor_control, &supervisor.boundary.control)?;
        let mount = UnixFileKey {
            device: boundary.mount_device,
            inode: boundary.mount_inode,
        };
        let mount_id = boundary.mount_id;
        let owner_pid = boundary.owner_pid;
        let ids = self.pair.process_ids();
        let startup = self.pair.retained_startup_bytes();
        let startup = (
            startup.0.to_vec(),
            startup
                .1
                .ok_or_else(|| super::super::super::refusal("supervisor startup is absent"))?
                .to_vec(),
        );
        self.guardian_control.write_all(b"COMMITTED")?;
        let guardian = self
            .pair
            .observe_guardian_terminal(Duration::from_secs(6))?;
        if !guardian.success
            || !guardian.original_process_exit_confirmed
            || !guardian.armed_ready_observed
            || !guardian.arm_attempted
            || !guardian.stderr.is_empty()
        {
            return Err(super::super::super::refusal(
                "original guardian terminal refused",
            ));
        }
        committed_thaw(&guardian.stdout)?;
        self.supervisor_control.write_all(b"THAWED")?;
        let supervisor = self
            .pair
            .observe_supervisor_terminal(Duration::from_secs(6))?
            .ok_or_else(|| {
                super::super::super::refusal("original supervisor terminal is absent")
            })?;
        if !supervisor.success
            || !supervisor.original_process_exit_confirmed
            || !supervisor.armed_ready_observed
            || !supervisor.arm_attempted
            || !supervisor.stderr.is_empty()
            || supervisor.stdout != b"{\"event\":\"GUARDIAN_FINISHED\"}\n"
        {
            return Err(super::super::super::refusal(
                "original supervisor terminal refused",
            ));
        }
        Ok(OriginalPairTerminalRelease {
            owner_pid,
            mount,
            mount_id,
            namespace: self.namespace,
            process_ids: (
                ids.0,
                ids.1
                    .ok_or_else(|| super::super::super::refusal("supervisor pid is absent"))?,
            ),
            startup,
            terminal: (
                (guardian.stdout, guardian.stderr),
                (supervisor.stdout, supervisor.stderr),
            ),
            completion: Completion::CommittedThawed,
            original_attempt: Some(original_attempt),
        })
    }
}

impl OutsidePreparationPair {
    pub(crate) fn original_attempt_scope(&self) -> io::Result<(String, u64)> {
        Ok((
            self.original_transaction
                .clone()
                .ok_or_else(|| super::super::super::refusal("original transaction scope absent"))?,
            self.guardian_arm_monotonic_ns
                .ok_or_else(|| super::super::super::refusal("original ARM timestamp absent"))?,
        ))
    }
}
