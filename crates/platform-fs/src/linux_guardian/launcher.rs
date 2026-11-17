//! Launch an explicitly retained guardian image through exact inherited descriptors.
//! Callers must authenticate the program bytes and complete READY before freeze.
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{fs::MetadataExt, process::CommandExt},
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const FIRST_PRIVATE_DESCRIPTOR: RawFd = 64;

/// Owns a sealed executable descriptor independently of the mutable source path.
pub struct OutsideHelperProgram {
    image: File,
}

fn private_duplicate(file: &File) -> io::Result<File> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates this live owned descriptor at or above
    // a fixed positive minimum; the returned descriptor has one new close owner.
    let fd = unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_DUPFD_CLOEXEC,
            FIRST_PRIVATE_DESCRIPTOR,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful duplication transfers one newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl OutsideHelperProgram {
    /// The caller supplies the artifact bytes from its accepted source manifest.
    /// Exact bytes, seals and bounds are checked before retaining this image.
    pub fn from_accepted_image(
        program: &crate::PinnedProgram,
        accepted_image: &[u8],
    ) -> io::Result<Self> {
        let expected_bytes = accepted_image.len() as u64;
        let reader = program.reader();
        let metadata = reader.metadata()?;
        if expected_bytes == 0
            || expected_bytes > 64 * 1024 * 1024
            || metadata.len() != expected_bytes
            || !metadata.is_file()
        {
            return Err(super::refusal(
                "exact bounded accepted helper image required",
            ));
        }
        // SAFETY: F_GET_SEALS only inspects a live descriptor.
        let seals = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GET_SEALS) };
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if seals < 0 || seals & required != required {
            return Err(super::refusal("immutable sealed helper image required"));
        }
        let mut image = private_duplicate(reader)?;
        image.seek(SeekFrom::Start(0))?;
        let mut offset = 0usize;
        let mut buffer = [0u8; 16_384];
        while offset < accepted_image.len() {
            let count = image.read(&mut buffer)?;
            if count == 0
                || offset
                    .checked_add(count)
                    .is_none_or(|end| end > accepted_image.len())
                || accepted_image[offset..offset + count] != buffer[..count]
            {
                return Err(super::refusal(
                    "sealed helper bytes differ from exact accepted image",
                ));
            }
            offset += count;
        }
        if image.read(&mut buffer[..1])? != 0 {
            return Err(super::refusal("sealed helper image has trailing bytes"));
        }
        image.seek(SeekFrom::Start(0))?;
        Ok(Self { image })
    }

    pub fn guardian(
        &self,
        mount: &File,
        owner: &File,
        control: &File,
        owner_pid: u32,
        seconds: u32,
    ) -> io::Result<OutsideHelperChild> {
        super::mount_boundary(mount)?;
        super::pidfd_identity(owner, owner_pid)?;
        super::control_boundary(control)?;
        super::bounded_deadline(seconds)?;
        self.launch("guardian", &[mount, owner, control], &[owner_pid, seconds])
    }

    pub fn supervisor(
        &self,
        mount: &File,
        owner: &File,
        guardian: &File,
        control: &File,
        lineage: (u32, u32),
        seconds: u32,
    ) -> io::Result<OutsideHelperChild> {
        let (owner_pid, guardian_pid) = lineage;
        if owner_pid == guardian_pid {
            return Err(super::refusal("distinct live owner and guardian required"));
        }
        super::mount_boundary(mount)?;
        super::pidfd_identity(owner, owner_pid)?;
        super::pidfd_identity(guardian, guardian_pid)?;
        super::control_boundary(control)?;
        super::bounded_deadline(seconds)?;
        self.launch(
            "supervisor",
            &[mount, owner, guardian, control],
            &[owner_pid, guardian_pid, seconds],
        )
    }

    fn launch(
        &self,
        mode: &str,
        descriptors: &[&File],
        values: &[u32],
    ) -> io::Result<OutsideHelperChild> {
        if !(3..=5).contains(&descriptors.len()) {
            return Err(super::refusal("bounded exact inherited helper descriptors"));
        }
        for (index, source) in descriptors.iter().enumerate() {
            if source.as_raw_fd() < 3 {
                return Err(super::refusal("standard streams cannot be helper inputs"));
            }
            let metadata = source.metadata()?;
            if metadata.mode() & libc::S_IFMT == libc::S_IFIFO {
                for other in descriptors.iter().skip(index + 1) {
                    let other = other.metadata()?;
                    if metadata.dev() == other.dev() && metadata.ino() == other.ino() {
                        return Err(super::refusal("aliased helper control pipes refused"));
                    }
                }
            }
            if descriptors
                .iter()
                .skip(index + 1)
                .any(|other| source.as_raw_fd() == other.as_raw_fd())
            {
                return Err(super::refusal("distinct source descriptors required"));
            }
        }
        // Each duplicated source owns a unique high descriptor. Inherit those
        // same slots directly instead of overwriting Rust's private exec pipe.
        let image = private_duplicate(&self.image)?;
        let inherited = descriptors
            .iter()
            .map(|source| private_duplicate(source))
            .collect::<io::Result<Vec<_>>>()?;
        let child_descriptors: Vec<_> = inherited.iter().map(AsRawFd::as_raw_fd).collect();
        let mut command = Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()));
        command
            .arg(mode)
            .args(child_descriptors.iter().map(RawFd::to_string))
            .args(values.iter().map(u32::to_string))
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: descriptors are uniquely owned private duplicates made before
        // fork. Only their CLOEXEC flags change, using pointer-free syscalls.
        // No destination is overwritten and no parent-death kill is installed.
        unsafe {
            command.pre_exec(move || {
                for descriptor in &child_descriptors {
                    let flags = libc::fcntl(*descriptor, libc::F_GETFD);
                    if flags < 0
                        || libc::fcntl(*descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        privileged_preparation()?;
        let boundary = HelperOriginalBoundary::capture(
            descriptors[0],
            descriptors[if mode.ends_with("supervisor") { 3 } else { 2 }],
            descriptors[1],
            if mode.ends_with("supervisor") {
                Some(descriptors[2])
            } else {
                None
            },
            values[0],
            if mode.ends_with("supervisor") {
                Some(values[1])
            } else {
                None
            },
        )?;
        let mut child = command.spawn()?;
        // Capture this freshly launched process before issuing READY observations.
        // SAFETY: pidfd_open takes a process number and zero flags, returning a
        // new owned descriptor; it does not signal or adopt a recovered process.
        let descriptor =
            unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) as libc::c_int };
        if descriptor < 0 {
            let error = io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        // SAFETY: successful pidfd_open transfers one new owned descriptor.
        let process = unsafe { File::from_raw_fd(descriptor) };
        if let Err(error) = super::pidfd_identity(&process, child.id()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let expected_ready = match mode {
            "guardian" => b"{\"event\":\"GUARD_READY\",\"actual_Rust_guardian\":true}".as_slice(),
            "supervisor" => {
                b"{\"event\":\"SUPERVISOR_READY\",\"actual_Rust_guardian\":true}".as_slice()
            }

            "prepared-guardian" => {
                b"{\"event\":\"GUARD_PREPARED\",\"actual_Rust_guardian\":true}".as_slice()
            }
            "prepared-supervisor" => {
                b"{\"event\":\"SUPERVISOR_PREPARED\",\"actual_Rust_guardian\":true}".as_slice()
            }
            _ => unreachable!("only typed guardian and supervisor launch"),
        };
        Ok(OutsideHelperChild {
            child,
            image,
            process,
            expected_ready,
            ready: false,
            preparation_mode: mode.starts_with("prepared-"),
            observation_failed: false,
            ready_observed_at: None,
            ready_bytes: Vec::new(),
            arm_written: false,
            terminal_poisoned: false,
            preparation: None,
            prepared: false,
            arm_attempted: false,
            cancellation_attempted: false,
            boundary,
            terminal_observed: false,
            terminal_stdout: Vec::new(),
            terminal_stderr: Vec::new(),
            terminal_out_eof: false,
            terminal_err_eof: false,
        })
    }
}

/// Keeps the exact program alive and exposes the real process for READY/pidfd.
/// There is deliberately no automatic kill on drop while a volume may be frozen.
#[must_use = "confirm READY and retain helper until actual thaw/exit"]
pub struct OutsideHelperChild {
    child: Child,
    image: File,
    process: File,
    expected_ready: &'static [u8],
    ready: bool,
    preparation_mode: bool,
    observation_failed: bool,
    ready_observed_at: Option<Instant>,
    ready_bytes: Vec<u8>,
    arm_written: bool,
    terminal_poisoned: bool,
    preparation: Option<File>,
    prepared: bool,
    arm_attempted: bool,
    cancellation_attempted: bool,
    boundary: HelperOriginalBoundary,
    terminal_observed: bool,
    terminal_stdout: Vec<u8>,
    terminal_stderr: Vec<u8>,
    terminal_out_eof: bool,
    terminal_err_eof: bool,
}

impl OutsideHelperChild {
    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }
    pub fn program_reader(&self) -> &File {
        &self.image
    }
}

impl OutsideHelperChild {
    /// Observe only this process's bounded exact READY line before any freeze.
    /// This observation has no mount mutation or restart authority.
    pub fn wait_ready(&mut self, timeout: Duration) -> io::Result<()> {
        if self.cancellation_attempted
            || (self.preparation_mode && (!self.arm_attempted || !self.arm_written))
        {
            return Err(super::refusal("PREPARED observation is not armed READY"));
        }
        self.read_expected_line(timeout)
    }

    fn read_expected_line(&mut self, timeout: Duration) -> io::Result<()> {
        if self.observation_failed {
            return Err(super::refusal(
                "failed startup observation cannot become READY",
            ));
        }
        let result = self.read_original_line(timeout);
        if result.is_err() {
            self.observation_failed = true;
        }
        result
    }

    fn read_original_line(&mut self, timeout: Duration) -> io::Result<()> {
        if self.ready || timeout.is_zero() || timeout > Duration::from_secs(1) {
            return Err(super::refusal("one bounded before-freeze READY required"));
        }
        let deadline = Instant::now() + timeout;
        self.ready_bytes.clear();
        let mut buffer = [0u8; 256];
        loop {
            if self.child.try_wait()?.is_some() {
                return Err(super::refusal("helper exited before complete READY"));
            }
            let output = self
                .child
                .stdout
                .as_mut()
                .ok_or_else(|| super::refusal("private helper stdout absent"))?;
            match crate::read_available(
                output,
                &mut buffer[..(257 - self.ready_bytes.len()).min(256)],
            )? {
                Some(0) => return Err(super::refusal("helper READY pipe closed")),
                Some(count) => {
                    self.ready_bytes.extend_from_slice(&buffer[..count]);
                    if self.ready_bytes.len() > 256 {
                        return Err(super::refusal(
                            "helper READY byte bound; overflow byte retained",
                        ));
                    }
                    if let Some(end) = self.ready_bytes.iter().position(|byte| *byte == b'\n') {
                        if end + 1 != self.ready_bytes.len()
                            || &self.ready_bytes[..end] != self.expected_ready
                        {
                            return Err(super::refusal("exact helper READY line required"));
                        }
                        super::pidfd_identity(&self.process, self.child.id())?;
                        self.boundary.verify()?;
                        self.ready = true;
                        self.ready_observed_at = Some(Instant::now());
                        return Ok(());
                    }
                }
                None => (),
            }
            if Instant::now() >= deadline {
                return Err(super::refusal("helper READY deadline"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub fn retained_process(&self) -> io::Result<&File> {
        if !self.ready
            || self.observation_failed
            || self.cancellation_attempted
            || self
                .ready_observed_at
                .is_none_or(|seen| seen.elapsed() > Duration::from_millis(100))
        {
            return Err(super::refusal("helper pidfd requires actual READY"));
        }
        super::pidfd_identity(&self.process, self.child.id())?;
        Ok(&self.process)
    }
}

fn preparation_pipe() -> io::Result<(File, File)> {
    let mut descriptors = [-1; 2];
    // SAFETY: sized writable pair and fixed CLOEXEC request. Successful pipe2
    // returns two independent newly owned descriptors with opposite directions.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 transfers each freshly returned descriptor once.
    let read = unsafe { File::from_raw_fd(descriptors[0]) };
    // SAFETY: this is the other independently owned descriptor from pipe2.
    let write = unsafe { File::from_raw_fd(descriptors[1]) };
    Ok((read, write))
}

impl OutsideHelperProgram {
    pub fn prepare_guardian(
        &self,
        mount: &File,
        owner: &File,
        control: &File,
        owner_pid: u32,
        seconds: u32,
    ) -> io::Result<OutsideHelperChild> {
        super::mount_boundary(mount)?;
        super::pidfd_identity(owner, owner_pid)?;
        super::control_boundary(control)?;
        super::bounded_deadline(seconds)?;
        let (read, write) = preparation_pipe()?;
        let mut child = self.launch(
            "prepared-guardian",
            &[mount, owner, control, &read],
            &[owner_pid, seconds],
        )?;
        child.preparation = Some(write);
        Ok(child)
    }

    pub fn prepare_supervisor(
        &self,
        mount: &File,
        owner: &File,
        guardian: &File,
        control: &File,
        lineage: (u32, u32),
        seconds: u32,
    ) -> io::Result<OutsideHelperChild> {
        let (owner_pid, guardian_pid) = lineage;
        if owner_pid == guardian_pid {
            return Err(super::refusal("distinct exact prepared owner and guardian"));
        }
        super::mount_boundary(mount)?;
        super::pidfd_identity(owner, owner_pid)?;
        super::pidfd_identity(guardian, guardian_pid)?;
        super::control_boundary(control)?;
        super::bounded_deadline(seconds)?;
        let (read, write) = preparation_pipe()?;
        let mut child = self.launch(
            "prepared-supervisor",
            &[mount, owner, guardian, control, &read],
            &[owner_pid, guardian_pid, seconds],
        )?;
        child.preparation = Some(write);
        Ok(child)
    }
}

impl OutsideHelperChild {
    /// Observe PREPARED using the original bounded reader, then clear READY.
    /// No watchdog is armed and no mount operation is permitted by this method.
    pub fn wait_prepared(&mut self, timeout: Duration) -> io::Result<()> {
        if !self.preparation_mode
            || self.preparation.is_none()
            || self.prepared
            || self.arm_attempted
            || self.cancellation_attempted
            || self.observation_failed
        {
            return Err(super::refusal("one live preparation observation required"));
        }
        self.read_expected_line(timeout)?;
        self.prepared = true;
        self.ready = false;
        self.ready_observed_at = None;
        Ok(())
    }

    /// Caller can identify the prepared helper to launch its supervisor.
    /// PREPARED remains an observation and carries no freeze/cleanup capability.
    pub fn prepared_process(&self) -> io::Result<&File> {
        if !self.prepared
            || self.arm_attempted
            || self.cancellation_attempted
            || self.observation_failed
            || !self.preparation_mode
        {
            return Err(super::refusal("unarmed prepared process required"));
        }
        super::pidfd_identity(&self.process, self.child.id())?;
        Ok(&self.process)
    }

    pub fn arm(&mut self, timeout: Duration) -> io::Result<()> {
        if !self.prepared
            || !self.preparation_mode
            || self.observation_failed
            || self.arm_attempted
            || self.ready
            || self.cancellation_attempted
            || timeout.is_zero()
            || timeout > Duration::from_secs(1)
        {
            return Err(super::refusal("single original preparation ARM required"));
        }
        super::pidfd_identity(&self.process, self.child.id())?;
        privileged_preparation()?;
        self.boundary.verify()?;
        self.arm_attempted = true;
        let mut preparation = self
            .preparation
            .take()
            .ok_or_else(|| super::refusal("original ARM pipe absent"))?;
        // SAFETY: F_GETFL only queries the private live pipe descriptor.
        let flags = unsafe { libc::fcntl(preparation.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: F_SETFL sets nonblocking on our private pipe; no pointer argument.
        if flags < 0
            // SAFETY: F_SETFL affects only the retained private pipe; no pointer
            // argument is passed and the original descriptor remains live.
            || unsafe {
                libc::fcntl(
                    preparation.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // One tiny PIPE_BUF-bounded write cannot wait for a full or stopped pipe.
        // Any partial result closes this single-use arm attempt permanently.
        if preparation.write(b"ARM\n")? != 4 {
            return Err(super::refusal("complete atomic ARM write required"));
        }
        drop(preparation);
        self.arm_written = true;
        self.expected_ready = if self.expected_ready
            == b"{\"event\":\"GUARD_PREPARED\",\"actual_Rust_guardian\":true}"
        {
            b"{\"event\":\"GUARD_READY\",\"actual_Rust_guardian\":true}"
        } else {
            b"{\"event\":\"SUPERVISOR_READY\",\"actual_Rust_guardian\":true}"
        };
        self.wait_ready(timeout)
    }

    /// Close an unarmed preparation; confirm bounded helper exit explicitly.
    /// An ARM attempt is never translated into this harmless-cancel path.
    pub fn cancel_preparation(&mut self, timeout: Duration) -> io::Result<()> {
        if self.preparation.is_none()
            || self.arm_attempted
            || self.cancellation_attempted
            || timeout.is_zero()
            || timeout > Duration::from_secs(4)
        {
            return Err(super::refusal("bounded cancellation only before ARM"));
        }
        self.cancellation_attempted = true;
        self.preparation.take();
        let observation = self.observe_terminal(timeout)?;
        if !observation.success
            || !observation.original_process_exit_confirmed
            || observation.arm_attempted
            || observation.armed_ready_observed
        {
            return Err(super::refusal(
                "unarmed cancellation requires actual successful exit",
            ));
        }
        Ok(())
    }
}

struct HelperOriginalBoundary {
    control: File,
    mount: File,
    mount_device: u64,
    mount_inode: u64,
    mount_id: u64,
    owner: File,
    owner_pid: u32,
    guardian: Option<(File, u32)>,
}

fn retained_mount_id(file: &File) -> io::Result<u64> {
    let mut bytes = Vec::with_capacity(512);
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?
        .take(4097)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(super::refusal("kernel mount fdinfo byte bound"));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| super::refusal("kernel mount fdinfo encoding"))?;
    let mut values = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let mount = values
        .next()
        .ok_or_else(|| super::refusal("kernel retained mount id absent"))?
        .trim()
        .parse::<u64>()
        .map_err(|_| super::refusal("kernel mount id invalid"))?;
    if mount == 0 || values.next().is_some() {
        return Err(super::refusal("unique mount id required"));
    }
    Ok(mount)
}

impl HelperOriginalBoundary {
    fn capture(
        mount: &File,
        control: &File,
        owner: &File,
        guardian: Option<&File>,
        owner_pid: u32,
        guardian_pid: Option<u32>,
    ) -> io::Result<Self> {
        super::mount_boundary(mount)?;
        super::pidfd_identity(owner, owner_pid)?;
        let metadata = mount.metadata()?;
        let result = Self {
            control: private_duplicate(control)?,
            mount: private_duplicate(mount)?,
            mount_device: metadata.dev(),
            mount_inode: metadata.ino(),
            mount_id: retained_mount_id(mount)?,
            owner: private_duplicate(owner)?,
            owner_pid,
            guardian: match (guardian, guardian_pid) {
                (Some(file), Some(pid)) => {
                    super::pidfd_identity(file, pid)?;
                    Some((private_duplicate(file)?, pid))
                }
                (None, None) => None,
                _ => {
                    return Err(super::refusal(
                        "complete original guardian identity required",
                    ))
                }
            },
        };
        result.verify()?;
        Ok(result)
    }
    fn verify(&self) -> io::Result<()> {
        super::mount_boundary(&self.mount)?;
        let metadata = self.mount.metadata()?;
        if metadata.dev() != self.mount_device
            || metadata.ino() != self.mount_inode
            || retained_mount_id(&self.mount)? != self.mount_id
        {
            return Err(super::refusal("retained original mount identity differs"));
        }
        super::pidfd_identity(&self.owner, self.owner_pid)?;
        if let Some((file, pid)) = &self.guardian {
            super::pidfd_identity(file, *pid)?;
        }
        Ok(())
    }
}

mod pair;
pub use pair::{OriginalPairTerminalRelease, OutsideHelperSession, OutsidePreparationPair};

fn privileged_preparation() -> io::Result<()> {
    // SAFETY: geteuid is pointer-free and only observes this process identity.
    if unsafe { libc::geteuid() } != 0 {
        return Err(super::refusal(
            "explicit privileged preparation owner required",
        ));
    }
    let mut bytes = Vec::with_capacity(4096);
    File::open("/proc/self/status")?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err(super::refusal("kernel privilege status byte bound"));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| super::refusal("kernel privilege status encoding"))?;
    let mut values = text.lines().filter_map(|line| line.strip_prefix("CapEff:"));
    let capabilities = u64::from_str_radix(
        values
            .next()
            .ok_or_else(|| super::refusal("effective kernel capabilities absent"))?
            .trim(),
        16,
    )
    .map_err(|_| super::refusal("effective kernel capabilities invalid"))?;
    if values.next().is_some() || capabilities & (1u64 << 21) == 0 {
        return Err(super::refusal("explicit effective CAP_SYS_ADMIN required"));
    }
    Ok(())
}

/// Immutable local observation. A successful process exit is not a native
/// transaction receipt, owner completion, persisted Final or cleanup authority.
#[derive(Debug)]
pub struct OutsideHelperExitObservation {
    pub process_id: u32,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub preparation_observed: bool,
    pub arm_attempted: bool,
    pub armed_ready_observed: bool,
    pub original_process_exit_confirmed: bool,
}

fn observe_pipe(file: &mut impl AsRawFd, bytes: &mut Vec<u8>) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pipe descriptor and sized pollfd output, zero wait.
    let available = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if available < 0 {
        return Err(io::Error::last_os_error());
    }
    if available == 0 {
        return Ok(false);
    }
    if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(super::refusal("terminal helper pipe invalid"));
    }
    if descriptor.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
        return Ok(false);
    }
    if bytes.len() > 4096 {
        return Err(super::refusal("terminal overflow is a permanent refusal"));
    }
    let mut buffer = [0u8; 512];
    // Preserve one exact overflow byte, and consume no further bytes on refusal.
    let capacity = buffer.len().min(4097 - bytes.len());
    // SAFETY: live readable pipe, fixed writable buffer and exact capacity.
    let count = unsafe { libc::read(file.as_raw_fd(), buffer.as_mut_ptr().cast(), capacity) };
    if count < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    if count == 0 {
        return Ok(true);
    }
    let count = usize::try_from(count).map_err(|_| super::refusal("helper pipe count"))?;
    bytes.extend_from_slice(&buffer[..count]);
    if bytes.len() > 4096 {
        return Err(super::refusal(
            "helper terminal stream byte bound; overflow byte retained",
        ));
    }
    Ok(false)
}

impl OutsideHelperChild {
    /// Wait without killing this watchdog. Raw nonzero exits are retained in
    /// observations; a stuck/inherited writer is bounded by the same deadline.
    pub fn observe_terminal(
        &mut self,
        timeout: Duration,
    ) -> io::Result<OutsideHelperExitObservation> {
        if self.terminal_observed
            || self.terminal_poisoned
            || timeout.is_zero()
            || timeout > Duration::from_secs(12)
        {
            return Err(super::refusal("single bounded helper terminal observation"));
        }
        // Close only our unarmed preparation pipe. This cancels preparation
        // without translating an attempted ARM into harmless cancellation.
        if self.preparation_mode && !self.arm_attempted {
            self.cancellation_attempted = true;
            self.preparation.take();
        }
        let deadline = Instant::now() + timeout;
        loop {
            if !self.terminal_out_eof {
                let observed = observe_pipe(
                    self.child
                        .stdout
                        .as_mut()
                        .ok_or_else(|| super::refusal("original stdout absent"))?,
                    &mut self.terminal_stdout,
                );
                match observed {
                    Ok(eof) => self.terminal_out_eof = eof,
                    Err(error) => {
                        self.terminal_poisoned = true;
                        return Err(error);
                    }
                }
            }
            if !self.terminal_err_eof {
                let observed = observe_pipe(
                    self.child
                        .stderr
                        .as_mut()
                        .ok_or_else(|| super::refusal("original stderr absent"))?,
                    &mut self.terminal_stderr,
                );
                match observed {
                    Ok(eof) => self.terminal_err_eof = eof,
                    Err(error) => {
                        self.terminal_poisoned = true;
                        return Err(error);
                    }
                }
            }
            if let Some(status) = self.child.try_wait()? {
                if self.terminal_out_eof && self.terminal_err_eof {
                    if super::wait(&[&self.process], Duration::ZERO)? != [0] {
                        return Err(super::refusal("exact helper pidfd exit unconfirmed"));
                    }
                    self.terminal_observed = true;
                    return Ok(OutsideHelperExitObservation {
                        process_id: self.child.id(),
                        exit_code: status.code(),
                        success: status.success(),
                        stdout: self.terminal_stdout.clone(),
                        stderr: self.terminal_stderr.clone(),
                        preparation_observed: self.prepared,
                        arm_attempted: self.arm_attempted,
                        armed_ready_observed: self.ready,
                        original_process_exit_confirmed: true,
                    });
                }
            }
            if Instant::now() >= deadline {
                return Err(super::refusal("helper terminal exit or pipe EOF deadline"));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl OutsideHelperChild {
    /// Already-read bytes remain available even when a deadline or resource
    /// bound refuses the observation. These are diagnostics, never authority.
    pub fn retained_terminal_bytes(&self) -> (&[u8], &[u8]) {
        (&self.terminal_stdout, &self.terminal_stderr)
    }
}

impl OutsideHelperChild {
    /// A refused startup keeps its consumed original bytes for diagnostics.
    pub fn retained_startup_bytes(&self) -> &[u8] {
        &self.ready_bytes
    }
}
