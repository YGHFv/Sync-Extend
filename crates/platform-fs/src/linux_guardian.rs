//! Linux outside-volume guardian for one exact inherited mount and process lineage.
//! The caller must bind this helper, its inherited descriptors and original
//! owner to a separate durable protocol before admitting any native mutation.
use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct ThawObservation {
    pub reason: &'static str,
    pub owner_exit_before_thaw: bool,
    pub guardian_exit_before_thaw: bool,
    pub exit_verified_ns: Option<u64>,
    pub guardian_exit_verified_ns: Option<u64>,
    pub thaw_finished_ns: u64,
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn pidfd_identity(file: &File, expected: u32) -> io::Result<()> {
    if expected <= 1 {
        return Err(refusal("explicit live original process identity required"));
    }
    let path = format!("/proc/self/fdinfo/{}", file.as_raw_fd());
    let mut bytes = Vec::new();
    File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(refusal("bounded kernel pidfd information required"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| refusal("kernel pidfd encoding"))?;
    let mut values = text.lines().filter_map(|line| line.strip_prefix("Pid:"));
    let pid = values
        .next()
        .ok_or_else(|| refusal("inherited descriptor is not a pidfd"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| refusal("inherited pidfd is already exited or invalid"))?;
    if pid != expected || values.next().is_some() {
        return Err(refusal("inherited original pidfd identity differs"));
    }
    Ok(())
}

fn mount_boundary(file: &File) -> io::Result<()> {
    // SAFETY: geteuid has no pointer arguments.
    if unsafe { libc::geteuid() } != 0 || !file.metadata()?.is_dir() {
        return Err(refusal(
            "explicit privileged retained mount directory required",
        ));
    }
    if std::fs::read_link("/proc/self/ns/mnt")? == std::fs::read_link("/proc/1/ns/mnt")? {
        return Err(refusal("explicit private mount namespace required"));
    }
    let mut status = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: retained live descriptor and properly sized writable output.
    if unsafe { libc::fstatfs(file.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the complete structure.
    if unsafe { status.assume_init() }.f_type != 0xef53 {
        return Err(refusal("explicit local ext4 mount required"));
    }
    let executable = File::open("/proc/self/exe")?;
    if executable.metadata()?.dev() == file.metadata()?.dev() {
        return Err(refusal(
            "guardian executable must be outside frozen filesystem",
        ));
    }
    Ok(())
}

fn control_boundary(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if metadata.mode() & libc::S_IFMT != libc::S_IFIFO {
        return Err(refusal("inherited private control pipe required"));
    }
    // SAFETY: live descriptor and pointer-free file status query.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(refusal("guardian control must be read-only"));
    }
    Ok(())
}

fn wait(files: &[&File], timeout: Duration) -> io::Result<Vec<usize>> {
    let mut descriptors: Vec<_> = files
        .iter()
        .map(|file| libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let started = Instant::now();
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        let milliseconds = remaining
            .as_millis()
            .saturating_add(u128::from(!remaining.is_zero()));
        let milliseconds = libc::c_int::try_from(milliseconds.min(i32::MAX as u128))
            .map_err(|_| refusal("bounded poll timeout required"))?;
        // SAFETY: every descriptor is live and the vector supplies exactly its
        // writable pollfd length. No borrowed pointer survives this syscall.
        let count = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                milliseconds,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if descriptors
            .iter()
            .any(|descriptor| descriptor.revents & (libc::POLLNVAL | libc::POLLERR) != 0)
        {
            return Err(refusal("inherited kernel descriptor poll failed"));
        }
        return Ok(descriptors
            .iter()
            .enumerate()
            .filter_map(|(index, descriptor)| {
                (descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0).then_some(index)
            })
            .collect());
    }
}

fn kill_confirm(file: &File) -> io::Result<()> {
    // SAFETY: Linux pidfd_send_signal receives a live pidfd, fixed SIGKILL,
    // null optional siginfo and zero flags. It never targets a reused PID.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            file.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    if wait(&[file], Duration::from_secs(5))? != [0] {
        return Err(refusal(
            "exact original process exit unconfirmed: refuse thaw",
        ));
    }
    Ok(())
}

fn thaw(file: &File) -> io::Result<()> {
    // SAFETY: live retained ext4 mount directory and Linux FITHAW, no pointer.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0xc004_5878_u32 as libc::Ioctl, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn monotonic_ns() -> io::Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: fixed valid clock and properly sized writable timespec output.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful clock_gettime initialized the complete timespec.
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec).map_err(|_| refusal("monotonic clock seconds"))?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| refusal("monotonic clock nanos"))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|time| time.checked_add(nanos))
        .ok_or_else(|| refusal("monotonic clock overflow"))
}

fn bounded_deadline(seconds: u32) -> io::Result<Instant> {
    if !(1..=30).contains(&seconds) {
        return Err(refusal("explicit bounded guardian deadline required"));
    }
    Ok(Instant::now() + Duration::from_secs(u64::from(seconds)))
}

/// Prepare and validate all inherited objects before the caller reports READY.
pub struct OutsideGuardian {
    mount: File,
    owner: File,
    control: File,
    seconds: u32,
}

impl OutsideGuardian {
    pub fn new(
        mount: File,
        owner: File,
        control: File,
        owner_pid: u32,
        seconds: u32,
    ) -> io::Result<Self> {
        mount_boundary(&mount)?;
        pidfd_identity(&owner, owner_pid)?;
        control_boundary(&control)?;
        bounded_deadline(seconds)?;
        Ok(Self {
            mount,
            owner,
            control,
            seconds,
        })
    }

    /// Run after READY. EOF cannot masquerade as a successful commit; an exiting
    /// owner gets the same bounded pidfd classification interval as the kernel probe.
    pub fn run(mut self) -> io::Result<ThawObservation> {
        let deadline = bounded_deadline(self.seconds)?;
        let reason = loop {
            let events = wait(
                &[&self.owner, &self.control],
                deadline.saturating_duration_since(Instant::now()),
            )?;
            if events.contains(&0) {
                break "owner_exited";
            }
            if events.contains(&1) {
                let mut token = [0u8; 16];
                let count = self.control.read(&mut token)?;
                if &token[..count] == b"COMMITTED" {
                    break "committed";
                }
                break if wait(&[&self.owner], Duration::from_millis(100))? == [0] {
                    "owner_exited"
                } else {
                    "control_closed_or_invalid"
                };
            }
            if Instant::now() >= deadline {
                break "deadline";
            }
        };
        let exited = reason != "committed";
        if exited {
            kill_confirm(&self.owner)?;
        }
        let exit_verified_ns = exited.then(monotonic_ns).transpose()?;
        thaw(&self.mount)?;
        Ok(ThawObservation {
            reason,
            owner_exit_before_thaw: exited,
            guardian_exit_before_thaw: false,
            exit_verified_ns,
            guardian_exit_verified_ns: None,
            thaw_finished_ns: monotonic_ns()?,
        })
    }
}

/// Independent watchdog; neither owner death nor guardian death kills this
/// helper automatically. The caller keeps its exact program/descriptor lineage.
pub struct OutsideSupervisor {
    mount: File,
    owner: File,
    guardian: File,
    control: File,
    seconds: u32,
}

impl OutsideSupervisor {
    pub fn new(
        mount: File,
        owner: File,
        guardian: File,
        control: File,
        owner_pid: u32,
        guardian_pid: u32,
        seconds: u32,
    ) -> io::Result<Self> {
        if owner_pid == guardian_pid {
            return Err(refusal("distinct exact owner and guardian required"));
        }
        mount_boundary(&mount)?;
        pidfd_identity(&owner, owner_pid)?;
        pidfd_identity(&guardian, guardian_pid)?;
        control_boundary(&control)?;
        bounded_deadline(seconds)?;
        Ok(Self {
            mount,
            owner,
            guardian,
            control,
            seconds,
        })
    }

    pub fn run(self) -> io::Result<Option<ThawObservation>> {
        self.run_with_completion_interval(Duration::ZERO)
    }

    /// Prepared pairs acknowledge the original guardian's observed thaw
    /// through their independent control pipe. No new process is adopted.
    pub fn run_after_preparation(self) -> io::Result<Option<ThawObservation>> {
        self.run_with_completion_interval(Duration::from_millis(100))
    }

    fn run_with_completion_interval(
        mut self,
        completion_interval: Duration,
    ) -> io::Result<Option<ThawObservation>> {
        let deadline = bounded_deadline(self.seconds)?;
        let reason = loop {
            let events = wait(
                &[&self.guardian, &self.control],
                deadline.saturating_duration_since(Instant::now()),
            )?;
            if events.contains(&0) {
                if !completion_interval.is_zero()
                    && wait(&[&self.control], completion_interval)? == [0]
                {
                    let mut token = [0u8; 16];
                    let count = self.control.read(&mut token)?;
                    if &token[..count] == b"THAWED" {
                        return Ok(None);
                    }
                }
                break "guardian_exited";
            }
            if events.contains(&1) {
                let mut token = [0u8; 16];
                let count = self.control.read(&mut token)?;
                if &token[..count] == b"THAWED" {
                    return Ok(None);
                }
                break "guardian_control_closed_or_invalid";
            }
            if Instant::now() >= deadline {
                break "guardian_deadline";
            }
        };
        kill_confirm(&self.owner)?;
        let exit_verified_ns = Some(monotonic_ns()?);
        kill_confirm(&self.guardian)?;
        let guardian_exit_verified_ns = Some(monotonic_ns()?);
        thaw(&self.mount)?;
        Ok(Some(ThawObservation {
            reason,
            owner_exit_before_thaw: true,
            guardian_exit_before_thaw: true,
            exit_verified_ns,
            guardian_exit_verified_ns,
            thaw_finished_ns: monotonic_ns()?,
        }))
    }
}

/// Take exactly one inherited native descriptor without opening a pathname.
///
/// # Safety
///
/// The caller must transfer sole close ownership of this inherited descriptor,
/// ensure it is live, and not pass it to this constructor more than once.
/// Semantic descriptor type and identity are checked by guardian construction.
pub unsafe fn take_inherited_descriptor(descriptor: u32) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    let descriptor = libc::c_int::try_from(descriptor)
        .map_err(|_| refusal("bounded inherited native descriptor required"))?;
    if descriptor < 3 {
        return Err(refusal("explicit inherited native descriptor required"));
    }
    // SAFETY: pointer-free query only inspects the caller-transferred descriptor.
    if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the caller transfers sole close ownership under this API contract.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

mod arming;
mod launcher;
pub use arming::OutsidePreparationGate;
pub use launcher::{
    OriginalPairTerminalRelease, OutsideHelperChild, OutsideHelperExitObservation,
    OutsideHelperProgram, OutsideHelperSession, OutsidePreparationPair,
};
