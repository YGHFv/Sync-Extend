//! One-use publication authority, separate from the acquired physical owner.
//! Neither diagnostics nor a persisted row can manufacture an epoch.
use crate::{
    LinuxCleanupAbsenceObservation, LinuxNamespaceCapability, OriginalPairTerminalRelease,
};
use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

pub(crate) struct PublicationEpochState {
    pub(crate) sequence: u64,
    pub(crate) generation: [u8; 16],
    pub(crate) helper_preparation_started: AtomicBool,
    pub(crate) attempt_issued: AtomicBool,
    pub(crate) attempt_scope: Mutex<Option<(String, u64)>>,
}

impl PublicationEpochState {
    fn new(sequence: u64, generation: [u8; 16]) -> Self {
        Self {
            sequence,
            generation,
            helper_preparation_started: AtomicBool::new(false),
            attempt_issued: AtomicBool::new(false),
            attempt_scope: Mutex::new(None),
        }
    }
}

pub(crate) struct PublicationCursor {
    pub(crate) current: Arc<PublicationEpochState>,
    initial_issued: bool,
}

impl PublicationCursor {
    pub(crate) fn initial(generation: [u8; 16]) -> Self {
        Self {
            current: Arc::new(PublicationEpochState::new(0, generation)),
            initial_issued: false,
        }
    }
}

/// One original epoch. Intentionally has no Clone, Deserialize or constructor.
pub struct LinuxPublicationEpoch {
    pub(crate) state: Arc<PublicationEpochState>,
}

/// Platform evidence only. Reconcile must also consume its own live Journal
/// cleanup receipt before publishing the returned epoch to the next request.
pub struct LinuxPendingSuccessor<'a> {
    owner: &'a LinuxNamespaceCapability,
    previous: Arc<PublicationEpochState>,
    next: u64,
    transaction: String,
    absence: Vec<LinuxCleanupAbsenceObservation<'a>>,
    worktree_lock: LinuxPublicationWorktreeLock<'a>,
    worktree_identity: LinuxPublicationWorktreeIdentity<'a>,
}

/// Observation of the original LocalSpace writer lock. It grants no native
/// authority and exempts only this exact descriptor from the closure inventory.
pub struct LinuxPublicationWorktreeLock<'a> {
    owner: &'a LinuxNamespaceCapability,
    file: &'a File,
    worktree: PathBuf,
    marker_key: crate::UnixFileKey,
    lock_key: crate::UnixFileKey,
    sequence: u64,
}

/// Borrows the actual LocalSpace root identity handle. Only that descriptor,
/// not another descriptor opened on the same directory, joins the inventory.
pub struct LinuxPublicationWorktreeIdentity<'a> {
    owner: &'a LinuxNamespaceCapability,
    file: &'a File,
    worktree: PathBuf,
    root_key: crate::UnixFileKey,
    sequence: u64,
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn descriptor_info(file: &File) -> io::Result<String> {
    let mut info = String::new();
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?
        .take(16 * 1024 + 1)
        .read_to_string(&mut info)?;
    if info.len() > 16 * 1024 {
        return Err(refusal("publication descriptor inventory exceeds bound"));
    }
    Ok(info)
}

fn descriptor_mount_id(info: &str) -> io::Result<u64> {
    let mut values = info.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let value = values
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or_else(|| refusal("publication descriptor mount identity absent or invalid"))?;
    if values.next().is_some() {
        return Err(refusal(
            "publication descriptor mount identity is ambiguous",
        ));
    }
    Ok(value)
}

impl LinuxPublicationEpoch {
    pub fn sequence(&self) -> u64 {
        self.state.sequence
    }
    pub fn verify_owner(&self, owner: &LinuxNamespaceCapability) -> io::Result<()> {
        owner.verify_publication_state(&self.state)
    }
}

impl LinuxNamespaceCapability {
    pub fn observe_publication_worktree_identity<'a>(
        &'a self,
        epoch: &LinuxPublicationEpoch,
        worktree: &Path,
        file: &'a File,
    ) -> io::Result<LinuxPublicationWorktreeIdentity<'a>> {
        epoch.verify_owner(self)?;
        let relative = worktree
            .strip_prefix(self.mount_path())
            .map_err(|_| refusal("publication root identity is outside the original mount"))?;
        let value = LinuxPublicationWorktreeIdentity {
            owner: self,
            file,
            worktree: relative.to_owned(),
            root_key: self.volume().directory(relative)?.original_key()?,
            sequence: epoch.sequence(),
        };
        value.verify()?;
        Ok(value)
    }

    pub fn observe_publication_worktree_lock<'a>(
        &'a self,
        epoch: &LinuxPublicationEpoch,
        worktree: &Path,
        file: &'a File,
    ) -> io::Result<LinuxPublicationWorktreeLock<'a>> {
        epoch.verify_owner(self)?;
        let relative = worktree
            .strip_prefix(self.mount_path())
            .map_err(|_| refusal("publication writer lock is outside the original mount"))?;
        let marker = self.volume().directory(&relative.join(".sync-extend"))?;
        let original = marker.original("writer.lock")?;
        let value = LinuxPublicationWorktreeLock {
            owner: self,
            file,
            worktree: relative.to_owned(),
            marker_key: marker.original_key()?,
            lock_key: original.observation()?,
            sequence: epoch.sequence(),
        };
        value.verify()?;
        Ok(value)
    }

    pub fn initial_publication_epoch(&self) -> io::Result<LinuxPublicationEpoch> {
        self.verify()?;
        let mut cursor = self
            .publication
            .lock()
            .map_err(|_| refusal("publication cursor poisoned"))?;
        if cursor.initial_issued || cursor.current.sequence != 0 {
            return Err(refusal("original initial publication epoch already issued"));
        }
        cursor.initial_issued = true;
        Ok(LinuxPublicationEpoch {
            state: Arc::clone(&cursor.current),
        })
    }

    pub(crate) fn verify_publication_state(
        &self,
        state: &Arc<PublicationEpochState>,
    ) -> io::Result<()> {
        self.verify()?;
        let cursor = self
            .publication
            .lock()
            .map_err(|_| refusal("publication cursor poisoned"))?;
        if !cursor.initial_issued
            || !Arc::ptr_eq(&cursor.current, state)
            || state.generation != self.owner_generation()
        {
            return Err(refusal("stale or foreign publication epoch"));
        }
        Ok(())
    }

    fn verify_descriptor_epoch(&self, sequence: u64) -> io::Result<()> {
        self.verify()?;
        let cursor = self
            .publication
            .lock()
            .map_err(|_| refusal("publication cursor poisoned"))?;
        if !cursor.initial_issued
            || cursor.current.sequence != sequence
            || cursor.current.generation != self.owner_generation()
        {
            return Err(refusal(
                "stale publication LocalSpace descriptor observation",
            ));
        }
        Ok(())
    }

    pub(crate) fn claim_helper_preparation(
        &self,
        epoch: &LinuxPublicationEpoch,
    ) -> io::Result<Arc<PublicationEpochState>> {
        epoch.verify_owner(self)?;
        if epoch
            .state
            .helper_preparation_started
            .swap(true, Ordering::AcqRel)
        {
            return Err(refusal("original epoch helper preparation already started"));
        }
        Ok(Arc::clone(&epoch.state))
    }

    fn verify_closed_publication_descriptors(
        &self,
        absence: &[LinuxCleanupAbsenceObservation<'_>],
        worktree_lock: &LinuxPublicationWorktreeLock<'_>,
        worktree_identity: &LinuxPublicationWorktreeIdentity<'_>,
    ) -> io::Result<()> {
        self.verify()?;
        worktree_lock.verify()?;
        worktree_identity.verify()?;
        if !std::ptr::eq(self, worktree_lock.owner)
            || !std::ptr::eq(self, worktree_identity.owner)
            || worktree_lock.worktree != worktree_identity.worktree
            || worktree_lock.sequence != worktree_identity.sequence
        {
            return Err(refusal(
                "successor LocalSpace descriptors belong to another scope",
            ));
        }
        let mount_id = self.volume().observation().runtime_mount_id;
        let mut allowed = vec![
            self.mount_descriptor().as_raw_fd(),
            worktree_lock.file.as_raw_fd(),
            worktree_identity.file.as_raw_fd(),
        ];
        allowed.extend(
            absence
                .iter()
                .map(|value| value.retained_parent_descriptor()),
        );
        let descriptors = std::fs::read_dir("/proc/self/fd")?
            .map(|entry| entry.map(|value| value.file_name()))
            .take(4097)
            .collect::<io::Result<Vec<_>>>()?;
        if descriptors.len() > 4096 {
            return Err(refusal("successor descriptor inventory exceeds bound"));
        }
        for descriptor in descriptors {
            let fd = descriptor
                .to_str()
                .and_then(|value| value.parse::<i32>().ok())
                .ok_or_else(|| refusal("successor descriptor encoding differs"))?;
            if allowed.contains(&fd) {
                continue;
            }
            let info = match std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")) {
                Ok(info) if info.len() <= 16 * 1024 => info,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                _ => {
                    return Err(refusal(
                        "successor descriptor inventory changed or exceeds bound",
                    ))
                }
            };
            let observed = descriptor_mount_id(&info)?;
            if observed == mount_id {
                return Err(refusal("successor has an unclosed native mount descriptor"));
            }
        }
        self.verify()
    }

    pub fn prepare_successor_epoch<'a>(
        &'a self,
        epoch: &LinuxPublicationEpoch,
        terminal: &OriginalPairTerminalRelease,
        absence: Vec<LinuxCleanupAbsenceObservation<'a>>,
        transaction: &str,
        worktree_lock: LinuxPublicationWorktreeLock<'a>,
        worktree_identity: LinuxPublicationWorktreeIdentity<'a>,
    ) -> io::Result<LinuxPendingSuccessor<'a>> {
        epoch.verify_owner(self)?;
        terminal.verify_committed_owner(self, transaction)?;
        if !Arc::ptr_eq(&epoch.state, &terminal.epoch)
            || worktree_lock.sequence != epoch.sequence()
            || worktree_identity.sequence != epoch.sequence()
            || absence.is_empty()
            || absence.len() > 3
        {
            return Err(refusal(
                "successor original epoch or bounded absence differs",
            ));
        }
        // Exactly current cursor, unique ready token, and original terminal.
        // Any retained session/native attempt/duplicate pending proof refuses.
        if Arc::strong_count(&epoch.state) != 3 {
            return Err(refusal(
                "publication epoch still has borrowed native or helper references",
            ));
        }
        self.verify_closed_publication_descriptors(&absence, &worktree_lock, &worktree_identity)?;
        let next = epoch
            .sequence()
            .checked_add(1)
            .ok_or_else(|| refusal("publication epoch exhausted"))?;
        for observed in &absence {
            observed.verify()?;
            if observed.owner_generation() != self.owner_generation() {
                return Err(refusal("successor absence belongs to another owner"));
            }
        }
        Ok(LinuxPendingSuccessor {
            owner: self,
            previous: Arc::clone(&epoch.state),
            next,
            transaction: transaction.to_owned(),
            absence,
            worktree_lock,
            worktree_identity,
        })
    }
}

impl LinuxPublicationWorktreeLock<'_> {
    fn verify(&self) -> io::Result<()> {
        self.owner.verify_descriptor_epoch(self.sequence)?;
        let metadata = self.file.metadata()?;
        let marker = self
            .owner
            .volume()
            .directory(&self.worktree.join(".sync-extend"))?;
        let original = marker.original("writer.lock")?;
        let info = descriptor_info(self.file)?;
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u32::from_str_radix(value.trim(), 8).ok());
        let mount = descriptor_mount_id(&info)?;
        if flags.is_none_or(|flags| flags & libc::O_ACCMODE as u32 != libc::O_RDWR as u32)
            || mount != self.owner.volume().observation().runtime_mount_id
            || !metadata.is_file()
            || metadata.uid() != self.owner.mount_descriptor().metadata()?.uid()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.len() != 0
            || marker.original_key()? != self.marker_key
            || original.observation()? != self.lock_key
            || metadata.dev() != self.lock_key.device
            || metadata.ino() != self.lock_key.inode
        {
            return Err(refusal("original publication writer lock identity changed"));
        }
        // fdinfo reports locks belonging to this open file description. A
        // separately opened same-inode fd has no such line; a dup inherits it
        // but remains undeclared unless it is the exact borrowed descriptor.
        // PID is interpreted in the same procfs namespace as /proc/self.
        let expected_pid = std::process::id();
        let mut matching = 0usize;
        for line in info.lines().filter_map(|line| line.strip_prefix("lock:")) {
            let columns: Vec<_> = line.split_whitespace().take(9).collect();
            if columns.len() != 8
                || columns[1] != "FLOCK"
                || columns[2] != "ADVISORY"
                || columns[3] != "WRITE"
                || columns[4].parse::<u32>().ok() != Some(expected_pid)
                || columns[6] != "0"
                || columns[7] != "EOF"
            {
                continue;
            }
            let parts: Vec<_> = columns[5].split(':').take(4).collect();
            if parts.len() == 3
                && u64::from_str_radix(parts[0], 16).ok()
                    == Some(libc::major(metadata.dev()) as u64)
                && u64::from_str_radix(parts[1], 16).ok()
                    == Some(libc::minor(metadata.dev()) as u64)
                && parts[2].parse::<u64>().ok() == Some(metadata.ino())
            {
                matching += 1;
            }
        }
        if matching != 1 {
            return Err(refusal(
                "original publication writer lock is not exclusively held",
            ));
        }
        self.owner.verify()
    }
}

impl LinuxPublicationWorktreeIdentity<'_> {
    fn verify(&self) -> io::Result<()> {
        self.owner.verify_descriptor_epoch(self.sequence)?;
        let metadata = self.file.metadata()?;
        let original = self.owner.volume().directory(&self.worktree)?;
        let info = descriptor_info(self.file)?;
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u32::from_str_radix(value.trim(), 8).ok());
        let mount = descriptor_mount_id(&info)?;
        if flags.is_none_or(|flags| {
            flags & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32
                || flags & libc::O_PATH as u32 != 0
        }) || mount != self.owner.volume().observation().runtime_mount_id
            || !metadata.is_dir()
            || metadata.uid() != self.owner.mount_descriptor().metadata()?.uid()
            || metadata.permissions().mode() & 0o077 != 0
            || original.original_key()? != self.root_key
            || metadata.dev() != self.root_key.device
            || metadata.ino() != self.root_key.inode
        {
            return Err(refusal("original publication root identity changed"));
        }
        self.owner.verify()
    }
}

impl LinuxPendingSuccessor<'_> {
    pub fn previous_sequence(&self) -> u64 {
        self.previous.sequence
    }
    pub fn next_sequence(&self) -> u64 {
        self.next
    }
    pub fn verify(
        &self,
        epoch: &LinuxPublicationEpoch,
        terminal: &OriginalPairTerminalRelease,
    ) -> io::Result<()> {
        epoch.verify_owner(self.owner)?;
        terminal.verify_committed_owner(self.owner, &self.transaction)?;
        if !Arc::ptr_eq(&epoch.state, &self.previous)
            || !Arc::ptr_eq(&terminal.epoch, &self.previous)
            || self.previous.sequence.checked_add(1) != Some(self.next)
            || Arc::strong_count(&self.previous) != 4
        {
            return Err(refusal(
                "successor scope, sequence or borrowed references changed",
            ));
        }
        for observed in &self.absence {
            observed.verify()?;
        }
        self.owner.verify_closed_publication_descriptors(
            &self.absence,
            &self.worktree_lock,
            &self.worktree_identity,
        )?;
        Ok(())
    }

    /// All fallible verification precedes consuming the unique old tokens.
    /// An error leaves epoch/terminal/pending in the caller's retained slots.
    pub fn consume(
        pending: &mut Option<Self>,
        epoch: &mut Option<LinuxPublicationEpoch>,
        terminal: &mut Option<OriginalPairTerminalRelease>,
    ) -> io::Result<LinuxPublicationEpoch> {
        let proof = pending
            .as_ref()
            .ok_or_else(|| refusal("successor proof absent"))?;
        let original = epoch
            .as_ref()
            .ok_or_else(|| refusal("original epoch absent"))?;
        let ended = terminal
            .as_ref()
            .ok_or_else(|| refusal("original terminal absent"))?;
        proof.verify(original, ended)?;
        let next = Arc::new(PublicationEpochState::new(
            proof.next,
            proof.owner.owner_generation(),
        ));
        let mut cursor = proof
            .owner
            .publication
            .lock()
            .map_err(|_| refusal("publication cursor poisoned"))?;
        if !Arc::ptr_eq(&cursor.current, &proof.previous) {
            return Err(refusal("successor predecessor was already consumed"));
        }
        cursor.current = Arc::clone(&next);
        drop(cursor);
        // No I/O, verification, or other fallible operation after this point.
        let _consumed_epoch = epoch.take();
        let _consumed_terminal = terminal.take();
        let _consumed_proof = pending.take();
        Ok(LinuxPublicationEpoch { state: next })
    }
}
