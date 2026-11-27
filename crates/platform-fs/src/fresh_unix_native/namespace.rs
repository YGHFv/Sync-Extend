//! A live kernel namespace handle; numeric observations cannot construct it.
use super::super::{
    current_uid, observe_fd, refuse, ClosedUnixOriginalResources, UnixOriginalCloseAttempt,
    UnixOriginalResourceCloseFailure, UnixProtectedArtifactKey,
};
use std::{
    cell::Cell,
    fs::File,
    io,
    marker::PhantomData,
    mem::MaybeUninit,
    os::fd::{AsRawFd, FromRawFd},
    rc::Rc,
};

const NSFS_MAGIC: libc::c_long = 0x6e736673;
const NS_GET_NSTYPE: libc::Ioctl = 0xb703;

fn current_tid() -> io::Result<libc::pid_t> {
    // SAFETY: gettid has no pointer arguments and returns this kernel thread ID.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    libc::pid_t::try_from(tid)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| refuse("current Unix namespace thread unavailable"))
}

fn open_current() -> io::Result<File> {
    // SAFETY: the fixed proc link deliberately resolves to a kernel nsfs object.
    // Its fs type and namespace kind are checked before it grants any scope.
    let fd = unsafe {
        libc::open(
            c"/proc/thread-self/ns/mnt".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful open transfers this fresh descriptor to the File.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn observed(file: &File) -> io::Result<UnixProtectedArtifactKey> {
    let mut fs = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the retained descriptor is live and statfs output is correctly sized.
    if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized this complete structure.
    if unsafe { fs.assume_init() }.f_type != NSFS_MAGIC {
        return Err(refuse("actual nsfs mount namespace descriptor required"));
    }
    // SAFETY: NS_GET_NSTYPE has no pointer argument; it interrogates this nsfs FD.
    let kind = unsafe { libc::ioctl(file.as_raw_fd(), NS_GET_NSTYPE) };
    if kind < 0 {
        return Err(io::Error::last_os_error());
    }
    if kind != libc::CLONE_NEWNS {
        return Err(refuse("actual original mount namespace required"));
    }
    let key = observe_fd(file.as_raw_fd())?.key;
    if key.inode == 0 {
        return Err(refuse("mount namespace inode unavailable"));
    }
    Ok(key)
}

/// Acquired from the calling thread's actual mount namespace. This is neither
/// a private mount capability nor protection from another same-UID process.
/// The !Send/!Sync marker and explicit thread/process checks bind every use.
pub struct OriginalUnixNamespace {
    state: Rc<NamespaceState>,
}

pub struct OriginalUnixNamespaceCloseFailure {
    pub error: io::Error,
    original: Option<Rc<NamespaceState>>,
    pub original_close: Option<UnixOriginalResourceCloseFailure>,
}

impl std::fmt::Debug for OriginalUnixNamespaceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalUnixNamespaceCloseFailure")
            .field("error", &self.error)
            .field("original_retained", &self.original.is_some())
            .field("original_close_uncertain", &self.original_close.is_some())
            .finish()
    }
}

impl OriginalUnixNamespaceCloseFailure {
    pub fn retains_original_namespace(&self) -> bool {
        self.original.is_some()
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original.take() {
            match Rc::try_unwrap(original) {
                Ok(state) => {
                    let mut close = UnixOriginalCloseAttempt::new();
                    if let Err(error) = state.verify_current() {
                        close.note_error(error);
                    }
                    close.close_file(state.original);
                    self.original_close = close.finish().err();
                }
                Err(original) => self.original = Some(original),
            }
        }
        if let Some(original) = self.original_close.take() {
            self.original_close = Some(original.close_remaining());
        }
        self
    }
}

impl Drop for OriginalUnixNamespaceCloseFailure {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let _ = Box::leak(Box::new(original));
        }
        if let Some(original) = self.original_close.take() {
            original.retain_until_process_exit();
        }
    }
}

pub(super) struct NamespaceState {
    original: File,
    key: UnixProtectedArtifactKey,
    process: u32,
    uid: u32,
    thread: libc::pid_t,
    failed: Cell<bool>,
    _thread_scope: PhantomData<Rc<()>>,
}

impl OriginalUnixNamespace {
    pub fn acquire_current() -> io::Result<Self> {
        let process = std::process::id();
        let uid = current_uid();
        let thread = current_tid()?;
        let original = open_current()?;
        let checked = observed(&original);
        let key = match checked {
            Ok(key) => key,
            Err(error) => {
                let mut close = UnixOriginalCloseAttempt::new();
                close.note_error(error);
                close.close_file(original);
                return Err(close
                    .finish()
                    .err()
                    .expect("namespace first error")
                    .retain_and_report());
            }
        };
        let result = Self {
            state: Rc::new(NamespaceState {
                original,
                key,
                process,
                uid,
                thread,
                failed: Cell::new(false),
                _thread_scope: PhantomData,
            }),
        };
        if let Err(error) = result.verify_current() {
            let mut close = UnixOriginalCloseAttempt::new();
            close.note_error(error);
            close.close_file(
                Rc::try_unwrap(result.state)
                    .ok()
                    .expect("unloaned original namespace")
                    .original,
            );
            return Err(close
                .finish()
                .err()
                .expect("namespace first error")
                .retain_and_report());
        }
        Ok(result)
    }

    pub fn verify_current(&self) -> io::Result<()> {
        self.state.verify_current()
    }

    pub(super) fn loan(&self) -> NamespaceLoan<'_> {
        NamespaceLoan {
            state: Rc::clone(&self.state),
            _scope: PhantomData,
        }
    }

    pub fn close_retaining(
        self,
    ) -> Result<ClosedUnixOriginalResources, OriginalUnixNamespaceCloseFailure> {
        let mut close = UnixOriginalCloseAttempt::new();
        let first = self.verify_current().err();
        match Rc::try_unwrap(self.state) {
            Ok(state) => {
                if let Some(error) = first {
                    close.note_error(error);
                }
                close.close_file(state.original);
            }
            Err(state) => {
                return Err(OriginalUnixNamespaceCloseFailure {
                    error: first.unwrap_or_else(|| {
                        refuse("original namespace still has retained actual resource loans")
                    }),
                    original: Some(state),
                    original_close: None,
                });
            }
        }
        close
            .finish()
            .map_err(|failure| OriginalUnixNamespaceCloseFailure {
                error: io::Error::new(failure.error.kind(), failure.error.to_string()),
                original: None,
                original_close: Some(failure),
            })
    }
}

#[derive(Clone)]
pub(super) struct NamespaceLoan<'namespace> {
    state: Rc<NamespaceState>,
    _scope: PhantomData<&'namespace OriginalUnixNamespace>,
}
impl NamespaceLoan<'_> {
    pub(super) fn key(&self) -> io::Result<UnixProtectedArtifactKey> {
        self.verify_current()?;
        Ok(self.state.key)
    }
    pub(super) fn verify_current(&self) -> io::Result<()> {
        self.state.verify_current()
    }
    pub(super) fn same_original(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.state, &other.state)
    }
    pub(super) fn on_original_thread(&self) -> bool {
        self.state.on_original_thread()
    }
}

impl NamespaceState {
    fn on_original_thread(&self) -> bool {
        self.process == std::process::id() && current_tid().ok() == Some(self.thread)
    }
    fn verify_current(&self) -> io::Result<()> {
        // A VFS registration is process-global. Foreign threads may discover
        // its name; reject them before touching any thread-local Cell or Rc.
        if !self.on_original_thread() {
            return Err(refuse(
                "original Unix namespace used by foreign process/thread",
            ));
        }
        if self.failed.get() {
            return Err(refuse(
                "original Unix namespace observation previously failed",
            ));
        }
        let checked = self.verify_current_once();
        if checked.is_err() {
            self.failed.set(true);
        }
        checked
    }

    fn verify_current_once(&self) -> io::Result<()> {
        if self.process != std::process::id()
            || self.uid != current_uid()
            || self.thread != current_tid()?
            || observed(&self.original)? != self.key
        {
            return Err(refuse("original Unix namespace process/thread/UID changed"));
        }
        let current = open_current()?;
        let checked = observed(&current).and_then(|key| {
            if key == self.key {
                Ok(())
            } else {
                Err(refuse("current thread left its original mount namespace"))
            }
        });
        let mut close = UnixOriginalCloseAttempt::new();
        if let Err(error) = checked {
            close.note_error(error);
        }
        close.close_file(current);
        close
            .finish()
            .map(|_| ())
            .map_err(UnixOriginalResourceCloseFailure::retain_and_report)
    }
}
