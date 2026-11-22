//! Mandatory open exclusion on an exact original regular file.
//! A break permanently invalidates this lease; it is never renewed.
use std::{
    fs::File,
    io,
    os::fd::{AsRawFd, IntoRawFd},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
};

const F_SETOWN_EX: libc::c_int = 15;
const F_OWNER_TID: libc::c_int = 0;
const F_SETLEASE: libc::c_int = 1024;
const F_GETLEASE: libc::c_int = 1025;

#[repr(C)]
struct Owner {
    kind: libc::c_int,
    pid: libc::pid_t,
}

pub(crate) struct OriginalWriteLease {
    file: Option<File>,
    broken: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<io::Result<()>>>,
}

impl OriginalWriteLease {
    pub(crate) fn acquire(original: &File) -> io::Result<Self> {
        let timeout = std::fs::read_to_string("/proc/sys/fs/lease-break-time")?
            .trim()
            .parse::<u64>()
            .map_err(|_| io::Error::other("kernel lease break timeout is invalid"))?;
        if timeout < 10 {
            return Err(io::Error::other(
                "kernel lease break timeout is below the native deadline",
            ));
        }
        let file = original.try_clone()?;
        let watched = file.try_clone()?;
        let broken = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_broken = broken.clone();
        let watcher_stop = stop.clone();
        let (ready, startup) = mpsc::sync_channel(1);
        let watcher = std::thread::Builder::new()
            .name("sync-original-write-lease".into())
            .spawn(move || {
                let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                // SAFETY: valid output storage and one fixed valid signal number.
                unsafe {
                    libc::sigemptyset(signals.as_mut_ptr());
                    libc::sigaddset(signals.as_mut_ptr(), libc::SIGIO);
                }
                // SAFETY: sigemptyset initialized the full set; old mask is optional.
                let mask = unsafe {
                    libc::pthread_sigmask(libc::SIG_BLOCK, signals.as_ptr(), std::ptr::null_mut())
                };
                let setup = if mask != 0 {
                    Err(io::Error::from_raw_os_error(mask))
                } else {
                    // SAFETY: gettid has no pointer arguments.
                    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
                    libc::pid_t::try_from(tid)
                        .map_err(|_| io::Error::other("original lease watcher task identity"))
                        .and_then(|pid| {
                            let owner = Owner {
                                kind: F_OWNER_TID,
                                pid,
                            };
                            // SAFETY: live original fd and correctly laid out f_owner_ex.
                            if unsafe { libc::fcntl(watched.as_raw_fd(), F_SETOWN_EX, &owner) } < 0
                            {
                                return Err(io::Error::last_os_error());
                            }
                            // SAFETY: write lease is acquired on this exact original description.
                            if unsafe {
                                libc::fcntl(watched.as_raw_fd(), F_SETLEASE, libc::F_WRLCK)
                            } < 0
                            {
                                return Err(io::Error::last_os_error());
                            }
                            Ok(())
                        })
                };
                let active = setup.is_ok();
                if ready.send(setup).is_err() || !active {
                    if active {
                        // SAFETY: startup failed after acquiring this original
                        // description; release before its owner thread exits.
                        unsafe { libc::fcntl(watched.as_raw_fd(), F_SETLEASE, libc::F_UNLCK) };
                    }
                    return close_original(watched);
                }
                // SAFETY: the set was completely initialized before mask/setup above.
                let signals = unsafe { signals.assume_init() };
                while !watcher_stop.load(Ordering::Acquire) {
                    let wait = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 20_000_000,
                    };
                    // SAFETY: initialized set and bounded wait, optional signal output is null.
                    let signal =
                        unsafe { libc::sigtimedwait(&signals, std::ptr::null_mut(), &wait) };
                    if signal == libc::SIGIO {
                        watcher_broken.store(true, Ordering::Release);
                    } else if signal == -1 {
                        let error = io::Error::last_os_error();
                        if !matches!(error.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                            watcher_broken.store(true, Ordering::Release);
                            break;
                        }
                    } else {
                        watcher_broken.store(true, Ordering::Release);
                        break;
                    }
                }
                close_original(watched)
            })?;
        match startup.recv() {
            Ok(Ok(())) => {}
            result => {
                stop.store(true, Ordering::Release);
                let _ = watcher.join();
                return Err(match result {
                    Ok(Err(error)) => error,
                    _ => io::Error::other("original write lease watcher did not become ready"),
                });
            }
        }
        let lease = Self {
            file: Some(file),
            broken,
            stop,
            watcher: Some(watcher),
        };
        lease.verify()?;
        Ok(lease)
    }

    pub(crate) fn verify(&self) -> io::Result<()> {
        let file = self.file.as_ref().ok_or_else(|| {
            io::Error::other("original mandatory write lease description has closed")
        })?;
        // SAFETY: pointer-free query on this retained original file description.
        let state = unsafe { libc::fcntl(file.as_raw_fd(), F_GETLEASE) };
        if state < 0 {
            return Err(io::Error::last_os_error());
        }
        if state != libc::F_WRLCK || self.broken.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "original mandatory write lease was broken",
            ));
        }
        Ok(())
    }

    /// Release only this original lease, join its actual owner task, and close
    /// both retained duplicates. A broken lease is never renewed or forgiven.
    pub(crate) fn close(mut self) -> io::Result<()> {
        let mut failure = self.verify().err();
        if let Err(error) = self.close_resources() {
            failure.get_or_insert(error);
        }
        failure.map_or(Ok(()), Err)
    }

    fn close_resources(&mut self) -> io::Result<()> {
        let mut failure = None;
        if let Some(file) = &self.file {
            // SAFETY: release this exact original open description before
            // stopping its specifically directed SIGIO watcher.
            if unsafe { libc::fcntl(file.as_raw_fd(), F_SETLEASE, libc::F_UNLCK) } < 0 {
                failure.get_or_insert_with(io::Error::last_os_error);
            }
            // SAFETY: actual kernel lease state through the same live FD.
            let state = unsafe { libc::fcntl(file.as_raw_fd(), F_GETLEASE) };
            if state != libc::F_UNLCK {
                failure.get_or_insert_with(|| {
                    if state < 0 {
                        io::Error::last_os_error()
                    } else {
                        io::Error::other("original mandatory kernel lease did not release")
                    }
                });
            }
        }
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            match watcher.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    failure.get_or_insert(error);
                }
                Err(_) => {
                    failure.get_or_insert_with(|| {
                        io::Error::other(
                            "original lease watcher task panicked before confirmed close",
                        )
                    });
                }
            }
        }
        if let Some(file) = self.file.take() {
            if let Err(error) = close_original(file) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for OriginalWriteLease {
    fn drop(&mut self) {
        // Best-effort abandonment never supplies a successful close receipt.
        let _ = self.close_resources();
    }
}

fn close_original(file: File) -> io::Result<()> {
    let descriptor = file.into_raw_fd();
    // SAFETY: consume this original descriptor exactly once. Never retry EINTR,
    // because Linux may already have closed and reused the descriptor number.
    if unsafe { libc::close(descriptor) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
