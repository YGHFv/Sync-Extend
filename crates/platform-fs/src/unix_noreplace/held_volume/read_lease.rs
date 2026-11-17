//! Linux file read lease with directed break notification and explicit invalidation.
//! This protects one original's bytes, not namespace slots or native Final atomicity.
use std::{
    fs::File,
    io,
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::JoinHandle,
};

// Linux fcntl ABI: F_SETOWN_EX targets the dedicated watcher task, never an
// application thread with the default process-wide SIGIO disposition.
const F_SETOWN_EX: libc::c_int = 15;
const F_OWNER_TID: libc::c_int = 0;
const F_SETLEASE: libc::c_int = 1024;
const F_GETLEASE: libc::c_int = 1025;

#[repr(C)]
struct Owner {
    kind: libc::c_int,
    pid: libc::pid_t,
}

pub struct ReadLease {
    file: File,
    broken: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
}

impl ReadLease {
    pub fn acquire(original: &File) -> io::Result<Self> {
        let file = original.try_clone()?;
        let watched = file.try_clone()?;
        let broken = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_broken = broken.clone();
        let watcher_stop = stop.clone();
        let (ready, startup) = mpsc::sync_channel(1);
        let watcher = std::thread::Builder::new()
            .name("sync-private-read-lease".to_owned())
            .spawn(move || {
                let setup = setup(&watched);
                let active = setup.is_ok();
                if ready.send(setup).is_err() || !active {
                    return;
                }
                while !watcher_stop.load(Ordering::Acquire) {
                    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                    // SAFETY: valid output storage and a valid fixed signal number.
                    unsafe {
                        libc::sigemptyset(signals.as_mut_ptr());
                        libc::sigaddset(signals.as_mut_ptr(), libc::SIGIO);
                    }
                    // SAFETY: sigemptyset initialized the complete set above.
                    let signals = unsafe { signals.assume_init() };
                    let wait = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 50_000_000,
                    };
                    // SAFETY: initialized signal set and timespec, null optional output.
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
            })?;
        let result = match startup.recv() {
            Ok(result) => result,
            Err(_) => {
                stop.store(true, Ordering::Release);
                let _ = watcher.join();
                return Err(io::Error::other("lease watcher startup failed"));
            }
        };
        if let Err(error) = result {
            stop.store(true, Ordering::Release);
            let _ = watcher.join();
            return Err(error);
        }
        let lease = Self {
            file,
            broken,
            stop,
            watcher: Some(watcher),
        };
        lease.verify()?;
        Ok(lease)
    }

    pub fn verify(&self) -> io::Result<()> {
        // SAFETY: live descriptor and a pointer-free Linux fcntl query.
        let state = unsafe { libc::fcntl(self.file.as_raw_fd(), F_GETLEASE) };
        if state == -1 {
            return Err(io::Error::last_os_error());
        }
        if self.broken.load(Ordering::Acquire) || state != libc::F_RDLCK {
            return Err(io::Error::other("original file read lease was broken"));
        }
        Ok(())
    }
}

fn setup(file: &File) -> io::Result<()> {
    let mut signals = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: valid output storage and fixed valid signal number.
    unsafe {
        libc::sigemptyset(signals.as_mut_ptr());
        libc::sigaddset(signals.as_mut_ptr(), libc::SIGIO);
    }
    // SAFETY: sigemptyset initialized signals; null old-mask output is allowed.
    let mask =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, signals.as_ptr(), std::ptr::null_mut()) };
    if mask != 0 {
        return Err(io::Error::from_raw_os_error(mask));
    }
    // SAFETY: Linux gettid syscall has no pointer arguments.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let pid = libc::pid_t::try_from(tid).map_err(|_| io::Error::other("lease watcher identity"))?;
    let owner = Owner {
        kind: F_OWNER_TID,
        pid,
    };
    // SAFETY: live file descriptor and correctly laid out Linux f_owner_ex input.
    if unsafe { libc::fcntl(file.as_raw_fd(), F_SETOWN_EX, &owner) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: live readonly regular descriptor and fixed Linux read lease value.
    if unsafe { libc::fcntl(file.as_raw_fd(), F_SETLEASE, libc::F_RDLCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for ReadLease {
    fn drop(&mut self) {
        // SAFETY: live descriptor; release precedes watcher shutdown, preventing
        // a future notification from targeting an exited or reused task identity.
        unsafe { libc::fcntl(self.file.as_raw_fd(), F_SETLEASE, libc::F_UNLCK) };
        self.stop.store(true, Ordering::Release);
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}
