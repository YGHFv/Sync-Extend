//! Bind a child to the owner's kernel lifetime before the child runs.
use std::{
    io,
    process::{Child, Command},
};

pub struct ManagedChild {
    child: Option<Child>,
    #[cfg(windows)]
    _job: Option<std::os::windows::io::OwnedHandle>,
}

#[cfg(windows)]
pub struct ManagedChildCloseFailure {
    pub error: io::Error,
    original: Option<ManagedChild>,
    handles: Option<crate::WindowsOriginalResourceCloseFailure>,
}

#[cfg(windows)]
impl ManagedChildCloseFailure {
    pub fn has_retained_originals(&self) -> bool {
        self.original.is_some()
            || self
                .handles
                .as_ref()
                .is_some_and(|failure| failure.retained_resource_groups() != 0)
    }
    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = self.original.take() {
            if let Err(mut failure) = original.close_retaining() {
                self.original = failure.original.take();
                if let Some(handles) = failure.handles.take() {
                    let mut close = crate::WindowsOriginalCloseAttempt::new();
                    if let Some(previous) = self.handles.take() {
                        close.append_failure(previous);
                    }
                    close.append_failure(handles);
                    self.handles = close.finish().err();
                }
            }
        }
        self.handles = self.handles.map(|failure| failure.close_remaining());
        self
    }
    pub fn retain_and_report(self) -> io::Error {
        let error = io::Error::new(self.error.kind(), self.error.to_string());
        let _ = Box::leak(Box::new(self));
        error
    }
}

impl ManagedChild {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Self::spawn_retaining(command).map_err(ManagedChildCloseFailure::retain_and_report)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: getpid has no pointers or preconditions and captures this owner.
            let owner_pid = unsafe { libc::getpid() };
            // SAFETY: pre_exec performs only async-signal-safe Linux syscalls; no allocation.
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    if libc::getppid() != owner_pid {
                        libc::_exit(126);
                    }
                    Ok(())
                });
            }
            Ok(Self {
                child: Some(command.spawn()?),
            })
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        {
            let _ = command;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "managed child platform unavailable",
            ))
        }
    }

    #[cfg(windows)]
    pub fn spawn_retaining(command: &mut Command) -> Result<Self, ManagedChildCloseFailure> {
        {
            use std::{
                mem::size_of,
                os::windows::{
                    io::{AsRawHandle, FromRawHandle, OwnedHandle},
                    process::CommandExt,
                },
                ptr,
            };
            use windows_sys::Win32::{
                Foundation::HANDLE,
                System::{
                    JobObjects::{
                        AssignProcessToJobObject, CreateJobObjectW,
                        JobObjectExtendedLimitInformation, SetInformationJobObject,
                        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    },
                    Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED},
                },
            };
            #[link(name = "ntdll")]
            unsafe extern "system" {
                fn NtResumeProcess(process: HANDLE) -> i32;
            }
            // SAFETY: default security attributes and unnamed job have no borrowed output.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if handle.is_null() {
                return Err(ManagedChildCloseFailure {
                    error: io::Error::last_os_error(),
                    original: None,
                    handles: None,
                });
            }
            // SAFETY: successful CreateJobObjectW transfers exactly one owned handle.
            let job = unsafe { OwnedHandle::from_raw_handle(handle) };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: job and fully sized initialized limit structure remain live.
            if unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    ptr::from_mut(&mut limits).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                let mut close = crate::WindowsOriginalCloseAttempt::new();
                close.close_identity_handle(job);
                return Err(ManagedChildCloseFailure {
                    error,
                    original: None,
                    handles: close.finish().err(),
                });
            }
            command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
            let child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    let mut close = crate::WindowsOriginalCloseAttempt::new();
                    close.close_identity_handle(job);
                    return Err(ManagedChildCloseFailure {
                        error,
                        original: None,
                        handles: close.finish().err(),
                    });
                }
            };
            let owned = Self {
                child: Some(child),
                _job: Some(job),
            };
            let child = owned.child.as_ref().expect("original suspended child");
            // SAFETY: live child process is suspended; assignment precedes any child code.
            if unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } == 0 {
                let error = io::Error::last_os_error();
                let mut failure =
                    owned
                        .close_retaining()
                        .err()
                        .unwrap_or(ManagedChildCloseFailure {
                            error: io::Error::other("child admission failed"),
                            original: None,
                            handles: None,
                        });
                failure.error = error;
                return Err(failure);
            }
            // SAFETY: resume only this newly created child after its kernel lifetime is bound.
            if unsafe { NtResumeProcess(child.as_raw_handle()) } < 0 {
                let mut failure =
                    owned
                        .close_retaining()
                        .err()
                        .unwrap_or(ManagedChildCloseFailure {
                            error: io::Error::other("child resume failed"),
                            original: None,
                            handles: None,
                        });
                failure.error = io::Error::other("managed child resume failed");
                return Err(failure);
            }
            Ok(owned)
        }
    }

    pub fn child(&mut self) -> &mut Child {
        self.child.as_mut().expect("live managed child")
    }

    /// Retain the identity of this exact child and its already pinned image.
    /// This is a read-only RPC witness, never child or network authority.
    pub fn rpc_owner(&self, program: &crate::PinnedProgram) -> io::Result<crate::ManagedRpcOwner> {
        crate::ManagedRpcOwner::new(self.child.as_ref().expect("live managed child"), program)
    }

    #[cfg(windows)]
    pub fn rpc_owner_retaining(
        &self,
        program: &crate::PinnedProgram,
    ) -> Result<crate::ManagedRpcOwner, crate::WindowsOriginalResourceOpenFailure> {
        crate::ManagedRpcOwner::new_retaining(
            self.child.as_ref().expect("live managed child"),
            program,
        )
    }

    /// End the actual child, wait its exit, then close its process and Job
    /// HANDLEs. Failure owns the same objects and never issues a success token.
    #[cfg(windows)]
    pub fn close_retaining(
        mut self,
    ) -> Result<crate::ClosedWindowsOriginalResources, ManagedChildCloseFailure> {
        let ended = (|| -> io::Result<()> {
            let child = self.child();
            if child.try_wait()?.is_none() {
                child.kill()?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while child.try_wait()?.is_none() {
                    if std::time::Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original managed child exit not observed",
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            let _ = child.wait()?;
            Ok(())
        })();
        if let Err(error) = ended {
            return Err(ManagedChildCloseFailure {
                error,
                original: Some(self),
                handles: None,
            });
        }
        let mut close = crate::WindowsOriginalCloseAttempt::new();
        let mut child = self.child.take().expect("same actual waited child");
        if let Some(pipe) = child.stdin.take() {
            close.close_identity_handle(pipe);
        }
        if let Some(pipe) = child.stdout.take() {
            close.close_identity_handle(pipe);
        }
        if let Some(pipe) = child.stderr.take() {
            close.close_identity_handle(pipe);
        }
        close.close_identity_handle(child);
        if let Some(job) = self._job.take() {
            close.close_identity_handle(job);
        }
        close.finish().map_err(|handles| ManagedChildCloseFailure {
            error: io::Error::new(handles.error.kind(), handles.error.to_string()),
            original: None,
            handles: Some(handles),
        })
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Drain only bytes already available; an inherited writer cannot delay a deadline.
pub fn read_available(
    stdout: &mut std::process::ChildStdout,
    buffer: &mut [u8],
) -> io::Result<Option<usize>> {
    use io::Read;
    #[cfg(windows)]
    {
        use std::{os::windows::io::AsRawHandle, ptr};
        use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, System::Pipes::PeekNamedPipe};
        let mut count = 0u32;
        // SAFETY: the live child pipe is read-only; count is a sized writable output.
        if unsafe {
            PeekNamedPipe(
                stdout.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(Some(0))
            } else {
                Err(error)
            };
        }
        if count == 0 {
            return Ok(None);
        }
        let length = buffer.len().min(count as usize);
        stdout.read(&mut buffer[..length]).map(Some)
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let mut descriptor = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pipe descriptor and a sized writable pollfd, zero timeout.
        let available = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if available < 0 {
            return Err(io::Error::last_os_error());
        }
        if available == 0 {
            return Ok(None);
        }
        stdout.read(buffer).map(Some)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        let _ = (stdout, buffer);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "managed pipe unavailable",
        ))
    }
}
