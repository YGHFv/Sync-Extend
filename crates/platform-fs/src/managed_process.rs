//! Bind a child to the owner's kernel lifetime before the child runs.
use std::{
    io,
    process::{Child, Command},
};

pub struct ManagedChild {
    child: Child,
    #[cfg(windows)]
    _job: std::os::windows::io::OwnedHandle,
}

impl ManagedChild {
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        #[cfg(windows)]
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
                return Err(io::Error::last_os_error());
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
                return Err(io::Error::last_os_error());
            }
            command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
            let mut child = command.spawn()?;
            // SAFETY: live child process is suspended; assignment precedes any child code.
            if unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } == 0 {
                let error = io::Error::last_os_error();
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            // SAFETY: resume only this newly created child after its kernel lifetime is bound.
            if unsafe { NtResumeProcess(child.as_raw_handle()) } < 0 {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::other("managed child resume failed"));
            }
            Ok(Self { child, _job: job })
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
                child: command.spawn()?,
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

    pub fn child(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
