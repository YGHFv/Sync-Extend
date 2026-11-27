//! Read-only proof that a loopback RPC listener belongs to an exact pinned child.
//! No connection is opened here. A caller must verify the same witness again
//! after its bounded query and discard output if either witness differs.
use std::{fs::File, io, net::SocketAddr, process::Child};

const MAX_TABLE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRpcBinding {
    pid: u32,
    start: u64,
    endpoint: SocketAddr,
    listener: u64,
}

pub struct ManagedRpcOwner {
    pid: u32,
    start: u64,
    image: File,
    #[cfg(windows)]
    process: std::os::windows::io::OwnedHandle,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    process: File,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    uid: u32,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    net_namespace: (u64, u64),
}

fn refused(reason: &'static str) -> io::Error {
    io::Error::other(reason)
}

impl ManagedRpcOwner {
    #[cfg(windows)]
    pub fn close_into_attempt(self, close: &mut crate::WindowsOriginalCloseAttempt) {
        close.close_file(self.image);
        close.close_identity_handle(self.process);
    }

    pub(crate) fn new(child: &Child, program: &crate::PinnedProgram) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Self::new_retaining(child, program)
                .map_err(crate::WindowsOriginalResourceOpenFailure::retain_and_report)
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::{fd::FromRawFd, unix::fs::MetadataExt};
            // SAFETY: pidfd_open takes only the exact newly spawned child PID
            // and zero flags; success transfers one kernel process descriptor.
            let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the successful syscall returned one newly owned descriptor.
            let process = unsafe { File::from_raw_fd(descriptor as libc::c_int) };
            let namespace = std::fs::metadata("/proc/self/ns/net")?;
            let mut owner = Self {
                pid: child.id(),
                start: 0,
                image: program.reader().try_clone()?,
                process,
                // SAFETY: geteuid has no pointers or preconditions.
                uid: unsafe { libc::geteuid() },
                net_namespace: (namespace.dev(), namespace.ino()),
            };
            owner.start = owner.linux_start()?;
            owner.verify_live()?;
            Ok(owner)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        {
            let _ = (child, program);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "RPC owner proof unavailable",
            ))
        }
    }

    #[cfg(windows)]
    pub(crate) fn new_retaining(
        child: &Child,
        program: &crate::PinnedProgram,
    ) -> Result<Self, crate::WindowsOriginalResourceOpenFailure> {
        use std::{
            os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
            ptr,
        };
        use windows_sys::Win32::{
            Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS},
            System::Threading::GetCurrentProcess,
        };
        let mut duplicate = ptr::null_mut();
        // SAFETY: the live Child owns the source process handle and the
        // current-process pseudo handle remains valid through duplication.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                child.as_raw_handle(),
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(crate::WindowsOriginalResourceOpenFailure {
                error: io::Error::last_os_error(),
                original_resources: None,
            });
        }
        // SAFETY: DuplicateHandle returned exactly one owned process handle.
        let process = unsafe { OwnedHandle::from_raw_handle(duplicate) };
        let image = match program.reader().try_clone() {
            Ok(image) => image,
            Err(error) => {
                let mut close = crate::WindowsOriginalCloseAttempt::new();
                close.close_identity_handle(process);
                return Err(crate::WindowsOriginalResourceOpenFailure {
                    error,
                    original_resources: close.finish().err(),
                });
            }
        };
        let mut owner = Self {
            pid: child.id(),
            start: 0,
            image,
            process,
        };
        let checked = (|| {
            owner.start = owner.windows_start()?;
            owner.verify_live()
        })();
        if let Err(error) = checked {
            let mut close = crate::WindowsOriginalCloseAttempt::new();
            owner.close_into_attempt(&mut close);
            return Err(crate::WindowsOriginalResourceOpenFailure {
                error,
                original_resources: close.finish().err(),
            });
        }
        Ok(owner)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Hex avoids losing Windows FILETIME precision in JavaScript projections.
    pub fn process_start(&self) -> String {
        format!("{:016x}", self.start)
    }

    /// Wait only on the retained process object, so exit invalidation can wake
    /// immediately without a control refresh polling numeric process IDs.
    pub fn wait_ended(&self, timeout: std::time::Duration) -> io::Result<bool> {
        let timeout_ms = timeout.as_millis().min(1000) as u32;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{
                Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
                System::Threading::WaitForSingleObject,
            };
            // SAFETY: one retained process object, with a bounded kernel wait.
            match unsafe { WaitForSingleObject(self.process.as_raw_handle(), timeout_ms) } {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                _ => Err(io::Error::last_os_error()),
            }
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            let mut descriptor = libc::pollfd {
                fd: self.process.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one retained pidfd and a sized writable pollfd, bounded timeout.
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms as libc::c_int) };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(result != 0)
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        {
            let _ = timeout_ms;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "RPC owner proof unavailable",
            ))
        }
    }

    pub fn verify_live(&self) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::{
                Foundation::WAIT_TIMEOUT,
                System::Threading::{
                    GetProcessId, QueryFullProcessImageNameW, WaitForSingleObject,
                },
            };
            let handle = self.process.as_raw_handle();
            // SAFETY: the retained handle identifies one original process;
            // zero timeout cannot wait or substitute a reused numeric PID.
            if unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT
                // SAFETY: the retained live process handle has query rights.
                || unsafe { GetProcessId(handle) } != self.pid
                || self.windows_start()? != self.start
            {
                return Err(refused("managed RPC child ended or changed"));
            }
            let mut path = vec![0u16; 32768];
            let mut count = path.len() as u32;
            // SAFETY: path is a sized writable UTF-16 buffer, count is live,
            // and the retained process handle has query rights.
            if unsafe { QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut count) } == 0
            {
                return Err(io::Error::last_os_error());
            }
            use std::os::windows::ffi::OsStringExt;
            let path =
                std::path::PathBuf::from(std::ffi::OsString::from_wide(&path[..count as usize]));
            if !crate::regular_file_matches_path(&self.image, &path)? {
                return Err(refused("managed RPC child image differs from held pin"));
            }
            Ok(())
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
            let mut descriptor = libc::pollfd {
                fd: self.process.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one retained pidfd and a sized writable pollfd, zero timeout.
            let outcome = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if outcome < 0 {
                return Err(io::Error::last_os_error());
            }
            if outcome != 0 || self.linux_start()? != self.start {
                return Err(refused("managed RPC child ended or changed"));
            }
            let base = format!("/proc/{}", self.pid);
            let executable = std::fs::metadata(format!("{base}/exe"))?;
            let expected = self.image.metadata()?;
            let namespace = std::fs::metadata(format!("{base}/ns/net"))?;
            if (executable.dev(), executable.ino()) != (expected.dev(), expected.ino())
                || (namespace.dev(), namespace.ino()) != self.net_namespace
            {
                return Err(refused(
                    "managed RPC child pin or network namespace differs",
                ));
            }
            let status = bounded_file(&format!("{base}/status"), 65536)?;
            let status = std::str::from_utf8(&status).map_err(|_| refused("RPC process status"))?;
            let effective = status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|line| line.split_ascii_whitespace().nth(1))
                .and_then(|uid| uid.parse::<u32>().ok());
            if effective != Some(self.uid) {
                return Err(refused("managed RPC child local owner differs"));
            }
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RPC owner proof unavailable",
        ))
    }

    pub fn verify_listener(&self, endpoint: SocketAddr) -> io::Result<ManagedRpcBinding> {
        if !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err(refused("exact loopback RPC endpoint required"));
        }
        self.verify_live()?;
        #[cfg(windows)]
        let listener = self.windows_listener(endpoint)?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let listener = self.linux_listener(endpoint)?;
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        let listener = return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RPC owner proof unavailable",
        ));
        self.verify_live()?;
        Ok(ManagedRpcBinding {
            pid: self.pid,
            start: self.start,
            endpoint,
            listener,
        })
    }

    #[cfg(windows)]
    fn windows_start(&self) -> io::Result<u64> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        // SAFETY: four initialized FILETIME outputs and the retained query handle are live.
        if unsafe {
            GetProcessTimes(
                self.process.as_raw_handle(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    #[cfg(windows)]
    fn windows_listener(&self, endpoint: SocketAddr) -> io::Result<u64> {
        use std::{
            mem::size_of,
            net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6},
            ptr,
        };
        use windows_sys::Win32::{
            Foundation::ERROR_INSUFFICIENT_BUFFER,
            NetworkManagement::IpHelper::{
                GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
                TCP_TABLE_OWNER_PID_LISTENER,
            },
            Networking::WinSock::{AF_INET, AF_INET6},
        };
        let mut found = 0usize;
        for family in [AF_INET, AF_INET6] {
            let mut size = 0u32;
            // SAFETY: null asks only for the bounded table size; size is live.
            let outcome = unsafe {
                GetExtendedTcpTable(
                    ptr::null_mut(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if outcome != ERROR_INSUFFICIENT_BUFFER || size as usize > MAX_TABLE_BYTES || size < 4 {
                return Err(refused(
                    "RPC listener owner table unavailable or over limit",
                ));
            }
            // u64 storage provides sufficient alignment for every Windows table row.
            let mut storage = vec![0u64; (size as usize).div_ceil(8)];
            // SAFETY: the aligned buffer contains at least size writable bytes.
            let outcome = unsafe {
                GetExtendedTcpTable(
                    storage.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if outcome != 0 || size as usize > storage.len() * 8 {
                return Err(refused("RPC listener owner table changed or unavailable"));
            }
            let base = storage.as_ptr().cast::<u8>();
            // SAFETY: the size-checked table contains its initialized u32 header.
            let count = unsafe { ptr::read_unaligned(base.cast::<u32>()) } as usize;
            let row_size = if family == AF_INET {
                size_of::<MIB_TCPROW_OWNER_PID>()
            } else {
                size_of::<MIB_TCP6ROW_OWNER_PID>()
            };
            if count > 32768
                || count
                    .checked_mul(row_size)
                    .and_then(|bytes| bytes.checked_add(4))
                    .is_none_or(|bytes| bytes > size as usize)
            {
                return Err(refused("RPC listener owner table bounds"));
            }
            for index in 0..count {
                let (address, port, pid) = if family == AF_INET {
                    // SAFETY: the full row was checked within initialized table bytes.
                    let row = unsafe {
                        ptr::read_unaligned(
                            base.add(4 + index * row_size)
                                .cast::<MIB_TCPROW_OWNER_PID>(),
                        )
                    };
                    (
                        IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                        u16::from_be(row.dwLocalPort as u16),
                        row.dwOwningPid,
                    )
                } else {
                    // SAFETY: the full row was checked within initialized table bytes.
                    let row = unsafe {
                        ptr::read_unaligned(
                            base.add(4 + index * row_size)
                                .cast::<MIB_TCP6ROW_OWNER_PID>(),
                        )
                    };
                    let socket = SocketAddrV6::new(
                        Ipv6Addr::from(row.ucLocalAddr),
                        u16::from_be(row.dwLocalPort as u16),
                        0,
                        row.dwLocalScopeId,
                    );
                    if socket.ip().is_loopback()
                        && matches!(endpoint, SocketAddr::V6(expected) if expected.scope_id() != socket.scope_id())
                    {
                        continue;
                    }
                    (IpAddr::V6(*socket.ip()), socket.port(), row.dwOwningPid)
                };
                if port == endpoint.port() && (address == endpoint.ip() || address.is_unspecified())
                {
                    if address != endpoint.ip() || pid != self.pid {
                        return Err(refused(
                            "RPC listener belongs to a different process or bind",
                        ));
                    }
                    found += 1;
                }
            }
        }
        if found != 1 {
            return Err(refused("one exact managed RPC listener required"));
        }
        // Windows reports listener PID/endpoints, not a socket-inode identity.
        // The retained process creation identity is checked before and after.
        Ok(0)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn linux_start(&self) -> io::Result<u64> {
        let bytes = bounded_file(&format!("/proc/{}/stat", self.pid), 4096)?;
        let value = std::str::from_utf8(&bytes).map_err(|_| refused("RPC process stat"))?;
        value
            .rsplit_once(") ")
            .and_then(|(_, fields)| fields.split_ascii_whitespace().nth(19))
            .and_then(|ticks| ticks.parse().ok())
            .ok_or_else(|| refused("RPC process start identity unavailable"))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn linux_listener(&self, endpoint: SocketAddr) -> io::Result<u64> {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let mut listener = None;
        for (name, ipv6) in [("tcp", false), ("tcp6", true)] {
            let path = format!("/proc/{}/net/{name}", self.pid);
            let bytes = match bounded_file(&path, MAX_TABLE_BYTES) {
                Err(error) if ipv6 && error.kind() == io::ErrorKind::NotFound => continue,
                result => result?,
            };
            let text =
                std::str::from_utf8(&bytes).map_err(|_| refused("RPC socket table encoding"))?;
            let mut count = 0usize;
            for line in text.lines().skip(1) {
                count += 1;
                if count > 32768 {
                    return Err(refused("RPC socket table row limit"));
                }
                let fields: Vec<_> = line.split_ascii_whitespace().collect();
                if fields.len() < 10 || fields[3] != "0A" {
                    continue;
                }
                let Some((address, port)) = fields[1].split_once(':') else {
                    return Err(refused("RPC socket table endpoint"));
                };
                let port =
                    u16::from_str_radix(port, 16).map_err(|_| refused("RPC socket table port"))?;
                if port != endpoint.port() {
                    continue;
                }
                let address = if ipv6 {
                    if address.len() != 32 {
                        return Err(refused("RPC IPv6 socket table address"));
                    }
                    let mut bytes = [0u8; 16];
                    for (index, word) in address.as_bytes().chunks_exact(8).enumerate() {
                        let word = u32::from_str_radix(
                            std::str::from_utf8(word)
                                .map_err(|_| refused("RPC IPv6 socket table encoding"))?,
                            16,
                        )
                        .map_err(|_| refused("RPC IPv6 socket table address"))?;
                        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_ne_bytes());
                    }
                    IpAddr::V6(Ipv6Addr::from(bytes))
                } else {
                    let word = u32::from_str_radix(address, 16)
                        .map_err(|_| refused("RPC IPv4 socket table address"))?;
                    IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
                };
                if address != endpoint.ip() && !address.is_unspecified() {
                    continue;
                }
                let inode = fields[9]
                    .parse::<u64>()
                    .map_err(|_| refused("RPC socket inode"))?;
                let uid = fields[7]
                    .parse::<u32>()
                    .map_err(|_| refused("RPC socket owner"))?;
                if address != endpoint.ip()
                    || uid != self.uid
                    || inode == 0
                    || listener.replace(inode).is_some()
                {
                    return Err(refused("RPC listener bind or owner is ambiguous"));
                }
            }
        }
        let inode = listener.ok_or_else(|| refused("managed RPC listener absent"))?;
        let mut held = false;
        for (index, entry) in std::fs::read_dir(format!("/proc/{}/fd", self.pid))?.enumerate() {
            if index >= 4096 {
                return Err(refused("RPC child descriptor limit"));
            }
            let entry = entry?;
            let target = match std::fs::read_link(entry.path()) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                result => result?,
            };
            if target.to_str() == Some(format!("socket:[{inode}]").as_str()) {
                held = true;
            }
        }
        if !held {
            return Err(refused("RPC listener is not held by exact managed child"));
        }
        Ok(inode)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bounded_file(path: &str, limit: usize) -> io::Result<Vec<u8>> {
    use io::Read;
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(refused("RPC process observation byte limit"));
    }
    Ok(bytes)
}
