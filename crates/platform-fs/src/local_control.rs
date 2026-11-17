//! Kernel-credential control bound to one held private state directory.
//! Abstract Unix sockets have no stale pathname or reusable PID-file authority.
use std::{
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::MetadataExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalControlOperation {
    Status,
    Stop,
}

fn refuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn private_directory(path: &Path, retained: &File) -> io::Result<(u64, u64, u32)> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(refuse("exact absolute local control directory required"));
    }
    let current = std::fs::symlink_metadata(path)?;
    let original = retained.metadata()?;
    // SAFETY: geteuid is a pointer-free query of this process's actual identity.
    let uid = unsafe { libc::geteuid() };
    if !current.is_dir()
        || current.file_type().is_symlink()
        || !original.is_dir()
        || original.uid() != uid
        || original.mode() & 0o077 != 0
        || current.dev() != original.dev()
        || current.ino() != original.ino()
        || current.uid() != uid
        || current.mode() & 0o077 != 0
    {
        return Err(refuse("original private local control directory changed"));
    }
    Ok((original.dev(), original.ino(), uid))
}

fn address(identity: (u64, u64, u32)) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let name = format!(
        "sync-extend.control.v1.{}.{}.{}",
        identity.2, identity.0, identity.1
    );
    // SAFETY: a zero-initialized sockaddr_un has valid integer and byte fields.
    let mut value: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if name.len() + 1 > value.sun_path.len() {
        return Err(refuse("local control address byte bound"));
    }
    value.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in value.sun_path[1..].iter_mut().zip(name.bytes()) {
        *target = byte as libc::c_char;
    }
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
    let length = libc::socklen_t::try_from(length)
        .map_err(|_| refuse("local control address integer bound"))?;
    Ok((value, length))
}

fn peer(stream: &UnixStream, owner: u32) -> io::Result<u32> {
    let mut value = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut size = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .map_err(|_| refuse("local control credential size"))?;
    // SAFETY: live Unix socket; output points to a correctly sized ucred and
    // getsockopt receives the exact writable size field for SO_PEERCRED.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            value.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if size as usize != std::mem::size_of::<libc::ucred>() {
        return Err(refuse("local control credential shape differs"));
    }
    // SAFETY: successful getsockopt returned exactly one initialized ucred.
    let value = unsafe { value.assume_init() };
    if value.uid != owner || value.pid <= 1 {
        return Err(refuse("local control peer has another kernel owner"));
    }
    u32::try_from(value.pid).map_err(|_| refuse("local control kernel PID bound"))
}

pub struct LocalControlListener {
    listener: UnixListener,
    directory: File,
    path: PathBuf,
    identity: (u64, u64, u32),
}

impl LocalControlListener {
    pub fn bind(path: &Path) -> io::Result<Self> {
        let directory = crate::acquire_sidecar_owner(path)?;
        let identity = private_directory(path, &directory)?;
        let (address, length) = address(identity)?;
        // SAFETY: pointer-free socket creation yields one owned close-on-exec fd.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the newly created descriptor transfers sole close ownership.
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        // SAFETY: the sockaddr_un remains live for this bind call, and length
        // contains precisely the abstract-name bytes initialized above.
        if unsafe {
            libc::bind(
                listener.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: live bound listener and fixed bounded backlog, no pointers.
        if unsafe { libc::listen(listener.as_raw_fd(), 4) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            listener,
            directory,
            path: path.to_owned(),
            identity,
        })
    }

    pub fn accept(&self) -> io::Result<Option<LocalControlConnection>> {
        if private_directory(&self.path, &self.directory)? != self.identity {
            return Err(refuse("local control original directory identity differs"));
        }
        let (stream, _) = match self.listener.accept() {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        peer(&stream, self.identity.2)?;
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_millis(250)))?;
        stream.set_write_timeout(Some(Duration::from_millis(250)))?;
        Ok(Some(LocalControlConnection { stream }))
    }
}

pub struct LocalControlConnection {
    stream: UnixStream,
}

impl LocalControlConnection {
    pub fn operation(&mut self) -> io::Result<LocalControlOperation> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0];
            if self.stream.read(&mut byte)? != 1 || bytes.len() >= 7 {
                return Err(refuse("bounded local control command required"));
            }
            bytes.push(byte[0]);
            if byte[0] == b'\n' {
                return match bytes.as_slice() {
                    b"STATUS\n" => Ok(LocalControlOperation::Status),
                    b"STOP\n" => Ok(LocalControlOperation::Stop),
                    _ => Err(refuse("unknown local control command")),
                };
            }
        }
    }

    pub fn respond(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
            return Err(refuse("bounded complete local control response required"));
        }
        self.stream.write_all(bytes)
    }
}

pub struct LocalControlResponse {
    pub peer_pid: u32,
    pub bytes: Vec<u8>,
}

pub fn request_local_control(
    path: &Path,
    operation: LocalControlOperation,
) -> io::Result<LocalControlResponse> {
    // A client holds the exact directory but does not acquire the server lock.
    let directory = super::unix_noreplace::open_control_directory(path)?;
    let identity = private_directory(path, &directory)?;
    let (address, length) = address(identity)?;
    // SAFETY: pointer-free socket creation yields one owned close-on-exec fd.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the new descriptor transfers sole close ownership to UnixStream.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    // SAFETY: live sockaddr_un with the precisely initialized abstract-name length.
    if unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let peer_pid = peer(&stream, identity.2)?;
    stream.write_all(match operation {
        LocalControlOperation::Status => b"STATUS\n",
        LocalControlOperation::Stop => b"STOP\n",
    })?;
    let mut bytes = Vec::new();
    (&mut stream).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err(refuse("local control response byte bound or incomplete"));
    }
    if private_directory(path, &directory)? != identity {
        return Err(refuse("local control client directory changed"));
    }
    Ok(LocalControlResponse { peer_pid, bytes })
}
