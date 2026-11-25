//! End only actual owned Windows HANDLEs. No pathname or reopening operation.
use crate::{LockedDirectory, WindowsProtectedArtifactParent};
use std::{
    fs::File,
    io,
    net::{TcpListener, TcpStream},
    os::windows::io::{FromRawHandle, FromRawSocket, IntoRawHandle, IntoRawSocket},
};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Networking::WinSock::{closesocket, WSAGetLastError};
use windows_sys::Win32::{
    Foundation::{ERROR_BROKEN_PIPE, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE},
    System::Pipes::PeekNamedPipe,
};

/// Only successful actual CloseHandle calls construct this witness. It grants
/// no replacement owner, creator, namespace, history or restart permission.
pub struct ClosedWindowsOriginalResources {
    handles: usize,
}

/// A rejected native open has already attempted the actual terminal of its
/// original HANDLE. A failed terminal retains that same HANDLE.
pub struct WindowsOriginalResourceOpenFailure {
    pub error: io::Error,
    pub original_resources: Option<WindowsOriginalResourceCloseFailure>,
}

impl WindowsOriginalResourceOpenFailure {
    pub fn retain_and_report(self) -> io::Error {
        if let Some(original) = self.original_resources {
            original.retain_until_process_exit();
        }
        self.error
    }
}
impl ClosedWindowsOriginalResources {
    pub fn actual_closed_handles(&self) -> usize {
        self.handles
    }
}

/// Failed original HANDLEs and borrowed original artifact parent scopes remain
/// owned here. This value has no serializer, clone or new-owner constructor.
pub struct WindowsOriginalResourceCloseFailure {
    pub error: io::Error,
    pub actual_closed_handles: usize,
    original_files: Vec<File>,
    original_artifact_parents: Vec<WindowsProtectedArtifactParent>,
}
impl std::fmt::Debug for WindowsOriginalResourceCloseFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("WindowsOriginalResourceCloseFailure")
            .field("error", &self.error)
            .field("actual_closed_handles", &self.actual_closed_handles)
            .field(
                "original_resource_groups_retained",
                &self.retained_resource_groups(),
            )
            .finish()
    }
}
impl WindowsOriginalResourceCloseFailure {
    pub fn retained_resource_groups(&self) -> usize {
        self.original_files.len() + self.original_artifact_parents.len()
    }

    /// Retry only resource ending on the same actual retained objects. The
    /// first failure remains recorded even if every later close succeeds.
    pub fn close_remaining(self) -> Self {
        let mut attempt = WindowsOriginalCloseAttempt::new();
        attempt.actual_closed_handles = self.actual_closed_handles;
        attempt.note_error(self.error);
        for file in self.original_files {
            attempt.close_file(file);
        }
        for parent in self.original_artifact_parents {
            attempt.close_artifact_parent(parent);
        }
        match attempt.finish() {
            Err(failure) => failure,
            Ok(_) => unreachable!("the retained first close error cannot disappear"),
        }
    }

    /// A terminal caller can report uncertainty and retain originals until the
    /// owning process exits. Drop is never presented as a successful close.
    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> io::Error {
        let error = match self.error.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(self.error.kind(), self.error.to_string()),
        };
        self.retain_until_process_exit();
        error
    }
}

/// Aggregates independent owned resources so one close failure cannot skip
/// the actual close of the remaining originals.
pub struct WindowsOriginalCloseAttempt {
    first_error: Option<io::Error>,
    actual_closed_handles: usize,
    original_files: Vec<File>,
    original_artifact_parents: Vec<WindowsProtectedArtifactParent>,
}
impl Default for WindowsOriginalCloseAttempt {
    fn default() -> Self {
        Self::new()
    }
}
impl WindowsOriginalCloseAttempt {
    pub fn new() -> Self {
        Self {
            first_error: None,
            actual_closed_handles: 0,
            original_files: Vec::new(),
            original_artifact_parents: Vec::new(),
        }
    }
    pub fn note_error(&mut self, error: io::Error) {
        self.first_error.get_or_insert(error);
    }
    /// Only platform-native owners call this after CloseHandle has actually
    /// succeeded on their original non-File HANDLE, such as a mapping section.
    pub(crate) fn note_actual_handle_closed(&mut self) {
        self.actual_closed_handles += 1;
    }
    pub(crate) fn append_original_handle_prefix(&mut self, handles: usize) {
        self.actual_closed_handles += handles;
    }
    pub(crate) fn original_close_error(&self) -> Option<&io::Error> {
        self.first_error.as_ref()
    }
    pub fn has_retained_originals(&self) -> bool {
        !self.original_files.is_empty() || !self.original_artifact_parents.is_empty()
    }
    pub fn close_file(&mut self, file: File) {
        match close_owned_original_file(file) {
            Ok(()) => self.actual_closed_handles += 1,
            Err((original, error)) => {
                self.note_error(error);
                self.original_files.push(original);
            }
        }
    }
    /// Consume a retained identity HANDLE, including a same-file identity
    /// wrapper. It ends that original HANDLE without opening another object.
    pub fn close_identity_handle(&mut self, original: impl IntoRawHandle) {
        let handle = original.into_raw_handle();
        // SAFETY: IntoRawHandle transfers ownership of this original HANDLE.
        // On failure the same HANDLE is retained solely for terminal close.
        if unsafe { CloseHandle(handle) } == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: CloseHandle failed and ownership of the original remains.
            let original = unsafe { File::from_raw_handle(handle) };
            self.note_error(error);
            self.original_files.push(original);
        } else {
            self.actual_closed_handles += 1;
        }
    }
    pub fn close_directory(&mut self, directory: LockedDirectory) {
        match directory.close_original() {
            Ok(()) => self.actual_closed_handles += 1,
            Err((original, error)) => {
                self.note_error(error);
                self.original_files
                    .push(original.into_terminal_original_file());
            }
        }
    }
    pub fn close_artifact_parent(&mut self, parent: WindowsProtectedArtifactParent) {
        match parent.close_retaining() {
            Ok(closed) => self.actual_closed_handles += closed.actual_closed_handles(),
            Err(failure) => self.append_failure(failure),
        }
    }
    pub fn append_failure(&mut self, failure: WindowsOriginalResourceCloseFailure) {
        self.note_error(failure.error);
        self.actual_closed_handles += failure.actual_closed_handles;
        self.original_files.extend(failure.original_files);
        self.original_artifact_parents
            .extend(failure.original_artifact_parents);
    }
    pub fn append_result(
        &mut self,
        result: Result<ClosedWindowsOriginalResources, WindowsOriginalResourceCloseFailure>,
    ) {
        match result {
            Ok(closed) => self.actual_closed_handles += closed.actual_closed_handles(),
            Err(failure) => self.append_failure(failure),
        }
    }
    pub(crate) fn retain_shared_artifact_parent(
        &mut self,
        parent: WindowsProtectedArtifactParent,
        error: io::Error,
    ) {
        self.note_error(error);
        self.original_artifact_parents.push(parent);
    }
    pub fn finish(
        self,
    ) -> Result<ClosedWindowsOriginalResources, WindowsOriginalResourceCloseFailure> {
        match self.first_error {
            Some(error) => Err(WindowsOriginalResourceCloseFailure {
                error,
                actual_closed_handles: self.actual_closed_handles,
                original_files: self.original_files,
                original_artifact_parents: self.original_artifact_parents,
            }),
            None => Ok(ClosedWindowsOriginalResources {
                handles: self.actual_closed_handles,
            }),
        }
    }
}

/// Issued only after closesocket succeeds on the original owned socket.
pub struct ClosedWindowsOriginalSocket {
    _private: (),
}

pub fn close_original_tcp_listener(
    listener: TcpListener,
) -> Result<ClosedWindowsOriginalSocket, (TcpListener, io::Error)> {
    let socket = listener.into_raw_socket();
    // SAFETY: the original owned TcpListener has transferred this socket.
    if unsafe { closesocket(socket as usize) } != 0 {
        // SAFETY: this is the error from the failed closesocket above.
        let error = io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
        // SAFETY: failed closesocket retains the same original owned socket.
        Err((unsafe { TcpListener::from_raw_socket(socket) }, error))
    } else {
        Ok(ClosedWindowsOriginalSocket { _private: () })
    }
}

pub fn close_original_tcp_stream(
    stream: TcpStream,
) -> Result<ClosedWindowsOriginalSocket, (TcpStream, io::Error)> {
    let socket = stream.into_raw_socket();
    // SAFETY: the original owned TcpStream has transferred this socket.
    if unsafe { closesocket(socket as usize) } != 0 {
        // SAFETY: this is the error from the failed closesocket above.
        let error = io::Error::from_raw_os_error(unsafe { WSAGetLastError() });
        // SAFETY: failed closesocket retains the same original owned socket.
        Err((unsafe { TcpStream::from_raw_socket(socket) }, error))
    } else {
        Ok(ClosedWindowsOriginalSocket { _private: () })
    }
}

/// Owns the same original inherited stdin pipe. No duplicate HANDLE, background
/// reader, pathname opening or replacement process is involved.
pub struct OriginalDeploymentOwnerInput {
    original: Option<File>,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(kind: u32) -> HANDLE;
    fn SetStdHandle(kind: u32, handle: HANDLE) -> i32;
}

impl OriginalDeploymentOwnerInput {
    pub fn take_original_stdin_pipe() -> io::Result<Self> {
        const STD_INPUT_HANDLE: u32 = (-10i32) as u32;
        // SAFETY: the fixed selector queries this process's original stdin.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "original stdin pipe is absent",
            ));
        }
        // SAFETY: GetStdHandle returned the current process's live HANDLE.
        if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "owner control requires its original stdin pipe",
            ));
        }
        // SAFETY: detach only this process's same original stdin HANDLE before
        // transferring it. No replacement input or new HANDLE is acquired.
        if unsafe { SetStdHandle(STD_INPUT_HANDLE, std::ptr::null_mut()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the original pipe has been detached and ownership is unique.
        let original = unsafe { File::from_raw_handle(handle) };
        Ok(Self {
            original: Some(original),
        })
    }

    /// Reads at most bytes actually available in this original pipe. EOF and
    /// read errors remain distinct; waiting cannot block native service stop.
    pub fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        use std::{io::Read, os::windows::io::AsRawHandle};
        let original = self.original.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "original owner input already closed",
            )
        })?;
        let mut available = 0u32;
        // SAFETY: the actual original pipe and sized count output stay live.
        if unsafe {
            PeekNamedPipe(
                original.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
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
        if available == 0 {
            return Ok(None);
        }
        let maximum = buffer.len().min(available as usize);
        original.read(&mut buffer[..maximum]).map(Some)
    }

    pub fn close_retaining(
        mut self,
    ) -> Result<ClosedWindowsOriginalResources, WindowsOriginalResourceCloseFailure> {
        let mut close = WindowsOriginalCloseAttempt::new();
        if let Some(original) = self.original.take() {
            close.close_file(original);
        }
        close.finish()
    }
}

impl Drop for OriginalDeploymentOwnerInput {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            let mut close = WindowsOriginalCloseAttempt::new();
            close.close_file(original);
            if let Err(original) = close.finish() {
                original.retain_until_process_exit();
            }
        }
    }
}

pub(crate) fn close_owned_original_file(file: File) -> Result<(), (File, io::Error)> {
    let handle = file.into_raw_handle();
    // SAFETY: this HANDLE has just been consumed from its actual owned File.
    // No other object is opened or acquired, and the failed HANDLE is restored.
    if unsafe { CloseHandle(handle) } == 0 {
        let error = io::Error::last_os_error();
        // SAFETY: CloseHandle failed, so the same original HANDLE remains ours.
        Err((unsafe { File::from_raw_handle(handle) }, error))
    } else {
        Ok(())
    }
}
