//! Before ARM, closing the preparation pipe exits without native or process effects.
use std::{
    fs::File,
    io::{self, Read},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

pub struct OutsidePreparationGate {
    control: File,
}

impl OutsidePreparationGate {
    pub fn new(control: File) -> io::Result<Self> {
        super::control_boundary(&control)?;
        Ok(Self { control })
    }

    /// Observe the explicit bounded ARM token. False is a cancelled startup;
    /// it never permits owner signalling, freeze, thaw, mutation or cleanup.
    pub fn wait_arm(mut self) -> io::Result<bool> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut token = [0u8; 5];
        let mut length = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let millis = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;
            let mut descriptor = libc::pollfd {
                fd: self.control.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one live read-only pipe descriptor and correctly sized
            // pollfd output; timeout is bounded before this pointer-taking call.
            let observed = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if observed < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if observed == 0 {
                return Ok(false);
            }
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(super::refusal("preparation control descriptor invalid"));
            }
            let count = self.control.read(&mut token[length..])?;
            if count == 0 {
                return Ok(length == 4 && token[..4] == *b"ARM\n");
            }
            length += count;
            if length > 4 || token[..length] != b"ARM\n"[..length] {
                return Err(super::refusal("exact preparation ARM token required"));
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }
}
