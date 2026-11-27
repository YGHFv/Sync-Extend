//! Shared bounded tombstone dispatch for original SQLite VFS registrations.
//!
//! SQLite's global registry lets callers cache a table beyond unregister. A
//! published table/name/dispatch therefore stays permanently allocated, while
//! the native owner clears this pointer before releasing its original state.
//! A foreign thread never receives a pointer to non-Sync native state.
use std::{
    ffi::{c_void, CString},
    io,
    ptr::NonNull,
    sync::atomic::{AtomicPtr, AtomicU64, Ordering},
};

pub(crate) const MAX_REGISTRATIONS: u64 = 1024;
pub(crate) const MAX_DISPATCH_BYTES: usize = 512;
pub(crate) const MAX_NAME_BYTES: usize = 96;

static NEXT_REGISTRATION: AtomicU64 = AtomicU64::new(1);
static NEXT_THREAD: AtomicU64 = AtomicU64::new(1);
thread_local! {
    // Exhaustion and TLS teardown reject use. A token is never recycled or
    // wrapped, so a later OS thread cannot inherit a prior native owner.
    static THREAD_TOKEN: Option<u64> = NEXT_THREAD
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_add(1))
        .ok();
}

/// Reserve before allocating any registration payload. Failed opens consume
/// their slot too, so the permanent payload is at most 1024 * 512 bytes,
/// excluding allocator bookkeeping. Registered names use this unique number.
pub(crate) fn reserve_registration() -> io::Result<u64> {
    if std::mem::size_of::<rusqlite::ffi::sqlite3_vfs>()
        + std::mem::size_of::<Dispatch>()
        + std::mem::size_of::<CString>()
        + MAX_NAME_BYTES
        > MAX_DISPATCH_BYTES
    {
        return Err(io::Error::other("bounded original SQLite dispatch payload"));
    }
    NEXT_REGISTRATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
            (next <= MAX_REGISTRATIONS).then_some(next + 1)
        })
        .map_err(|_| io::Error::other("original SQLite registration budget exhausted"))
}

pub(crate) struct Dispatch {
    process: u32,
    thread_token: u64,
    state: AtomicPtr<c_void>,
}

impl Dispatch {
    pub(crate) fn new() -> io::Result<Self> {
        let thread_token = THREAD_TOKEN
            .try_with(|token| *token)
            .ok()
            .flatten()
            .ok_or_else(|| io::Error::other("original SQLite thread identity unavailable"))?;
        Ok(Self {
            process: std::process::id(),
            thread_token,
            state: AtomicPtr::new(std::ptr::null_mut()),
        })
    }

    pub(crate) fn on_original_thread(&self) -> bool {
        self.process == std::process::id()
            && THREAD_TOKEN
                .try_with(|token| *token == Some(self.thread_token))
                .unwrap_or(false)
    }

    pub(crate) fn publish(&self, state: *mut c_void) {
        self.state.store(state, Ordering::Release);
    }

    pub(crate) fn clear(&self) {
        self.state.store(std::ptr::null_mut(), Ordering::Release);
    }

    /// Only the owning thread can dereference returned state. That same thread
    /// clears the pointer after unregister and before releasing native state.
    pub(crate) fn original_state(&self) -> Option<NonNull<c_void>> {
        if !self.on_original_thread() {
            return None;
        }
        NonNull::new(self.state.load(Ordering::Acquire))
    }
}
