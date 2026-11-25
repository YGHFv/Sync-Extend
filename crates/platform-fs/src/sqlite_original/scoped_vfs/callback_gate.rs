//! Global SQLite lookups may retain a VFS table after unregister. Keep only
//! bounded, reusable inert tables alive; never expose their live Rc policy.
use super::Policy;
use rusqlite::ffi;
use std::{
    cell::{Cell, UnsafeCell},
    ffi::{CStr, CString},
    io,
    marker::PhantomData,
    ops::Deref,
    rc::Rc,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

const MAXIMUM_CALLBACK_SLOTS: usize = 4096;

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalCallbackPurpose {
    MainOpen,
    RollbackReset,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct OriginalCallbackPermit {
    slot: usize,
    epoch: u64,
    purpose: OriginalCallbackPurpose,
}

thread_local! {
    static ORIGINAL_CALLBACK_PERMIT: Cell<Option<OriginalCallbackPermit>> =
        const { Cell::new(None) };
}

pub(in super::super) struct OriginalCallbackScope {
    previous: Option<OriginalCallbackPermit>,
    original: OriginalCallbackPermit,
    _same_thread: PhantomData<Rc<()>>,
}

impl Drop for OriginalCallbackScope {
    fn drop(&mut self) {
        ORIGINAL_CALLBACK_PERMIT.with(|permit| {
            if permit.get() == Some(self.original) {
                permit.set(self.previous);
            }
        });
    }
}

struct ActivePolicy {
    pointer: usize,
    epoch: u64,
    thread: u32,
    main_open_consumed: bool,
}

struct SlotState {
    last_epoch: u64,
    active: Option<ActivePolicy>,
}

pub(super) struct CallbackSlot {
    // SQLite alone mutates pNext under its STATIC_MAIN registry mutex. The
    // remaining ABI, name and pAppData never change after first registration.
    table: UnsafeCell<ffi::sqlite3_vfs>,
    name: CString,
    base: usize,
    gate: Mutex<SlotState>,
}

// SAFETY: stable tables/names are retained by the bounded process-lifetime pool.
// All active raw policy access is guarded and admitted only on its whole
// owner's current thread. The only mutable ABI field is SQLite's own pNext.
unsafe impl Send for CallbackSlot {}
unsafe impl Sync for CallbackSlot {}

pub(super) struct CallbackRegistration {
    slot: Arc<CallbackSlot>,
    epoch: u64,
    policy: usize,
    registered: bool,
    detached: bool,
}

pub(super) struct OriginalPolicyGuard<'a> {
    state: MutexGuard<'a, SlotState>,
    slot: usize,
}

impl Deref for OriginalPolicyGuard<'_> {
    type Target = Policy;

    fn deref(&self) -> &Policy {
        let active = self
            .state
            .active
            .as_ref()
            .expect("admitted original policy");
        // SAFETY: callback and owner guards hold the slot gate. The original Rc
        // remains in its whole context until this exact active pointer detaches.
        unsafe { &*(active.pointer as *const Policy) }
    }
}

impl OriginalPolicyGuard<'_> {
    fn permits(&self, purpose: OriginalCallbackPurpose) -> bool {
        let Some(active) = self.state.active.as_ref() else {
            return false;
        };
        let original = OriginalCallbackPermit {
            slot: self.slot,
            epoch: active.epoch,
            purpose,
        };
        ORIGINAL_CALLBACK_PERMIT.with(|permit| permit.get() == Some(original))
    }

    pub(super) fn take_single_main_open(&mut self) -> bool {
        if !self.permits(OriginalCallbackPurpose::MainOpen) {
            return false;
        }
        let Some(active) = self.state.active.as_mut() else {
            return false;
        };
        if active.main_open_consumed {
            return false;
        }
        active.main_open_consumed = true;
        true
    }

    pub(super) fn permits_rollback_reset(&self) -> bool {
        self.permits(OriginalCallbackPurpose::RollbackReset)
    }
}

fn pool() -> &'static Mutex<Vec<Arc<CallbackSlot>>> {
    static POOL: OnceLock<Mutex<Vec<Arc<CallbackSlot>>>> = OnceLock::new();
    POOL.get_or_init(|| Mutex::new(Vec::new()))
}

impl CallbackRegistration {
    /// The caller retains this same Policy in its private whole context until
    /// successful unregister and detach; no callback receives that Rc itself.
    pub(super) unsafe fn register(
        mut table: ffi::sqlite3_vfs,
        base: *mut ffi::sqlite3_vfs,
        policy: *const Policy,
    ) -> io::Result<Self> {
        if base.is_null() || policy.is_null() {
            return Err(io::Error::other(
                "original callback registration input absent",
            ));
        }
        let mut slots = pool()
            .lock()
            .map_err(|_| io::Error::other("original callback slot pool poisoned"))?;
        let mut selected = None;
        for slot in slots.iter() {
            if slot.base != base as usize {
                continue;
            }
            let Ok(mut state) = slot.gate.try_lock() else {
                continue;
            };
            if state.active.is_some() {
                continue;
            }
            let Some(epoch) = state.last_epoch.checked_add(1) else {
                continue;
            };
            state.last_epoch = epoch;
            state.active = Some(ActivePolicy {
                pointer: policy as usize,
                epoch,
                // SAFETY: pointer-free Windows thread identity.
                thread: unsafe { GetCurrentThreadId() },
                main_open_consumed: false,
            });
            selected = Some((Arc::clone(slot), epoch));
            break;
        }
        let (slot, epoch) = match selected {
            Some(value) => value,
            None => {
                if slots.len() == MAXIMUM_CALLBACK_SLOTS {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "bounded original callback slots exhausted before native xOpen",
                    ));
                }
                let index = slots.len();
                let name =
                    CString::new(format!("sync-original-{}-slot{index}", std::process::id()))
                        .map_err(|_| io::Error::other("bounded original callback slot name"))?;
                table.pNext = std::ptr::null_mut();
                table.zName = name.as_ptr();
                table.pAppData = std::ptr::null_mut();
                let slot = Arc::new(CallbackSlot {
                    table: UnsafeCell::new(table),
                    name,
                    base: base as usize,
                    gate: Mutex::new(SlotState {
                        last_epoch: 1,
                        active: Some(ActivePolicy {
                            pointer: policy as usize,
                            epoch: 1,
                            // SAFETY: pointer-free Windows thread identity.
                            thread: unsafe { GetCurrentThreadId() },
                            main_open_consumed: false,
                        }),
                    }),
                });
                // SAFETY: this fresh stable table is not globally visible yet.
                // Pool ownership is established before its first registration.
                unsafe {
                    (*slot.table.get()).pAppData =
                        Arc::as_ptr(&slot).cast_mut().cast::<std::ffi::c_void>();
                }
                slots.push(Arc::clone(&slot));
                (slot, 1)
            }
        };
        drop(slots);
        // No slot gate crosses a SQLite call which may invoke this slot.
        // makeDefault=0 preserves the existing default VFS.
        let registered = unsafe { ffi::sqlite3_vfs_register(slot.table.get(), 0) };
        if registered != ffi::SQLITE_OK {
            if let Ok(mut state) = slot.gate.lock() {
                if state.active.as_ref().is_some_and(|active| {
                    active.pointer == policy as usize && active.epoch == epoch
                }) {
                    state.active = None;
                }
            }
            return Err(io::Error::other(format!(
                "original callback VFS registration returned {registered}"
            )));
        }
        Ok(Self {
            slot,
            epoch,
            policy: policy as usize,
            registered: true,
            detached: false,
        })
    }

    pub(super) fn name(&self) -> &CStr {
        &self.slot.name
    }

    pub(super) fn slot(&self) -> Arc<CallbackSlot> {
        Arc::clone(&self.slot)
    }

    pub(super) fn lock_owner_on_slot<'a>(
        &self,
        slot: &'a CallbackSlot,
    ) -> io::Result<OriginalPolicyGuard<'a>> {
        if self.detached || !std::ptr::eq(slot, Arc::as_ptr(&self.slot)) {
            return Err(io::Error::other("same original callback slot absent"));
        }
        let mut state = slot
            .gate
            .lock()
            .map_err(|_| io::Error::other("original callback owner gate poisoned"))?;
        let active = state
            .active
            .as_mut()
            .filter(|active| active.pointer == self.policy && active.epoch == self.epoch)
            .ok_or_else(|| io::Error::other("original callback slot epoch differs"))?;
        // SAFETY: only the whole unique owner can migrate this authority.
        active.thread = unsafe { GetCurrentThreadId() };
        Ok(OriginalPolicyGuard {
            state,
            slot: slot as *const CallbackSlot as usize,
        })
    }

    pub(super) fn activate_current_thread(&self) -> io::Result<()> {
        let slot = self.slot();
        drop(self.lock_owner_on_slot(&slot)?);
        Ok(())
    }

    fn enter_original_scope(
        &self,
        purpose: OriginalCallbackPurpose,
    ) -> io::Result<OriginalCallbackScope> {
        let slot = self.slot();
        let owner = self.lock_owner_on_slot(&slot)?;
        if purpose == OriginalCallbackPurpose::MainOpen
            && owner
                .state
                .active
                .as_ref()
                .is_none_or(|active| active.main_open_consumed)
        {
            return Err(io::Error::other(
                "original main xOpen permit already consumed",
            ));
        }
        let original = OriginalCallbackPermit {
            slot: Arc::as_ptr(&self.slot) as usize,
            epoch: self.epoch,
            purpose,
        };
        drop(owner);
        let previous = ORIGINAL_CALLBACK_PERMIT.with(|permit| permit.replace(Some(original)));
        Ok(OriginalCallbackScope {
            previous,
            original,
            _same_thread: PhantomData,
        })
    }

    pub(super) fn begin_single_main_open(&self) -> io::Result<OriginalCallbackScope> {
        self.enter_original_scope(OriginalCallbackPurpose::MainOpen)
    }

    pub(super) fn begin_original_rollback_reset(&self) -> io::Result<OriginalCallbackScope> {
        self.enter_original_scope(OriginalCallbackPurpose::RollbackReset)
    }

    pub(super) fn unregister(&mut self) -> io::Result<()> {
        if self.registered {
            // SQLite's registry operation never invokes a VFS callback. This
            // exact stable table remains alive even for a delayed foreign find.
            let closed = unsafe { ffi::sqlite3_vfs_unregister(self.slot.table.get()) };
            if closed != ffi::SQLITE_OK {
                return Err(io::Error::other(format!(
                    "original SQLite VFS unregister returned {closed}"
                )));
            }
            self.registered = false;
        }
        Ok(())
    }

    pub(super) fn detach(&mut self, owner: &mut OriginalPolicyGuard<'_>) -> io::Result<()> {
        if self.registered
            || owner.slot != Arc::as_ptr(&self.slot) as usize
            || owner
                .state
                .active
                .as_ref()
                .is_none_or(|active| active.pointer != self.policy || active.epoch != self.epoch)
        {
            return Err(io::Error::other(
                "original callback detach identity differs",
            ));
        }
        // Clearing under the same gate precedes freeing the private Rc/context.
        // The bounded stable table/name retains no native or policy capability.
        owner.state.active = None;
        self.detached = true;
        Ok(())
    }
}

/// Reject a foreign thread before dereferencing any live Policy or Rc state.
pub(super) unsafe fn callback_policy(
    vfs: *mut ffi::sqlite3_vfs,
) -> Option<OriginalPolicyGuard<'static>> {
    if vfs.is_null() {
        return None;
    }
    // SAFETY: every globally visible callback table comes from the bounded
    // process-lifetime pool and stores that same stable slot in pAppData.
    let slot = unsafe { ((*vfs).pAppData as *const CallbackSlot).as_ref() }?;
    let state = slot.gate.lock().ok()?;
    let active = state.active.as_ref()?;
    // SAFETY: pointer-free current Windows thread identity.
    if active.thread != unsafe { GetCurrentThreadId() } {
        return None;
    }
    Some(OriginalPolicyGuard {
        state,
        slot: slot as *const CallbackSlot as usize,
    })
}

/// These callbacks use only the immutable process-lifetime builtin VFS. A
/// foreign memory/empty/failed-open DB never touches the original Policy.
pub(super) unsafe fn callback_base(vfs: *mut ffi::sqlite3_vfs) -> *mut ffi::sqlite3_vfs {
    if vfs.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: stable bounded slot; this base is SQLite's process-lifetime table.
    let Some(slot) = (unsafe { ((*vfs).pAppData as *const CallbackSlot).as_ref() }) else {
        return std::ptr::null_mut();
    };
    slot.base as *mut ffi::sqlite3_vfs
}
