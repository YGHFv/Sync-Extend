//! SCM callbacks remain in the narrow platform adapter; no detached helper process.
use std::{
    ffi::c_void,
    io,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        Mutex, OnceLock,
    },
};
use windows_sys::Win32::{
    Foundation::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR},
    System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS,
    },
};

type Runner = Box<dyn FnOnce(ServiceReporter) -> io::Result<()> + Send>;
static RUNNER: OnceLock<Mutex<Option<Runner>>> = OnceLock::new();
static NAME: OnceLock<Vec<u16>> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
static HANDLE: AtomicUsize = AtomicUsize::new(0);
static STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);
static EXIT: AtomicU32 = AtomicU32::new(1);
static STATUS_GATE: Mutex<()> = Mutex::new(());

pub fn service_stop_requested() -> bool {
    STOP.load(Ordering::Acquire)
}

pub struct ServiceReporter;
impl ServiceReporter {
    /// Called after the role has opened its resources or bound its listener.
    pub fn running(&self) -> io::Result<()> {
        status(Some(SERVICE_RUNNING), 0)
    }
}

/// Foreground processes have no SCM status handle and keep their original behavior.
pub fn report_service_ready() -> io::Result<()> {
    if HANDLE.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    ServiceReporter.running()
}

fn status(next: Option<u32>, failure: u32) -> io::Result<()> {
    let _gate = STATUS_GATE
        .lock()
        .map_err(|_| io::Error::other("service status gate poisoned"))?;
    let state = next.unwrap_or_else(|| STATE.load(Ordering::Acquire));
    if next.is_some()
        && matches!(state, SERVICE_START_PENDING | SERVICE_RUNNING)
        && service_stop_requested()
    {
        return Err(io::Error::other("service stopped during startup"));
    }
    let handle = HANDLE.load(Ordering::Acquire) as *mut c_void;
    if handle.is_null() {
        return Err(io::Error::other("SCM status handle absent"));
    }
    let value = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if failure == 0 {
            0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: failure,
        dwCheckPoint: u32::from(matches!(
            state,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING
        )),
        dwWaitHint: if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            60_000
        } else {
            0
        },
    };
    // SAFETY: SCM issued this status handle; initialized status lives through the call.
    if unsafe { SetServiceStatus(handle, &value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    STATE.store(state, Ordering::Release);
    Ok(())
}

unsafe extern "system" fn control(
    command: u32,
    _event: u32,
    _data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match command {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::Release);
            status(Some(SERVICE_STOP_PENDING), 0).map_or(1, |_| 0)
        }
        SERVICE_CONTROL_INTERROGATE => status(None, 0).map_or(1, |_| 0),
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let Some(name) = NAME.get() else { return };
    // SAFETY: terminated immutable service name and static callback remain live
    // until dispatcher completion; callback receives no borrowed Rust context.
    let handle =
        unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), ptr::null()) };
    if handle.is_null() {
        EXIT.store(1, Ordering::Release);
        return;
    }
    HANDLE.store(handle as usize, Ordering::Release);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        status(Some(SERVICE_START_PENDING), 0)?;
        let runner = RUNNER
            .get()
            .ok_or_else(|| io::Error::other("service runner absent"))?
            .lock()
            .map_err(|_| io::Error::other("service runner poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("service runner already consumed"))?;
        std::thread::Builder::new()
            .name("syncd-scm-main".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || runner(ServiceReporter))?
            .join()
            .map_err(|_| io::Error::other("service runtime thread panicked"))?
    }));
    let exit = u32::from(!matches!(outcome, Ok(Ok(()))));
    EXIT.store(exit, Ordering::Release);
    let _ = status(Some(SERVICE_STOPPED), exit);
    HANDLE.store(0, Ordering::Release);
}

/// Must be invoked only by the native service command, once per process.
pub fn run_windows_service(
    name: &str,
    runner: impl FnOnce(ServiceReporter) -> io::Result<()> + Send + 'static,
) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(io::Error::other("bounded ASCII service name required"));
    }
    NAME.set(name.encode_utf16().chain(Some(0)).collect())
        .map_err(|_| io::Error::other("service dispatcher already initialized"))?;
    RUNNER
        .set(Mutex::new(Some(Box::new(runner))))
        .map_err(|_| io::Error::other("service runner already initialized"))?;
    STOP.store(false, Ordering::Release);
    let mut name = NAME.get().unwrap().clone();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: null-terminated two-row dispatcher table and service name stay live
    // through this blocking call; static callbacks contain all application panics.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if EXIT.load(Ordering::Acquire) != 0 {
        return Err(io::Error::other("native service exited with failure"));
    }
    Ok(())
}
