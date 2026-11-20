//! Optional local lifecycle control; authentication is the kernel peer UID.
use super::webdav::GatewayProbe;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use sync_extend_platform_fs::{LocalControlListener, LocalControlOperation};

pub static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
pub static READY: AtomicBool = AtomicBool::new(false);

pub struct LocalControl {
    done: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    gateway: GatewaySlot,
}

pub type GatewaySlot = Arc<Mutex<Option<Arc<GatewayProbe>>>>;

pub struct GatewayRegistration(GatewaySlot);

impl GatewayRegistration {
    pub fn register(slot: GatewaySlot, gateway: GatewayProbe) -> Self {
        if let Ok(mut current) = slot.lock() {
            *current = Some(Arc::new(gateway));
        }
        Self(slot)
    }
}

impl Drop for GatewayRegistration {
    fn drop(&mut self) {
        if let Ok(mut current) = self.0.lock() {
            *current = None;
        }
    }
}

impl LocalControl {
    pub fn start(directory: &Path) -> std::io::Result<Self> {
        let listener = LocalControlListener::bind(directory)?;
        let done = Arc::new(AtomicBool::new(false));
        let closing = Arc::clone(&done);
        let gateway: GatewaySlot = Arc::default();
        let live_gateway = Arc::clone(&gateway);
        let worker = thread::Builder::new()
            .name("syncd-local-control".to_owned())
            .spawn(move || {
                while !closing.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok(Some(mut connection)) => match connection.operation() {
                            Ok(operation) => {
                                if operation == LocalControlOperation::Stop {
                                    STOP_REQUESTED.store(true, Ordering::Release);
                                }
                                let mut response = serde_json::json!({
                                    "format_version":1,
                                    "owner_pid":std::process::id(),
                                    "ready":READY.load(Ordering::Acquire),
                                    "stop_requested":STOP_REQUESTED.load(Ordering::Acquire),
                                    "kernel_owner_authenticated":true,
                                });
                                if let LocalControlOperation::ProbeWebDav(export) = operation {
                                    let url = if response["ready"] == true
                                        && response["stop_requested"] == false
                                    {
                                        let live =
                                            live_gateway.lock().ok().and_then(|slot| slot.clone());
                                        live.and_then(|gateway| gateway.test(&export).ok())
                                    } else {
                                        None
                                    };
                                    response["webdav"] = serde_json::json!({
                                        "export": export,
                                        "export_accessible": url.is_some(),
                                        "url": url,
                                        "remote_backup_complete": false,
                                    });
                                }
                                match serde_json::to_vec(&response) {
                                    Ok(mut bytes) => {
                                        bytes.push(b'\n');
                                        if let Err(error) = connection.respond(&bytes) {
                                            eprintln!(
                                                "syncd: local control response failed: {error}"
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        eprintln!("syncd: local control response failed: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!("syncd: local control command refused: {error}");
                            }
                        },
                        Ok(None) => thread::sleep(Duration::from_millis(20)),
                        Err(error) => {
                            eprintln!("syncd: local control peer refused: {error}");
                            thread::sleep(Duration::from_millis(20));
                        }
                    }
                }
            })?;
        Ok(Self {
            done,
            thread: Some(worker),
            gateway,
        })
    }

    pub fn gateway_slot(&self) -> GatewaySlot {
        Arc::clone(&self.gateway)
    }
}

impl Drop for LocalControl {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
        if let Some(worker) = self.thread.take() {
            if worker.join().is_err() {
                eprintln!("syncd: local control worker failed during shutdown");
            }
        }
    }
}

pub fn request(
    directory: &Path,
    operation: LocalControlOperation,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let probe = match &operation {
        LocalControlOperation::ProbeWebDav(name) => Some(name.clone()),
        _ => None,
    };
    let response = sync_extend_platform_fs::request_local_control(directory, operation)?;
    let value: serde_json::Value = serde_json::from_slice(&response.bytes)?;
    if value["format_version"] != 1
        || value["owner_pid"].as_u64() != Some(u64::from(response.peer_pid))
        || value["kernel_owner_authenticated"] != true
        || !value["ready"].is_boolean()
        || !value["stop_requested"].is_boolean()
    {
        return Err("local control reply differs from connected kernel owner".into());
    }
    if let Some(name) = probe {
        let tested = &value["webdav"];
        let url_valid = match tested["export_accessible"].as_bool() {
            Some(true) => tested["url"].is_string(),
            Some(false) => tested["url"].is_null(),
            None => false,
        };
        if tested["export"] != name || !url_valid || tested["remote_backup_complete"] != false {
            return Err("local control probe reply differs from the selected export".into());
        }
    }
    Ok(value)
}
