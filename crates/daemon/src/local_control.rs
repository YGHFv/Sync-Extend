//! Optional local lifecycle control; authentication is the kernel peer UID.
use super::webdav::GatewayProbe;
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use sync_extend_platform_fs::{LocalControlListener, LocalControlOperation};

pub static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
pub static READY: AtomicBool = AtomicBool::new(false);
const MAX_RESPONSE: usize = 4096;

fn encode_response(response: &mut serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec(response)?;
    if bytes.len() >= MAX_RESPONSE {
        response["dashboard"] = serde_json::Value::Null;
        response["dashboard_state"] = "over_limit".into();
        bytes = serde_json::to_vec(response)?;
    }
    if bytes.len() >= MAX_RESPONSE {
        return Err(serde_json::Error::io(std::io::Error::other(
            "local control response exceeds its existing bound",
        )));
    }
    bytes.push(b'\n');
    Ok(bytes)
}

pub struct LocalControl {
    done: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    gateway: GatewaySlot,
    _dashboard: super::management::LocalDashboardRegistration,
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
        let dashboard = super::management::register_local_dashboard();
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
                                    super::easytier::clear_observations();
                                }
                                let mut response = serde_json::json!({
                                    "format_version":1,
                                    "owner_pid":std::process::id(),
                                    "ready":READY.load(Ordering::Acquire),
                                    "stop_requested":STOP_REQUESTED.load(Ordering::Acquire),
                                    "kernel_owner_authenticated":true,
                                    "dashboard":null,
                                    "dashboard_state":"not_requested",
                                });
                                if response["stop_requested"] == true {
                                    response["dashboard_state"] = "stopping".into();
                                } else if response["ready"] != true {
                                    response["dashboard_state"] = "not_ready".into();
                                } else if operation == LocalControlOperation::Status {
                                    let (dashboard, state) = super::management::local_dashboard();
                                    response["dashboard"] =
                                        dashboard.unwrap_or(serde_json::Value::Null);
                                    response["dashboard_state"] = state.into();
                                }
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
                                // A deferred/stopping resource must not retain the
                                // sample copied before the final readiness check.
                                let stopping = STOP_REQUESTED.load(Ordering::Acquire)
                                    || super::management::control_stop_requested();
                                let ready = READY.load(Ordering::Acquire);
                                response["stop_requested"] = stopping.into();
                                response["ready"] = ready.into();
                                if stopping || !ready {
                                    response["dashboard"] = serde_json::Value::Null;
                                    response["dashboard_state"] =
                                        if stopping { "stopping" } else { "not_ready" }.into();
                                    if response["webdav"].is_object() {
                                        response["webdav"]["export_accessible"] = false.into();
                                        response["webdav"]["url"] = serde_json::Value::Null;
                                    }
                                }
                                match encode_response(&mut response) {
                                    Ok(bytes) => {
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
            _dashboard: dashboard,
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
    if !value["dashboard_state"].is_null() {
        let state = value["dashboard_state"]
            .as_str()
            .ok_or("local dashboard state differs")?;
        let dashboard = &value["dashboard"];
        let available = state == "available";
        if !matches!(
            state,
            "available"
                | "no_observation"
                | "not_ready"
                | "stopping"
                | "not_requested"
                | "over_limit"
                | "unavailable"
        ) || (available
            && (value["ready"] != true
                || value["stop_requested"] != false
                || dashboard["dashboard_format_version"] != 1
                || dashboard["remote_backup_complete"] != false
                || serde_json::to_vec(dashboard)?.len() > super::management::MAX_LOCAL_DASHBOARD))
            || (!available && !dashboard.is_null())
        {
            return Err("local dashboard differs from its bounded owner state".into());
        }
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
