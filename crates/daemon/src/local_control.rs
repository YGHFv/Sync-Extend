//! Optional local lifecycle control; authentication is the kernel peer UID.
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
}

impl LocalControl {
    pub fn start(directory: &Path) -> std::io::Result<Self> {
        let listener = LocalControlListener::bind(directory)?;
        let done = Arc::new(AtomicBool::new(false));
        let closing = Arc::clone(&done);
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
                                let response = serde_json::json!({
                                    "format_version":1,
                                    "owner_pid":std::process::id(),
                                    "ready":READY.load(Ordering::Acquire),
                                    "stop_requested":STOP_REQUESTED.load(Ordering::Acquire),
                                    "kernel_owner_authenticated":true,
                                });
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
        })
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
    Ok(value)
}
