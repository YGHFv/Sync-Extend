//! Process termination used by foreground, KSU and container lifecycle paths.
use std::io;

#[cfg(unix)]
async fn local_control_requested() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    while !super::local_control::STOP_REQUESTED.load(std::sync::atomic::Ordering::Acquire) {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    std::future::pending::<()>().await;
}

/// Resource readiness is separate from parsing configuration and constructing a runtime.
pub fn ready() -> io::Result<()> {
    started(true)
}

/// Report a controllable service before its first worktree scan has completed.
pub fn started(resources_ready: bool) -> io::Result<()> {
    #[cfg(windows)]
    sync_extend_platform_fs::report_service_ready()?;
    set_resources_ready(resources_ready);
    Ok(())
}

pub fn set_resources_ready(ready: bool) {
    if ready {
        super::management::resources_ready();
    } else {
        super::management::resources_deferred();
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    super::local_control::READY.store(ready, std::sync::atomic::Ordering::Release);
}

pub async fn requested() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            signal = terminate.recv() => {
                signal.ok_or_else(|| io::Error::other("termination signal stream closed"))?;
                Ok(())
            }
            _ = local_control_requested() => Ok(()),
            _ = management_stop_requested() => Ok(()),
        }
    }
    #[cfg(windows)]
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = management_stop_requested() => Ok(()),
            _ = async {
                loop {
                    if sync_extend_platform_fs::service_stop_requested() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            } => Ok(()),
        }
    }
    #[cfg(not(any(unix, windows)))]
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = management_stop_requested() => Ok(()),
    }
}

async fn management_stop_requested() {
    while !super::management::control_stop_requested() {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}
