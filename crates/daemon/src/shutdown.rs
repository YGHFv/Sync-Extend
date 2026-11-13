//! Process termination used by foreground, KSU and container lifecycle paths.
use std::io;

/// Resource readiness is separate from parsing configuration and constructing a runtime.
pub fn ready() -> io::Result<()> {
    #[cfg(windows)]
    sync_extend_platform_fs::report_service_ready()?;
    Ok(())
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
        }
    }
    #[cfg(windows)]
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
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
    tokio::signal::ctrl_c().await
}
