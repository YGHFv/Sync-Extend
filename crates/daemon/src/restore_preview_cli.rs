//! Explicit readonly preview arguments; source handles never use mutable open().
use super::{Cli, Command};
use std::path::Path;
use sync_extend_reconcile::{ReadOnlyLocalSpace, RestorePreviewSelection};

/// Reject every unrelated global filesystem input before main can enter owner
/// preparation, deployment or the ordinary local-limits reader.
pub fn precheck(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(&cli.command, Command::RestorePreview { .. }) {
        return Ok(());
    }
    ReadOnlyLocalSpace::restore_preview_available()?;
    if cli.limits.is_some() {
        return Err(
            "readonly restore preview requires its explicit --budgets and refuses global --limits"
                .into(),
        );
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if cli.control_directory.is_some() {
        return Err("readonly restore preview refuses global --control-directory".into());
    }
    #[cfg(target_os = "linux")]
    if cli.linux_namespace_config.is_some() {
        return Err("readonly restore preview refuses global --linux-namespace-config".into());
    }
    Ok(())
}

pub fn run(
    data_dir: &Path,
    snapshot: &str,
    baseline: Option<&str>,
    path: Option<&str>,
    budgets: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    ReadOnlyLocalSpace::restore_preview_available()?;
    let preview = ReadOnlyLocalSpace::restore_preview_with_budget_file(
        data_dir,
        snapshot.parse()?,
        baseline.map(str::parse).transpose()?,
        match path {
            Some(path) => RestorePreviewSelection::File {
                path: sync_extend_core_model::PortablePath::new(path)?,
            },
            None => RestorePreviewSelection::Full,
        },
        budgets,
    )?;
    let json = serde_json::to_string(&preview)?;
    if json.len() + 1 != preview.output_bytes_including_lf
        || json.len() + 1 > preview.output_byte_limit
    {
        return Err("readonly restore preview encoded response exceeds budget".into());
    }
    // Compact UTF-8 with exactly one LF; the byte limit covers the actual wire.
    use std::io::Write;
    let mut output = std::io::stdout().lock();
    output.write_all(json.as_bytes())?;
    output.write_all(b"\n")?;
    Ok(())
}
