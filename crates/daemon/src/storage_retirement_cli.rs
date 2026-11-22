//! Explicit operator-selected storage retirement actions.
use clap::Subcommand;
use std::path::Path;
use sync_extend_reconcile::StorageNode;

#[cfg(target_os = "linux")]
#[derive(Subcommand)]
pub enum LinuxOwnerAction {
    /// Initialize a fresh empty metadata root with exactly three storage identity rows.
    Init,
    /// Read storage status through its reacquired original full-FD Journal.
    Status,
    /// Audit original metadata and retained storage history without native actions.
    Audit,
    /// Inspect one retired original and report its complete stable expectations.
    Inspect {
        #[arg(long)]
        storage_id: String,
        #[arg(long)]
        content_id: String,
    },
    /// Admit a versioned fresh intent after actual exclusive original inspection.
    Admit {
        #[arg(long)]
        intent: std::path::PathBuf,
    },
    /// Replay an already stored complete request using only verified metadata.
    Replay {
        #[arg(long)]
        request: std::path::PathBuf,
    },
    /// Read immutable Unix retirement requests and cancellation history.
    History,
    /// Cancel a Unix fence before native activation.
    Cancel {
        #[arg(long)]
        request_id: String,
    },
}

#[cfg(target_os = "linux")]
enum ParsedLinuxOwnerAction {
    Init,
    Status,
    Audit,
    Inspect(
        sync_extend_core_model::ContentId,
        sync_extend_core_model::ContentId,
    ),
    Admit(Box<sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementIntent>),
    Replay(Box<sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementRequest>),
    History,
    Cancel(sync_extend_core_model::EntryId),
}

#[cfg(target_os = "linux")]
fn bounded_unix_input<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> Result<T, Box<dyn std::error::Error>> {
    use std::io::Read;
    let limit =
        sync_extend_core_model::storage_retirement_unix::UNIX_STORAGE_RETIREMENT_REQUEST_BYTES;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("bounded nonempty Unix retirement input required".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Dedicated before-threads storage routing. A fresh intent is materialized
/// inside this one live owner; complete requests have a separate replay mode.
#[cfg(target_os = "linux")]
pub fn run_linux_owner_before_threads(
    config_path: &Path,
    action: &LinuxOwnerAction,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use sync_extend_reconcile::{read_linux_storage_owner_config, LinuxStorageOwner};
    // Parse both complete typed inputs and IDs before owner/native acquisition.
    let parsed = match action {
        LinuxOwnerAction::Init => ParsedLinuxOwnerAction::Init,
        LinuxOwnerAction::Status => ParsedLinuxOwnerAction::Status,
        LinuxOwnerAction::Audit => ParsedLinuxOwnerAction::Audit,
        LinuxOwnerAction::Inspect {
            storage_id,
            content_id,
        } => ParsedLinuxOwnerAction::Inspect(storage_id.parse()?, content_id.parse()?),
        LinuxOwnerAction::Admit { intent } => {
            ParsedLinuxOwnerAction::Admit(Box::new(bounded_unix_input(intent)?))
        }
        LinuxOwnerAction::Replay { request } => {
            ParsedLinuxOwnerAction::Replay(Box::new(bounded_unix_input(request)?))
        }
        LinuxOwnerAction::History => ParsedLinuxOwnerAction::History,
        LinuxOwnerAction::Cancel { request_id } => {
            ParsedLinuxOwnerAction::Cancel(request_id.parse()?)
        }
    };
    let initialize = matches!(&parsed, ParsedLinuxOwnerAction::Init);
    let config = read_linux_storage_owner_config(config_path)?;
    config.validate(initialize)?;
    let storage_config = config.storage.clone();
    if matches!(
        &parsed,
        ParsedLinuxOwnerAction::Inspect(..)
            | ParsedLinuxOwnerAction::Admit(..)
            | ParsedLinuxOwnerAction::Cancel(..)
    ) && config.format_version != 2
    {
        return Err(
            "original Unix inspection and fresh admission require an explicit v2 owner".into(),
        );
    }
    match &parsed {
        ParsedLinuxOwnerAction::Admit(intent) => intent.validate(
            &storage_config,
            config
                .expected_device
                .as_ref()
                .ok_or("actual storage device expectation required")?,
        )?,
        ParsedLinuxOwnerAction::Replay(request) => request.validate(
            &storage_config,
            config
                .expected_device
                .as_ref()
                .ok_or("actual storage device expectation required")?,
        )?,
        _ => {}
    }
    let owner = Arc::new(if initialize {
        LinuxStorageOwner::prepare_new(config)?
    } else {
        LinuxStorageOwner::reopen_existing(config)?
    });
    let metadata_before_journal_open = owner.observation()?.metadata;
    let opened = if initialize {
        StorageNode::initialize_with_linux_storage_owner(storage_config.clone(), owner.clone())
    } else {
        StorageNode::open_with_linux_storage_owner(storage_config.clone(), owner.clone())
    };
    let report = (|| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let node = opened?;
        let result = match &parsed {
            ParsedLinuxOwnerAction::Init | ParsedLinuxOwnerAction::Status => {
                serde_json::Value::Null
            }
            ParsedLinuxOwnerAction::Audit => serde_json::json!({
                "admissions":node.storage_retirement_admissions()?,
                "owners":node.storage_retirement_owner_receipts()?,
                "payloads":node.storage_retirement_payloads()?,
                "disposals":node.storage_retirement_disposals()?,
                "terminals":node.storage_retirement_terminals()?,
                "unix_admissions":node.unix_storage_retirement_admissions()?,
            }),
            ParsedLinuxOwnerAction::Inspect(storage_id, content_id) => {
                let inspection =
                    node.inspect_unix_retired_storage_object(storage_id, content_id)?;
                let observed = serde_json::to_value(inspection.observation()?);
                let closed = inspection.close();
                match (observed, closed) {
                    (Ok(observation), Ok(())) => serde_json::json!({
                        "observation":observation, "original_inspection_closed":true,
                    }),
                    (Err(error), Ok(())) => return Err(error.into()),
                    (Ok(_), Err(error)) => return Err(error.into()),
                    (Err(error), Err(closed)) => {
                        return Err(format!(
                            "{error}; original inspection closure refused: {closed}"
                        )
                        .into())
                    }
                }
            }
            ParsedLinuxOwnerAction::Admit(intent) => {
                serde_json::to_value(node.admit_unix_storage_retirement_intent(intent)?)?
            }
            ParsedLinuxOwnerAction::Replay(request) => {
                serde_json::to_value(node.replay_unix_storage_retirement(request)?)?
            }
            ParsedLinuxOwnerAction::History => {
                serde_json::to_value(node.unix_storage_retirement_admissions()?)?
            }
            ParsedLinuxOwnerAction::Cancel(request_id) => {
                serde_json::to_value(node.cancel_unix_storage_retirement(request_id)?)?
            }
        };
        let inventory = node.linux_storage_journal_inventory()?;
        let status = if matches!(
            &parsed,
            ParsedLinuxOwnerAction::Init
                | ParsedLinuxOwnerAction::Status
                | ParsedLinuxOwnerAction::Audit
        ) {
            Some(node.status()?)
        } else {
            None
        };
        let history = if matches!(&parsed, ParsedLinuxOwnerAction::Audit) {
            result.clone()
        } else {
            serde_json::Value::Null
        };
        Ok(serde_json::json!({
            "status":status,
            "owner":owner.observation()?,
            "metadata_before_journal_open":metadata_before_journal_open,
            "journal":{
                "schema_version":inventory.schema_version(),
                "tables":inventory.tables().len(),
                "stored_rows":inventory.rows().len(),
                "logical_bytes":inventory.logical_bytes(),
                "fingerprint":inventory.fingerprint(),
                "local_state_rows":inventory.rows().iter().filter(|row| row.table()=="local_state").count(),
            },
            "retirement_result":result,
            "retirement_history":history,
            "restore_authority":false,
            "native_authority":false,
            "cleanup_authority":false,
            "pending_resume_authority":false,
        }))
    })();
    let owner = Arc::try_unwrap(owner)
        .map_err(|_| "storage-only node retained its live owner after closure")?;
    let closed = owner.finish();
    match (report, closed) {
        (Ok(report), Ok(closed)) => {
            super::print(&serde_json::json!({"result":report,"closed":closed}))?;
            Ok(())
        }
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(error), Err(closed)) => Err(format!(
            "{error}; storage-only original owner closure also refused: {closed}"
        )
        .into()),
    }
}

#[derive(Subcommand)]
pub enum Action {
    /// Read retained admission, original owner, payload and terminal history.
    Audit,
    /// Create the original owner marker for one admitted request.
    #[cfg(windows)]
    CreateOwner {
        #[arg(long)]
        request_id: String,
    },
    /// Move one exact admitted payload into quarantine without overwrite.
    #[cfg(windows)]
    Quarantine {
        #[arg(long)]
        request_id: String,
    },
    /// Restore one exact quarantined payload without overwrite.
    #[cfg(windows)]
    Restore {
        #[arg(long)]
        request_id: String,
    },
    /// Delete one exact quarantined payload and close its original owner marker.
    #[cfg(windows)]
    Dispose {
        #[arg(long)]
        request_id: String,
    },
    /// Close the original owner marker after exact payload restoration.
    #[cfg(windows)]
    CloseRestored {
        #[arg(long)]
        request_id: String,
    },
    /// Release one content fence after its exact native closure is recorded.
    Release {
        #[arg(long)]
        request_id: String,
    },
}

pub fn run(config: &Path, action: Action) -> Result<(), Box<dyn std::error::Error>> {
    // Reject malformed IDs before provisioning or opening storage.
    let id = match &action {
        Action::Audit => None,
        Action::Release { request_id } => {
            Some(request_id.parse::<sync_extend_core_model::EntryId>()?)
        }
        #[cfg(windows)]
        Action::CreateOwner { request_id }
        | Action::Quarantine { request_id }
        | Action::Restore { request_id }
        | Action::Dispose { request_id }
        | Action::CloseRestored { request_id } => {
            Some(request_id.parse::<sync_extend_core_model::EntryId>()?)
        }
    };
    let node = StorageNode::open(super::storage::load(config)?)?;
    match action {
        Action::Audit => super::print(&serde_json::json!({
            "admissions":node.storage_retirement_admissions()?,
            "owners":node.storage_retirement_owner_receipts()?,
            "payloads":node.storage_retirement_payloads()?,
            "disposals":node.storage_retirement_disposals()?,
            "terminals":node.storage_retirement_terminals()?,
        }))?,
        #[cfg(windows)]
        Action::CreateOwner { .. } => {
            let owner =
                node.create_storage_retirement_owner(id.as_ref().ok_or("request ID required")?)?;
            owner.verify_original()?;
            super::print(owner.receipt())?;
        }
        #[cfg(windows)]
        Action::Quarantine { .. } => super::print(
            &node
                .quarantine_storage_retirement_payload(id.as_ref().ok_or("request ID required")?)?,
        )?,
        #[cfg(windows)]
        Action::Restore { .. } => super::print(
            &node.restore_storage_retirement_payload(id.as_ref().ok_or("request ID required")?)?,
        )?,
        #[cfg(windows)]
        Action::Dispose { .. } => super::print(
            &node.dispose_storage_retirement_payload(id.as_ref().ok_or("request ID required")?)?,
        )?,
        #[cfg(windows)]
        Action::CloseRestored { .. } => super::print(
            &node.close_restored_storage_retirement(id.as_ref().ok_or("request ID required")?)?,
        )?,
        Action::Release { .. } => super::print(
            &node.release_storage_retirement_terminal(id.as_ref().ok_or("request ID required")?)?,
        )?,
    }
    Ok(())
}
