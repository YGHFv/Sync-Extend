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
}

/// Dedicated storage-only routing. No Tokio runtime, helper or LocalSpace is
/// constructed; native retirement actions remain unavailable in this phase.
#[cfg(target_os = "linux")]
pub fn run_linux_owner_before_threads(
    config_path: &Path,
    action: &LinuxOwnerAction,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use sync_extend_reconcile::{read_linux_storage_owner_config, LinuxStorageOwner};
    let initialize = matches!(action, LinuxOwnerAction::Init);
    let config = read_linux_storage_owner_config(config_path)?;
    config.validate(initialize)?;
    let storage_config = config.storage.clone();
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
        let inventory = node.linux_storage_journal_inventory()?;
        let status = node.status()?;
        let history = if matches!(action, LinuxOwnerAction::Audit) {
            serde_json::json!({
                "admissions":node.storage_retirement_admissions()?,
                "owners":node.storage_retirement_owner_receipts()?,
                "payloads":node.storage_retirement_payloads()?,
                "disposals":node.storage_retirement_disposals()?,
                "terminals":node.storage_retirement_terminals()?,
            })
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
