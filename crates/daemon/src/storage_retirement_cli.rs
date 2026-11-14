//! Explicit operator-selected storage retirement actions.
use clap::Subcommand;
use std::path::Path;
use sync_extend_reconcile::StorageNode;

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
