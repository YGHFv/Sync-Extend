pub mod config;
pub mod gc_recovery;
pub mod ids;
pub mod limits;
pub mod operation;
pub mod original_retention;
pub mod path;
pub mod persisted_rename;
pub mod reference_owner;
pub mod tree_coordinator_lifecycle;
pub mod tree_execution_records;
pub mod tree_final_description;
pub mod tree_original_disposition;
pub mod tree_original_reference;
pub mod tree_owner_marker;
pub mod tree_restore;
pub mod tree_restore_execution_intent;
pub mod tree_restore_history;
pub mod tree_restore_identity;

pub use ids::*;
pub use operation::*;
pub use path::PortablePath;

pub const FORMAT_VERSION: u32 = 1;
pub const PROTOCOL_VERSION: u32 = 1;
pub const EASYTIER_VERSION: &str = "2.6.4";

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("invalid identifier")]
    InvalidId,
    #[error("invalid portable path: {0}")]
    InvalidPath(&'static str),
    #[error("invalid data: {0}")]
    InvalidData(&'static str),
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("operating system random generator failed")]
    Random,
}

pub type Result<T> = std::result::Result<T, ModelError>;
