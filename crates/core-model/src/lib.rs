pub mod config;
pub mod ids;
pub mod operation;
pub mod path;

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
