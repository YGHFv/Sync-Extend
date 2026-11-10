mod conflict_resolution;
mod connection;
mod identity;
mod metadata_cycle;
mod operation_batch;
mod signed;
mod tls;
mod wire;

pub use conflict_resolution::{
    verify_equivalent_file_resolutions, verify_received_resolution_prefix,
    EquivalentFileResolutions, FileResolutionPayload, ReceivedResolutionPrefix,
    SignedFileResolution, MAX_EQUIVALENT_RESOLVERS,
};
pub use connection::{Connection, Listener, MAX_BLOCK_BYTES, MAX_CONTROL_BYTES};
pub use identity::{PeerIdentity, TransportIdentity};
pub use metadata_cycle::{MetadataCycleHello, MAX_METADATA_CYCLE_ROUNDS};
pub use operation_batch::{
    OperationBatchRequest, OperationReceiveReceipt, SignedOperationBatch,
    SignedOperationReceiveReceipt,
};
pub use signed::{Hello, Receipt, ReceiptState, SignedHello, SignedOperation, SignedReceipt};
pub use wire::{FileOffer, FileRequest, FileResponse, SignedFileOffer, MAX_OFFER_BYTES};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS failed: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate creation failed: {0}")]
    Certificate(#[from] rcgen::Error),
    #[error("invalid transport model: {0}")]
    Model(#[from] sync_extend_core_model::ModelError),
    #[error("transport serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("transport authorization failed: {0}")]
    Authorization(&'static str),
    #[error("transport resource limit exceeded: {0}")]
    Limit(&'static str),
    #[error("transport protocol violation: {0}")]
    Protocol(&'static str),
    #[error("QUIC connection failed: {0}")]
    Connection(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;
