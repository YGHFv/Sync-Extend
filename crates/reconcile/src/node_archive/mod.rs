//! Consistent stopped-writer node images; complete node recovery remains separate.
mod capture;
mod captured_file;
mod created_section;
mod file_content;
mod layout;
mod verifier;
pub use capture::CapturedNodeArchive;
pub use created_section::CreatedNodeSection;
pub use layout::{ArchiveBounds, ArchiveRole, FramedNodeArchive};
pub use verifier::VerifiedNodeStateArchive;

mod created_bytes;
mod created_current_file;
mod current_manifest;
mod restore_layout;
pub use created_current_file::CreatedNodeCurrentFile;
pub use restore_layout::{NodeRestoreDirectory, NodeRestoreFile, NodeRestoreLayout};

mod evidence;
mod external;
mod ledger;
pub use evidence::NodeLedgerEvidence;
pub use ledger::{InitializedNodeLedger, LedgerBounds, NodeRestoreAttempt, NodeRestoreLedger};

mod roots;
pub use roots::CreatedNodeRestoreRoots;

mod marker;
pub use marker::CreatedNodeWorktreeMarker;

mod directories;
mod files;
mod layout_mapping;
mod portable_source;
pub use directories::CreatedNodeDirectorySet;
pub use files::CreatedNodeFileSet;
pub use layout_mapping::{NodeRestoreMappedLayout, NodeRestoreSlot, NodeTargetRoot};

mod assembly;
mod data_locks;
mod local_space;
mod read_content;
pub use assembly::OriginalNodeReadAssembly;
pub use data_locks::CreatedNodeDataLocks;
pub use local_space::OriginalRestoredLocalSpace;
mod inventory;

mod preflight;
mod prepared_files;
pub use preflight::PreparedOriginalNodeRestore;

mod completion;
mod durable_schema;
mod restart_classification;
pub use completion::{OriginalNodeCompletionManifest, OriginalNodeCompletionObservation};
pub use ledger::OriginalNodeCompletionEvidence;
pub use restart_classification::OriginalNodeRestartClassification;

mod completion_codec;

mod restart_evidence;

mod node_write_transition;
pub use local_space::{
    OriginalNodeWriteCloseFailure, OriginalNodeWriteClosed, OriginalNodeWriteOpenFailure,
    OriginalNodeWriteSession,
};
pub use node_write_transition::OriginalNodeWriteFrameClassification;

mod config_mapping;
pub use config_mapping::ExplicitOriginalConfigMapping;

mod config_install;

mod original_content;

pub use node_write_transition::ReacquiredClosedNodeReadScope;

pub use node_write_transition::ReacquiredClosedNodeLockedReadScope;

pub use node_write_transition::FreshRecoveredNodeSqliteSession;

pub use node_write_transition::FreshDurableRecoveredSession;

#[cfg(windows)]
pub use node_write_transition::FreshRecoveredNodeWalSession;

#[cfg(windows)]
pub use node_write_transition::RecoveredWalFrameClassification;

#[cfg(windows)]
pub use node_write_transition::FreshRecoveredNodeWalV2Session;

#[cfg(windows)]
pub use node_write_transition::RecoveredHistoryCloseClassification;

#[cfg(windows)]
pub use node_write_transition::RecoveredLiveHistoryBinding;
