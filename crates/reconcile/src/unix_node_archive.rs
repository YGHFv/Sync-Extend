//! Shared bounded image semantics; Unix original-resource restoration is separate.
//! Reusing validation grants none of the Windows acquisition/creator authority.
#[path = "node_archive/layout.rs"]
mod layout;
#[path = "node_archive/file_content.rs"]
mod file_content;
#[path = "node_archive/verifier.rs"]
mod verifier;
#[path = "node_archive/current_manifest.rs"]
mod current_manifest;
#[path = "node_archive/completion_codec.rs"]
mod completion_codec;
#[path = "node_archive/completion_frames.rs"]
mod completion_frames;
mod generation_budget;
pub use layout::{ArchiveBounds, ArchiveRole, FramedNodeArchive};
pub use verifier::VerifiedNodeStateArchive;
mod plan;
pub use plan::{PreparedUnixNodeRestore, UnixNodeRestoreBounds};
mod restore;
pub use restore::{ClosedOriginalUnixRestore, OriginalUnixRestoredNode, OriginalUnixRestoreFailure};
