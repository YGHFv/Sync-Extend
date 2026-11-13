//! Read-only borrowed views keep exclusive original handles out of path reopens.
use sync_extend_journal::{
    NativePublicationFileObservation, NativePublicationFileView, RemoteReplaceFileView,
    TreeNativeExecutionFileView, TreeNativeOwnerFileView,
};

pub(crate) trait NativeFileView {
    fn verify(&self) -> sync_extend_journal::Result<()>;
    fn observe_file(
        &self,
        path: &std::path::Path,
    ) -> sync_extend_journal::Result<Option<NativePublicationFileObservation>>;
    fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64>;
}

macro_rules! readonly_view {
    ($view:ident) => {
        impl NativeFileView for $view<'_> {
            fn verify(&self) -> sync_extend_journal::Result<()> {
                self.verify()
            }
            fn observe_file(
                &self,
                path: &std::path::Path,
            ) -> sync_extend_journal::Result<Option<NativePublicationFileObservation>> {
                self.observe_file(path)
            }
            fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64> {
                self.remaining_internal_bytes()
            }
        }
    };
}
readonly_view!(NativePublicationFileView);
readonly_view!(RemoteReplaceFileView);
readonly_view!(TreeNativeExecutionFileView);

impl NativeFileView for TreeNativeOwnerFileView<'_> {
    fn verify(&self) -> sync_extend_journal::Result<()> {
        self.verify()
    }
    fn observe_file(
        &self,
        path: &std::path::Path,
    ) -> sync_extend_journal::Result<Option<NativePublicationFileObservation>> {
        self.observe_file(path)
    }
    fn remaining_internal_bytes(&self) -> sync_extend_journal::Result<u64> {
        // The owner has only a completed marker. TREE content obligations
        // are supplied separately by the audited preparation.
        Ok(0)
    }
}
