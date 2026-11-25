//! Original CAS callbacks share an explicitly owned reader terminal.
mod deployment_resources;
pub use deployment_resources::OriginalManagedCasResourceCloseFailure;
pub(crate) use deployment_resources::{
    OriginalManagedCasReadPreparationFailure, OriginalManagedCasReadResources,
};

impl crate::LocalSpace {
    pub(crate) fn existing_original_managed_cas(
        data_dir: &std::path::Path,
        journal: &sync_extend_journal::Journal,
    ) -> crate::Result<(sync_extend_cas::Cas, OriginalManagedCasReadResources)> {
        deployment_resources::assemble(data_dir, journal)
    }

    pub(crate) fn existing_original_managed_cas_retaining(
        data_dir: &std::path::Path,
        journal: &sync_extend_journal::Journal,
    ) -> std::result::Result<
        (sync_extend_cas::Cas, OriginalManagedCasReadResources),
        OriginalManagedCasReadPreparationFailure,
    > {
        deployment_resources::assemble_retaining(data_dir, journal)
    }
}
