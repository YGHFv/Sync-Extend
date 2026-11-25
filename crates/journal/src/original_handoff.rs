//! Original CREATE-issued main handoff retained through readonly Journal assembly.
use crate::{Journal, JournalError, NodeInspectionBounds, OriginalReadonlyJournalOpenFailure};
use sync_extend_platform_fs::OriginalSqliteMainHandoff;
impl Journal {
    pub fn reopen_original_handoff_readonly(
        main: OriginalSqliteMainHandoff,
        bounds: NodeInspectionBounds,
    ) -> std::result::Result<Self, OriginalReadonlyJournalOpenFailure> {
        let prepare = || -> crate::Result<sync_extend_platform_fs::ReleasedOriginalFileIdentity> {
            main.verify()?;
            if !main.read_protection_established() {
                return Err(JournalError::Invariant(
                    "original main capability lacks actual readonly protection",
                ));
            }
            Ok(main.retain_read_identity_observer()?)
        };
        let observer = match prepare() {
            Ok(observer) => observer,
            Err(error) => {
                return Err(
                    OriginalReadonlyJournalOpenFailure::before_native(error).retain_main(main)
                );
            }
        };
        let mut journal = match Self::reopen_original_readonly_image(main.path(), bounds, observer)
        {
            Ok(journal) => journal,
            Err(original) => return Err(original.retain_main(main)),
        };
        if let Err(error) = journal.verify_original_created_image() {
            return Err(
                OriginalReadonlyJournalOpenFailure::from_failed_journal(journal, error)
                    .retain_main(main),
            );
        }
        journal.original_main_handoff = Some(main);
        Ok(journal)
    }
}
