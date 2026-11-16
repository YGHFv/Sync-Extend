//! Original CREATE-issued main handoff retained through readonly Journal assembly.
use crate::{Journal, JournalError, NodeInspectionBounds};
use sync_extend_platform_fs::OriginalSqliteMainHandoff;
impl Journal {
    pub fn reopen_original_handoff_readonly(
        main: OriginalSqliteMainHandoff,
        bounds: NodeInspectionBounds,
    ) -> std::result::Result<Self, (Box<OriginalSqliteMainHandoff>, JournalError)> {
        let attempt = || -> crate::Result<Self> {
            main.verify()?;
            if !main.read_protection_established() {
                return Err(JournalError::Invariant(
                    "original main capability lacks actual readonly protection",
                ));
            }
            let observer = main.retain_read_identity_observer()?;
            let journal = Self::reopen_original_readonly_image(main.path(), bounds, observer)
                .map_err(|(_, error)| error)?;
            journal.verify_original_created_image()?;
            Ok(journal)
        };
        match attempt() {
            Ok(mut journal) => {
                journal.original_main_handoff = Some(main);
                Ok(journal)
            }
            Err(error) => Err((Box::new(main), error)),
        }
    }
}
