//! Actual original sentinel binding for all restored Journal CAS acquisitions.
use crate::{Journal, JournalError, Result};
use sync_extend_platform_fs::ReleasedOriginalCoordinationFile;

impl Journal {
    pub fn bind_original_cas_coordination(
        &mut self,
        original: ReleasedOriginalCoordinationFile,
    ) -> std::result::Result<(), (Box<ReleasedOriginalCoordinationFile>, JournalError)> {
        let validate = || -> Result<()> {
            self.verify_original_created_image()?;
            if self.original_cas_coordination.is_some() {
                return Err(JournalError::Invariant(
                    "original CAS sentinel already bound",
                ));
            }
            let path = self
                .database_path
                .parent()
                .ok_or(JournalError::Invariant(
                    "original CAS sentinel parent absent",
                ))?
                .join("cas-access.lock");
            original.verify(&path)?;
            Ok(())
        };
        if let Err(error) = validate() {
            return Err((Box::new(original), error));
        }
        self.original_cas_coordination = Some(original);
        Ok(())
    }
}
