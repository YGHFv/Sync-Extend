use crate::{Journal, JournalError, Publication, Result};
use rusqlite::OptionalExtension;
use sync_extend_core_model::EntryId;

impl Journal {
    /// Absence is distinct from malformed existing metadata or a database error.
    pub fn find_publication(&self, id: &EntryId) -> Result<Option<Publication>> {
        let exists: Option<String> = self
            .connection
            .query_row(
                "SELECT transaction_id FROM publications WHERE transaction_id=?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(stored) = exists {
            if stored != id.as_str() {
                return Err(JournalError::Invariant(
                    "publication lookup identity mismatch",
                ));
            }
            return self.publication(id).map(Some);
        }
        Ok(None)
    }
}
