//! Borrowed audit implementation, without budget, transaction or native authority.
use crate::Journal;
use rusqlite::Connection;

pub(crate) struct JournalReadView<'a> {
    pub(crate) connection: &'a Connection,
}

impl Journal {
    pub(crate) fn read_view(&self) -> JournalReadView<'_> {
        JournalReadView {
            connection: &self.connection,
        }
    }
}
