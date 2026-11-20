//! Borrowed audit implementation, without budget, transaction or native authority.
use crate::Journal;
use rusqlite::Connection;

pub(crate) struct JournalReadView<'a> {
    pub(crate) connection: &'a Connection,
    pub(crate) dav_read_charge_cache: Option<crate::webdav_native::DavReadChargeSource<'a>>,
}

impl Journal {
    pub(crate) fn read_view(&self) -> JournalReadView<'_> {
        JournalReadView {
            connection: &self.connection,
            dav_read_charge_cache: Some(self.webdav_native_read_charges.reader()),
        }
    }
}

impl JournalReadView<'_> {
    pub(crate) fn dav_read_charges(&self) -> crate::Result<crate::webdav_native::DavReadCharges> {
        match self.dav_read_charge_cache {
            Some(cache) => cache.charges(self.connection),
            None => {
                let audited = crate::webdav_native::VerifiedDavReadAudit::read(self.connection)?;
                audited.charges(self.connection)
            }
        }
    }
}
