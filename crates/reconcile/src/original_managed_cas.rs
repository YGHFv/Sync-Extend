//! CAS coordination retains original image identity on every actual Journal connection.
use crate::{LocalSpace, Result, SessionGuard};
use std::sync::{Arc, Mutex};
use sync_extend_cas::Cas;

struct OriginalCoordinationReaders {
    access: sync_extend_journal::Journal,
    session: sync_extend_journal::Journal,
    suspended: bool,
}

impl LocalSpace {
    pub(crate) fn existing_original_managed_cas(
        data_dir: &std::path::Path,
        journal: &sync_extend_journal::Journal,
    ) -> Result<Cas> {
        let readers = Arc::new(Mutex::new(OriginalCoordinationReaders {
            access: journal.open_original_coordination_connection()?,
            session: journal.open_original_coordination_connection()?,
            suspended: false,
        }));
        let access_readers = Arc::clone(&readers);
        let session_readers = Arc::clone(&readers);
        Ok(Cas::open_existing_session_coordinated_with_read_handoff(
            &data_dir.join("cas"),
            move |id| {
                let state = access_readers
                    .lock()
                    .map_err(|_| "original CAS readers poisoned")?;
                if state.suspended {
                    return Err("original CAS read coordination has entered handoff".into());
                }
                state
                    .access
                    .verify_original_created_image()
                    .map_err(|error| error.to_string())?;
                state
                    .access
                    .acquire_cas_access(id)
                    .map(|guard| -> Box<dyn Send> {
                        crate::fault::checkpoint("after_cas_access_lock");
                        Box::new(guard)
                    })
                    .map_err(|error| error.to_string())
            },
            move || {
                let state = session_readers
                    .lock()
                    .map_err(|_| "original CAS readers poisoned")?;
                if state.suspended {
                    return Err("original CAS read coordination has entered handoff".into());
                }
                state
                    .session
                    .verify_original_created_image()
                    .map_err(|error| error.to_string())?;
                state
                    .session
                    .acquire_cas_session()
                    .map(|guard| -> Box<dyn Send> {
                        crate::fault::checkpoint("after_cas_session_lock");
                        Box::new(SessionGuard { _guard: guard })
                    })
                    .map_err(|error| error.to_string())
            },
            move || {
                let mut state = readers
                    .lock()
                    .map_err(|_| "original CAS readers poisoned")?;
                if state.suspended {
                    return Err("original CAS read handoff is already attempted".into());
                }
                // Refuse further access before either close. On any failure
                // all original objects remain owned and the suspension persists.
                state.suspended = true;
                state
                    .access
                    .close_original_coordination_connection()
                    .map_err(|error| error.to_string())?;
                state
                    .session
                    .close_original_coordination_connection()
                    .map_err(|error| error.to_string())?;
                Ok(())
            },
        )?)
    }
}
