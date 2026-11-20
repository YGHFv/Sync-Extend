//! Private descriptive audits for one unchanged connection read phase.
//! These values never issue an effect, receipt, SQL write, or native identity.
use super::{invalid, WebDavNativeAdmission};
use crate::Result;
use rusqlite::Connection;
use std::{
    cell::{Cell, RefCell},
    sync::Arc,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct SqlGeneration {
    changes: u64,
    data_version: u64,
    schema_version: u64,
    temp_schema_version: u64,
    user_version: u64,
    autocommit: bool,
}

impl SqlGeneration {
    pub(super) fn capture(connection: &Connection) -> Result<Self> {
        Ok(Self {
            changes: connection.total_changes(),
            data_version: connection
                .pragma_query_value(Some("main"), "data_version", |row| crate::sql_u64(row, 0))?,
            schema_version: connection.pragma_query_value(
                Some("main"),
                "schema_version",
                |row| crate::sql_u64(row, 0),
            )?,
            temp_schema_version: connection.pragma_query_value(
                Some("temp"),
                "schema_version",
                |row| crate::sql_u64(row, 0),
            )?,
            user_version: connection
                .pragma_query_value(Some("main"), "user_version", |row| crate::sql_u64(row, 0))?,
            autocommit: connection.is_autocommit(),
        })
    }

    pub(super) fn verify(&self, connection: &Connection) -> Result<()> {
        if *self != Self::capture(connection)? {
            return Err(invalid());
        }
        Ok(())
    }

    fn matches(&self, connection: &Connection) -> Result<bool> {
        Ok(*self == Self::capture(connection)?)
    }
}

/// Only a complete description audit can construct this private owned context.
/// The connection and its SQL generation remain part of every read access.
pub(super) struct VerifiedDescriptions<'connection> {
    connection: &'connection Connection,
    generation: SqlGeneration,
    descriptions: Vec<WebDavNativeAdmission>,
}

impl<'connection> VerifiedDescriptions<'connection> {
    pub(super) fn read(connection: &'connection Connection) -> Result<Self> {
        let generation = SqlGeneration::capture(connection)?;
        let descriptions = super::audit_descriptions(connection)?;
        generation.verify(connection)?;
        Ok(Self {
            connection,
            generation,
            descriptions,
        })
    }

    pub(super) fn verify(&self, connection: &Connection) -> Result<()> {
        if !std::ptr::eq(self.connection, connection) {
            return Err(invalid());
        }
        self.generation.verify(connection)
    }

    pub(super) fn matches_generation(&self, connection: &Connection) -> Result<bool> {
        if !std::ptr::eq(self.connection, connection) {
            return Err(invalid());
        }
        self.generation.matches(connection)
    }

    pub(super) fn connection(&self) -> Result<&Connection> {
        self.verify(self.connection)?;
        Ok(self.connection)
    }

    pub(super) fn values(&self, connection: &Connection) -> Result<&[WebDavNativeAdmission]> {
        self.verify(connection)?;
        Ok(&self.descriptions)
    }
}

/// One complete immutable DAV read from one actual connection and SQL snapshot.
/// The owned audit is private; its values cannot authorize a native or SQL write.
pub(crate) struct VerifiedDavReadAudit<'connection> {
    descriptions: VerifiedDescriptions<'connection>,
    executions: Vec<super::execution::WebDavDurableExecution>,
    manifests: Vec<super::manifest_audit::CompleteManifest>,
}

/// Owned exact result of one complete DAV audit. The connection identity and
/// SQL generation remain part of every access, but no connection reference is
/// retained, so the value can be cached by its owning Journal.
pub(super) struct VerifiedDavReadSnapshot {
    connection_address: usize,
    generation: SqlGeneration,
    descriptions: Vec<WebDavNativeAdmission>,
    executions: Vec<super::execution::WebDavDurableExecution>,
    manifests: Vec<super::manifest_audit::CompleteManifest>,
}

impl VerifiedDavReadSnapshot {
    fn read(connection: &Connection) -> Result<Self> {
        let VerifiedDavReadAudit {
            descriptions,
            executions,
            manifests,
        } = VerifiedDavReadAudit::read(connection)?;
        Ok(Self {
            connection_address: std::ptr::from_ref(connection) as usize,
            generation: descriptions.generation,
            descriptions: descriptions.descriptions,
            executions,
            manifests,
        })
    }

    pub(super) fn matches_generation(&self, connection: &Connection) -> Result<bool> {
        if self.connection_address != std::ptr::from_ref(connection) as usize {
            return Err(invalid());
        }
        self.generation.matches(connection)
    }

    pub(super) fn verify(&self, connection: &Connection) -> Result<()> {
        if self.connection_address != std::ptr::from_ref(connection) as usize {
            return Err(invalid());
        }
        self.generation.verify(connection)
    }

    pub(super) fn descriptions(&self, connection: &Connection) -> Result<&[WebDavNativeAdmission]> {
        self.verify(connection)?;
        Ok(&self.descriptions)
    }

    pub(super) fn executions(
        &self,
        connection: &Connection,
    ) -> Result<&[super::execution::WebDavDurableExecution]> {
        self.verify(connection)?;
        Ok(&self.executions)
    }

    pub(super) fn manifests(
        &self,
        connection: &Connection,
    ) -> Result<&[super::manifest_audit::CompleteManifest]> {
        self.verify(connection)?;
        Ok(&self.manifests)
    }

    pub(super) fn charges(&self, connection: &Connection) -> Result<DavReadCharges> {
        self.verify(connection)?;
        charges_from_audit(&self.descriptions, &self.executions, &self.manifests)
    }
}

/// Arithmetic liabilities derived from the same fully audited read.
#[derive(Clone, Copy)]
pub(crate) struct DavReadCharges {
    cancellation: sync_extend_core_model::tree_storage_capacity::TreeStorageCharge,
    execution: sync_extend_core_model::tree_storage_capacity::TreeStorageCharge,
    internal: sync_extend_core_model::tree_storage_capacity::TreeStorageCharge,
}

/// Selects an existing committed cache or one privately borrowed capacity read.
/// The scoped variant cannot outlive the immutable phase which constructed it.
#[derive(Clone, Copy)]
pub(crate) enum DavReadChargeSource<'a> {
    Committed(&'a DavReadChargeCache),
    Capacity(&'a VerifiedDavReadChargePhase<'a>),
}

impl DavReadChargeSource<'_> {
    pub(crate) fn charges(&self, connection: &Connection) -> Result<DavReadCharges> {
        match self {
            Self::Committed(cache) => cache.charges(connection),
            Self::Capacity(phase) => phase.charges(connection),
        }
    }
}

/// Arithmetic from a complete DAV audit, borrowed only by one private,
/// non-mutating capacity audit. No SQL/native effect or owner grant is retained.
pub(crate) struct VerifiedDavReadChargePhase<'connection> {
    connection: &'connection Connection,
    generation: SqlGeneration,
    charges: DavReadCharges,
}

impl<'connection> VerifiedDavReadChargePhase<'connection> {
    pub(crate) fn read(
        connection: &'connection Connection,
        source: Option<DavReadChargeSource<'_>>,
    ) -> Result<Self> {
        let generation = SqlGeneration::capture(connection)?;
        let charges = match source {
            Some(source) => source.charges(connection)?,
            None => {
                let audited = VerifiedDavReadAudit::read(connection)?;
                audited.charges(connection)?
            }
        };
        generation.verify(connection)?;
        Ok(Self {
            connection,
            generation,
            charges,
        })
    }

    pub(crate) fn verify(&self, connection: &Connection) -> Result<()> {
        if !std::ptr::eq(self.connection, connection) {
            return Err(invalid());
        }
        self.generation.verify(connection)
    }

    fn charges(&self, connection: &Connection) -> Result<DavReadCharges> {
        self.verify(connection)?;
        Ok(self.charges)
    }

    pub(crate) fn reader(&self) -> DavReadChargeSource<'_> {
        DavReadChargeSource::Capacity(self)
    }
}

/// Owned by one Journal, never by a global map or an effect issuer.
/// The exact complete audit is retained only across one unchanged SQL
/// generation. Non-autocommit generations are retained only while an explicit
/// WebDAV transaction scope is alive, so rollback can never leak a stale proof.
#[derive(Default)]
pub(crate) struct DavReadChargeCache {
    current: RefCell<Option<Arc<VerifiedDavReadSnapshot>>>,
    transaction_scopes: Cell<u32>,
}

impl DavReadChargeCache {
    fn clear(&self) {
        if let Ok(mut current) = self.current.try_borrow_mut() {
            *current = None;
        }
    }

    pub(crate) fn scope(&self) -> DavReadScope<'_> {
        self.clear();
        self.transaction_scopes
            .set(self.transaction_scopes.get().saturating_add(1));
        DavReadScope { cache: self }
    }

    pub(crate) fn reader(&self) -> DavReadChargeSource<'_> {
        DavReadChargeSource::Committed(self)
    }

    pub(super) fn read(&self, connection: &Connection) -> Result<Arc<VerifiedDavReadSnapshot>> {
        let generation = SqlGeneration::capture(connection)?;
        let scoped = self.transaction_scopes.get() != 0;
        if !generation.autocommit && !scoped {
            // Without a transaction scope, a generation cannot distinguish a
            // rollback from the committed state that preceded it.
            self.clear();
            return Ok(Arc::new(VerifiedDavReadSnapshot::read(connection)?));
        }
        let address = std::ptr::from_ref(connection) as usize;
        {
            let cached = self.current.try_borrow().map_err(|_| invalid())?;
            if let Some(cached) = cached.as_ref() {
                if cached.connection_address == address
                    && cached.generation == generation
                    && cached.matches_generation(connection)?
                {
                    return Ok(Arc::clone(cached));
                }
            }
        }
        // Journal movement, transaction state, main/TEMP schema or user-version
        // changes, and any actual SQL change discard the old descriptive proof.
        self.clear();
        let snapshot = Arc::new(VerifiedDavReadSnapshot::read(connection)?);
        generation.verify(connection)?;
        *self.current.try_borrow_mut().map_err(|_| invalid())? = Some(Arc::clone(&snapshot));
        Ok(snapshot)
    }

    pub(crate) fn charges(&self, connection: &Connection) -> Result<DavReadCharges> {
        let generation = SqlGeneration::capture(connection)?;
        let scoped = self.transaction_scopes.get() != 0;
        if !generation.autocommit && !scoped {
            *self.current.try_borrow_mut().map_err(|_| invalid())? = None;
            let audited = VerifiedDavReadAudit::read(connection)?;
            let charges = audited.charges(connection)?;
            generation.verify(connection)?;
            return Ok(charges);
        }
        let address = std::ptr::from_ref(connection) as usize;
        {
            let cached = self.current.try_borrow().map_err(|_| invalid())?;
            if let Some(cached) = cached.as_ref() {
                if cached.connection_address == address
                    && cached.generation == generation
                    && cached.matches_generation(connection)?
                {
                    cached.generation.verify(connection)?;
                    return cached.charges(connection);
                }
            }
        }
        self.clear();
        let snapshot = Arc::new(VerifiedDavReadSnapshot::read(connection)?);
        let charges = snapshot.charges(connection)?;
        generation.verify(connection)?;
        *self.current.try_borrow_mut().map_err(|_| invalid())? = Some(snapshot);
        Ok(charges)
    }
}

pub(crate) struct DavReadScope<'cache> {
    cache: &'cache DavReadChargeCache,
}

impl Drop for DavReadScope<'_> {
    fn drop(&mut self) {
        let remaining = self.cache.transaction_scopes.get().saturating_sub(1);
        self.cache.transaction_scopes.set(remaining);
        if remaining == 0 {
            self.cache.clear();
        }
    }
}

fn charges_from_audit(
    descriptions: &[WebDavNativeAdmission],
    executions: &[super::execution::WebDavDurableExecution],
    manifests: &[super::manifest_audit::CompleteManifest],
) -> Result<DavReadCharges> {
    use crate::storage_inventory::reader::add;
    use sync_extend_core_model::tree_storage_capacity::TreeStorageCharge;
    let cancellation_rows = descriptions
        .iter()
        .filter(|row| row.writer_gate_held)
        .count() as u64;
    let cancellation = TreeStorageCharge {
        rows: cancellation_rows,
        logical_bytes: cancellation_rows.checked_mul(40).ok_or_else(invalid)?,
    };
    let execution = executions.iter().try_fold(
        TreeStorageCharge::default(),
        |total, row| -> Result<TreeStorageCharge> {
            Ok(TreeStorageCharge {
                rows: add(total.rows, row.future_rows)?,
                logical_bytes: add(total.logical_bytes, row.future_bytes)?,
            })
        },
    )?;
    let internal = manifests.iter().try_fold(
        TreeStorageCharge::default(),
        |total, row| -> Result<TreeStorageCharge> {
            Ok(TreeStorageCharge {
                rows: add(total.rows, row.additional_future.rows)?,
                logical_bytes: add(total.logical_bytes, row.additional_future.logical_bytes)?,
            })
        },
    )?;
    Ok(DavReadCharges {
        cancellation,
        execution,
        internal,
    })
}

impl DavReadCharges {
    pub(crate) fn cancellation(
        &self,
    ) -> sync_extend_core_model::tree_storage_capacity::TreeStorageCharge {
        self.cancellation
    }
    pub(crate) fn execution(
        &self,
    ) -> sync_extend_core_model::tree_storage_capacity::TreeStorageCharge {
        self.execution
    }
    pub(crate) fn internal(
        &self,
    ) -> sync_extend_core_model::tree_storage_capacity::TreeStorageCharge {
        self.internal
    }
}

impl<'connection> VerifiedDavReadAudit<'connection> {
    pub(crate) fn read(connection: &'connection Connection) -> Result<Self> {
        let descriptions = VerifiedDescriptions::read(connection)?;
        let executions = super::execution::audit_verified(&descriptions)?;
        let manifests = super::manifest_audit::audit(
            connection,
            descriptions.values(connection)?,
            &executions,
        )?;
        descriptions.verify(connection)?;
        Ok(Self {
            descriptions,
            executions,
            manifests,
        })
    }

    pub(crate) fn charges(&self, connection: &Connection) -> Result<DavReadCharges> {
        charges_from_audit(
            self.descriptions.values(connection)?,
            &self.executions,
            &self.manifests,
        )
    }
}
