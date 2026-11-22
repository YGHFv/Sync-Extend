//! Storage v2 payload access through the acquired original image FDs only.
//! Ordinary/v1 CAS and every retired native boundary keep their original scope.
use crate::{LinuxStorageOwner, ReconcileError};
use std::{io, sync::Arc};
use sync_extend_cas::{Cas, CasError, CasSessionGuard, Result, MAX_CHUNK};
use sync_extend_core_model::{ChunkRef, ContentId, FileManifest};
use sync_extend_journal::{CasAccessGuard, Journal};
use sync_extend_platform_fs::{
    LinuxStorageCasDirectoryGuard, LinuxStorageCasFileGuard, LinuxStorageCasFileObservation,
    LinuxStorageCasInventory,
};

pub(super) enum StorageCas {
    Ordinary(Cas),
    Inside(LinuxManagedStorageCas),
}

pub(super) struct StorageCasSessionGuard {
    _ordinary: Option<CasSessionGuard>,
    _inside: Option<LinuxStorageCasSessionGuard>,
}

impl StorageCas {
    pub(super) fn retirement_owner_observation(
        &self,
    ) -> crate::Result<crate::LinuxStorageOwnerObservation> {
        match self {
            Self::Inside(cas) => cas.owner.observation(),
            Self::Ordinary(_) => Err(ReconcileError::Invariant(
                "Unix retirement requires an acquired original v2 inside-image owner",
            )),
        }
    }

    pub(super) fn inspect_retirement_original(
        &self,
        exclusive: &sync_extend_platform_fs::LinuxStorageCasExclusiveCoordination<'_>,
        reference: &ChunkRef,
    ) -> crate::Result<sync_extend_platform_fs::LinuxStorageCasRetirementInspection> {
        match self {
            Self::Ordinary(_) => Err(ReconcileError::Invariant(
                "ordinary/v1 storage cannot inspect an original inside-image payload",
            )),
            Self::Inside(cas) => {
                cas.verify_owner()?;
                let original = cas
                    .owner
                    .inside_cas()?
                    .inspect_retirement_original(
                        exclusive,
                        reference.content_id.as_str(),
                        u64::from(reference.length),
                    )
                    .map_err(|error| cas.actual_io(error))?;
                cas.verify_owner()?;
                Ok(original)
            }
        }
    }

    pub(super) fn retirement_failure(&self, error: &impl std::fmt::Display) {
        if let Self::Inside(cas) = self {
            cas.owner.poison_inside_cas(error);
        }
    }

    pub(super) fn inside(owner: Arc<LinuxStorageOwner>) -> crate::Result<Self> {
        if !owner.has_inside_cas() {
            return Err(ReconcileError::Invariant(
                "actual v2 inside-image owner required for storage CAS",
            ));
        }
        owner.verify()?;
        let access_journal = owner.open_journal()?;
        let session_journal = owner.open_journal()?;
        Ok(Self::Inside(LinuxManagedStorageCas {
            access_journal: Some(access_journal),
            session_journal: Some(session_journal),
            owner,
        }))
    }

    pub(super) fn read(&self, reference: &ChunkRef) -> Result<Vec<u8>> {
        match self {
            Self::Ordinary(cas) => cas.read(reference),
            Self::Inside(cas) => cas.read(reference),
        }
    }

    pub(super) fn put(&self, bytes: &[u8]) -> Result<ChunkRef> {
        match self {
            Self::Ordinary(cas) => cas.put(bytes),
            Self::Inside(cas) => cas.put(bytes),
        }
    }

    pub(super) fn verify(&self, manifest: &FileManifest) -> Result<()> {
        match self {
            Self::Ordinary(cas) => cas.verify(manifest),
            Self::Inside(cas) => cas.verify(manifest),
        }
    }

    pub(super) fn acquire_session(&self) -> Result<StorageCasSessionGuard> {
        match self {
            Self::Ordinary(cas) => Ok(StorageCasSessionGuard {
                _ordinary: Some(cas.acquire_session()?),
                _inside: None,
            }),
            Self::Inside(cas) => Ok(StorageCasSessionGuard {
                _ordinary: None,
                _inside: Some(cas.acquire_session()?),
            }),
        }
    }

    pub(super) fn verify_inside_owner(&self) -> Result<()> {
        match self {
            Self::Ordinary(_) => Ok(()),
            Self::Inside(cas) => cas.verify_owner(),
        }
    }

    pub(super) fn inside_inventory(&self) -> Result<Option<LinuxStorageCasInventory>> {
        match self {
            Self::Ordinary(_) => Ok(None),
            Self::Inside(cas) => {
                cas.verify_owner()?;
                let original = cas.owner.inside_cas().map_err(owner_error)?;
                let context = cas
                    .journal(false)?
                    .unix_storage_retirement_inventory_context(
                        original
                            .observation()
                            .map_err(|error| cas.actual_io(error))?
                            .expected_layout,
                    )
                    .map_err(|error| CasError::Io(io::Error::other(error.to_string())))?;
                let inventory = original
                    .inventory_with_retirement_prefixes(&context)
                    .map_err(|error| cas.actual_io(error))?;
                cas.verify_owner()?;
                Ok(Some(inventory))
            }
        }
    }

    pub(super) fn remember_retirement_inventory(&self, journal: &Journal) -> crate::Result<()> {
        if let Self::Inside(cas) = self {
            cas.owner.remember_retirement_inventory(journal)?;
        }
        Ok(())
    }

    pub(super) fn close(self) -> crate::Result<()> {
        match self {
            Self::Ordinary(cas) => {
                drop(cas);
                Ok(())
            }
            Self::Inside(mut cas) => {
                let mut first = None;
                for journal in [&mut cas.access_journal, &mut cas.session_journal] {
                    if let Some(journal) = journal.take() {
                        if let Err(error) = journal.close_linux_storage_cas_coordination() {
                            first.get_or_insert(ReconcileError::from(error));
                        }
                    }
                }
                if let Some(error) = first {
                    cas.owner.poison_inside_cas(&error);
                    return Err(error);
                }
                cas.owner.verify()
            }
        }
    }

    pub(super) fn hold_inside_session(&self) -> Result<LinuxStorageCasSessionGuard> {
        match self {
            Self::Inside(cas) => cas.acquire_session(),
            Self::Ordinary(_) => Err(CasError::AccessDeferred(
                "ordinary/v1 storage has no inside-image CAS session capability".into(),
            )),
        }
    }

    pub(super) fn hold_inside_read(
        &self,
        reference: &ChunkRef,
    ) -> Result<LinuxStorageCasReadGuard> {
        match self {
            Self::Inside(cas) => cas.read_guard(reference),
            Self::Ordinary(_) => Err(CasError::AccessDeferred(
                "ordinary/v1 storage has no inside-image CAS file capability".into(),
            )),
        }
    }
}

fn owner_error(error: ReconcileError) -> CasError {
    CasError::Io(io::Error::other(error.to_string()))
}

fn combine<T>(operation: Result<T>, close: Result<()>) -> Result<T> {
    match (operation, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(close)) => Err(CasError::Io(io::Error::other(format!(
            "{error}; actual original CAS guard close also refused: {close}"
        )))),
    }
}

fn checked_bytes(reference: &ChunkRef, bytes: &[u8]) -> Result<()> {
    if reference.length == 0
        || reference.length as usize > MAX_CHUNK
        || bytes.len() != reference.length as usize
        || ContentId::hash(bytes) != reference.content_id
    {
        return Err(CasError::Integrity);
    }
    Ok(())
}

pub(super) struct LinuxManagedStorageCas {
    // Both real full-FD Journal callbacks close before their outer owner loan.
    access_journal: Option<Journal>,
    session_journal: Option<Journal>,
    owner: Arc<LinuxStorageOwner>,
}

impl LinuxManagedStorageCas {
    fn actual_io(&self, error: io::Error) -> CasError {
        if error.kind() != io::ErrorKind::NotFound {
            self.owner.poison_inside_cas(&error);
        }
        CasError::Io(error)
    }

    fn verify_owner(&self) -> Result<()> {
        self.owner.verify().map_err(|error| {
            self.owner.poison_inside_cas(&error);
            owner_error(error)
        })
    }

    fn journal(&self, session: bool) -> Result<&Journal> {
        let journal = if session {
            &self.session_journal
        } else {
            &self.access_journal
        };
        journal.as_ref().ok_or_else(|| {
            CasError::AccessDeferred("original inside CAS Journal callback already closed".into())
        })
    }

    fn acquire_access(&self, reference: &ChunkRef) -> Result<CasAccessGuard> {
        self.verify_owner()?;
        let acquired = self
            .journal(false)?
            .acquire_cas_access(&reference.content_id);
        // Fence refusal is an ordinary deferral. An actual owner/slot/lease
        // failure retains its first diagnostic and cannot become a cache miss.
        self.verify_owner()?;
        acquired.map_err(|error| CasError::AccessDeferred(error.to_string()))
    }

    fn close_access(&self, guard: CasAccessGuard) -> Result<()> {
        guard.close_linux_storage_original().map_err(|error| {
            self.owner.poison_inside_cas(&error);
            CasError::Io(io::Error::other(error.to_string()))
        })
    }

    fn read_guard(&self, reference: &ChunkRef) -> Result<LinuxStorageCasReadGuard> {
        if reference.length == 0 || reference.length as usize > MAX_CHUNK {
            return Err(CasError::Integrity);
        }
        let access = self.acquire_access(reference)?;
        let original = self
            .owner
            .inside_cas()
            .map_err(owner_error)
            .and_then(|cas| {
                cas.original(reference.content_id.as_str(), u64::from(reference.length))
                    .map_err(|error| self.actual_io(error))
            });
        let original = match original {
            Ok(original) => original,
            Err(error) => return combine(Err(error), self.close_access(access)),
        };
        let guard = LinuxStorageCasReadGuard {
            original: Some(original),
            access: Some(access),
            reference: reference.clone(),
            owner: Some(Arc::clone(&self.owner)),
        };
        if let Err(error) = guard.read_bytes() {
            return combine(Err(error), guard.close());
        }
        Ok(guard)
    }

    fn read(&self, reference: &ChunkRef) -> Result<Vec<u8>> {
        let guard = self.read_guard(reference)?;
        let bytes = guard.read_bytes();
        combine(bytes, guard.close())
    }

    fn put(&self, bytes: &[u8]) -> Result<ChunkRef> {
        if bytes.is_empty() || bytes.len() > MAX_CHUNK {
            return Err(CasError::Integrity);
        }
        let reference = ChunkRef {
            content_id: ContentId::hash(bytes),
            length: bytes.len() as u32,
        };
        let access = self.acquire_access(&reference)?;
        let mut directories = None;
        let operation = (|| {
            let cas = self.owner.inside_cas().map_err(owner_error)?;
            let original = if cas
                .contains(reference.content_id.as_str())
                .map_err(|error| self.actual_io(error))?
            {
                cas.original(reference.content_id.as_str(), bytes.len() as u64)
                    .map_err(|error| self.actual_io(error))?
            } else {
                let staged = cas
                    .stage_new(reference.content_id.as_str(), bytes)
                    .map_err(|error| {
                        if error.kind() == io::ErrorKind::StorageFull {
                            // The platform preserves this kind only for whole
                            // budget refusal before any receive CREATE. Actual
                            // publish/write/close failures still poison below.
                            CasError::Io(error)
                        } else {
                            self.actual_io(error)
                        }
                    })?;
                let actual = staged.read_bytes().map_err(|error| self.actual_io(error))?;
                if let Err(error) = checked_bytes(&reference, &actual) {
                    self.owner.poison_inside_cas(&error);
                    // Drop only closes the actual staged FD/lease. The named
                    // first failed receive prefix is preserved and not adopted.
                    return Err(error);
                }
                staged.publish().map_err(|error| self.actual_io(error))?
            };
            let verified = original
                .read_bytes()
                .map_err(|error| self.actual_io(error))
                .and_then(|actual| checked_bytes(&reference, &actual));
            if let Err(error) = &verified {
                self.owner.poison_inside_cas(error);
            }
            let closed = original
                .close_file()
                .map_err(|error| self.actual_io(error))
                .map(|original| directories = Some(original));
            combine(verified, closed)?;
            self.verify_owner()?;
            Ok(reference)
        })();
        let operation = combine(operation, self.close_access(access));
        let closed = directories.map_or(Ok(()), |original| {
            original.close().map_err(|error| self.actual_io(error))
        });
        combine(operation, closed)
    }

    fn acquire_session(&self) -> Result<LinuxStorageCasSessionGuard> {
        self.verify_owner()?;
        let acquired = self.journal(true)?.acquire_cas_session();
        self.verify_owner()?;
        let access = acquired.map_err(|error| CasError::AccessDeferred(error.to_string()))?;
        let original = self
            .owner
            .inside_cas()
            .map_err(owner_error)
            .and_then(|cas| cas.directory_guard().map_err(|error| self.actual_io(error)));
        let original = match original {
            Ok(original) => original,
            Err(error) => return combine(Err(error), self.close_access(access)),
        };
        let guard = LinuxStorageCasSessionGuard {
            original: Some(original),
            access: Some(access),
            owner: Some(Arc::clone(&self.owner)),
        };
        guard.verify()?;
        Ok(guard)
    }

    fn verify(&self, manifest: &FileManifest) -> Result<()> {
        manifest.validate()?;
        let session = self.acquire_session()?;
        let operation = (|| {
            let mut hasher = blake3::Hasher::new();
            for chunk in &manifest.chunks {
                let actual = self.read(chunk)?;
                hasher.update(&actual);
            }
            if ContentId::from_hasher(&hasher) != manifest.content_id {
                return Err(CasError::Integrity);
            }
            self.verify_owner()
        })();
        combine(operation, session.close())
    }
}

impl Drop for LinuxManagedStorageCas {
    fn drop(&mut self) {
        for journal in [&mut self.access_journal, &mut self.session_journal] {
            if let Some(journal) = journal.take() {
                if let Err(error) = journal.close_linux_storage_cas_coordination() {
                    self.owner.poison_inside_cas(error);
                }
            }
        }
    }
}

/// A real original shared Journal session, original inside directory FDs and
/// outer storage owner Arc. It cannot be cloned or deserialized from a report.
pub struct LinuxStorageCasSessionGuard {
    original: Option<LinuxStorageCasDirectoryGuard>,
    access: Option<CasAccessGuard>,
    owner: Option<Arc<LinuxStorageOwner>>,
}

impl LinuxStorageCasSessionGuard {
    pub fn verify(&self) -> Result<()> {
        let owner = self.owner.as_ref().ok_or_else(|| {
            CasError::AccessDeferred("original inside CAS session is closed".into())
        })?;
        let operation = (|| {
            owner.verify().map_err(owner_error)?;
            self.access
                .as_ref()
                .ok_or_else(|| {
                    CasError::AccessDeferred(
                        "original inside CAS session coordinator guard is closed".into(),
                    )
                })?
                .verify_linux_storage_original()
                .map_err(|error| CasError::Io(io::Error::other(error.to_string())))?;
            self.original
                .as_ref()
                .ok_or_else(|| {
                    CasError::AccessDeferred(
                        "original inside CAS session directory loan is closed".into(),
                    )
                })?
                .verify()?;
            owner.verify().map_err(owner_error)
        })();
        if let Err(error) = &operation {
            owner.poison_inside_cas(error);
        }
        operation
    }

    fn release(&mut self) -> Result<()> {
        let Some(owner) = &self.owner else {
            return Ok(());
        };
        let mut first = owner.verify().err().map(owner_error);
        if let Some(access) = self.access.take() {
            if let Err(error) = access.close_linux_storage_original() {
                first.get_or_insert(CasError::Io(io::Error::other(error.to_string())));
            }
        }
        if let Some(original) = self.original.take() {
            if let Err(error) = original.close() {
                first.get_or_insert(CasError::Io(error));
            }
        }
        if let Err(error) = owner.verify() {
            first.get_or_insert(owner_error(error));
        }
        if let Some(error) = &first {
            owner.poison_inside_cas(error);
        }
        drop(self.owner.take());
        first.map_or(Ok(()), Err)
    }

    pub fn close(mut self) -> Result<()> {
        self.release()
    }
}

impl Drop for LinuxStorageCasSessionGuard {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// Exact original payload FD and mandatory kernel lease, true Journal access
/// guard/fence and outer storage owner Arc. No pathname CAS is hidden here.
pub struct LinuxStorageCasReadGuard {
    original: Option<LinuxStorageCasFileGuard>,
    access: Option<CasAccessGuard>,
    reference: ChunkRef,
    owner: Option<Arc<LinuxStorageOwner>>,
}

impl LinuxStorageCasReadGuard {
    pub fn read_bytes(&self) -> Result<Vec<u8>> {
        let owner = self.owner.as_ref().ok_or_else(|| {
            CasError::AccessDeferred("original inside CAS read guard is closed".into())
        })?;
        let operation = (|| {
            owner.verify().map_err(owner_error)?;
            self.access
                .as_ref()
                .ok_or_else(|| {
                    CasError::AccessDeferred(
                        "original inside CAS read coordinator guard is closed".into(),
                    )
                })?
                .verify_linux_storage_original()
                .map_err(|error| CasError::Io(io::Error::other(error.to_string())))?;
            let bytes = self
                .original
                .as_ref()
                .ok_or_else(|| {
                    CasError::AccessDeferred("original inside CAS file loan is closed".into())
                })?
                .read_bytes()?;
            checked_bytes(&self.reference, &bytes)?;
            owner.verify().map_err(owner_error)?;
            Ok(bytes)
        })();
        if let Err(error) = &operation {
            owner.poison_inside_cas(error);
        }
        operation
    }

    pub fn observation(&self) -> Result<LinuxStorageCasFileObservation> {
        self.read_bytes()?;
        Ok(self
            .original
            .as_ref()
            .ok_or_else(|| {
                CasError::AccessDeferred("original inside CAS file loan is closed".into())
            })?
            .observation()?)
    }

    fn release(&mut self) -> Result<()> {
        let Some(owner) = &self.owner else {
            return Ok(());
        };
        let mut first = owner.verify().err().map(owner_error);
        let mut directories = None;
        if let Some(original) = self.original.take() {
            match original.close_file() {
                Ok(original) => directories = Some(original),
                Err(error) => {
                    first.get_or_insert(CasError::Io(error));
                }
            }
        }
        if let Some(access) = self.access.take() {
            if let Err(error) = access.close_linux_storage_original() {
                first.get_or_insert(CasError::Io(io::Error::other(error.to_string())));
            }
        }
        if let Some(original) = directories {
            if let Err(error) = original.close() {
                first.get_or_insert(CasError::Io(error));
            }
        }
        if let Err(error) = owner.verify() {
            first.get_or_insert(owner_error(error));
        }
        if let Some(error) = &first {
            owner.poison_inside_cas(error);
        }
        drop(self.owner.take());
        first.map_or(Ok(()), Err)
    }

    pub fn close(mut self) -> Result<()> {
        self.release()
    }
}

impl Drop for LinuxStorageCasReadGuard {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
