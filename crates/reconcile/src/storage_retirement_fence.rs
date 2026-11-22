//! Exact observed storage admission; persistent fences never authorize native effects.
use crate::{now_ms, ReconcileError, Result, StorageNode};
use sync_extend_core_model::storage_retirement::StorageRetirementRequest;
use sync_extend_journal::StorageRetirementAdmission;

impl StorageNode {
    /// Native activation requires this fresh intent and this process's actual
    /// original inspection. A previously admitted request has no writer path.
    #[cfg(target_os = "linux")]
    pub fn execute_unix_storage_retirement_intent(
        &self,
        intent: &sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementIntent,
        disposition: sync_extend_journal::UnixStorageRetirementNativeDisposition,
    ) -> Result<LinuxStorageRetirementNativeTerminal<'_>> {
        self.verify_storage()?;
        self.cas.retirement_owner_observation()?;
        let reference = sync_extend_core_model::ChunkRef {
            content_id: intent.content_id.clone(),
            length: intent.expected_original.length,
        };
        let activation = sync_extend_core_model::EntryId::random()?;
        let terminal = self.journal.execute_unix_storage_retirement_intent(
            intent,
            &self.config,
            &self.device,
            &activation,
            disposition,
            || {
                now_ms().map_err(|error| {
                    sync_extend_journal::JournalError::Io(std::io::Error::other(error.to_string()))
                })
            },
            |exclusive| {
                self.cas
                    .inspect_retirement_original(exclusive, &reference)
                    .map_err(|error| {
                        sync_extend_journal::JournalError::Io(std::io::Error::other(
                            error.to_string(),
                        ))
                    })
            },
        )?;
        Ok(LinuxStorageRetirementNativeTerminal {
            node: self,
            original: Some(terminal),
        })
    }

    #[cfg(target_os = "linux")]
    pub fn unix_storage_retirement_native_states(
        &self,
    ) -> Result<Vec<sync_extend_journal::UnixStorageRetirementNativeState>> {
        self.verify_storage()?;
        Ok(self.journal.unix_storage_retirement_native_states()?)
    }

    #[cfg(target_os = "linux")]
    pub fn admit_unix_storage_retirement_intent(
        &self,
        intent: &sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementIntent,
    ) -> Result<sync_extend_journal::UnixStorageRetirementAdmission> {
        use crate::storage_retirement_inspection::combine_unix;
        self.verify_storage()?;
        self.cas.retirement_owner_observation()?;
        let reference = sync_extend_core_model::ChunkRef {
            content_id: intent.content_id.clone(),
            length: intent.expected_original.length,
        };
        let (held, admitted) = self.journal.with_unix_storage_retirement_intent(
            intent,
            &self.config,
            &self.device,
            now_ms,
            |exclusive| self.cas.inspect_retirement_original(exclusive, &reference),
        )?;
        let (coordination, original) = held.ok_or(ReconcileError::Invariant(
            "fresh Unix intent must retain its actual original inspection",
        ))?;
        combine_unix(
            Ok(admitted),
            self.close_unix_retirement_original(coordination, original),
        )
    }

    #[cfg(target_os = "linux")]
    pub fn replay_unix_storage_retirement(
        &self,
        request: &sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementRequest,
    ) -> Result<sync_extend_journal::UnixStorageRetirementAdmission> {
        self.verify_storage()?;
        self.journal
            .replay_unix_storage_retirement(request, &self.config, &self.device)
            .map_err(ReconcileError::from)
    }

    #[cfg(target_os = "linux")]
    pub fn unix_storage_retirement_admissions(
        &self,
    ) -> Result<Vec<sync_extend_journal::UnixStorageRetirementAdmission>> {
        self.verify_storage()?;
        self.journal
            .unix_storage_retirement_admissions()
            .map_err(ReconcileError::from)
    }

    #[cfg(target_os = "linux")]
    pub fn admit_unix_storage_retirement(
        &self,
        request: &sync_extend_core_model::storage_retirement_unix::UnixStorageRetirementRequest,
    ) -> Result<sync_extend_journal::UnixStorageRetirementAdmission> {
        use crate::storage_retirement_inspection::combine_unix;
        self.verify_storage()?;
        self.cas.retirement_owner_observation()?;
        let reference = sync_extend_core_model::ChunkRef {
            content_id: request.content_id.clone(),
            length: request.binding.length,
        };
        let (held, admitted) = self.journal.with_unix_storage_retirement_admission(
            request,
            &self.config,
            &self.device,
            now_ms,
            |exclusive| self.cas.inspect_retirement_original(exclusive, &reference),
        )?;
        let closed = match held {
            Some((coordination, original)) => {
                self.close_unix_retirement_original(coordination, original)
            }
            None => Ok(()),
        };
        combine_unix(Ok(admitted), closed)
    }

    #[cfg(target_os = "linux")]
    pub fn cancel_unix_storage_retirement(
        &self,
        request: &sync_extend_core_model::EntryId,
    ) -> Result<sync_extend_journal::UnixStorageRetirementAdmission> {
        self.verify_storage()?;
        self.journal
            .cancel_unix_storage_retirement(request, &self.config, &self.device, now_ms()?)
            .map_err(ReconcileError::from)
    }

    pub fn storage_retirement_admissions(&self) -> Result<Vec<StorageRetirementAdmission>> {
        self.verify_storage()?;
        self.journal
            .storage_retirement_admissions()
            .map_err(ReconcileError::from)
    }

    #[cfg(not(windows))]
    pub fn admit_storage_retirement(
        &self,
        _: &StorageRetirementRequest,
    ) -> Result<StorageRetirementAdmission> {
        Err(ReconcileError::Invariant(
            "storage retirement requires exact native handle observation",
        ))
    }

    #[cfg(windows)]
    pub fn admit_storage_retirement(
        &self,
        request: &StorageRetirementRequest,
    ) -> Result<StorageRetirementAdmission> {
        use crate::{filesystem::physical_identity, guarded_mutation::directory_chain};
        use std::io::Read;
        use sync_extend_platform_fs::GuardedReadFile;
        self.verify_storage()?;
        let (guard, admitted) = self.journal.with_storage_retirement_admission(
            request,
            &self.config,
            &self.device,
            now_ms,
            || -> Result<_> {
                self.verify_storage()?;
                let (_, chunks) = self.retired_storage_chunks(&request.storage_id)?;
                let chunk = chunks
                    .get(&request.content_id)
                    .ok_or(ReconcileError::Invariant(
                        "storage retirement chunk absent from exact original owner",
                    ))?;
                if chunk.length != request.length {
                    return Err(ReconcileError::Invariant("storage retirement exact length"));
                }
                let path = self.cas.object_path(&request.content_id);
                let shard = path
                    .parent()
                    .ok_or(ReconcileError::Invariant("storage retirement shard"))?;
                let directories = directory_chain(shard)?;
                for directory in &directories {
                    directory.require_case_insensitive()?;
                }
                let file = GuardedReadFile::open(&path)?;
                file.verify_single_link()?;
                let before = file.reader().metadata()?;
                let key =
                    sync_extend_core_model::ContentId::hash(file.key()?.to_string().as_bytes());
                let stamp = u64::try_from(
                    before
                        .modified()?
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| ReconcileError::Invariant("storage retirement timestamp"))?
                        .as_nanos(),
                )
                .map_err(|_| ReconcileError::Invariant("storage retirement timestamp overflow"))?;
                let cas = self.config.data_dir.join("cas");
                if key != request.object_identity
                    || physical_identity(&path)? != request.object_identity
                    || physical_identity(&self.config.data_dir)? != request.data_identity
                    || physical_identity(&cas)? != request.cas_identity
                    || physical_identity(&cas.join("objects"))? != request.objects_identity
                    || physical_identity(shard)? != request.shard_identity
                    || before.len() != u64::from(request.length)
                    || stamp != request.modified_at_ns
                {
                    return Err(ReconcileError::Invariant(
                        "storage retirement complete physical identity",
                    ));
                }
                let mut reader = file.reader();
                let mut hash = blake3::Hasher::new();
                let mut total = 0u64;
                let mut buffer = [0u8; 65536];
                loop {
                    let count = reader.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    total = total
                        .checked_add(count as u64)
                        .filter(|total| *total <= u64::from(request.length))
                        .ok_or(ReconcileError::Unstable)?;
                    hash.update(&buffer[..count]);
                }
                let after = file.reader().metadata()?;
                if total != u64::from(request.length)
                    || sync_extend_core_model::ContentId::from_hasher(&hash) != request.content_id
                    || after.len() != before.len()
                    || after.modified()? != before.modified()?
                    || physical_identity(&path)? != key
                {
                    return Err(ReconcileError::Unstable);
                }
                file.verify_single_link()?;
                self.verify_storage()?;
                Ok((directories, file))
            },
        )?;
        // The ephemeral CAS/file guards expire; only the audited durable fence remains.
        drop(guard);
        Ok(admitted)
    }

    pub fn cancel_storage_retirement(
        &self,
        request: &sync_extend_core_model::EntryId,
    ) -> Result<StorageRetirementAdmission> {
        self.verify_storage()?;
        self.journal
            .cancel_storage_retirement(request, &self.config, &self.device, now_ms()?)
            .map_err(ReconcileError::from)
    }
}

/// Borrowed live terminal holder. Serializable reports and old IDs cannot
/// construct it or recover its actual independent parent witnesses.
#[cfg(target_os = "linux")]
#[must_use = "explicitly release or close the original terminal witnesses"]
pub struct LinuxStorageRetirementNativeTerminal<'node> {
    node: &'node StorageNode,
    original: Option<sync_extend_journal::UnixStorageRetirementNativeTerminal<'node>>,
}

#[cfg(target_os = "linux")]
impl LinuxStorageRetirementNativeTerminal<'_> {
    pub fn observation(&self) -> Result<sync_extend_journal::UnixStorageRetirementNativeState> {
        self.node.cas.retirement_owner_observation()?;
        Ok(self
            .original
            .as_ref()
            .ok_or(ReconcileError::Invariant(
                "original Unix retirement terminal already closed",
            ))?
            .observation()?)
    }

    pub fn close(mut self) -> Result<()> {
        let observed = self
            .node
            .cas
            .remember_retirement_inventory(&self.node.journal);
        let closed = self
            .original
            .take()
            .ok_or(ReconcileError::Invariant(
                "original Unix retirement terminal already closed",
            ))?
            .close()
            .map_err(ReconcileError::from);
        let result = crate::storage_retirement_inspection::combine_unix(observed, closed);
        if let Err(error) = &result {
            self.node.cas.retirement_failure(error);
        }
        result
    }

    /// Explicitly consume the live terminal in a second independently gated
    /// release call. The twelve-step terminal itself keeps its content fence.
    pub fn release(mut self) -> Result<sync_extend_journal::UnixStorageRetirementNativeState> {
        let result = self
            .original
            .take()
            .ok_or(ReconcileError::Invariant(
                "original Unix retirement terminal already closed",
            ))?
            .release(|| {
                now_ms().map_err(|error| {
                    sync_extend_journal::JournalError::Io(std::io::Error::other(error.to_string()))
                })
            })
            .map_err(ReconcileError::from);
        let closed = self
            .node
            .cas
            .remember_retirement_inventory(&self.node.journal);
        let result = crate::storage_retirement_inspection::combine_unix(result, closed);
        if let Err(error) = &result {
            self.node.cas.retirement_failure(error);
        }
        result
    }
}
