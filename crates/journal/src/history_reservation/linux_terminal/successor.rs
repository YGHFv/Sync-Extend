//! A live issuer, not historical JSON, closes one publication epoch.
use super::*;
use crate::Journal;
use sync_extend_platform_fs::{LinuxMetadataBudget, LinuxNamespaceCapability};

const SUCCESSOR: &str = "original.linux-native.successor.v1.";

impl Journal {
    pub fn bind_original_linux_publisher(
        &self,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
    ) -> Result<OriginalLinuxPublisherBinding> {
        owner.verify()?;
        budget.validate_namespace_owner(owner)?;
        if state(&self.connection, super::super::KEY)?.is_some() {
            return Err(JournalError::Invariant(
                "pending history reservation refuses publisher binding",
            ));
        }
        Ok(OriginalLinuxPublisherBinding {
            issuer: self.original_local_history_issuer.clone(),
        })
    }

    pub fn verify_original_linux_publisher_binding(
        &self,
        binding: &OriginalLinuxPublisherBinding,
    ) -> Result<()> {
        if !std::sync::Arc::ptr_eq(&binding.issuer, &self.original_local_history_issuer) {
            return Err(JournalError::Invariant(
                "publisher epoch belongs to another live Journal issuer",
            ));
        }
        Ok(())
    }

    pub fn verify_original_linux_cleanup_completion(
        &self,
        completion: &OriginalLinuxCleanupCompletion,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
    ) -> Result<()> {
        let permit = &completion.permit;
        permit.verify_issuer(self)?;
        owner.verify()?;
        budget.validate_namespace_owner(owner)?;
        let value = &permit.final_record;
        let volume = owner.volume().observation().root_key;
        if value.owner_generation != owner.owner_generation()
            || permit.cleanup_owner_generation != owner.owner_generation()
            || value.persistent_metadata_generation != budget.persistent_owner_generation()
            || value.backing_image
                != (
                    owner.backing_image_key().device,
                    owner.backing_image_key().inode,
                )
            || permit.current_volume_root != (volume.device, volume.inode)
            || value.volume_root != permit.current_volume_root
            || state(&self.connection, super::super::KEY)?.is_some()
        {
            return Err(JournalError::Invariant(
                "successor completion original live owner or idle scope differs",
            ));
        }
        let (_, stored) = validate_final(&permit.final_json)?;
        validate_context(&self.connection, value, &stored)?;
        validate_thawed(&permit.thawed_json, &permit.final_json, value)?;
        let prepared = permit
            .prepared_json
            .as_deref()
            .ok_or(JournalError::Invariant(
                "successor cleanup preparation absent",
            ))?;
        let cleaned = permit
            .cleaned_json
            .as_deref()
            .ok_or(JournalError::Invariant(
                "successor cleanup completion absent",
            ))?;
        validate_progress(
            prepared,
            &permit.final_json,
            &permit.thawed_json,
            value,
            None,
        )?;
        validate_progress(
            cleaned,
            &permit.final_json,
            &permit.thawed_json,
            value,
            Some(prepared),
        )?;
        if self.current(&stored.planned.space_id)?.as_ref() != Some(&stored.planned) {
            return Err(JournalError::Invariant(
                "successor current manifest differs from exact Final",
            ));
        }
        Ok(())
    }

    pub fn record_original_linux_successor(
        &mut self,
        completion: &OriginalLinuxCleanupCompletion,
        previous: Option<&OriginalLinuxSuccessorReceipt>,
        owner: &LinuxNamespaceCapability,
        budget: &LinuxMetadataBudget,
        sequence: (u64, u64),
        max: usize,
    ) -> Result<OriginalLinuxSuccessorReceipt> {
        self.verify_original_linux_cleanup_completion(completion, owner, budget)?;
        let (sequence, next) = sequence;
        if sequence.checked_add(1) != Some(next) {
            return Err(JournalError::Invariant(
                "successor sequence exhausted or skipped",
            ));
        }
        let previous_digest = if let Some(previous) = previous {
            previous.verify(self, owner, sequence)?;
            Some(ContentId::hash(previous.exact_json.as_bytes()))
        } else {
            if sequence != 0 {
                return Err(JournalError::Invariant(
                    "successor predecessor live receipt absent",
                ));
            }
            None
        };
        let permit = &completion.permit;
        let cleaned = permit
            .cleaned_json
            .as_deref()
            .ok_or(JournalError::Invariant("successor cleaned receipt absent"))?;
        let (_, stored) = validate_final(&permit.final_json)?;
        // Append-only and bounded by normal full-table capacity auditing. The
        // predecessor transaction key is unique, even if cleanup is replayed.
        let row_key = key(SUCCESSOR, &permit.final_record.attempt);
        let json = serde_json::to_string(&(
            1u32,
            owner.owner_generation(),
            sequence,
            next,
            &permit.final_record.attempt,
            ContentId::hash(permit.final_json.as_bytes()),
            ContentId::hash(permit.thawed_json.as_bytes()),
            ContentId::hash(cleaned.as_bytes()),
            stored.planned.root()?,
            previous_digest,
        ))?;
        self.append_original_linux_state(&row_key, &json, &stored.planned.space_id, max)?;
        Ok(OriginalLinuxSuccessorReceipt {
            issuer: self.original_local_history_issuer.clone(),
            row_key,
            exact_json: json,
            owner_generation: owner.owner_generation(),
            next_sequence: next,
        })
    }
}

impl OriginalLinuxCleanupCompletion {
    pub fn transaction_id(&self) -> &EntryId {
        &self.permit.final_record.attempt
    }
    pub fn snapshot_id(&self) -> Result<SnapshotId> {
        let stored: Stored = parse(&self.permit.final_record.reservation_json)?;
        stored.planned.root().map_err(Into::into)
    }
}

impl OriginalLinuxSuccessorReceipt {
    fn verify(
        &self,
        journal: &Journal,
        owner: &LinuxNamespaceCapability,
        sequence: u64,
    ) -> Result<()> {
        if !std::sync::Arc::ptr_eq(&self.issuer, &journal.original_local_history_issuer)
            || self.owner_generation != owner.owner_generation()
            || self.next_sequence != sequence
            || state(&journal.connection, &self.row_key)?.as_deref()
                != Some(self.exact_json.as_str())
        {
            return Err(JournalError::Invariant(
                "successor original issuer, predecessor or exact append differs",
            ));
        }
        Ok(())
    }
}
