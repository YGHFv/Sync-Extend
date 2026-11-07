//! Close original writers before receipt-backed, mutation-excluding reads.
use super::{
    creation::{key, Base},
    physical, Header, Key,
};
use crate::{
    storage_inventory::reader::{hash, invalid},
    storage_policy, CasAccessGuard, Journal, NativePublicationCreation, Result,
};
use rusqlite::{Transaction, TransactionBehavior};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};
use sync_extend_core_model::{ContentId, EntryId};
use sync_extend_platform_fs::{LockedDirectory, LockedDirectoryMutation, LockedFile};

/// Receipt-backed live verified content only; not durable Ready, publication or
/// cleanup authority. No writer access, construction, Clone or serialization.
pub struct NativePublicationReadiness {
    ancestors: Vec<LockedDirectory>,
    parent: LockedDirectory,
    base: Base,
    owner: LockedDirectoryMutation,
    marker: LockedFile,
    payload: LockedFile,
    _cas: CasAccessGuard,
    header: Header,
    marker_key: Key,
    payload_key: Key,
}
impl NativePublicationReadiness {
    pub fn transaction_id(&self) -> &EntryId {
        &self.header.intent.transaction_id
    }

    pub fn payload_reader(&self) -> &File {
        self.payload.reader()
    }

    pub fn verify_content(&self) -> Result<()> {
        if self.ancestors.len() != self.header.ancestors.len()
            || key(self.parent.key()?) != self.header.parent
        {
            return Err(invalid("native readiness retained ancestor differs"));
        }
        for (held, expected) in self.ancestors.iter().zip(&self.header.ancestors) {
            held.require_case_insensitive()?;
            if key(held.key()?) != expected.key {
                return Err(invalid("native readiness full ancestor differs"));
            }
        }
        self.owner.original_creation()?.verify()?;
        sync_extend_platform_fs::verify_regular_file(self.marker.reader())?;
        sync_extend_platform_fs::verify_regular_file(self.payload.reader())?;
        if key(self.marker.key()?) != self.marker_key
            || key(self.payload.key()?) != self.payload_key
        {
            return Err(invalid("native readiness original file identity differs"));
        }
        let mut marker = self.marker.reader();
        marker.seek(SeekFrom::Start(0))?;
        let mut bytes = [0u8; 32];
        marker.read_exact(&mut bytes)?;
        if marker.read(&mut [0u8; 1])? != 0 || bytes != self.transaction_id().as_str().as_bytes() {
            return Err(invalid("native readiness original marker bytes differ"));
        }
        let mut payload = self.payload.reader();
        let before = payload.metadata()?;
        if before.len() != self.header.intent.content.length {
            return Err(invalid("native readiness payload length differs"));
        }
        payload.seek(SeekFrom::Start(0))?;
        let mut whole = blake3::Hasher::new();
        let mut buffer = [0u8; 65536];
        for chunk in &self.header.intent.content.chunks {
            let mut remaining = u64::from(chunk.length);
            let mut digest = blake3::Hasher::new();
            while remaining != 0 {
                let selected = remaining.min(buffer.len() as u64) as usize;
                payload.read_exact(&mut buffer[..selected])?;
                digest.update(&buffer[..selected]);
                whole.update(&buffer[..selected]);
                remaining -= selected as u64;
            }
            if ContentId::from_hasher(&digest) != chunk.content_id {
                return Err(invalid("native readiness chunk hash differs"));
            }
        }
        if payload.read(&mut buffer[..1])? != 0
            || ContentId::from_hasher(&whole) != self.header.intent.content.content_id
            || before.len() != payload.metadata()?.len()
            || before.modified()? != payload.metadata()?.modified()?
        {
            return Err(invalid("native readiness full content changed"));
        }
        Ok(())
    }
}

fn creator_key(
    snapshot: &crate::storage_capacity::CapacitySnapshot,
    header: &Header,
    step: u64,
) -> Result<Key> {
    let row = snapshot
        .rows
        .iter()
        .find(|row| {
            row.table() == "native_publication_creators"
                && row.primary_key() == [header.intent.transaction_id.as_str(), &step.to_string()]
        })
        .ok_or(invalid("native readiness requires exact original receipt"))?;
    Ok(Key {
        volume: super::field(row, "volume")?.into(),
        id: super::field(row, "full_id")?.into(),
    })
}
impl Journal {
    /// Consumes and flushes original writers, then reacquires exact receipt-backed
    /// guarded reads. Leaked writable clones refuse; errors preserve all objects.
    /// No SQL Ready or native publication/cleanup effect is issued by this call.
    pub fn seal_native_publication_creation(
        &mut self,
        creation: NativePublicationCreation,
    ) -> Result<NativePublicationReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid("native readiness refuses caller-owned transaction"));
        }
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&creation.header.intent.space_id, bounds)?;
        if self
            .current(&creation.header.intent.space_id)?
            .map(|m| m.root())
            .transpose()?
            .as_ref()
            != Some(&creation.header.intent.baseline_root)
        {
            return Err(invalid("native readiness baseline changed"));
        }
        for content in creation
            .header
            .intent
            .completion
            .as_ref()
            .ok_or(invalid("native readiness original completion missing"))?
            .protected_objects
            .keys()
        {
            self.require_cas_access(content)?;
        }
        let stored = before
            .rows
            .iter()
            .find(|row| {
                row.table() == "native_publication_headers"
                    && row.primary_key() == [creation.transaction.as_str()]
            })
            .ok_or(invalid("native readiness original header missing"))?;
        if super::field(stored, "header_hash")? != hash(&creation.header)?.as_str()
            || !before.report.within_accounted_limits()
        {
            return Err(invalid(
                "native readiness original header or capacity differs",
            ));
        }
        creation.verify_originals()?;
        let marker_key = creator_key(&before, &creation.header, 2)?;
        let payload_key = creator_key(&before, &creation.header, 3)?;
        if key(creation.marker.key()?) != marker_key
            || key(creation.payload.key()?) != payload_key
            || key(creation._owner.key()?) != creator_key(&before, &creation.header, 1)?
        {
            return Err(invalid(
                "native readiness creator differs from original receipt",
            ));
        }
        let base_key = if let Some(existing) = &creation.header.existing_base {
            existing.clone()
        } else {
            creator_key(&before, &creation.header, 0)?
        };
        if key(creation._base.key()?) != base_key {
            return Err(invalid("native readiness scaffold differs"));
        }
        creation.marker.reader().sync_all()?;
        creation.payload.reader().sync_all()?;
        let NativePublicationCreation {
            _ancestors,
            _parent,
            _base,
            _owner,
            marker,
            payload,
            _cas,
            transaction: _,
            header,
        } = creation;
        let owner_path = PathBuf::from(&header.ancestors[0].path)
            .join(".sync-tmp")
            .join(format!("native-{}", header.generation));
        drop(marker);
        drop(payload);
        let held = NativePublicationReadiness {
            ancestors: _ancestors,
            parent: _parent,
            base: _base,
            owner: _owner,
            marker: LockedFile::open(&owner_path.join("owner"))?,
            payload: LockedFile::open(&owner_path.join("payload-0"))?,
            _cas,
            header,
            marker_key,
            payload_key,
        };
        held.verify_content()?;
        if physical(&key(held.parent.key()?))?
            != *held
                .header
                .intent
                .parent_identity
                .as_ref()
                .ok_or(invalid("native readiness parent missing"))?
            || key(held.base.key()?) != base_key
        {
            return Err(invalid("native readiness retained scope differs"));
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&held.header.intent.space_id, bounds)?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid("native readiness changed stored state"));
        }
        held.verify_content()?;
        tx.commit()?;
        Ok(held)
    }
}
