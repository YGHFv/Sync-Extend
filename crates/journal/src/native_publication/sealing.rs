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

#[path = "publishing.rs"]
pub(super) mod publishing;
pub use publishing::NativePublicationObservation;

/// Receipt-backed live verified content only; not by itself publication or
/// cleanup authority. No writer access, construction, Clone or serialization.
pub struct NativePublicationReadiness {
    ancestors: Vec<LockedDirectory>,
    parent: LockedDirectory,
    base: Base,
    owner: LockedDirectoryMutation,
    pub(super) marker: LockedFile,
    pub(super) payload: LockedFile,
    _cas: CasAccessGuard,
    pub(super) header: Header,
    marker_key: Key,
    payload_key: Key,
    owner_key: Key,
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
        self.base.require_case_insensitive()?;
        self.owner.require_case_insensitive()?;
        if key(self.owner.key()?) != self.owner_key {
            return Err(invalid("native readiness original owner identity differs"));
        }
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
    /// Reacquire guarded content only from a complete original creator set and
    /// exact durable Ready. This never creates, repairs, publishes or deletes.
    pub fn reopen_native_publication_ready(
        &mut self,
        id: &EntryId,
    ) -> Result<NativePublicationReadiness> {
        self.reopen_native_publication_guarded(id, false)
    }

    fn reopen_native_publication_guarded(
        &mut self,
        id: &EntryId,
        forward: bool,
    ) -> Result<NativePublicationReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "native Ready reopen refuses caller-owned transaction",
            ));
        }
        let cas = self.acquire_cas_coordination()?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let publication = self.publication(id)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&publication.intent.space_id, bounds)?;
        let stored = before
            .rows
            .iter()
            .find(|row| {
                row.table() == "native_publication_headers" && row.primary_key() == [id.as_str()]
            })
            .ok_or(invalid("native Ready reopen header missing"))?;
        let header: Header = serde_json::from_str(super::field(stored, "header")?)?;
        if !before.rows.iter().any(|row| {
            row.table() == "native_publication_phases"
                && row.primary_key() == [id.as_str(), "0", "ready"]
        }) || !before.report.within_accounted_limits()
        {
            return Err(invalid(
                "native Ready reopen requires durable phase and capacity",
            ));
        }
        let publishing = before.rows.iter().any(|row| {
            row.table() == "native_publication_phases"
                && row.primary_key() == [id.as_str(), "0", "publishing"]
        });
        if publishing != forward {
            return Err(invalid("native guarded reopen forward scope differs"));
        }
        if self
            .current(&header.intent.space_id)?
            .map(|m| m.root())
            .transpose()?
            .as_ref()
            != Some(&header.intent.baseline_root)
        {
            return Err(invalid("native Ready reopen baseline changed"));
        }
        for content in header
            .intent
            .completion
            .as_ref()
            .ok_or(invalid("native Ready reopen history missing"))?
            .protected_objects
            .keys()
        {
            self.require_cas_access(content)?;
        }
        let mut ancestors = Vec::new();
        for expected in &header.ancestors {
            let path = PathBuf::from(&expected.path);
            let held = LockedDirectory::open(&path)?;
            held.require_local_ntfs(&path)?;
            held.require_case_insensitive()?;
            if key(held.key()?) != expected.key {
                return Err(invalid("native Ready reopen original ancestor changed"));
            }
            ancestors.push(held);
        }
        let parent_path = PathBuf::from(&header.ancestors[0].path);
        let parent = LockedDirectory::open(&parent_path)?;
        let base_path = parent_path.join(".sync-tmp");
        let base = if header.existing_base.is_some() {
            Base::Existing(LockedDirectory::open(&base_path)?)
        } else {
            Base::Created(LockedDirectoryMutation::open(&base_path)?)
        };
        let base_key = header
            .existing_base
            .clone()
            .map(Ok)
            .unwrap_or_else(|| creator_key(&before, &header, 0))?;
        if key(base.key()?) != base_key {
            return Err(invalid("native Ready reopen original scaffold changed"));
        }
        let owner_path = base_path.join(format!("native-{}", header.generation));
        let owner_key = creator_key(&before, &header, 1)?;
        let source_path = owner_path.join("payload-0");
        let target_path = publishing::target_path(&header)?;
        let source_present = publishing::slot_present(&source_path)?;
        let target_present = publishing::slot_present(&target_path)?;
        let payload_path = if forward && !source_present && target_present {
            target_path
        } else if source_present && (!forward || !target_present) {
            source_path
        } else {
            return Err(invalid("native guarded reopen ambiguous source or target"));
        };
        let held = NativePublicationReadiness {
            ancestors,
            parent,
            base,
            owner: LockedDirectoryMutation::open(&owner_path)?,
            marker: LockedFile::open(&owner_path.join("owner"))?,
            payload: LockedFile::open(&payload_path)?,
            _cas: cas,
            marker_key: creator_key(&before, &header, 2)?,
            payload_key: creator_key(&before, &header, 3)?,
            owner_key,
            header,
        };
        held.verify_content()?;
        if forward {
            publishing::verify_forward_slot(&held)?;
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&held.header.intent.space_id, bounds)?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid("native Ready reopen changed stored state"));
        }
        held.verify_content()?;
        if forward {
            publishing::verify_forward_slot(&held)?;
        }
        tx.commit()?;
        Ok(held)
    }

    /// Persist the sole Ready row while exact receipt-backed guarded content
    /// remains live. This neither publishes nor changes legacy publication state.
    pub fn record_native_publication_ready(
        &mut self,
        held: NativePublicationReadiness,
    ) -> Result<NativePublicationReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid("native Ready refuses caller-owned transaction"));
        }
        held.verify_content()?;
        let header = &held.header;
        let owner = key(held.owner.key()?);
        let text = |value: &str| rusqlite::types::Value::Text(value.into());
        self.native_insert(
            header,
            "native_publication_phases",
            vec![
                text(header.intent.transaction_id.as_str()),
                text(header.generation.as_str()),
                rusqlite::types::Value::Integer(0),
                text(hash(header)?.as_str()),
                text("ready"),
                text(physical(&held.payload_key)?.as_str()),
                text(header.intent.content.content_id.as_str()),
                text(hash(&header.intent.target_path)?.as_str()),
                rusqlite::types::Value::Integer(header.intent.created_at_ms as i64),
                text(&owner.volume),
                text(&owner.id),
                text(&header.parent.volume),
                text(&header.parent.id),
                text(header.intent.target_path.as_str()),
            ],
            false,
            || held.verify_content(),
        )?;
        Ok(held)
    }

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
        let owner_key = creator_key(&before, &creation.header, 1)?;
        if key(creation.marker.key()?) != marker_key
            || key(creation.payload.key()?) != payload_key
            || key(creation._owner.key()?) != owner_key
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
            owner_key,
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
