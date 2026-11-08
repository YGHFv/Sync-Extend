//! One original writable payload; closing it never mints a new creator receipt.
use super::windows::*;
use super::*;
use rusqlite::{Transaction, TransactionBehavior};
use std::fs::File;
use sync_extend_platform_fs::{LockedFile, OwnedFileCreation};

pub struct RemoteReplaceCreation {
    pub(super) held: RemoteReplaceSource,
    pub(super) payload: OwnedFileCreation,
    key: Key,
}
pub struct RemoteReplaceReadiness {
    pub(super) held: RemoteReplaceSource,
}
impl RemoteReplaceCreation {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    pub fn payload_writer(&mut self) -> &mut File {
        self.payload.writer()
    }
    pub(super) fn verify(&self) -> Result<()> {
        self.held.source_slot()?;
        let original = self.payload.original_creation()?;
        original.verify()?;
        if key(original.key()?) != self.key
            || Some(key(original.parent_key()?)) != self.held.owner_key
            || original.created_component() != "payload-0"
        {
            return Err(invalid("remote Replace original payload lineage differs"));
        }
        Ok(())
    }
}
impl RemoteReplaceReadiness {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    pub fn verify_content(&self) -> Result<()> {
        self.held.source_slot()?;
        self.held.payload_slot()
    }
}
impl Journal {
    pub fn create_remote_replace_payload(
        &mut self,
        held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceCreation> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace payload caller transaction"));
        }
        held.source_slot()?;
        let activated: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.remote_replace_activations WHERE transaction_id=?1 AND step=2)",
            [held.transaction_id().as_str()], |r| r.get(0),
        )?;
        if activated {
            return Err(invalid(
                "remote Replace original payload CREATE is one-shot",
            ));
        }
        let owner = held
            ._owner
            .as_ref()
            .ok_or(invalid("remote Replace original owner missing"))?;
        let p = key(owner.key()?);
        let values = vec![
            text(held.transaction_id().as_str()),
            text(held.header.generation.as_str()),
            rusqlite::types::Value::Integer(2),
            text(hash(&held.header)?.as_str()),
            text("payload-0"),
            text("file"),
            text(&p.volume),
            text(&p.id),
        ];
        self.replace_original_row(&held, "remote_replace_activations", values.clone(), || {
            Ok(())
        })?;
        let payload = owner.create_new_file("payload-0")?;
        let original = payload.original_creation()?;
        let k = key(original.key()?);
        let mut values = values;
        values.extend([text(&k.volume), text(&k.id)]);
        self.replace_original_row(&held, "remote_replace_creators", values, || {
            original.verify()?;
            if key(original.key()?) != k
                || key(original.parent_key()?) != p
                || original.created_component() != "payload-0"
            {
                return Err(invalid(
                    "remote Replace payload differs from original activation",
                ));
            }
            Ok(())
        })?;
        let creation = RemoteReplaceCreation {
            held,
            payload,
            key: k,
        };
        creation.verify()?;
        Ok(creation)
    }
    /// Flush and close the sole original writer before reacquiring exact guarded
    /// reads. Leaked writable clones refuse; no path-open writer is ever issued.
    pub fn seal_remote_replace_payload(
        &mut self,
        creation: RemoteReplaceCreation,
    ) -> Result<RemoteReplaceReadiness> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace seal caller transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.replace_before(&creation.held.header)?;
        creation.verify()?;
        if self.replace_creator_key(&creation.held.header, 2)?.as_ref() != Some(&creation.key) {
            return Err(invalid("remote Replace seal original receipt differs"));
        }
        creation.payload.reader().sync_all()?;
        let RemoteReplaceCreation {
            mut held,
            payload,
            key: original_key,
        } = creation;
        drop(payload);
        let reopened = LockedFile::open(&owner_path(&held.header).join("payload-0"))?;
        if key(reopened.key()?) != original_key {
            return Err(invalid("remote Replace just-closed payload slot changed"));
        }
        held.payload_key = Some(original_key);
        held.payload = Some(reopened);
        held.source_slot()?;
        held.payload_slot()?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&held.header.baseline.space_id, before.report.limits())?;
        if before.rows != after.rows || before.report != after.report {
            return Err(invalid("remote Replace seal changed stored values"));
        }
        tx.commit()?;
        Ok(RemoteReplaceReadiness { held })
    }
    pub fn record_remote_replace_ready(
        &mut self,
        ready: RemoteReplaceReadiness,
    ) -> Result<RemoteReplaceReadiness> {
        ready.verify_content()?;
        self.replace_phase(&ready.held, "ready")?;
        Ok(ready)
    }
}
