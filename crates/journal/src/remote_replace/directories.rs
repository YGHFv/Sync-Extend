use super::windows::*;
use super::*;
use rusqlite::{Transaction, TransactionBehavior};
use std::path::Path;
use sync_extend_platform_fs::{LockedDirectory, LockedDirectoryMutation};

impl Journal {
    pub(super) fn replace_creator_key(&self, header: &Header, step: u64) -> Result<Option<Key>> {
        Ok(self.connection.query_row(
            "SELECT volume,full_id FROM main.remote_replace_creators WHERE transaction_id=?1 AND step=?2",
            rusqlite::params![header.transaction_id.as_str(),step as i64],
            |r|Ok(Key { volume:r.get(0)?,id:r.get(1)? }),
        ).optional()?)
    }
    pub(super) fn replace_original_row(
        &mut self,
        held: &RemoteReplaceSource,
        table: &str,
        values: Vec<rusqlite::types::Value>,
        verify: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace creator caller transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.replace_before(&held.header)?;
        let mut expected = rows(&before);
        self.replace_insert(&mut expected, &held.header, table, values, None)?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&held.header.baseline.space_id, before.report.limits())?;
        receipt(&expected, &after)?;
        if before.report.accounted_total() != after.report.accounted_total() {
            return Err(invalid("remote Replace creator original liability drift"));
        }
        held.source_slot()?;
        verify()?;
        tx.commit()?;
        Ok(())
    }
    fn create_replace_directory(
        &mut self,
        held: &RemoteReplaceSource,
        step: u64,
        parent: &LockedDirectory,
        path: &Path,
    ) -> Result<LockedDirectoryMutation> {
        let p = key(parent.key()?);
        let name = component(&held.header, step);
        let values = vec![
            text(held.transaction_id().as_str()),
            text(held.header.generation.as_str()),
            rusqlite::types::Value::Integer(step as i64),
            text(hash(&held.header)?.as_str()),
            text(&name),
            text("directory"),
            text(&p.volume),
            text(&p.id),
        ];
        self.replace_original_row(
            held,
            "remote_replace_activations",
            values.clone(),
            || Ok(()),
        )?;
        let created = if step == 0 {
            parent.create_new_staging_directory()?
        } else {
            parent.create_new_child(&name)?
        };
        let original = created.original_creation()?;
        original.verify()?;
        if original.created_component() != name || key(original.parent_key()?) != p {
            return Err(invalid(
                "remote Replace original directory differs from activation",
            ));
        }
        let k = key(original.key()?);
        let mut values = values;
        values.extend([text(&k.volume), text(&k.id)]);
        self.replace_original_row(held, "remote_replace_creators", values, || {
            original.verify()?;
            if key(original.key()?) != k || key(original.parent_key()?) != p {
                return Err(invalid("remote Replace retained original directory drift"));
            }
            Ok(())
        })?;
        if !path.is_absolute() {
            return Err(invalid("remote Replace directory path"));
        }
        Ok(created)
    }
    pub(super) fn retain_remote_replace_directories(
        &mut self,
        mut held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceSource> {
        let base = held
            .header
            .existing_base
            .clone()
            .or(self.replace_creator_key(&held.header, 0)?);
        let owner = self.replace_creator_key(&held.header, 1)?;
        for (path, expected) in [
            (base_path(&held.header), base.clone()),
            (owner_path(&held.header), owner.clone()),
        ] {
            if let Some(expected) = expected {
                let guard = LockedDirectory::open(&path)?;
                guard.require_local_ntfs(&path)?;
                guard.require_case_insensitive()?;
                if key(guard.key()?) != expected {
                    return Err(invalid("remote Replace original directory replacement"));
                }
                if path == base_path(&held.header) {
                    held._base = Some(guard);
                } else {
                    held._owner = Some(guard);
                }
            }
        }
        held.base_key = base;
        held.owner_key = owner;
        held.verify_content()?;
        Ok(held)
    }
    pub fn create_remote_replace_directories(
        &mut self,
        mut held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceSource> {
        held.source_slot()?;
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace CREATE caller transaction"));
        }
        for step in 0..=1 {
            if step == 0 && held.header.existing_base.is_some() {
                continue;
            }
            let activated:bool=self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.remote_replace_activations WHERE transaction_id=?1 AND step=?2)",
                rusqlite::params![held.transaction_id().as_str(),step as i64],|r|r.get(0))?;
            let created = self.replace_creator_key(&held.header, step)?;
            if activated && created.is_none() {
                return Err(invalid(
                    "remote Replace incomplete original CREATE cannot retry or adopt",
                ));
            }
            if created.is_some() {
                continue;
            }
            let parent_path = if step == 0 {
                std::path::PathBuf::from(&held.header.source_chain[0].path)
            } else {
                base_path(&held.header)
            };
            let parent = LockedDirectory::open(&parent_path)?;
            let expected = if step == 0 {
                held.header.source_chain[0].key.clone()
            } else {
                held.header
                    .existing_base
                    .clone()
                    .or(self.replace_creator_key(&held.header, 0)?)
                    .ok_or(invalid("remote Replace original base missing"))?
            };
            if key(parent.key()?) != expected {
                return Err(invalid("remote Replace creator parent replacement"));
            }
            let path = if step == 0 {
                base_path(&held.header)
            } else {
                owner_path(&held.header)
            };
            let created = self.create_replace_directory(&held, step, &parent, &path)?;
            let k = key(created.key()?);
            drop(created);
            let guard = LockedDirectory::open(&path)?;
            if key(guard.key()?) != k {
                return Err(invalid(
                    "remote Replace just-created directory slot differs",
                ));
            }
            if step == 0 {
                held._base = Some(guard);
                held.base_key = Some(k);
            } else {
                held._owner = Some(guard);
                held.owner_key = Some(k);
            }
        }
        self.retain_remote_replace_directories(held)
    }
}
