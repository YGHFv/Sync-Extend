use super::windows::*;
use super::*;
use crate::storage_policy;
use rusqlite::{params_from_iter, Transaction, TransactionBehavior};
use sync_extend_platform_fs::{LockedDirectory, LockedDirectoryMutation, LockedFile};

impl Journal {
    fn replace_cleanup_row(
        &mut self,
        header: &Header,
        table: &str,
        values: Vec<rusqlite::types::Value>,
        closing: bool,
        verify: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace cleanup caller transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&header.baseline.space_id, bounds)?;
        if !before.report.within_accounted_limits() {
            return Err(invalid("remote Replace cleanup lowered capacity"));
        }
        let current = self
            .remote_replace_receipts(&header.baseline.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == header.transaction_id)
            .ok_or(invalid("remote Replace cleanup receipt missing"))?;
        if !current.local_committed || current.native_cleanup_complete {
            return Err(invalid("remote Replace cleanup original Final missing"));
        }
        let mut expected = rows(&before);
        if closing {
            let (pk, cols) = columns(table, &values)?;
            expected.insert((table.into(), pk), cols);
            let mut permitted = vec![text("phases")];
            permitted.extend(values.clone());
            let _permit = self
                .remote_replace_issuance
                .permit(Some(permitted), Some("cleanup"))?;
            tx.execute(
                "INSERT INTO main.remote_replace_phases VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params_from_iter(values),
            )?;
            for (role, id) in pins(header) {
                expected.remove(&(
                    "remote_replace_objects".into(),
                    vec![
                        header.transaction_id.to_string(),
                        role.into(),
                        id.to_string(),
                    ],
                ));
            }
            tx.execute(
                "DELETE FROM main.remote_replace_objects WHERE transaction_id=?1",
                [header.transaction_id.as_str()],
            )?;
        } else {
            self.replace_insert(&mut expected, header, table, values, None)?;
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&header.baseline.space_id, bounds)?;
        receipt(&expected, &after)?;
        if !closing && before.report.accounted_total() != after.report.accounted_total() {
            return Err(invalid("remote Replace cleanup exact liability drift"));
        }
        verify()?;
        tx.commit()?;
        Ok(())
    }
    /// Dispose only the exact original quarantine and empty original directories.
    /// Final is not cleaned; foreign slots/children and preexisting base stay intact.
    pub fn cleanup_remote_replace(&mut self, id: &EntryId) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace cleanup caller transaction"));
        }
        let header = self.replace_header(id)?;
        let receipt = self
            .remote_replace_receipts(&header.baseline.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == *id)
            .ok_or(invalid("remote Replace cleanup receipt missing"))?;
        if receipt.native_cleanup_complete {
            return Ok(());
        }
        if !receipt.local_committed {
            return Err(invalid("remote Replace cleanup requires original Final"));
        }
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if !self
            .read_view()
            .audit_local_commit_capacity(&header.baseline.space_id, bounds)?
            .report
            .within_accounted_limits()
        {
            return Err(invalid("remote Replace cleanup lowered capacity"));
        }
        tx.commit()?;
        let originals = std::collections::BTreeMap::from([
            (
                0,
                header
                    .existing_base
                    .clone()
                    .or(self.replace_creator_key(&header, 0)?),
            ),
            (1, self.replace_creator_key(&header, 1)?),
            (3, Some(header.source_key.clone())),
        ]);
        for step in [3u64, 1, 0] {
            if step == 0 && header.existing_base.is_some() {
                continue;
            }
            let stage_exists = |stage: &str| -> Result<bool> {
                Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM main.remote_replace_dispositions WHERE transaction_id=?1 AND step=?2 AND stage=?3)",
                    rusqlite::params![id.as_str(),step as i64,stage],|r|r.get(0))?)
            };
            if stage_exists("terminal")? {
                continue;
            }
            let intended = stage_exists("intended")?;
            let absent_recorded = stage_exists("absent")?;
            let mut ancestors = Vec::new();
            for expected in &header.source_chain {
                let guard = LockedDirectory::open(std::path::Path::new(&expected.path))?;
                guard.require_case_insensitive()?;
                if key(guard.key()?) != expected.key {
                    return Err(invalid("remote Replace cleanup parent replacement"));
                }
                ancestors.push(guard);
            }
            let base = if step > 0 {
                let guard = LockedDirectory::open(&base_path(&header))?;
                if Some(key(guard.key()?)) != originals[&0] {
                    return Err(invalid("remote Replace cleanup base differs"));
                }
                Some(guard)
            } else {
                None
            };
            let owner = if step == 3 {
                let guard = LockedDirectory::open(&owner_path(&header))?;
                if Some(key(guard.key()?)) != originals[&1] {
                    return Err(invalid("remote Replace cleanup owner differs"));
                }
                Some(guard)
            } else {
                None
            };
            let path = match step {
                3 => owner_path(&header).join("original"),
                1 => owner_path(&header),
                _ => base_path(&header),
            };
            let original = originals[&step]
                .as_ref()
                .ok_or(invalid("remote Replace original cleanup key missing"))?;
            // Intended replay is still a native effect: tightened policy must
            // be checked before retrying descriptor disposition, not afterward.
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            if !self
                .read_view()
                .audit_local_commit_capacity(&header.baseline.space_id, bounds)?
                .report
                .within_accounted_limits()
            {
                return Err(invalid("remote Replace disposition lowered capacity"));
            }
            tx.commit()?;
            let values = |stage: &str| -> Result<Vec<rusqlite::types::Value>> {
                Ok(vec![
                    text(id.as_str()),
                    text(header.generation.as_str()),
                    rusqlite::types::Value::Integer(step as i64),
                    text(hash(&header)?.as_str()),
                    text(stage),
                    text(&original.volume),
                    text(&original.id),
                ])
            };
            let absent = || -> Result<()> {
                if present(&path)? {
                    return Err(invalid(
                        "remote Replace disposition pending or foreign slot preserved",
                    ));
                }
                Ok(())
            };
            if present(&path)? {
                if absent_recorded {
                    return Err(invalid(
                        "remote Replace foreign slot after absence preserved",
                    ));
                }
                if step == 3 {
                    let file = LockedFile::open(&path)?;
                    let verify = || -> Result<()> {
                        if key(file.key()?) != *original || !file.matches_path(&path)? {
                            return Err(invalid("remote Replace quarantine fullkey differs"));
                        }
                        verify_file(&file, &header.source)?;
                        Ok(())
                    };
                    verify()?;
                    if !intended {
                        self.replace_cleanup_row(
                            &header,
                            "remote_replace_dispositions",
                            values("intended")?,
                            false,
                            verify,
                        )?;
                    }
                    file.delete_on_close()?;
                } else {
                    let directory = LockedDirectoryMutation::open(&path)?;
                    let verify = || -> Result<()> {
                        if key(directory.key()?) != *original {
                            return Err(invalid("remote Replace original empty directory differs"));
                        }
                        directory.require_case_insensitive()?;
                        Ok(())
                    };
                    verify()?;
                    if !intended {
                        self.replace_cleanup_row(
                            &header,
                            "remote_replace_dispositions",
                            values("intended")?,
                            false,
                            verify,
                        )?;
                    }
                    directory.delete_empty_on_close()?;
                }
            } else if !intended {
                return Err(invalid("remote Replace missing original before intended"));
            }
            absent()?;
            if !absent_recorded {
                self.replace_cleanup_row(
                    &header,
                    "remote_replace_dispositions",
                    values("absent")?,
                    false,
                    absent,
                )?;
            }
            self.replace_cleanup_row(
                &header,
                "remote_replace_dispositions",
                values("terminal")?,
                false,
                absent,
            )?;
            drop(owner);
            drop(base);
            drop(ancestors);
        }
        self.replace_cleanup_row(
            &header,
            "remote_replace_phases",
            phase_values(&header, "cleanup")?,
            true,
            || Ok(()),
        )
    }
}
