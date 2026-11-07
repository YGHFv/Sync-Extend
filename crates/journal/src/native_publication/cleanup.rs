//! Exact original staging disposition, never published-target or recursive delete.
use super::{creation::key, field, issuance, physical, Header, Key};
use crate::{
    storage_inventory::reader::{hash, invalid},
    storage_policy, Journal, JournalStorageColumn, JournalStorageColumnValue, PublicationState,
    Result,
};
use rusqlite::{params_from_iter, types::Value, Transaction, TransactionBehavior};
use std::{collections::BTreeMap, fs, io::Read, path::PathBuf};
use sync_extend_core_model::EntryId;
use sync_extend_platform_fs::{LockedDirectory, LockedDirectoryMutation, LockedFile};

fn present(path: &std::path::Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn absent(path: &std::path::Path) -> Result<()> {
    if present(path)? {
        return Err(invalid("native cleanup pending or foreign slot preserved"));
    }
    Ok(())
}
fn text(value: &str) -> Value {
    Value::Text(value.into())
}
type Rows = BTreeMap<(String, Vec<String>), Vec<JournalStorageColumn>>;
fn rows(snapshot: &crate::storage_capacity::CapacitySnapshot) -> Rows {
    snapshot
        .rows
        .iter()
        .map(|row| {
            (
                (row.table().into(), row.primary_key().to_vec()),
                row.columns().to_vec(),
            )
        })
        .collect()
}
impl Journal {
    fn native_cleanup_row(
        &mut self,
        header: &Header,
        table: &'static str,
        values: Vec<Value>,
        closing: bool,
        recheck: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&header.intent.space_id, bounds)?;
        let publication = self.publication(&header.intent.transaction_id)?;
        if publication.intent != header.intent
            || publication.state != PublicationState::Committed
            || publication.cleaned
            || !before.report.within_accounted_limits()
        {
            return Err(invalid(
                "native cleanup original committed owner or capacity differs",
            ));
        }
        let spec = super::schema::TABLES
            .iter()
            .find(|spec| spec.name == table)
            .ok_or(invalid("native cleanup schema missing"))?;
        if spec.columns.len() != values.len() {
            return Err(invalid("native cleanup exact width differs"));
        }
        let columns = spec
            .columns
            .iter()
            .zip(&values)
            .map(|(column, value)| {
                Ok(JournalStorageColumn {
                    name: column.name.into(),
                    value: match value {
                        Value::Text(value) => JournalStorageColumnValue::Text(value.clone()),
                        Value::Integer(value) => JournalStorageColumnValue::Integer(
                            u64::try_from(*value).map_err(|_| invalid("native cleanup integer"))?,
                        ),
                        _ => return Err(invalid("native cleanup value")),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let pk = spec
            .columns
            .iter()
            .zip(&values)
            .filter(|(column, _)| column.primary_key != 0)
            .map(|(_, value)| match value {
                Value::Text(value) => Ok(value.clone()),
                Value::Integer(value) => Ok(value.to_string()),
                _ => Err(invalid("native cleanup PK")),
            })
            .collect::<Result<Vec<_>>>()?;
        let mut expected = rows(&before);
        if expected.insert((table.into(), pk), columns).is_some() {
            return Err(invalid("native cleanup one-shot stage already recorded"));
        }
        if closing {
            let publication = expected
                .get_mut(&(
                    "publications".into(),
                    vec![header.intent.transaction_id.to_string()],
                ))
                .ok_or(invalid("native cleanup owner missing"))?;
            publication
                .iter_mut()
                .find(|column| column.name == "cleaned")
                .ok_or(invalid("native cleanup cleaned column missing"))?
                .value = JournalStorageColumnValue::Integer(1);
        }
        let kind = table
            .strip_prefix("native_publication_")
            .ok_or(invalid("native cleanup namespace"))?;
        let mut authorized = vec![text(kind)];
        authorized.extend(values.clone());
        let _permit = issuance::permit(&self.native_issuance, authorized)?;
        let params = (1..=values.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(",");
        if tx.execute(
            &format!("INSERT INTO main.{table} VALUES ({params})"),
            params_from_iter(&values),
        )? != 1
        {
            return Err(invalid("native cleanup insert missing"));
        }
        if closing && tx.execute("UPDATE publications SET cleaned=1 WHERE transaction_id=?1 AND state='committed' AND cleaned=0",
            [header.intent.transaction_id.as_str()])? != 1 {
            return Err(invalid("native cleanup closing owner changed"));
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&header.intent.space_id, bounds)?;
        if rows(&after) != expected
            || !after.report.within_accounted_limits()
            || (!closing && before.report.accounted_total() != after.report.accounted_total())
            || (closing
                && (after.report.accounted_total().rows > before.report.accounted_total().rows
                    || after.report.accounted_total().logical_bytes
                        > before.report.accounted_total().logical_bytes))
        {
            return Err(invalid("native cleanup exact receipt or liability drift"));
        }
        recheck()?;
        tx.commit()?;
        Ok(())
    }

    /// Dispose only exact original staging objects after durable original Final.
    /// Unknown children, foreign replacements and delayed absence are preserved.
    /// A completed repeat is metadata-only and never reopens old native slots.
    pub fn cleanup_native_publication(&mut self, id: &EntryId) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("native cleanup refuses caller-owned transaction"));
        }
        self.native_publication_final_snapshot(id)?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let snapshot = self
            .read_view()
            .audit_local_commit_capacity(&self.publication(id)?.intent.space_id, bounds)?;
        if self.publication(id)?.cleaned {
            tx.commit()?;
            return Ok(());
        }
        let row = snapshot
            .rows
            .iter()
            .find(|row| {
                row.table() == "native_publication_headers" && row.primary_key() == [id.as_str()]
            })
            .ok_or(invalid("native cleanup header missing"))?;
        let header: Header = serde_json::from_str(field(row, "header")?)?;
        tx.commit()?;
        let mut original = BTreeMap::new();
        for row in snapshot.rows.iter().filter(|row| {
            row.table() == "native_publication_creators" && row.primary_key()[0] == id.as_str()
        }) {
            original.insert(
                super::number(row, "step")?,
                Key {
                    volume: field(row, "volume")?.into(),
                    id: field(row, "full_id")?.into(),
                },
            );
        }
        let parent_path = PathBuf::from(&header.ancestors[0].path);
        let base_path = parent_path.join(".sync-tmp");
        let owner_path = base_path.join(format!("native-{}", header.generation));
        for step in [3u64, 2, 1, 0] {
            if step == 0 && header.existing_base.is_some() {
                continue;
            }
            let stage_exists = |stage: &str| -> Result<bool> {
                Ok(self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM native_publication_dispositions WHERE transaction_id=?1 AND step=?2 AND stage=?3)",
                    rusqlite::params![id.as_str(),step as i64,stage],|row|row.get(0))?)
            };
            if stage_exists("terminal")? {
                continue;
            }
            let intended = stage_exists("intended")?;
            let absent_recorded = stage_exists("absent")?;
            let mut ancestors = Vec::new();
            for expected in &header.ancestors {
                let held = LockedDirectory::open(&PathBuf::from(&expected.path))?;
                held.require_local_ntfs(&PathBuf::from(&expected.path))?;
                held.require_case_insensitive()?;
                if key(held.key()?) != expected.key {
                    return Err(invalid("native cleanup ancestor changed"));
                }
                ancestors.push(held);
            }
            let base = if step > 0 {
                let held = LockedDirectory::open(&base_path)?;
                held.require_case_insensitive()?;
                let expected = header
                    .existing_base
                    .as_ref()
                    .or_else(|| original.get(&0))
                    .ok_or(invalid("native cleanup scaffold receipt missing"))?;
                if key(held.key()?) != *expected {
                    return Err(invalid("native cleanup scaffold changed"));
                }
                Some(held)
            } else {
                None
            };
            let owner = if step >= 2 {
                let held = LockedDirectory::open(&owner_path)?;
                held.require_case_insensitive()?;
                if key(held.key()?) != original[&1] {
                    return Err(invalid("native cleanup owner changed"));
                }
                Some(held)
            } else {
                None
            };
            let path = match step {
                3 => owner_path.join("payload-0"),
                2 => owner_path.join("owner"),
                1 => owner_path.clone(),
                _ => base_path.clone(),
            };
            let original_key = original
                .get(&step)
                .ok_or(invalid("native cleanup original missing"))?;
            let values = |stage: &str| -> Result<Vec<Value>> {
                Ok(vec![
                    text(id.as_str()),
                    text(header.generation.as_str()),
                    Value::Integer(step as i64),
                    text(hash(&header)?.as_str()),
                    text(stage),
                    text(physical(original_key)?.as_str()),
                    Value::Integer(header.intent.created_at_ms as i64),
                ])
            };
            if step == 3 {
                absent(&path)?;
                if !intended {
                    self.native_cleanup_row(
                        &header,
                        "native_publication_dispositions",
                        values("intended")?,
                        false,
                        || absent(&path),
                    )?;
                }
            } else if present(&path)? {
                if absent_recorded {
                    return Err(invalid(
                        "native cleanup new occupant after absence preserved",
                    ));
                }
                if step == 2 {
                    let held = LockedFile::open(&path)?;
                    let verify = || -> Result<()> {
                        if key(held.key()?) != *original_key || !held.matches_path(&path)? {
                            return Err(invalid("native cleanup marker identity differs"));
                        }
                        let mut reader = held.reader();
                        use std::io::{Seek, SeekFrom};
                        reader.seek(SeekFrom::Start(0))?;
                        let mut bytes = [0u8; 32];
                        reader.read_exact(&mut bytes)?;
                        if bytes != *id.as_str().as_bytes() || reader.read(&mut [0u8; 1])? != 0 {
                            return Err(invalid("native cleanup marker bytes differ"));
                        }
                        Ok(())
                    };
                    verify()?;
                    if !intended {
                        self.native_cleanup_row(
                            &header,
                            "native_publication_dispositions",
                            values("intended")?,
                            false,
                            verify,
                        )?;
                    }
                    held.delete_on_close()?;
                } else {
                    let held = LockedDirectoryMutation::open(&path)?;
                    if key(held.key()?) != *original_key {
                        return Err(invalid("native cleanup directory identity differs"));
                    }
                    if !intended {
                        self.native_cleanup_row(
                            &header,
                            "native_publication_dispositions",
                            values("intended")?,
                            false,
                            || {
                                if key(held.key()?) != *original_key {
                                    return Err(invalid(
                                        "native cleanup retained directory differs",
                                    ));
                                }
                                Ok(())
                            },
                        )?;
                    }
                    held.delete_empty_on_close()?;
                }
            } else if !intended {
                return Err(invalid("native cleanup missing original before intended"));
            }
            absent(&path)?;
            if !absent_recorded {
                self.native_cleanup_row(
                    &header,
                    "native_publication_dispositions",
                    values("absent")?,
                    false,
                    || absent(&path),
                )?;
            }
            self.native_cleanup_row(
                &header,
                "native_publication_dispositions",
                values("terminal")?,
                false,
                || absent(&path),
            )?;
            drop(owner);
            drop(base);
            drop(ancestors);
        }
        let payload = original
            .get(&3)
            .ok_or(invalid("native cleanup payload receipt missing"))?;
        let owner = original
            .get(&1)
            .ok_or(invalid("native cleanup owner receipt missing"))?;
        self.native_cleanup_row(
            &header,
            "native_publication_phases",
            vec![
                text(id.as_str()),
                text(header.generation.as_str()),
                Value::Integer(0),
                text(hash(&header)?.as_str()),
                text("cleanup"),
                text(physical(payload)?.as_str()),
                text(header.intent.content.content_id.as_str()),
                text(hash(&header.intent.target_path)?.as_str()),
                Value::Integer(header.intent.created_at_ms as i64),
                text(&owner.volume),
                text(&owner.id),
                text(&header.parent.volume),
                text(&header.parent.id),
                text(header.intent.target_path.as_str()),
            ],
            true,
            || Ok(()),
        )?;
        Ok(())
    }
}
