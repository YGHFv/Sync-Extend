use super::*;
use crate::{
    storage_capacity::CapacitySnapshot, storage_policy, CasAccessGuard, JournalStorageColumn,
    JournalStorageColumnValue as ColumnValue,
};
use rusqlite::{params, params_from_iter, types::Value, Transaction, TransactionBehavior};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use sync_extend_platform_fs::{FileKey, LockedDirectory, LockedFile};

type Rows = BTreeMap<(String, Vec<String>), Vec<JournalStorageColumn>>;
pub(super) fn rows(snapshot: &CapacitySnapshot) -> Rows {
    snapshot
        .rows
        .iter()
        .map(|r| {
            (
                (r.table().into(), r.primary_key().to_vec()),
                r.columns().to_vec(),
            )
        })
        .collect()
}
pub(super) fn key(key: FileKey) -> Key {
    Key {
        volume: format!("{:016x}", key.volume),
        id: format!("{:032x}", key.id),
    }
}
pub(super) fn text(s: &str) -> Value {
    Value::Text(s.into())
}
fn column(name: &str, value: &Value) -> Result<JournalStorageColumn> {
    Ok(JournalStorageColumn {
        name: name.into(),
        value: match value {
            Value::Text(s) => ColumnValue::Text(s.clone()),
            Value::Integer(n) => ColumnValue::Integer(
                u64::try_from(*n).map_err(|_| invalid("remote Replace signed value"))?,
            ),
            _ => return Err(invalid("remote Replace SQL value type")),
        },
    })
}
pub(super) fn columns(
    table: &str,
    values: &[Value],
) -> Result<(Vec<String>, Vec<JournalStorageColumn>)> {
    let spec = schema::TABLES
        .iter()
        .find(|s| s.name == table)
        .ok_or(invalid("remote Replace table"))?;
    if spec.columns.len() != values.len() {
        return Err(invalid("remote Replace row width"));
    }
    let columns = spec
        .columns
        .iter()
        .zip(values)
        .map(|(c, v)| column(c.name, v))
        .collect::<Result<_>>()?;
    let mut keys: Vec<_> = spec
        .columns
        .iter()
        .zip(values)
        .filter(|(c, _)| c.primary_key != 0)
        .map(|(c, v)| {
            Ok((
                c.primary_key,
                match v {
                    Value::Text(s) => s.clone(),
                    Value::Integer(n) => n.to_string(),
                    _ => return Err(invalid("remote Replace key type")),
                },
            ))
        })
        .collect::<Result<_>>()?;
    keys.sort_by_key(|(index, _)| *index);
    Ok((keys.into_iter().map(|(_, s)| s).collect(), columns))
}
pub(super) fn receipt(expected: &Rows, after: &CapacitySnapshot) -> Result<()> {
    if rows(after) != *expected || !after.report.within_accounted_limits() {
        return Err(invalid(
            "remote Replace exact all-value receipt or capacity",
        ));
    }
    Ok(())
}
pub(super) fn at(header: &Header, path: &PortablePath) -> PathBuf {
    Path::new(&header.root.path).join(path.as_str())
}
fn header_existing_base(header: &Header) -> Option<Key> {
    header.existing_base.clone()
}
pub(super) fn base_path(header: &Header) -> PathBuf {
    Path::new(&header.source_chain[0].path).join(".sync-tmp")
}
pub(super) fn owner_path(header: &Header) -> PathBuf {
    base_path(header).join(component(header, 1))
}
pub(super) fn destination(header: &Header) -> PathBuf {
    owner_path(header).join("original")
}
pub(super) fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
pub(super) fn chain(path: &Path) -> Result<(Vec<LockedDirectory>, Vec<Ancestor>)> {
    let mut guards = Vec::new();
    let mut ancestors = Vec::new();
    for path in path.ancestors() {
        let held = LockedDirectory::open(path)?;
        held.require_case_insensitive()?;
        ancestors.push(Ancestor {
            path: path
                .to_str()
                .ok_or(invalid("remote Replace nonUTF8 ancestor"))?
                .into(),
            key: key(held.key()?),
        });
        guards.push(held);
    }
    Ok((guards, ancestors))
}

pub(super) fn verify_file(file: &LockedFile, entry: &Entry) -> Result<()> {
    let expected = entry
        .content
        .as_ref()
        .ok_or(invalid("remote Replace file content missing"))?;
    if file.reader().metadata()?.len() != expected.length {
        return Err(invalid("remote Replace original source key/length differs"));
    }
    let mut reader = file.reader();
    reader.seek(SeekFrom::Start(0))?;
    let mut hash = blake3::Hasher::new();
    let mut left = expected.length;
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        left = left
            .checked_sub(n as u64)
            .ok_or(invalid("remote Replace source grew"))?;
        hash.update(&buffer[..n]);
    }
    if left != 0 || ContentId::from_hasher(&hash) != expected.content_id {
        return Err(invalid("remote Replace original content differs"));
    }
    Ok(())
}
/// One exact admitted existing original source; no public construction or Clone.
pub struct RemoteReplaceSource {
    pub(super) header: Header,
    pub(super) file: LockedFile,
    pub(super) _source: Vec<LockedDirectory>,
    pub(super) _base: Option<LockedDirectory>,
    pub(super) _owner: Option<LockedDirectory>,
    pub(super) base_key: Option<Key>,
    pub(super) owner_key: Option<Key>,
    pub(super) _cas: CasAccessGuard,
    pub(super) payload: Option<LockedFile>,
    pub(super) payload_key: Option<Key>,
}
/// Exact admitted original source observed at its non-overwritten destination.
pub struct RemoteReplaceObservation {
    pub(super) held: RemoteReplaceSource,
}
impl RemoteReplaceSource {
    pub fn transaction_id(&self) -> &EntryId {
        &self.header.transaction_id
    }
    pub fn verify_content(&self) -> Result<()> {
        if key(self.file.key()?) != self.header.source_key {
            return Err(invalid("remote Replace original fullkey differs"));
        }
        verify_file(&self.file, &self.header.source)?;
        for (held, a) in self._source.iter().zip(&self.header.source_chain) {
            held.require_case_insensitive()?;
            if key(held.key()?) != a.key {
                return Err(invalid("remote Replace retained parent changed"));
            }
        }
        for (guard, expected) in [
            (&self._base, self.base_key.clone()),
            (&self._owner, self.owner_key.clone()),
        ] {
            if let Some(guard) = guard {
                if Some(key(guard.key()?)) != expected {
                    return Err(invalid("remote Replace original directory guard differs"));
                }
            }
        }
        if let Some(payload) = &self.payload {
            if Some(key(payload.key()?)) != self.payload_key {
                return Err(invalid("remote Replace original payload fullkey differs"));
            }
            verify_file(payload, &self.incoming()?)?;
        }
        Ok(())
    }
    pub(super) fn incoming(&self) -> Result<Entry> {
        Ok(self
            .header
            .target
            .entries
            .get(&self.header.source.entry_id)
            .ok_or(invalid("remote Replace target entry missing"))?
            .clone())
    }
    pub(super) fn payload_slot(&self) -> Result<()> {
        self.verify_content()?;
        if !self
            .payload
            .as_ref()
            .ok_or(invalid("remote Replace payload not sealed"))?
            .matches_path(&owner_path(&self.header).join("payload-0"))?
        {
            return Err(invalid("remote Replace staging fullkey differs"));
        }
        Ok(())
    }
    pub(super) fn published_slot(&self) -> Result<()> {
        self.verify_content()?;
        if !self.file.matches_path(&destination(&self.header))?
            || present(&owner_path(&self.header).join("payload-0"))?
            || !self
                .payload
                .as_ref()
                .ok_or(invalid("remote Replace published payload missing"))?
                .matches_path(&at(&self.header, &self.header.source.path))?
        {
            return Err(invalid(
                "remote Replace target, original quarantine or stage absence differs",
            ));
        }
        Ok(())
    }
    pub(super) fn source_slot(&self) -> Result<()> {
        self.verify_content()?;
        if !self
            .file
            .matches_path(&at(&self.header, &self.header.source.path))?
            || present(&destination(&self.header))?
        {
            return Err(invalid("remote Replace source or occupied target differs"));
        }
        Ok(())
    }
    pub(super) fn quarantine_slot(&self) -> Result<()> {
        self.verify_content()?;
        if present(&at(&self.header, &self.header.source.path))?
            || !self.file.matches_path(&destination(&self.header))?
        {
            return Err(invalid(
                "remote Replace exact target or source absence differs",
            ));
        }
        Ok(())
    }
}
impl RemoteReplaceObservation {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    pub fn manifest(&self) -> &Manifest {
        &self.held.header.target
    }
    pub fn verify_content(&self) -> Result<()> {
        self.held.published_slot()
    }
}
fn header_values(header: &Header) -> Result<Vec<Value>> {
    Ok(vec![
        text(header.transaction_id.as_str()),
        text(header.baseline.space_id.as_str()),
        text(header.generation.as_str()),
        text(hash(header)?.as_str()),
        text(header.baseline.root()?.as_str()),
        Value::Integer(header.reserved.rows as i64),
        Value::Integer(header.reserved.logical_bytes as i64),
        text(&serde_json::to_string(header)?),
    ])
}
pub(super) fn phase_values(header: &Header, phase: &str) -> Result<Vec<Value>> {
    Ok(vec![
        text(header.transaction_id.as_str()),
        text(header.generation.as_str()),
        text(hash(header)?.as_str()),
        text(phase),
        text(&header.source_key.volume),
        text(&header.source_key.id),
        text(header.target_root.as_str()),
    ])
}
fn original_state(journal: &Journal, header: &Header, state: &str) -> Result<()> {
    header.proof.verify()?;
    let (json, stored): (String, String) = journal.connection.query_row(
        "SELECT payload,state FROM main.operations WHERE op_id=?1",
        [header.proof.operation.op_id.as_str()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if json != serde_json::to_string(&header.proof.operation)? || stored != state {
        return Err(invalid("remote Replace exact original received state"));
    }
    Ok(())
}
impl Journal {
    pub(super) fn replace_insert(
        &self,
        expected: &mut Rows,
        _header: &Header,
        table: &str,
        values: Vec<Value>,
        scope: Option<&'static str>,
    ) -> Result<()> {
        let (key, columns) = columns(table, &values)?;
        if expected.insert((table.into(), key), columns).is_some() {
            return Err(invalid("remote Replace reused row"));
        }
        let mut permitted = vec![text(table.strip_prefix("remote_replace_").unwrap())];
        permitted.extend(values.clone());
        let _permit = self
            .remote_replace_issuance
            .permit(Some(permitted), scope)?;
        let binds = (1..=values.len())
            .map(|n| format!("?{n}"))
            .collect::<Vec<_>>()
            .join(",");
        if self.connection.execute(
            &format!("INSERT INTO main.{table} VALUES({binds})"),
            params_from_iter(values),
        )? != 1
        {
            return Err(invalid("remote Replace original insert missing"));
        }
        Ok(())
    }
    pub(super) fn replace_before(&self, header: &Header) -> Result<CapacitySnapshot> {
        header.validate()?;
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&header.baseline.space_id, bounds)?;
        if !before.report.within_accounted_limits()
            || self.current(&header.baseline.space_id)?.as_ref() != Some(&header.baseline)
        {
            return Err(invalid(
                "remote Replace original baseline or lowered capacity",
            ));
        }
        if let Some(stored) = before.rows.iter().find(|row| {
            row.table() == "remote_replace_headers"
                && row.primary_key() == [header.transaction_id.as_str()]
        }) {
            if field(stored, "header")? != serde_json::to_string(header)? {
                return Err(invalid(
                    "remote Replace live guard differs from admitted original",
                ));
            }
        }
        original_state(self, header, "received")?;
        for (_, content) in pins(header) {
            self.require_cas_access(&content)?;
        }
        Ok(before)
    }
    /// Journal opens the original source directly and records its complete native
    /// keys before any rename. A caller cannot supply a synthetic source proof.
    pub fn begin_remote_replace(
        &mut self,
        proof: &RemotePublicationProof,
    ) -> Result<RemoteReplaceSource> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace caller transaction"));
        }
        proof.verify()?;
        let replay = self.replay_remote_operation(proof)?;
        if replay.disposition != crate::RemoteReplayDisposition::NativeMutationUnavailable {
            return Err(invalid(
                "remote Replace causal conflict or missing ancestry",
            ));
        }
        let baseline = self
            .current(&proof.operation.payload.space_id)?
            .ok_or(invalid("remote Replace baseline missing"))?;
        let (target, source) = target(&baseline, proof)?;
        let root = self
            .state("worktree")?
            .ok_or(invalid("remote Replace initialized root missing"))?;
        let source_path = Path::new(&root).join(source.path.as_str());

        let (source_guards, source_chain) = chain(
            source_path
                .parent()
                .ok_or(invalid("remote Replace source parent"))?,
        )?;
        let base_path = source_path.parent().unwrap().join(".sync-tmp");
        let base = if present(&base_path)? {
            Some(LockedDirectory::open(&base_path)?)
        } else {
            None
        };
        if let Some(base) = &base {
            base.require_local_ntfs(&base_path)?;
            base.require_case_insensitive()?;
        }
        let root_key = source_chain
            .iter()
            .find(|a| a.path == root)
            .ok_or(invalid("remote Replace root ancestor missing"))?
            .clone();
        let file = LockedFile::open(&source_path)?;
        let mut header = Header {
            format: 1,
            transaction_id: remote_replace_transaction(&proof.operation.op_id)?,
            generation: EntryId::random()?,
            proof: proof.clone(),
            baseline,
            target_root: target.root()?,
            target,
            source,
            root: root_key,
            source_chain,
            existing_base: base.as_ref().map(|b| b.key().map(key)).transpose()?,
            history_reserved: TreeStorageCharge::default(),
            source_key: key(file.key()?),
            reserved: TreeStorageCharge::default(),
        };
        header.history_reserved = history_reserve(&header)?;
        header.reserved = reserve(&header)?;
        header.validate()?;
        if serde_json::to_vec(&header)?.len() > crate::MAX_OPERATION_BYTES {
            return Err(invalid("remote Replace header byte budget"));
        }
        let held = RemoteReplaceSource {
            header: header.clone(),
            file,
            _source: source_guards,
            base_key: header_existing_base(&header),
            owner_key: None,
            _base: base,
            _owner: None,
            _cas: self.acquire_cas_session()?,
            payload: None,
            payload_key: None,
        };
        held.source_slot()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.replace_before(&held.header)?;
        storage_policy::receive::tree_gate(&before)?;
        storage_policy::receive::completion_gate(&before)?;
        self.require_no_remote_replace(&held.header.baseline.space_id)?;
        self.require_no_remote_delete(&held.header.baseline.space_id)?;
        self.require_no_remote_rename(&held.header.baseline.space_id)?;
        let values = header_values(&held.header)?;
        let added_bytes = values
            .iter()
            .map(|v| match v {
                Value::Text(s) => s.len() as u64,
                Value::Integer(_) => 8,
                _ => 0,
            })
            .sum::<u64>();
        let own_pins = pins(&held.header);
        let prior = before.report.accounted_total();
        let bounds = before.report.limits();
        if prior
            .rows
            .checked_add(1 + own_pins.len() as u64 + held.header.reserved.rows)
            .is_none_or(|n| n > bounds.max_rows)
            || prior
                .logical_bytes
                .checked_add(
                    added_bytes + own_pins.len() as u64 * 104 + held.header.reserved.logical_bytes,
                )
                .is_none_or(|n| n > bounds.max_logical_bytes)
        {
            return Err(invalid("remote Replace pre-effect complete capacity"));
        }
        let mut expected = rows(&before);
        self.replace_insert(
            &mut expected,
            &held.header,
            "remote_replace_headers",
            values,
            None,
        )?;
        for (role, id) in own_pins {
            let values = vec![
                text(held.header.transaction_id.as_str()),
                text(role),
                text(id.as_str()),
            ];
            self.replace_insert(
                &mut expected,
                &held.header,
                "remote_replace_objects",
                values,
                None,
            )?;
        }
        // The new exact own pins invalidate any original live GC mark in the same transaction.
        for row in &before.rows {
            if row.table() == "gc_marks"
                && pins(&held.header)
                    .iter()
                    .any(|(_, id)| field(row, "content_id").is_ok_and(|s| s == id.as_str()))
                && !expected.contains_key(&("gc_cancellations".into(), row.primary_key().to_vec()))
            {
                let mark = field(row, "mark_id")?;
                expected
                    .entry(("gc_invalidations".into(), vec![mark.into()]))
                    .or_insert_with(|| {
                        vec![JournalStorageColumn {
                            name: "mark_id".into(),
                            value: ColumnValue::Text(mark.into()),
                        }]
                    });
            }
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&held.header.baseline.space_id, bounds)?;
        receipt(&expected, &after)?;
        held.source_slot()?;
        tx.commit()?;

        Ok(held)
    }
    pub(super) fn replace_phase(
        &mut self,
        held: &RemoteReplaceSource,
        phase: &'static str,
    ) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace phase caller transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.replace_before(&held.header)?;
        let mut expected = rows(&before);
        self.replace_insert(
            &mut expected,
            &held.header,
            "remote_replace_phases",
            phase_values(&held.header, phase)?,
            None,
        )?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&held.header.baseline.space_id, before.report.limits())?;
        receipt(&expected, &after)?;
        if before.report.accounted_total() != after.report.accounted_total() {
            return Err(invalid("remote Replace phase liability changed"));
        }
        match phase {
            "ready" | "executing" => {
                held.source_slot()?;
                held.payload_slot()?;
            }
            "quarantined" | "publishing" => {
                held.quarantine_slot()?;
                held.payload_slot()?;
            }
            "observed" => held.published_slot()?,
            _ => return Err(invalid("remote Replace unsupported phase writer")),
        }
        tx.commit()?;
        Ok(())
    }
    pub fn start_remote_replace(
        &mut self,
        ready: super::payload::RemoteReplaceReadiness,
    ) -> Result<RemoteReplaceSource> {
        let held = ready.held;
        held.source_slot()?;
        held.payload_slot()?;
        self.replace_phase(&held, "executing")?;
        Ok(held)
    }
    fn has_replace_phase(&self, header: &Header, phase: &str) -> Result<bool> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM main.remote_replace_phases WHERE transaction_id=?1 AND phase=?2)",
            params![header.transaction_id.as_str(), phase], |r| r.get(0))?)
    }
    fn replace_effect_gate(&self, held: &RemoteReplaceSource, phase: &str) -> Result<()> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace native effect caller transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.replace_before(&held.header)?;
        if !self.has_replace_phase(&held.header, phase)? {
            return Err(invalid(
                "remote Replace native effect lacks exact durable phase",
            ));
        }
        held.verify_content()?;
        tx.commit()?;
        Ok(())
    }
    pub fn quarantine_remote_replace(
        &mut self,
        held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceSource> {
        self.replace_effect_gate(&held, "executing")?;
        held.payload_slot()?;
        if present(&at(&held.header, &held.header.source.path))? {
            held.source_slot()?;
            held.file.rename_no_replace(&destination(&held.header))?;
        }
        held.quarantine_slot()?;
        if !self.has_replace_phase(&held.header, "quarantined")? {
            self.replace_phase(&held, "quarantined")?;
        }
        Ok(held)
    }
    pub fn start_remote_replace_publication(
        &mut self,
        held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceSource> {
        held.quarantine_slot()?;
        held.payload_slot()?;
        self.replace_phase(&held, "publishing")?;
        Ok(held)
    }
    pub fn publish_remote_replace(
        &mut self,
        held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceObservation> {
        self.replace_effect_gate(&held, "publishing")?;
        if present(&owner_path(&held.header).join("payload-0"))? {
            held.quarantine_slot()?;
            held.payload_slot()?;
            held.payload
                .as_ref()
                .ok_or(invalid("remote Replace original payload missing"))?
                .rename_no_replace(&at(&held.header, &held.header.source.path))?;
            // std cannot flush NTFS directory handles. Process-crash, not physical power-loss certification.
        }
        held.published_slot()?;
        if !self.has_replace_phase(&held.header, "observed")? {
            self.replace_phase(&held, "observed")?;
        }
        Ok(RemoteReplaceObservation { held })
    }
    pub(super) fn replace_header(&self, id: &EntryId) -> Result<Header> {
        let json: String = self.connection.query_row(
            "SELECT CASE WHEN length(CAST(header AS BLOB))<=16777216 THEN header ELSE '' END
             FROM main.remote_replace_headers WHERE transaction_id=?1",
            [id.as_str()],
            |r| r.get(0),
        )?;
        let header: Header = serde_json::from_str(&json)?;
        header.validate()?;
        Ok(header)
    }
    pub fn remote_replace_original(&self, id: &EntryId) -> Result<RemotePublicationProof> {
        Ok(self.replace_header(id)?.proof)
    }
    pub fn recover_remote_replace(&mut self, id: &EntryId) -> Result<RemoteReplaceObservation> {
        let held = self.reopen_remote_replace_source(id)?;
        self.resume_remote_replace(held)
    }
    pub fn reopen_remote_replace_source(&mut self, id: &EntryId) -> Result<RemoteReplaceSource> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace recovery caller transaction"));
        }
        let header = self.replace_header(id)?;
        let receipt = self
            .remote_replace_receipts(&header.baseline.space_id)?
            .into_iter()
            .find(|r| r.transaction_id == *id)
            .ok_or(invalid("remote Replace receipt missing"))?;
        if receipt.local_committed {
            return Err(invalid("remote Replace Final is metadata only"));
        }
        let (source, source_chain) = chain(Path::new(&header.source_chain[0].path))?;
        if source_chain != header.source_chain {
            return Err(invalid("remote Replace recovery parent replacement"));
        }
        // Each durable phase admits only the exact original before/after layout.
        let ready = self.has_replace_phase(&header, "ready")?;
        if !ready && self.replace_creator_key(&header, 2)?.is_some() {
            return Err(invalid(
                "remote Replace unsealed payload cannot reopen writer or adopt",
            ));
        }
        let executing = self.has_replace_phase(&header, "executing")?;
        let publishing = self.has_replace_phase(&header, "publishing")?;
        let source_path = at(&header, &header.source.path);
        let original_path = if executing && present(&destination(&header))? {
            destination(&header)
        } else {
            source_path.clone()
        };
        let file = LockedFile::open(&original_path)?;
        let payload_key = if ready {
            self.replace_creator_key(&header, 2)?
        } else {
            None
        };
        let payload = if ready {
            let path = if publishing && !present(&owner_path(&header).join("payload-0"))? {
                source_path.clone()
            } else {
                owner_path(&header).join("payload-0")
            };
            Some(LockedFile::open(&path)?)
        } else {
            None
        };
        let held = RemoteReplaceSource {
            header: header.clone(),
            file,
            _source: source,
            _base: None,
            _owner: None,
            base_key: header_existing_base(&header),
            owner_key: None,
            _cas: self.acquire_cas_session()?,
            payload,
            payload_key,
        };
        let held = self.retain_remote_replace_directories(held)?;
        held.verify_content()?;
        if publishing {
            if present(&owner_path(&header).join("payload-0"))? {
                held.quarantine_slot()?;
                held.payload_slot()?;
            } else {
                held.published_slot()?;
            }
        } else if executing {
            held.payload_slot()?;
            if present(&destination(&header))? {
                held.quarantine_slot()?;
            } else {
                held.source_slot()?;
            }
        } else {
            held.source_slot()?;
            if ready {
                held.payload_slot()?;
            }
        }
        Ok(held)
    }
    pub fn resume_remote_replace(
        &mut self,
        mut held: RemoteReplaceSource,
    ) -> Result<RemoteReplaceObservation> {
        if !self.has_replace_phase(&held.header, "ready")? {
            return Err(invalid(
                "remote Replace recovery requires durable original Ready; no writer adoption",
            ));
        }
        if !self.has_replace_phase(&held.header, "executing")? {
            self.replace_phase(&held, "executing")?;
        }
        if !self.has_replace_phase(&held.header, "publishing")? {
            held = self.quarantine_remote_replace(held)?;
            held = self.start_remote_replace_publication(held)?;
        }
        self.publish_remote_replace(held)
    }
    /// Atomically finalize only the exact original signed Replace, with all-table
    /// projection and live original target guards. No receive cursor write.
    pub fn finalize_remote_replace(
        &mut self,
        observation: RemoteReplaceObservation,
    ) -> Result<SnapshotId> {
        if !self.connection.is_autocommit() {
            return Err(invalid("remote Replace final caller transaction"));
        }
        observation.verify_content()?;
        let header = &observation.held.header;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let before = self.replace_before(header)?;
        let mut expected = rows(&before);
        if !expected.contains_key(&(
            "remote_replace_phases".into(),
            vec![header.transaction_id.to_string(), "observed".into()],
        )) {
            return Err(invalid("remote Replace original observed phase missing"));
        }
        let mut authorized = vec![text("phases")];
        let values = phase_values(header, "final")?;
        authorized.extend(values.clone());
        let _permit = self
            .remote_replace_issuance
            .permit(Some(authorized), Some("final"))?;
        let (pk, cols) = columns("remote_replace_phases", &values)?;
        expected.insert(("remote_replace_phases".into(), pk), cols);
        // Only the private transaction-local Final scope opens these writes;
        // durable Final alone retains writer fences until scoped cleanup.
        tx.execute(
            "INSERT INTO main.remote_replace_phases VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params_from_iter(values.clone()),
        )?;
        let op = header.proof.operation.op_id.as_str();
        let operation = expected
            .get_mut(&("operations".into(), vec![op.into()]))
            .ok_or(invalid("remote Replace original row missing"))?;
        operation
            .iter_mut()
            .find(|c| c.name == "state")
            .unwrap()
            .value = ColumnValue::Text("materialized".into());
        if tx.execute("UPDATE main.operations SET state='materialized' WHERE op_id=?1 AND payload=?2 AND state='received'",
            params![op,serde_json::to_string(&header.proof.operation)?])?!=1 { return Err(invalid("remote Replace original update missing")); }
        let root = header.target_root.as_str();
        let json = serde_json::to_string(&header.target)?;
        let snapshot_key = ("snapshots".into(), vec![root.into()]);
        if let Some(stored) = expected.get(&snapshot_key) {
            if stored
                .iter()
                .find(|c| c.name == "manifest")
                .map(|c| &c.value)
                != Some(&ColumnValue::Text(json.clone()))
                || stored.iter().find(|c| c.name == "state").map(|c| &c.value)
                    != Some(&ColumnValue::Text("materialized".into()))
            {
                return Err(invalid("remote Replace target snapshot reuse differs"));
            }
        } else {
            tx.execute(
                "INSERT INTO main.snapshots VALUES(?1,?2,?3,?4,'materialized',0)",
                params![
                    root,
                    header.target.space_id.as_str(),
                    json,
                    i64::try_from(header.proof.operation.payload.created_at_ms)
                        .map_err(|_| invalid("remote Replace SQLite time overflow"))?
                ],
            )?;
            let col = |name: &str, value: ColumnValue| JournalStorageColumn {
                name: name.into(),
                value,
            };
            expected.insert(
                snapshot_key,
                vec![
                    col("snapshot_id", ColumnValue::Text(root.into())),
                    col(
                        "space_id",
                        ColumnValue::Text(header.target.space_id.to_string()),
                    ),
                    col("manifest", ColumnValue::Text(json)),
                    col(
                        "created_at_ms",
                        ColumnValue::Integer(header.proof.operation.payload.created_at_ms),
                    ),
                    col("state", ColumnValue::Text("materialized".into())),
                    col("locked", ColumnValue::Integer(0)),
                ],
            );
        }
        let pointer = expected
            .get_mut(&(
                "current_manifests".into(),
                vec![header.target.space_id.to_string()],
            ))
            .unwrap();
        pointer
            .iter_mut()
            .find(|c| c.name == "snapshot_id")
            .unwrap()
            .value = ColumnValue::Text(root.into());
        if tx.execute(
            "UPDATE main.current_manifests SET snapshot_id=?1 WHERE space_id=?2 AND snapshot_id=?3",
            params![
                root,
                header.target.space_id.as_str(),
                header.baseline.root()?.as_str()
            ],
        )? != 1
        {
            return Err(invalid("remote Replace original pointer update missing"));
        }
        for id in contents(&header.target) {
            let pk = ("snapshot_objects".into(), vec![root.into(), id.to_string()]);
            if let std::collections::btree_map::Entry::Vacant(entry) = expected.entry(pk) {
                entry.insert(vec![
                    JournalStorageColumn {
                        name: "snapshot_id".into(),
                        value: ColumnValue::Text(root.into()),
                    },
                    JournalStorageColumn {
                        name: "content_id".into(),
                        value: ColumnValue::Text(id.to_string()),
                    },
                ]);
                tx.execute(
                    "INSERT INTO main.snapshot_objects VALUES(?1,?2)",
                    params![root, id.as_str()],
                )?;
            }
        }
        let own_liability = before
            .report
            .ordinary_obligations()
            .iter()
            .find(|o| {
                o.family == "original_remote_replace_remaining"
                    && o.owner_key == [header.transaction_id.to_string()]
            })
            .ok_or(invalid("remote Replace final remaining liability missing"))?
            .charge;
        let value_bytes = |columns: &[JournalStorageColumn]| -> u64 {
            columns
                .iter()
                .map(|c| match &c.value {
                    ColumnValue::Null => 0,
                    ColumnValue::Integer(_) => 8,
                    ColumnValue::Text(s) => s.len() as u64,
                })
                .sum()
        };
        let before_rows = rows(&before);
        let old_bytes: u64 = before_rows.values().map(|cols| value_bytes(cols)).sum();
        let new_bytes: u64 = expected.values().map(|cols| value_bytes(cols)).sum();
        if expected.len() as u64 > before_rows.len() as u64 + own_liability.rows
            || new_bytes > old_bytes + own_liability.logical_bytes
        {
            return Err(invalid(
                "remote Replace final pre-release peak exceeds original liability",
            ));
        }
        // Snapshot pin triggers may consume an existing GC invalidation liability.
        for row in &before.rows {
            if row.table() == "gc_marks"
                && contents(&header.target)
                    .iter()
                    .any(|id| field(row, "content_id").is_ok_and(|value| value == id.as_str()))
                && !expected.contains_key(&("gc_cancellations".into(), row.primary_key().to_vec()))
            {
                let mark = field(row, "mark_id")?;
                expected
                    .entry(("gc_invalidations".into(), vec![mark.into()]))
                    .or_insert_with(|| {
                        vec![JournalStorageColumn {
                            name: "mark_id".into(),
                            value: ColumnValue::Text(mark.into()),
                        }]
                    });
            }
        }
        expected.remove(&(
            "rename_observations".into(),
            vec![header.target.space_id.to_string()],
        ));
        tx.execute(
            "DELETE FROM main.rename_observations WHERE space_id=?1",
            [header.target.space_id.as_str()],
        )?;
        // Original pins remain in the peak audit until the new snapshot is durable
        // within this same transaction; future liability is consumed at Final.
        let after = self
            .read_view()
            .audit_local_commit_capacity(&header.target.space_id, before.report.limits())?;
        receipt(&expected, &after)?;
        observation.verify_content()?;
        tx.commit()?;
        Ok(header.target_root.clone())
    }
}
