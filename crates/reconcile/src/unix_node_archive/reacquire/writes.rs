use super::*;
use sync_extend_core_model::{
    Change, Entry, EntryId, EntryKind, Operation, OperationPayload, PortablePath, FORMAT_VERSION,
};

impl<'a, 'n> ReacquiredOriginalUnixNode<'a, 'n> {
    pub(super) fn create(&mut self, slot: &Slot, bytes: &[u8]) -> Result<()> {
        let parent = slot.parent();
        let result = if parent.parts.is_empty() {
            self.root(slot.data)
                .create_file(slot.name(), (bytes.len() as u64).max(1))
        } else {
            self.directories
                .get(&parent)
                .ok_or(ReconcileError::Invariant(
                    "same original creation parent absent",
                ))?
                .create_file(slot.name(), (bytes.len() as u64).max(1))
        };
        let created = result.map_err(|failure| {
            let error = io(&failure.error);
            self.create_failures.push(failure);
            error
        })?;
        self.creations.push(created);
        self.creations
            .last_mut()
            .unwrap()
            .write_ordered_and_sync(&[bytes])?;
        let created = self.creations.pop().unwrap();
        let sealed = created
            .seal_projected_metadata(&[bytes], None)
            .map_err(|mut f| {
                let error = io(&f.error);
                if let Some(file) = f.original.take() {
                    self.creations.push(file);
                }
                error
            })?;
        self.created.insert(slot.clone(), sealed);
        Ok(())
    }
    pub(super) fn describe_created(&self, slot: &Slot, role: &str, bytes: &[u8]) -> Result<budget::Object> {
        let file = self
            .created
            .get(slot)
            .ok_or(ReconcileError::Invariant("actual sealed creation absent"))?;
        Ok(budget::Object {
            role: role.into(),
            path: slot.parts.join("/"),
            original: budget::Key::observed(file.key()?),
            parent: budget::Key::observed(file.parent_key()?),
            bytes: file.bytes()?,
            digest: Some(ContentId::hash(bytes)),
            projected_metadata: if slot.data {
                None
            } else {
                Some(crate::filesystem::portable_metadata_from_capture(
                    file.metadata()?,
                )?)
            },
        })
    }
    /// Create a new root file using held CAS/worktree creators and one durable
    /// original-session intent. Replacement and nested callers use polling.
    pub fn create_root_file(
        &mut self,
        name: &str,
        bytes: &[u8],
    ) -> Result<sync_extend_core_model::SnapshotId> {
        self.verify()?;
        let path = PortablePath::new(name)?;
        if path.as_str().contains('/')
            || [".sync-extend", ".git", ".sync-tmp"]
                .iter()
                .any(|n| name.eq_ignore_ascii_case(n))
            || self.manifest.entries.values().any(|e| e.path == path)
        {
            return Err(ReconcileError::Invariant(
                "new original Unix root file required",
            ));
        }
        if bytes.len() as u64 > self.bounds.maximum_file_bytes || bytes.len() > 32 * 1024 * 1024 {
            return Err(ReconcileError::ResourceLimit("Unix native new file input"));
        }
        let content =
            sync_extend_cas::plan_bounded_content(bytes, self.bounds.maximum_file_bytes, 4096)?;
        let mut additional = Vec::new();
        let future = budget::Key::observed(self.root(true).key()?);
        additional.push(budget::Object {
            role: "work_file".into(),
            path: name.into(),
            original: future.clone(),
            parent: future.clone(),
            bytes: bytes.len() as u64,
            digest: Some(ContentId::hash(bytes)),
            projected_metadata: Some(budget::future_metadata()),
        });
        for (chunk, data) in &content.chunks {
            let path = format!(
                "cas/objects/{}/{}",
                &chunk.content_id.as_str()[..2],
                chunk.content_id
            );
            if !self
                .record
                .objects
                .iter()
                .any(|o| o.role == "data_file" && o.path == path)
            {
                additional.push(budget::Object {
                    role: "data_file".into(),
                    path,
                    original: future.clone(),
                    parent: future.clone(),
                    bytes: data.len() as u64,
                    digest: Some(chunk.content_id.clone()),
                    projected_metadata: None,
                });
            }
        }
        let intent_name = format!(
            "unix-local-{}-{}.intent",
            self.record.generation, self.record.turns
        );
        additional.push(budget::Object {
            role: "local_intent".into(),
            path: intent_name.clone(),
            original: future.clone(),
            parent: future.clone(),
            bytes: 4096,
            digest: Some(ContentId::hash(&[])),
            projected_metadata: None,
        });
        // Include possible new prefix directories before any creator effect.
        let mut prefixes = std::collections::BTreeSet::new();
        for (chunk, _) in &content.chunks {
            let prefix = &chunk.content_id.as_str()[..2];
            let slot = Slot::new(true, &["cas", "objects", prefix]);
            if !self.directories.contains_key(&slot) {
                prefixes.insert(prefix.to_owned());
            }
        }
        for prefix in &prefixes {
            additional.push(budget::Object {
                role: "data_directory".into(),
                path: format!("cas/objects/{prefix}"),
                original: future.clone(),
                parent: future.clone(),
                bytes: 0,
                digest: None,
                projected_metadata: None,
            });
        }
        self.require_next_close_budget(&self.record, &additional, 1)?;
        if self.record.objects.len() + additional.len() + 10 > self.bounds.maximum_creations {
            return Err(ReconcileError::ResourceLimit(
                "Unix native complete creator membership",
            ));
        }
        self.poisoned = true;
        for prefix in prefixes {
            let slot = Slot::new(true, &["cas", "objects", &prefix]);
            let directory = self
                .directories
                .get(&slot.parent())
                .ok_or(ReconcileError::Invariant(
                    "original CAS objects parent absent",
                ))?
                .acquire_new_child(&prefix)
                .map_err(|f| {
                    let e = io(&f.error);
                    self.directory_failures.push(f);
                    e
                })?;
            self.directories.insert(slot.clone(), directory);
            let directory = &self.directories[&slot];
            self.record.objects.push(budget::Object {
                role: "data_directory".into(),
                path: slot.parts.join("/"),
                original: budget::Key::observed(directory.key()?),
                parent: budget::Key::observed(directory.parent_key()?),
                bytes: 0,
                digest: None,
                projected_metadata: None,
            });
        }
        for (chunk, data) in &content.chunks {
            let slot = Slot::new(
                true,
                &[
                    "cas",
                    "objects",
                    &chunk.content_id.as_str()[..2],
                    chunk.content_id.as_str(),
                ],
            );
            if self
                .record
                .objects
                .iter()
                .any(|o| o.role == "data_file" && o.path == slot.parts.join("/"))
            {
                continue;
            }
            self.create(&slot, data)?;
            self.record
                .objects
                .push(self.describe_created(&slot, "data_file", data)?);
        }
        let work = Slot::new(false, &[name]);
        self.create(&work, bytes)?;
        let described = self.describe_created(&work, "work_file", bytes)?;
        let mut manifest = self.manifest.clone();
        let entry = Entry {
            entry_id: EntryId::random()?,
            path,
            kind: EntryKind::File,
            content: Some(content.manifest),
            metadata: described.projected_metadata.clone(),
        };
        manifest
            .entries
            .insert(entry.entry_id.clone(), entry.clone());
        let timestamp = crate::now_ms()?;
        let seq = manifest
            .version_vector
            .get(self.archive.device())
            .checked_add(1)
            .ok_or(ReconcileError::Invariant("Unix local sequence exhausted"))?;
        let operation = Operation::new(OperationPayload {
            format_version: FORMAT_VERSION,
            space_id: self.archive.space().clone(),
            origin_device_id: self.archive.device().clone(),
            origin_seq: seq,
            causal: manifest.version_vector.clone(),
            change: Change::Put { entry },
            created_at_ms: timestamp,
        })?;
        manifest
            .version_vector
            .observe(self.archive.device().clone(), seq);
        let prepared = self
            .journal
            .as_mut()
            .expect("actual original Journal")
            .prepare_local_commit(
                Some(&self.manifest.root()?),
                &manifest,
                &[operation],
                timestamp,
            )?;
        let intent = prepared.durable_intent_bytes().to_vec();
        let intent_slot = Slot::new(true, &[&intent_name]);
        self.create(&intent_slot, &intent)?;
        let root = self
            .journal
            .as_mut()
            .expect("same original Journal")
            .commit_prepared_local(prepared, &self.created[&intent_slot])?;
        self.record.objects.push(described);
        self.record
            .objects
            .push(self.describe_created(&intent_slot, "local_intent", &intent)?);
        self.record.turns += 1;
        self.manifest = manifest;
        let observed = self.journal.as_mut().unwrap().observe_original_session()?;
        self.record.root = observed.root;
        self.record.rows = observed.rows;
        self.poisoned = false;
        self.verify()?;
        Ok(root)
    }
}
