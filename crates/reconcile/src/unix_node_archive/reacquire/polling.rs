//! Bounded parent-relative polling with actual observations retained to commit.
use super::*;
use sync_extend_core_model::{
    Change, EntryKind, Operation, OperationPayload, PortablePath, FORMAT_VERSION,
};

fn internal(slot: &Slot) -> bool {
    slot.parts.first().is_some_and(|p| {
        [".sync-extend", ".git", ".sync-tmp"]
            .iter()
            .any(|n| p.eq_ignore_ascii_case(n))
    })
}
impl<'a, 'n> ReacquiredOriginalUnixNode<'a, 'n> {
    fn visit(
        &mut self,
        parent: Slot,
        scan: &mut crate::scan::Scan,
        chunks: &mut BTreeMap<ContentId, Vec<u8>>,
        bytes: &mut u64,
        listings: &mut BTreeMap<Slot, Vec<String>>,
    ) -> Result<()> {
        let names = if parent.parts.is_empty() {
            self.root(false).observed_child_names(budget::MAX_OBJECTS)?
        } else {
            self.directories
                .get(&parent)
                .ok_or(ReconcileError::Invariant("actual polling directory absent"))?
                .observed_child_names(budget::MAX_OBJECTS)?
        };
        listings.insert(parent.clone(), names.clone());
        for name in names {
            let mut slot = parent.clone();
            slot.parts.push(name.clone());
            if internal(&slot) {
                continue;
            }
            if scan.len() >= budget::MAX_OBJECTS || slot.parts.len() > 64 {
                return Err(ReconcileError::ResourceLimit(
                    "bounded Unix polling entries/depth",
                ));
            }
            let path = PortablePath::new(slot.parts.join("/"))?;
            let directory = if parent.parts.is_empty() {
                self.root(false).child_is_directory(&name)?
            } else {
                self.directories[&parent].child_is_directory(&name)?
            };
            if directory {
                let acquired = if parent.parts.is_empty() {
                    self.root(false).acquire_existing_child(&name)
                } else {
                    self.directories[&parent].acquire_existing_child(&name)
                }
                .map_err(|f| {
                    let e = io(&f.error);
                    self.directory_failures.push(f);
                    e
                })?;
                self.directories.insert(slot.clone(), acquired);
                let key = self.directories[&slot].key()?;
                scan.insert(
                    path,
                    crate::scan::ScannedEntry {
                        kind: EntryKind::Directory,
                        content: None,
                        metadata: None,
                        physical_identity: ContentId::hash(
                            format!("{}:{}:{}", key.device, key.inode, key.uid).as_bytes(),
                        ),
                        single_link: true,
                    },
                );
                self.visit(slot, scan, chunks, bytes, listings)?;
            } else {
                let maximum = usize::try_from(self.bounds.maximum_file_bytes.min(32 * 1024 * 1024))
                    .map_err(|_| ReconcileError::ResourceLimit("Unix polling file bound"))?;
                let observed = if parent.parts.is_empty() {
                    self.root(false).observe_file(&name, maximum, false)
                } else {
                    self.directories[&parent].observe_file(&name, maximum, false)
                }?;
                self.observed.insert(slot.clone(), observed);
                let observed = &self.observed[&slot];
                *bytes = bytes
                    .checked_add(observed.bytes()?)
                    .filter(|v| {
                        *v <= budget::MAX_HELD_BYTES && *v <= self.bounds.maximum_total_bytes
                    })
                    .ok_or(ReconcileError::ResourceLimit("complete Unix polling bytes"))?;
                let data = observed.read_bounded()?;
                let key = observed.key()?;
                let metadata =
                    crate::filesystem::portable_metadata_from_capture(observed.metadata()?)?;
                let content = sync_extend_cas::plan_bounded_content(
                    &data,
                    self.bounds.maximum_file_bytes,
                    4096,
                )?;
                for (chunk, data) in content.chunks {
                    chunks.entry(chunk.content_id).or_insert(data);
                }
                scan.insert(
                    path,
                    crate::scan::ScannedEntry {
                        kind: EntryKind::File,
                        content: Some(content.manifest),
                        metadata: Some(metadata),
                        physical_identity: ContentId::hash(
                            format!("{}:{}:{}", key.device, key.inode, key.uid).as_bytes(),
                        ),
                        single_link: true,
                    },
                );
            }
        }
        Ok(())
    }
    fn verify_listings(&self, listings: &BTreeMap<Slot, Vec<String>>) -> Result<()> {
        for (parent, expected) in listings {
            let actual = if parent.parts.is_empty() {
                self.root(false).observed_child_names(budget::MAX_OBJECTS)?
            } else {
                self.directories
                    .get(parent)
                    .ok_or(ReconcileError::Invariant("polling original directory lost"))?
                    .observed_child_names(budget::MAX_OBJECTS)?
            };
            if actual != *expected {
                return Err(ReconcileError::Unstable);
            }
        }
        Ok(())
    }
    /// Observe external changes through original directory descriptors, publish
    /// bounded chunks, and commit through the same original Journal session.
    pub fn poll_local_changes(&mut self) -> Result<crate::ScanResult> {
        if self.poisoned {
            return Err(ReconcileError::Invariant(
                "original polling session poisoned",
            ));
        }
        self.root(true).verify()?;
        self.root(false).verify()?;
        self.journal
            .as_mut()
            .ok_or(ReconcileError::Invariant("original polling Journal absent"))?
            .verify()?;
        for lock in &self.locks {
            lock.verify()?;
        }
        // Old user-file captures are expected to change. Their actual close is
        // separate from unchanged membership proof; protected data stays held.
        self.poisoned = true;
        let mut close = UnixOriginalCloseAttempt::new();
        let slots: Vec<_> = self
            .observed
            .keys()
            .filter(|s| !s.data && !internal(s))
            .cloned()
            .collect();
        for slot in slots {
            close.append_result(self.observed.remove(&slot).unwrap().end_observation());
        }
        let slots: Vec<_> = self
            .created
            .keys()
            .filter(|s| !s.data && !internal(s))
            .cloned()
            .collect();
        for slot in slots {
            close.append_result(self.created.remove(&slot).unwrap().end_observation());
        }
        let slots: Vec<_> = self
            .directories
            .keys()
            .filter(|s| !s.data && !internal(s))
            .cloned()
            .collect();
        for slot in slots.into_iter().rev() {
            close.append_result(self.directories.remove(&slot).unwrap().end_observation());
        }
        if let Err(failure) = close.finish() {
            let e = io(&failure.error);
            self.close_failures.push(failure);
            return Err(e);
        }
        let mut listings = BTreeMap::new();
        let mut scan = crate::scan::Scan::new();
        let mut chunks = BTreeMap::new();
        self.visit(
            Slot::new(false, &[]),
            &mut scan,
            &mut chunks,
            &mut 0,
            &mut listings,
        )?;
        let mut candidates = BTreeMap::new();
        for (path, entry) in &scan {
            let matches: Vec<_> = self
                .manifest
                .entries
                .values()
                .filter(|old| old.path != *path && old.kind == entry.kind)
                .filter(|old| {
                    self.record
                        .objects
                        .iter()
                        .find(|o| o.path == old.path.as_str() && o.role.starts_with("work_"))
                        .is_some_and(|o| {
                            let k = o.original.described();
                            ContentId::hash(
                                format!("{}:{}:{}", k.device, k.inode, k.uid).as_bytes(),
                            ) == entry.physical_identity
                        })
                })
                .collect();
            if matches.len() == 1 {
                candidates.insert(path.clone(), matches[0].entry_id.clone());
            }
        }
        let mut manifest = crate::build_manifest(&self.manifest, &scan, &candidates)?;
        // Preserve unknown historical metadata while unchanged native content
        // remains at its mapped entry; newly observed entries carry metadata.
        for entry in manifest.entries.values_mut() {
            if let Some(old) = self.manifest.entries.get(&entry.entry_id) {
                if old.metadata.is_none() && old.content == entry.content && old.kind == entry.kind
                {
                    entry.metadata = None;
                }
            }
        }
        let timestamp = crate::now_ms()?;
        let mut changes = Vec::new();
        for entry in manifest.entries.values() {
            match self.manifest.entries.get(&entry.entry_id) {
                None => changes.push(Change::Put {
                    entry: entry.clone(),
                }),
                Some(old) => {
                    if old.path != entry.path {
                        changes.push(Change::Rename {
                            entry_id: entry.entry_id.clone(),
                            path: entry.path.clone(),
                        });
                    }
                    if old.kind != entry.kind
                        || old.content != entry.content
                        || old.metadata != entry.metadata
                    {
                        changes.push(Change::Put {
                            entry: entry.clone(),
                        });
                    }
                }
            }
        }
        for entry_id in self.manifest.entries.keys() {
            if !manifest.entries.contains_key(entry_id) {
                changes.push(Change::Delete {
                    entry_id: entry_id.clone(),
                });
            }
        }
        let mut operations = Vec::new();
        for change in changes {
            let seq = manifest
                .version_vector
                .get(self.archive.device())
                .checked_add(1)
                .ok_or(ReconcileError::Invariant("Unix polling sequence exhausted"))?;
            let operation = Operation::new(OperationPayload {
                format_version: FORMAT_VERSION,
                space_id: self.archive.space().clone(),
                origin_device_id: self.archive.device().clone(),
                origin_seq: seq,
                causal: manifest.version_vector.clone(),
                change,
                created_at_ms: timestamp,
            })?;
            if let Change::Delete { entry_id } = &operation.payload.change {
                manifest
                    .tombstones
                    .insert(entry_id.clone(), operation.op_id.clone());
            }
            manifest
                .version_vector
                .observe(self.archive.device().clone(), seq);
            operations.push(operation);
        }
        let mut record = self.record.clone();
        record.objects.retain(|o| {
            !matches!(o.role.as_str(), "work_file" | "work_directory")
                || o.path.split('/').next().is_some_and(|n| {
                    [".sync-extend", ".git", ".sync-tmp"]
                        .iter()
                        .any(|i| n.eq_ignore_ascii_case(i))
                })
        });
        for (slot, file) in &self.observed {
            if slot.data || internal(slot) {
                continue;
            }
            record.objects.push(budget::Object {
                role: "work_file".into(),
                path: slot.parts.join("/"),
                original: budget::Key::observed(file.key()?),
                parent: budget::Key::observed(file.parent_key()?),
                bytes: file.bytes()?,
                digest: Some(ContentId::hash(&file.read_bounded()?)),
                projected_metadata: Some(crate::filesystem::portable_metadata_from_capture(
                    file.metadata()?,
                )?),
            });
        }
        for (slot, dir) in &self.directories {
            if slot.data || internal(slot) {
                continue;
            }
            record.objects.push(budget::Object {
                role: "work_directory".into(),
                path: slot.parts.join("/"),
                original: budget::Key::observed(dir.key()?),
                parent: budget::Key::observed(dir.parent_key()?),
                bytes: 0,
                digest: None,
                projected_metadata: None,
            });
        }
        let key = budget::Key::observed(self.root(true).key()?);
        let mut extra = Vec::new();
        let mut prefixes = std::collections::BTreeSet::new();
        for (id, data) in &chunks {
            let prefix = &id.as_str()[..2];
            let path = format!("cas/objects/{prefix}/{id}");
            if !record
                .objects
                .iter()
                .any(|o| o.role == "data_file" && o.path == path)
            {
                extra.push(budget::Object {
                    role: "data_file".into(),
                    path,
                    original: key.clone(),
                    parent: key.clone(),
                    bytes: data.len() as u64,
                    digest: Some(id.clone()),
                    projected_metadata: None,
                });
                if !self
                    .directories
                    .contains_key(&Slot::new(true, &["cas", "objects", prefix]))
                {
                    prefixes.insert(prefix.to_owned());
                }
            }
        }
        for prefix in &prefixes {
            extra.push(budget::Object {
                role: "data_directory".into(),
                path: format!("cas/objects/{prefix}"),
                original: key.clone(),
                parent: key.clone(),
                bytes: 0,
                digest: None,
                projected_metadata: None,
            });
        }
        let intent_name = format!("unix-local-{}-{}.intent", record.generation, record.turns);
        if !operations.is_empty() {
            extra.push(budget::Object {
                role: "local_intent".into(),
                path: intent_name.clone(),
                original: key.clone(),
                parent: key,
                bytes: 4096,
                digest: Some(ContentId::hash(&[])),
                projected_metadata: None,
            });
        }
        self.require_next_close_budget(&record, &extra, u32::from(!operations.is_empty()))?;
        if record.objects.len() + extra.len() + 10 > self.bounds.maximum_creations {
            return Err(ReconcileError::ResourceLimit(
                "complete polling creator membership",
            ));
        }
        self.verify_listings(&listings)?;
        self.record = record;
        for prefix in prefixes {
            let slot = Slot::new(true, &["cas", "objects", &prefix]);
            let dir = self.directories[&slot.parent()]
                .acquire_new_child(&prefix)
                .map_err(|f| {
                    let e = io(&f.error);
                    self.directory_failures.push(f);
                    e
                })?;
            self.directories.insert(slot.clone(), dir);
            let dir = &self.directories[&slot];
            self.record.objects.push(budget::Object {
                role: "data_directory".into(),
                path: slot.parts.join("/"),
                original: budget::Key::observed(dir.key()?),
                parent: budget::Key::observed(dir.parent_key()?),
                bytes: 0,
                digest: None,
                projected_metadata: None,
            });
        }
        for (id, data) in chunks {
            let slot = Slot::new(true, &["cas", "objects", &id.as_str()[..2], id.as_str()]);
            if self
                .record
                .objects
                .iter()
                .any(|o| o.role == "data_file" && o.path == slot.parts.join("/"))
            {
                continue;
            }
            self.create(&slot, &data)?;
            self.record
                .objects
                .push(self.describe_created(&slot, "data_file", &data)?);
        }
        let count = operations.len();
        if count != 0 {
            let prepared = self.journal.as_mut().unwrap().prepare_local_commit(
                Some(&self.manifest.root()?),
                &manifest,
                &operations,
                timestamp,
            )?;
            let intent = prepared.durable_intent_bytes().to_vec();
            let slot = Slot::new(true, &[&intent_name]);
            self.create(&slot, &intent)?;
            for f in self.observed.values() {
                f.verify()?;
            }
            self.verify_listings(&listings)?;
            self.journal
                .as_mut()
                .unwrap()
                .commit_prepared_local(prepared, &self.created[&slot])?;
            self.record
                .objects
                .push(self.describe_created(&slot, "local_intent", &intent)?);
            self.record.turns += 1;
        }
        self.manifest = manifest;
        let actual = self.journal.as_mut().unwrap().observe_original_session()?;
        self.record.root = actual.root;
        self.record.rows = actual.rows;
        self.poisoned = false;
        self.verify_manifest_membership()?;
        self.verify()?;
        Ok(crate::ScanResult {
            space_id: self.archive.space().clone(),
            snapshot_id: self.manifest.root()?,
            entries: self.manifest.entries.len(),
            operations: count,
            files: self
                .manifest
                .entries
                .values()
                .filter(|e| e.kind == EntryKind::File)
                .count(),
            logical_bytes: self
                .manifest
                .entries
                .values()
                .filter_map(|e| e.content.as_ref())
                .map(|c| c.length)
                .sum(),
            network_enabled: false,
        })
    }
}
