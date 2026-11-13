//! Ordered native C/D effects. Each effect retains exact original handles.
use super::*;
use sync_extend_core_model::{
    tree_native_action_layout::{TreeNativeActionIntent, TreeNativeActionObservation},
    PortablePath,
};

pub struct TreeNativeExecution {
    space: SpaceId,
    transaction: EntryId,
    scope: Scope,
    directory: LockedDirectory,
    marker: LockedFile,
    owner_path: PathBuf,
    marker_path: PathBuf,
    directory_key: FileKey,
    marker_key: FileKey,
    marker_bytes: Vec<u8>,
    members: BTreeSet<PathBuf>,
    resumed_creator: Option<ResumedCreator>,
    _coordination: CasAccessGuard,
}

enum ResumedCreator {
    File(LockedFile, FileKey, FileManifest),
}

pub struct TreeNativeObservation {
    held: TreeNativeExecution,
}

/// Borrow only the exact held scope and original in-flight creator for quota
/// inventory. This provides no writer, action attempt or ownership issuer.
pub struct TreeNativeExecutionFileView<'a> {
    execution: &'a TreeNativeExecution,
    creator: Option<&'a fs::File>,
    remaining: u64,
}

impl TreeNativeExecutionFileView<'_> {
    pub fn transaction_id(&self) -> &EntryId {
        &self.execution.transaction
    }
    pub fn verify(&self) -> Result<()> {
        self.execution.verify()
    }
    pub fn remaining_internal_bytes(&self) -> Result<u64> {
        Ok(self.remaining)
    }
    pub fn observe_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        let file = if same_slot_spelling(path, &self.execution.marker_path) {
            self.execution.marker.reader()
        } else if let Some(file) = self
            .execution
            .scope
            .files
            .iter()
            .find(|file| same_slot_spelling(&file.path, path))
        {
            file.held.reader()
        } else if let Some(file) = self
            .creator
            .filter(|file| regular_file_matches_path(file, path).unwrap_or(false))
        {
            file
        } else {
            return Ok(None);
        };
        self.verify()?;
        if !regular_file_matches_path(file, path)? {
            return Err(invalid("tree execution view exact physical slot differs"));
        }
        let key = FileKey::from_file(file)?;
        Ok(Some(crate::NativePublicationFileObservation {
            metadata: file.metadata()?,
            physical_identity: ContentId::hash(
                format!("windows:{}:{}", key.volume, key.id).as_bytes(),
            ),
            content: None,
        }))
    }
}

pub struct TreeNativeFinalized {
    held: TreeNativeObservation,
    snapshot_id: sync_extend_core_model::SnapshotId,
}

pub struct TreeNativeCleanupReceipt {
    pub(crate) transaction: EntryId,
    pub(crate) snapshot_id: sync_extend_core_model::SnapshotId,
}

impl TreeNativeCleanupReceipt {
    pub fn transaction_id(&self) -> &EntryId {
        &self.transaction
    }
    pub fn snapshot_id(&self) -> &sync_extend_core_model::SnapshotId {
        &self.snapshot_id
    }
    pub fn owner_cleanup_complete(&self) -> bool {
        true
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

impl TreeNativeFinalized {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    pub fn snapshot_id(&self) -> &sync_extend_core_model::SnapshotId {
        &self.snapshot_id
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
}

impl TreeNativeObservation {
    pub fn transaction_id(&self) -> &EntryId {
        &self.held.transaction
    }
    pub fn native_tree_completed(&self) -> bool {
        true
    }
    pub fn history_committed(&self) -> bool {
        false
    }
    pub fn tree_atomic(&self) -> bool {
        false
    }
    pub fn file_view(&self) -> TreeNativeExecutionFileView<'_> {
        TreeNativeExecutionFileView {
            execution: &self.held,
            creator: None,
            remaining: 0,
        }
    }
}

impl TreeNativeExecution {
    pub fn transaction_id(&self) -> &EntryId {
        &self.transaction
    }

    fn verify(&self) -> Result<()> {
        self.scope.verify()?;
        if self.directory.key()? != self.directory_key
            || self.marker.key()? != self.marker_key
            || !self.directory.matches_path(&self.owner_path)?
            || !self.marker.matches_path(&self.marker_path)?
        {
            return Err(invalid("tree executor exact owner slot differs"));
        }
        verify_marker(self.marker.reader(), &self.marker_bytes)?;
        let mut actual = BTreeSet::new();
        for child in fs::read_dir(&self.owner_path)? {
            if actual.len() >= self.members.len() {
                return Err(invalid("tree executor foreign owner member"));
            }
            actual.insert(child?.path());
        }
        if actual != self.members {
            return Err(invalid("tree executor owner membership differs"));
        }
        Ok(())
    }

    fn parent(
        &self,
        path: &PortablePath,
        expected: &TreeNativeIdentity,
    ) -> Result<&LockedDirectory> {
        let parent = self.scope.root.join(path.as_str());
        let parent = parent.parent().ok_or(invalid("tree step parent absent"))?;
        let held = self
            .scope
            .directories
            .iter()
            .find(|directory| directory.path == parent)
            .ok_or(invalid("tree executor retained parent absent"))?;
        if native(held.key) != *expected || !held.held.matches_path(parent)? {
            return Err(invalid("tree executor original destination parent changed"));
        }
        Ok(&held.held)
    }

    fn original_index(&self, path: &PortablePath, expected: &TreeNativeIdentity) -> Result<usize> {
        let path = self.scope.root.join(path.as_str());
        self.scope
            .files
            .iter()
            .position(|file| file.path == path && native(file.key) == *expected)
            .ok_or(invalid("tree executor original file guard absent"))
    }

    fn add_file(&mut self, path: PathBuf, expected: FileKey, content: FileManifest) -> Result<()> {
        let held = LockedFile::open(&path)?;
        if held.key()? != expected || !held.matches_path(&path)? {
            return Err(invalid("tree executor original creator handoff changed"));
        }
        verify_content(held.reader(), &content)?;
        self.scope.files.push(File {
            path,
            held,
            key: expected,
            content: Some(content),
        });
        Ok(())
    }

    fn verify_final_originals(
        &self,
        complete: &sync_extend_core_model::tree_native_action_layout::TreeNativeActionCompletedLayout,
        preparation: &TreeRestorePreparation,
    ) -> Result<()> {
        let mut expected = BTreeSet::from([self.marker_path.clone()]);
        for (&index, identity) in &complete.retained_originals {
            let original = &preparation
                .original_pins
                .as_ref()
                .ok_or(invalid("tree Final originals missing"))?
                .originals[&index];
            let component = preparation
                .owner_description
                .as_ref()
                .ok_or(invalid("tree Final owner description missing"))?
                .intent
                .steps[&index]
                .original_component
                .as_ref()
                .ok_or(invalid("tree Final original component"))?;
            let path = self.owner_path.join(component);
            let file = self
                .scope
                .files
                .iter()
                .find(|file| file.path == path)
                .ok_or(invalid("tree Final retained original guard missing"))?;
            if native(file.key) != *identity || *identity != original.original_identity {
                return Err(invalid("tree Final retained original fullID differs"));
            }
            verify_content(file.held.reader(), &original.original_content)?;
            expected.insert(path);
        }
        if self.members != expected {
            return Err(invalid("tree Final retained original membership differs"));
        }
        Ok(())
    }
}

impl Journal {
    pub(crate) fn tree_disposition_row(
        &self,
        row: &sync_extend_core_model::tree_storage_footprint::TreeStorageRowValues,
    ) -> Result<()> {
        let table = super::super::disposition_state::table(row.key().table)?;
        let values: Vec<Value> = row
            .columns()
            .iter()
            .map(|column| match &column.value {
                TreeStorageColumnValue::Text(value) => Ok(Value::Text(value.clone())),
                TreeStorageColumnValue::Integer(value) => {
                    Ok(Value::Integer(crate::sql_integer(*value)?))
                }
            })
            .collect::<Result<_>>()?;
        let mut permit_values = vec![Value::Text(table.into())];
        permit_values.extend(values.clone());
        let permit = self.tree_native_issuance.permit(vec![permit_values])?;
        let placeholders = vec!["?"; values.len()].join(",");
        self.connection.execute(
            &format!("INSERT INTO main.{table} VALUES({placeholders})"),
            params_from_iter(values),
        )?;
        permit.require_consumed()?;
        Ok(())
    }

    /// Dispose only exact retained originals after actual NEW Final, then
    /// consume the original marker and the truly empty owner directory.
    pub fn cleanup_tree_native_owner(
        &self,
        finalized: TreeNativeFinalized,
        max: usize,
    ) -> Result<TreeNativeCleanupReceipt> {
        let space = finalized.held.held.space.clone();
        let id = finalized.held.held.transaction.clone();
        let expected = finalized.snapshot_id.clone();
        finalized.held.held.verify()?;
        drop(finalized);
        let receipt = self.resume_tree_native_cleanup(&space, &id, max)?;
        if receipt.snapshot_id != expected {
            return Err(invalid("tree cleanup exact Final handoff differs"));
        }
        Ok(receipt)
    }

    /// Atomically publish NEW history after every native C/D action is observed.
    /// Only exact input pins are released; original content owners stay retained.
    pub fn commit_tree_native_final(
        &self,
        observation: TreeNativeObservation,
        max: usize,
    ) -> Result<TreeNativeFinalized> {
        use sync_extend_core_model::tree_storage_footprint::tree_final_terminal_row_values;
        let execution = &observation.held;
        execution.verify()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) =
            self.tree_owner_state(&execution.space, &execution.transaction, max)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&execution.space, self.writer_capacity_limits(max)?)?;
        let plan = super::super::final_state::plan(
            &self.connection,
            &preparation,
            &progress.records,
            &progress.layout,
            max,
        )?;
        let complete = progress
            .layout
            .completed_native_layout()
            .ok_or(invalid("tree Final incomplete native layout"))?;
        if native(execution.directory_key) != complete.owner_directory
            || native(execution.marker_key) != complete.owner_marker
        {
            return Err(invalid("tree Final observed owner identity differs"));
        }
        let expected: BTreeMap<_, _> = complete
            .entries
            .iter()
            .map(|(path, entry)| (path.as_str().to_owned(), entry.kind))
            .collect();
        if execution.scope.expected != expected {
            return Err(invalid("tree Final complete native membership differs"));
        }
        for (path, entry) in &complete.entries {
            let path = execution.scope.root.join(path.as_str());
            let key = if entry.kind == EntryKind::File {
                execution
                    .scope
                    .files
                    .iter()
                    .find(|file| file.path == path)
                    .map(|file| file.key)
            } else {
                execution
                    .scope
                    .directories
                    .iter()
                    .find(|directory| directory.path == path)
                    .map(|directory| directory.key)
            }
            .ok_or(invalid("tree Final observed entry guard absent"))?;
            if native(key) != entry.identity {
                return Err(invalid("tree Final complete native entry identity differs"));
            }
        }
        execution.verify_final_originals(complete, &preparation)?;
        let history = plan.history().rows();
        let prior_observation =
            crate::rename_observation::audit_observation(&self.connection, &execution.space, max)?;
        if prior_observation.as_ref()
            != preparation
                .native_future_admission
                .as_ref()
                .ok_or(invalid("tree Final future missing"))?
                .prior_observation()
        {
            return Err(invalid("tree Final current prior observation differs"));
        }
        let mut permits = Vec::new();
        for row in &history.operations {
            permits.push(vec![
                Value::Text("operations:insert".into()),
                Value::Text(row.op_id.to_string()),
                Value::Text(row.space_id.to_string()),
                Value::Text(row.origin_device_id.to_string()),
                Value::Integer(crate::sql_integer(row.origin_seq)?),
                Value::Text(row.payload.clone()),
                Value::Text(row.state.clone()),
            ]);
        }
        let snapshot = &history.snapshot;
        permits.push(vec![
            Value::Text("snapshots:insert".into()),
            Value::Text(snapshot.snapshot_id.to_string()),
            Value::Text(snapshot.space_id.to_string()),
            Value::Text(snapshot.manifest.clone()),
            Value::Integer(crate::sql_integer(snapshot.created_at_ms)?),
            Value::Text(snapshot.state.clone()),
            Value::Integer(snapshot.locked as i64),
        ]);
        permits.push(vec![
            Value::Text("current_manifests:update".into()),
            Value::Text(history.current.space_id.to_string()),
            Value::Text(history.current.prior_snapshot_id.to_string()),
            Value::Text(history.current.space_id.to_string()),
            Value::Text(history.current.snapshot_id.to_string()),
        ]);
        permits.push(vec![
            Value::Text("receive_cursors:update".into()),
            Value::Text(history.cursor.space_id.to_string()),
            Value::Text(history.cursor.device_id.to_string()),
            Value::Integer(crate::sql_integer(history.cursor.prior_seq)?),
            Value::Text(history.cursor.space_id.to_string()),
            Value::Text(history.cursor.device_id.to_string()),
            Value::Integer(crate::sql_integer(history.cursor.contiguous_seq)?),
        ]);
        for row in &history.input_release {
            permits.push(vec![
                Value::Text("tree_restore_objects:delete".into()),
                Value::Text(row.transaction_id.to_string()),
                Value::Text(row.content_id.to_string()),
                Value::Integer(i64::from(row.length)),
            ]);
        }
        if let Some(row) = &history.observation_invalidation {
            permits.push(vec![
                Value::Text("rename_observations:delete".into()),
                Value::Text(row.space_id.to_string()),
                Value::Text(row.snapshot_id.to_string()),
                Value::Text(row.observation.clone()),
                Value::Text(row.observation_hash.to_string()),
            ]);
        }
        for row in &history.input_release {
            permits.push(vec![
                Value::Text("tree_restore_objects:admission_delete".into()),
                Value::Text(row.transaction_id.to_string()),
                Value::Text(row.content_id.to_string()),
                Value::Integer(i64::from(row.length)),
            ]);
        }
        let terminals = tree_final_terminal_row_values(&plan)?;
        for row in &terminals {
            let mut values = vec![Value::Text(
                super::super::final_state::terminal_table(row.key().table)?.into(),
            )];
            values.extend(
                row.columns()
                    .iter()
                    .map(|column| match &column.value {
                        TreeStorageColumnValue::Text(value) => Ok(Value::Text(value.clone())),
                        TreeStorageColumnValue::Integer(value) => {
                            Ok(Value::Integer(crate::sql_integer(*value)?))
                        }
                    })
                    .collect::<Result<Vec<_>>>()?,
            );
            permits.push(values);
        }
        let permit = self.tree_native_issuance.permit(permits)?;
        for row in &history.operations {
            self.connection.execute(
                "INSERT INTO main.operations(op_id,space_id,origin_device_id,origin_seq,payload,state) VALUES(?1,?2,?3,?4,?5,?6)",
                rusqlite::params![row.op_id.as_str(),row.space_id.as_str(),row.origin_device_id.as_str(),
                    crate::sql_integer(row.origin_seq)?,&row.payload,&row.state],
            )?;
        }
        self.connection.execute(
            "INSERT INTO main.snapshots(snapshot_id,space_id,manifest,created_at_ms,state,locked) VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![snapshot.snapshot_id.as_str(),snapshot.space_id.as_str(),&snapshot.manifest,
                crate::sql_integer(snapshot.created_at_ms)?,&snapshot.state,crate::sql_integer(snapshot.locked)?],
        )?;
        for row in &history.snapshot_objects {
            self.connection.execute(
                "INSERT INTO main.snapshot_objects(snapshot_id,content_id) VALUES(?1,?2)",
                rusqlite::params![row.snapshot_id.as_str(), row.content_id.as_str()],
            )?;
        }
        if self.connection.execute(
            "UPDATE main.receive_cursors SET contiguous_seq=?1 WHERE space_id=?2 AND device_id=?3 AND contiguous_seq=?4",
            rusqlite::params![crate::sql_integer(history.cursor.contiguous_seq)?,history.cursor.space_id.as_str(),
                history.cursor.device_id.as_str(),crate::sql_integer(history.cursor.prior_seq)?],
        )? != 1 || self.connection.execute(
            "UPDATE main.current_manifests SET snapshot_id=?1 WHERE space_id=?2 AND snapshot_id=?3",
            rusqlite::params![history.current.snapshot_id.as_str(),history.current.space_id.as_str(),
                history.current.prior_snapshot_id.as_str()],
        )? != 1 {
            return Err(invalid("tree Final exact current/cursor update refused"));
        }
        for row in &terminals {
            let values: Vec<Value> = row
                .columns()
                .iter()
                .map(|column| match &column.value {
                    TreeStorageColumnValue::Text(value) => Ok(Value::Text(value.clone())),
                    TreeStorageColumnValue::Integer(value) => {
                        Ok(Value::Integer(crate::sql_integer(*value)?))
                    }
                })
                .collect::<Result<_>>()?;
            let table = super::super::final_state::terminal_table(row.key().table)?;
            let placeholders = vec!["?"; values.len()].join(",");
            self.connection.execute(
                &format!("INSERT INTO main.{table} VALUES({placeholders})"),
                params_from_iter(values),
            )?;
        }
        for row in &history.input_release {
            if self.connection.execute(
                "DELETE FROM main.tree_restore_objects WHERE transaction_id=?1 AND content_id=?2 AND length=?3",
                rusqlite::params![row.transaction_id.as_str(),row.content_id.as_str(),row.length],
            )? != 1 {
                return Err(invalid("tree Final exact input pin release refused"));
            }
        }
        permit.require_consumed()?;
        self.tree_owner_state(&execution.space, &execution.transaction, max)?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(&execution.space, self.writer_capacity_limits(max)?)?;
        let allowed: BTreeSet<(String, Vec<String>)> = history
            .operations
            .iter()
            .map(|row| ("operations".into(), vec![row.op_id.to_string()]))
            .chain(std::iter::once((
                "snapshots".into(),
                vec![snapshot.snapshot_id.to_string()],
            )))
            .chain(history.snapshot_objects.iter().map(|row| {
                (
                    "snapshot_objects".into(),
                    vec![row.snapshot_id.to_string(), row.content_id.to_string()],
                )
            }))
            .chain([
                (
                    "current_manifests".into(),
                    vec![history.current.space_id.to_string()],
                ),
                (
                    "receive_cursors".into(),
                    vec![
                        history.cursor.space_id.to_string(),
                        history.cursor.device_id.to_string(),
                    ],
                ),
            ])
            .chain(history.input_release.iter().map(|row| {
                (
                    "tree_restore_objects".into(),
                    vec![row.transaction_id.to_string(), row.content_id.to_string()],
                )
            }))
            .chain(
                history
                    .observation_invalidation
                    .iter()
                    .map(|row| ("rename_observations".into(), vec![row.space_id.to_string()])),
            )
            .chain(
                terminals
                    .iter()
                    .map(|row| {
                        Ok((
                            super::super::final_state::terminal_table(row.key().table)?.to_owned(),
                            row.key().key.clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
            .collect();
        let prior: BTreeMap<_, _> = before
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint(),
                )
            })
            .collect();
        let current: BTreeMap<_, _> = after
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint(),
                )
            })
            .collect();
        for key in prior.keys().chain(current.keys()) {
            if !allowed.contains(key) && prior.get(key) != current.get(key) {
                return Err(invalid(
                    "tree Final collateral row changed outside exact write set",
                ));
            }
        }
        execution.verify()?;
        checkpoint("before_tree_final_commit");
        tx.commit()?;
        checkpoint("after_tree_final_commit");
        Ok(TreeNativeFinalized {
            snapshot_id: snapshot.snapshot_id.clone(),
            held: observation,
        })
    }

    /// Continue only exact observed original lineage. A committed attempt
    /// without its observation never grants CREATE, WRITE, rename or adoption.
    pub fn reopen_tree_native_execution(
        &self,
        space: &SpaceId,
        transaction: &EntryId,
        max: usize,
    ) -> Result<TreeNativeExecution> {
        use TreeNativeActionIntent as I;
        use TreeNativeActionObservation as O;
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "tree execution recovery refuses caller transaction",
            ));
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) = self.tree_owner_state(space, transaction, max)?;
        if ["native_finalized", "native_cleaned"].contains(&preparation.state) {
            return Err(invalid(
                "tree execution already finalized; resume scoped cleanup",
            ));
        }
        if progress.records.len() < 10 {
            return Err(invalid("tree execution recovery original owner incomplete"));
        }
        if progress.layout.awaiting_observation() {
            let ordinal = progress
                .records
                .last()
                .ok_or(invalid("tree recovery last record"))?
                .action_ordinal;
            let attempted: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.tree_native_action_attempts
                 WHERE transaction_id=?1 AND action_ordinal=?2)",
                rusqlite::params![transaction.as_str(), ordinal as i64],
                |row| row.get(0),
            )?;
            if attempted {
                return Err(invalid(
                    "tree recovery ambiguous attempted effect cannot retry or adopt",
                ));
            }
        }
        let (projection, _, _) = crate::tree_native_storage::initial_layout(
            &self.connection,
            &preparation,
            preparation
                .native_storage
                .as_ref()
                .ok_or(invalid("tree recovery prewrite"))?
                .request(),
            max,
        )?;
        let owner = &preparation
            .owner_description
            .as_ref()
            .ok_or(invalid("tree recovery owner"))?
            .intent;
        let ready = &progress.records[9];
        let TreeNativeActionPayload::Observed {
            observation:
                O::OwnerReady {
                    directory: owner_id,
                    marker: marker_id,
                },
            ..
        } = &ready.payload
        else {
            return Err(invalid("tree recovery original owner Ready kind differs"));
        };
        let root: PathBuf = self
            .state("worktree")?
            .ok_or(invalid("tree recovery root absent"))?
            .into();
        let parent = root.join(".sync-extend");
        let owner_path = parent.join(&owner.published_component);
        let marker_path = owner_path.join(&owner.marker_component);
        let mut scope = Scope {
            directories: Vec::new(),
            files: Vec::new(),
            root: root.clone(),
            parent: parent.clone(),
            parent_key: FileKey { volume: 0, id: 0 },
            expected: BTreeMap::new(),
            max,
        };
        let mut ancestors: Vec<_> = root
            .ancestors()
            .filter(|path| path.is_absolute())
            .map(Path::to_owned)
            .collect();
        ancestors.reverse();
        for path in ancestors {
            scope.directory(&path)?;
        }
        let root_key = scope
            .directories
            .last()
            .ok_or(invalid("tree recovery root handle"))?
            .key;
        scope.parent_key = scope.directory(&parent)?;
        let inventory = projection.identity().inventory();
        if native(root_key) != inventory.root
            || native(scope.parent_key) != inventory.marker_directory
        {
            return Err(invalid(
                "tree recovery root or space marker directory identity differs",
            ));
        }
        let space_marker_path = parent.join("space-id");
        let space_marker = LockedFile::open(&space_marker_path)?;
        let space_marker_key = space_marker.key()?;
        if native(space_marker_key) != inventory.marker_file {
            return Err(invalid("tree recovery original space marker changed"));
        }
        verify_marker(space_marker.reader(), space.as_str().as_bytes())?;
        scope.files.push(File {
            path: space_marker_path,
            held: space_marker,
            key: space_marker_key,
            content: None,
        });
        let directory = LockedDirectory::open(&owner_path)?;
        let marker = LockedFile::open(&marker_path)?;
        if native(directory.key()?) != *owner_id || native(marker.key()?) != *marker_id {
            return Err(invalid(
                "tree recovery exact observed owner identities differ",
            ));
        }
        let mut execution = TreeNativeExecution {
            space: space.clone(),
            transaction: transaction.clone(),
            directory_key: directory.key()?,
            marker_key: marker.key()?,
            scope,
            directory,
            marker,
            owner_path,
            marker_path: marker_path.clone(),
            marker_bytes: encode_history_record(&owner.marker_payload, MAX_OPERATION_BYTES as u64)?,
            members: [marker_path].into_iter().collect(),
            resumed_creator: None,
            _coordination: coordination,
        };
        // Reconstruct exact current slots from independently audited observed
        // records, while immutable baseline identity metadata remains historical.
        let mut live: BTreeMap<String, (EntryKind, TreeNativeIdentity, Option<FileManifest>)> =
            projection
                .baseline()
                .entries
                .values()
                .map(|entry| {
                    let native_entry = &inventory.entries[&entry.path];
                    (
                        entry.path.as_str().to_owned(),
                        (
                            entry.kind,
                            native_entry.identity.clone(),
                            entry.content.clone(),
                        ),
                    )
                })
                .collect();
        let mut retained = BTreeMap::new();
        let mut staged: Option<(String, EntryKind, TreeNativeIdentity, Option<FileManifest>)> =
            None;
        for pair in progress.records[10..].chunks(2) {
            if pair.len() != 2 {
                break;
            }
            let TreeNativeActionPayload::Intended { intent } = &pair[0].payload else {
                return Err(invalid("tree recovery intended transcript kind"));
            };
            let TreeNativeActionPayload::Observed { observation, .. } = &pair[1].payload else {
                return Err(invalid("tree recovery observed transcript kind"));
            };
            match (intent.as_ref(), observation) {
                (
                    I::MoveOriginal {
                        path,
                        component,
                        original,
                        content,
                        ..
                    },
                    O::Moved { identity },
                ) if identity == original => {
                    live.remove(path.as_str())
                        .ok_or(invalid("tree recovery displaced original missing"))?;
                    retained.insert(component.clone(), (original.clone(), content.clone()));
                }
                (
                    I::CreateEntry {
                        component, kind, ..
                    },
                    O::Created { identity },
                ) => {
                    if staged
                        .replace((component.clone(), *kind, identity.clone(), None))
                        .is_some()
                    {
                        return Err(invalid("tree recovery overlapping staged creators"));
                    }
                }
                (
                    I::MaterializeEntry {
                        content, creator, ..
                    },
                    O::Materialized { identity, .. },
                ) if creator == identity => {
                    let stage = staged
                        .as_mut()
                        .ok_or(invalid("tree recovery staged file missing"))?;
                    stage.3 = Some(content.clone());
                }
                (
                    I::PublishEntry {
                        path,
                        component,
                        kind,
                        creator,
                        ..
                    },
                    O::Moved { identity },
                ) if creator == identity => {
                    let (name, stage_kind, stage_identity, content) = staged
                        .take()
                        .ok_or(invalid("tree recovery published original creator missing"))?;
                    if name != *component
                        || stage_kind != *kind
                        || stage_identity != *identity
                        || live
                            .insert(path.as_str().to_owned(), (*kind, identity.clone(), content))
                            .is_some()
                    {
                        return Err(invalid("tree recovery published exact slot differs"));
                    }
                }
                (I::DisposeEmptyDirectory { path, .. }, O::EmptyDirectoryAbsent { .. }) => {
                    live.remove(path.as_str())
                        .ok_or(invalid("tree recovery disposed directory missing"))?;
                }
                (I::CompleteStep { .. }, O::StepComplete { .. }) => {}
                _ => return Err(invalid("tree recovery unexpected exact phase binding")),
            }
        }
        let key = |identity: &TreeNativeIdentity| -> Result<FileKey> {
            Ok(FileKey {
                volume: identity.volume_serial,
                id: u128::from_str_radix(&identity.file_id, 16)
                    .map_err(|_| invalid("tree recovery native fullID encoding"))?,
            })
        };
        for (relative, (kind, identity, content)) in live {
            let path = root.join(&relative);
            execution.scope.expected.insert(relative, kind);
            if kind == EntryKind::Directory {
                if execution.scope.directory(&path)? != key(&identity)? {
                    return Err(invalid(
                        "tree recovery observed directory current fullID differs",
                    ));
                }
            } else {
                execution.add_file(
                    path,
                    key(&identity)?,
                    content.ok_or(invalid("tree recovery live file content"))?,
                )?;
            }
        }
        for (component, (identity, content)) in retained {
            let path = execution.owner_path.join(component);
            execution.members.insert(path.clone());
            execution.add_file(path, key(&identity)?, content)?;
        }
        if let Some((component, kind, identity, content)) = staged {
            let path = execution.owner_path.join(component);
            execution.members.insert(path.clone());
            let expected = key(&identity)?;
            execution.resumed_creator = Some(if kind == EntryKind::File {
                let content = content.ok_or(invalid(
                    "tree recovery unsealed staged file cannot resume writer",
                ))?;
                let file = LockedFile::open(&path)?;
                if file.key()? != expected || !file.matches_path(&path)? {
                    return Err(invalid("tree recovery original staged file fullID changed"));
                }
                verify_content(file.reader(), &content)?;
                ResumedCreator::File(file, expected, content)
            } else {
                // A Created observation retains identity, not the original
                // live directory creator. No sealing phase has consumed that
                // writer before PublishEntry, so recovery cannot reopen it as
                // publication authority merely because its slot is empty.
                return Err(invalid(
                    "tree recovery unsealed staged directory cannot resume writer",
                ));
            });
        }
        execution.verify()?;
        if progress.records.len() == 10 {
            let next = progress
                .layout
                .next_intent()
                .ok_or(invalid("tree recovery first action missing"))?;
            self.tree_owner_record(
                &preparation,
                &TreeNativeActionLayoutRecord {
                    scope: progress.layout.scope().clone(),
                    record_index: 10,
                    action_ordinal: 5,
                    previous_hash: hash(ready)?,
                    recorded_at_ms: ready.recorded_at_ms,
                    payload: TreeNativeActionPayload::Intended {
                        intent: Box::new(next.clone()),
                    },
                },
            )?;
            self.tree_owner_state(space, transaction, max)?;
        }
        tx.commit()?;
        Ok(execution)
    }

    /// Owner Ready is consumed once into the same original native scope.
    pub fn begin_tree_native_execution(
        &self,
        ready: TreeNativeOwnerReadiness,
        space: &SpaceId,
        max: usize,
    ) -> Result<TreeNativeExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid("tree executor refuses caller transaction"));
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (preparation, progress) = self.tree_owner_state(space, &ready.transaction, max)?;
        if progress.records.len() != 10 || progress.layout.awaiting_observation() {
            return Err(invalid("tree executor requires exact initial owner Ready"));
        }
        let owner = preparation
            .owner_description
            .as_ref()
            .ok_or(invalid("tree executor owner description absent"))?;
        let owner_path = ready._scope.parent.join(&owner.intent.published_component);
        let marker_path = owner_path.join(&owner.intent.marker_component);
        let execution = TreeNativeExecution {
            space: space.clone(),
            transaction: ready.transaction,
            directory_key: ready._directory.key()?,
            marker_key: ready._marker.key()?,
            scope: ready._scope,
            directory: ready._directory,
            marker: ready._marker,
            marker_bytes: encode_history_record(
                &owner.intent.marker_payload,
                MAX_OPERATION_BYTES as u64,
            )?,
            members: [marker_path.clone()].into_iter().collect(),
            owner_path,
            marker_path,
            resumed_creator: None,
            _coordination: ready._coordination,
        };
        execution.verify()?;
        let next = progress
            .layout
            .next_intent()
            .ok_or(invalid("tree executor missing first step"))?;
        self.tree_owner_record(
            &preparation,
            &TreeNativeActionLayoutRecord {
                scope: progress.layout.scope().clone(),
                record_index: progress.records.len(),
                action_ordinal: progress.records.len() / 2,
                previous_hash: hash(
                    progress
                        .records
                        .last()
                        .ok_or(invalid("tree Ready absent"))?,
                )?,
                recorded_at_ms: progress
                    .records
                    .last()
                    .ok_or(invalid("tree Ready absent"))?
                    .recorded_at_ms,
                payload: TreeNativeActionPayload::Intended {
                    intent: Box::new(next.clone()),
                },
            },
        )?;
        self.tree_owner_state(space, &execution.transaction, max)?;
        execution.verify()?;
        tx.commit()?;
        checkpoint("after_tree_executor_begin");
        Ok(execution)
    }

    /// Execute the remaining ordered native actions under the retained scope.
    /// This performs no logical history commit or input/original pin release.
    pub fn execute_tree_native(
        &self,
        execution: TreeNativeExecution,
        max: usize,
    ) -> Result<TreeNativeObservation> {
        self.execute_tree_native_checked(execution, max, |_| Ok(()))
    }

    /// A policy inspector can veto progress; it cannot create attempts,
    /// observations or native authority. The original scope is always checked.
    pub fn execute_tree_native_checked(
        &self,
        mut execution: TreeNativeExecution,
        max: usize,
        mut inspect_policy: impl FnMut(&TreeNativeExecutionFileView<'_>) -> Result<()>,
    ) -> Result<TreeNativeObservation> {
        use TreeNativeActionIntent as I;
        use TreeNativeActionObservation as O;
        enum Creator {
            File(OwnedFileCreation, FileKey),
            SealedFile(LockedFile, FileKey, FileManifest),
            Directory(LockedDirectoryMutation, FileKey),
        }
        let mut creator = execution
            .resumed_creator
            .take()
            .map(|creator| match creator {
                ResumedCreator::File(file, key, content) => Creator::SealedFile(file, key, content),
            });
        loop {
            let mut published_handoff = None;
            execution.verify()?;
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
            let (preparation, progress) =
                self.tree_owner_state(&execution.space, &execution.transaction, max)?;
            let Some(intent) = progress.layout.next_intent().cloned() else {
                tx.commit()?;
                if creator.is_some() || !progress.layout.complete_layout() {
                    return Err(invalid("tree executor incomplete original creator"));
                }
                return Ok(TreeNativeObservation { held: execution });
            };
            if !progress.layout.awaiting_observation() {
                return Err(invalid("tree executor exact preceding intention missing"));
            }
            let remaining = preparation
                .steps
                .iter()
                .filter(|step| {
                    step.index
                        >= match &intent {
                            I::MoveOriginal { step_index, .. }
                            | I::CreateEntry { step_index, .. }
                            | I::MaterializeEntry { step_index, .. }
                            | I::PublishEntry { step_index, .. }
                            | I::DisposeEmptyDirectory { step_index, .. }
                            | I::CompleteStep { step_index, .. } => *step_index,
                            _ => usize::MAX,
                        }
                })
                .filter_map(|step| {
                    step.historical_target_entry
                        .as_ref()
                        .and_then(|entry| entry.content.as_ref())
                })
                .try_fold(0u64, |sum, content| {
                    sum.checked_add(content.length)
                        .ok_or(invalid("tree forward remaining worktree capacity overflow"))
                })?;
            let creator_file = match creator.as_ref() {
                Some(Creator::File(file, _)) => Some(file.reader()),
                Some(Creator::SealedFile(file, _, _)) => Some(file.reader()),
                _ => None,
            };
            inspect_policy(&TreeNativeExecutionFileView {
                execution: &execution,
                creator: creator_file,
                remaining,
            })?;
            tx.commit()?;
            let attempt = self.tree_owner_attempt(
                &execution.space,
                &execution.transaction,
                max,
                &execution.scope,
            )?;
            checkpoint_index(
                "after_tree_step_activation",
                progress
                    .records
                    .last()
                    .ok_or(invalid("tree action ordinal missing"))?
                    .action_ordinal,
            );
            let observation = match &intent {
                I::MoveOriginal {
                    path,
                    original,
                    parent,
                    component,
                    content,
                    ..
                } => {
                    execution.parent(path, parent)?;
                    let index = execution.original_index(path, original)?;
                    let destination = execution.owner_path.join(component);
                    absent(&destination)?;
                    verify_content(execution.scope.files[index].held.reader(), content)?;
                    execution.scope.files[index]
                        .held
                        .rename_no_replace(&destination)?;
                    execution.scope.files[index].path = destination.clone();
                    execution.scope.expected.remove(path.as_str());
                    execution.members.insert(destination);
                    checkpoint_index(
                        "after_tree_original_moved",
                        progress
                            .records
                            .last()
                            .ok_or(invalid("tree action ordinal missing"))?
                            .action_ordinal,
                    );
                    O::Moved {
                        identity: original.clone(),
                    }
                }
                I::CreateEntry {
                    component, kind, ..
                } => {
                    if creator.is_some() {
                        return Err(invalid("tree executor preceding creator still writable"));
                    }
                    let path = execution.owner_path.join(component);
                    absent(&path)?;
                    let key = match kind {
                        EntryKind::File => {
                            let file = execution.directory.create_new_file(component)?;
                            let key = file.original_creation()?.key()?;
                            creator = Some(Creator::File(file, key));
                            key
                        }
                        EntryKind::Directory => {
                            let directory = execution.directory.create_new_child(component)?;
                            let key = directory.original_creation()?.key()?;
                            creator = Some(Creator::Directory(directory, key));
                            key
                        }
                    };
                    execution.members.insert(path);
                    checkpoint_index(
                        "after_tree_entry_created",
                        progress
                            .records
                            .last()
                            .ok_or(invalid("tree action ordinal missing"))?
                            .action_ordinal,
                    );
                    O::Created {
                        identity: native(key),
                    }
                }
                I::MaterializeEntry {
                    creator: expected,
                    content,
                    ..
                } => {
                    let Some(Creator::File(file, key)) = &mut creator else {
                        return Err(invalid(
                            "tree executor materialization original writer absent",
                        ));
                    };
                    if native(*key) != *expected || file.reader().metadata()?.len() != 0 {
                        return Err(invalid("tree executor materialization creator differs"));
                    }
                    file.original_creation()?.verify()?;
                    let parent = self
                        .database_path
                        .parent()
                        .ok_or(invalid("tree executor CAS parent"))?;
                    for chunk in &content.chunks {
                        self.require_cas_access(&chunk.content_id)?;
                        let path = parent
                            .join("cas/objects")
                            .join(&chunk.content_id.as_str()[..2])
                            .join(chunk.content_id.as_str());
                        let held = GuardedReadFile::open(&path)?;
                        let mut reader = held.reader();
                        let mut bytes = vec![0; chunk.length as usize];
                        reader.read_exact(&mut bytes)?;
                        if reader.read(&mut [0u8; 1])? != 0
                            || ContentId::hash(&bytes) != chunk.content_id
                        {
                            return Err(invalid("tree executor CAS chunk differs"));
                        }
                        file.writer().write_all(&bytes)?;
                    }
                    file.writer().sync_all()?;
                    verify_content(file.reader(), content)?;
                    checkpoint_index(
                        "after_tree_entry_materialized",
                        progress
                            .records
                            .last()
                            .ok_or(invalid("tree action ordinal missing"))?
                            .action_ordinal,
                    );
                    O::Materialized {
                        identity: expected.clone(),
                        content_hash: content.content_id.clone(),
                        length: content.length,
                    }
                }
                I::PublishEntry {
                    path,
                    parent,
                    component,
                    creator: expected,
                    kind,
                    step_index,
                    ..
                } => {
                    execution.parent(path, parent)?;
                    let destination = execution.scope.root.join(path.as_str());
                    absent(&destination)?;
                    let original = creator
                        .as_ref()
                        .ok_or(invalid("tree executor publication creator absent"))?;
                    let (key, content) = match original {
                        Creator::File(file, key) if *kind == EntryKind::File => {
                            if native(*key) != *expected {
                                return Err(invalid("tree publish creator fullID differs"));
                            }
                            file.original_creation()?.verify()?;
                            let content = self
                                .tree_owner_state(&execution.space, &execution.transaction, max)?
                                .0
                                .steps[*step_index]
                                .historical_target_entry
                                .as_ref()
                                .and_then(|entry| entry.content.clone())
                                .ok_or(invalid("tree publish target content absent"))?;
                            verify_content(file.reader(), &content)?;
                            file.rename_no_replace(&destination)?;
                            (*key, Some(content))
                        }
                        Creator::Directory(directory, key) if *kind == EntryKind::Directory => {
                            if native(*key) != *expected {
                                return Err(invalid("tree publish directory fullID differs"));
                            }
                            directory.original_creation()?.verify()?;
                            if fs::read_dir(execution.owner_path.join(component))?
                                .next()
                                .is_some()
                            {
                                return Err(invalid(
                                    "tree publish directory acquired foreign member",
                                ));
                            }
                            directory.rename_no_replace(&destination)?;
                            (*key, None)
                        }
                        Creator::SealedFile(file, key, content) if *kind == EntryKind::File => {
                            if native(*key) != *expected {
                                return Err(invalid("tree recovered creator fullID differs"));
                            }
                            verify_content(file.reader(), content)?;
                            file.rename_no_replace(&destination)?;
                            (*key, Some(content.clone()))
                        }
                        _ => return Err(invalid("tree publish original creator kind differs")),
                    };
                    execution
                        .members
                        .remove(&execution.owner_path.join(component));
                    execution
                        .scope
                        .expected
                        .insert(path.as_str().to_owned(), *kind);
                    published_handoff = Some((destination, key, content));
                    checkpoint_index(
                        "after_tree_entry_published",
                        progress
                            .records
                            .last()
                            .ok_or(invalid("tree action ordinal missing"))?
                            .action_ordinal,
                    );
                    O::Moved {
                        identity: expected.clone(),
                    }
                }
                I::DisposeEmptyDirectory {
                    path,
                    parent,
                    original,
                    ..
                } => {
                    execution.parent(path, parent)?;
                    let target = execution.scope.root.join(path.as_str());
                    let index = execution
                        .scope
                        .directories
                        .iter()
                        .position(|d| d.path == target)
                        .ok_or(invalid("tree empty directory original guard absent"))?;
                    if native(execution.scope.directories[index].key) != *original
                        || fs::read_dir(&target)?.next().is_some()
                    {
                        return Err(invalid(
                            "tree empty directory identity or membership differs",
                        ));
                    }
                    // The read guard is consumed only after durable activation.
                    drop(execution.scope.directories.remove(index));
                    let directory = LockedDirectoryMutation::open(&target)?;
                    if native(directory.key()?) != *original || !directory.matches_path(&target)? {
                        return Err(invalid("tree empty directory exact handle handoff changed"));
                    }
                    directory.delete_empty_on_close()?;
                    drop(directory);
                    absent(&target)?;
                    execution.scope.expected.remove(path.as_str());
                    checkpoint_index(
                        "after_tree_empty_directory_absent",
                        progress
                            .records
                            .last()
                            .ok_or(invalid("tree action ordinal missing"))?
                            .action_ordinal,
                    );
                    O::EmptyDirectoryAbsent {
                        original: original.clone(),
                    }
                }
                I::CompleteStep {
                    original,
                    published,
                    ..
                } => {
                    if creator.is_some() {
                        return Err(invalid("tree step completed before all writers consumed"));
                    }
                    execution.verify()?;
                    O::StepComplete {
                        original: original.clone(),
                        published: published.clone(),
                    }
                }
                _ => return Err(invalid("tree executor unsupported owner action")),
            };
            self.tree_owner_observed(attempt, observation, max, || {
                if let Some(creator) = &creator {
                    match creator {
                        Creator::File(file, key) => {
                            let original = file.original_creation()?;
                            original.verify()?;
                            if original.key()? != *key
                                || original.parent_key()? != execution.directory_key
                            {
                                return Err(invalid("tree observed original file creator changed"));
                            }
                            let path = match &intent {
                                I::PublishEntry { path, .. } => {
                                    execution.scope.root.join(path.as_str())
                                }
                                _ => execution.owner_path.join(original.created_component()),
                            };
                            if !regular_file_matches_path(file.reader(), &path)? {
                                return Err(invalid(
                                    "tree original creator current file slot changed",
                                ));
                            }
                        }
                        Creator::Directory(directory, key) => {
                            let path = match &intent {
                                I::CreateEntry { component, .. } => {
                                    execution.owner_path.join(component)
                                }
                                I::PublishEntry { path, .. } => {
                                    execution.scope.root.join(path.as_str())
                                }
                                _ => return Err(invalid("tree directory creator phase")),
                            };
                            if directory.key()? != *key || !directory.matches_path(&path)? {
                                return Err(invalid(
                                    "tree observed original directory creator changed",
                                ));
                            }
                            directory.original_creation()?.verify()?;
                        }
                        Creator::SealedFile(file, key, content) => {
                            if file.key()? != *key {
                                return Err(invalid("tree recovered sealed creator differs"));
                            }
                            verify_content(file.reader(), content)?;
                        }
                    }
                }
                execution.verify()
            })?;
            if let Some((path, key, content)) = published_handoff {
                // The actual original writer remains live until its complete
                // observed SQL transaction committed above.
                drop(creator.take());
                if let Some(content) = content {
                    execution.add_file(path, key, content)?;
                } else if execution.scope.directory(&path)? != key {
                    return Err(invalid("tree published directory read handoff differs"));
                }
            }
            checkpoint_index(
                "after_tree_step_observed",
                progress
                    .records
                    .last()
                    .ok_or(invalid("tree action ordinal missing"))?
                    .action_ordinal,
            );
        }
    }
}
