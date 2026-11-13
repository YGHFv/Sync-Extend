//! Resume only canonical Final disposition under exact original identities.
use super::owner::*;
use super::*;
use crate::Journal;
use rusqlite::{Transaction, TransactionBehavior};
use std::{fs, path::PathBuf};
use sync_extend_core_model::{
    tree_native_final_layout::TreeNativeFinalLayoutPlan,
    tree_original_terminal_layout::{
        plan_tree_original_release_layout, TreeOriginalTerminalLayoutPlan,
        TreeOriginalTerminalRowsLayout,
    },
    tree_owner_cleanup_layout::TreeOwnerCleanupRecordLayout,
    tree_owner_cleanup_values::{
        tree_owner_cleanup_intent_row_values, tree_owner_cleanup_record_row_values,
    },
    tree_restore_identity::TreeNativeIdentity,
    tree_storage_footprint::{
        tree_original_terminal_row_values, TreeStorageRowValues, TreeStorageTable,
    },
    EntryKind, FileManifest, SpaceId,
};
use sync_extend_platform_fs::{FileKey, LockedDirectory, LockedDirectoryMutation, LockedFile};

fn key(identity: &TreeNativeIdentity) -> Result<FileKey> {
    Ok(FileKey {
        volume: identity.volume_serial,
        id: u128::from_str_radix(&identity.file_id, 16)
            .map_err(|_| invalid("tree cleanup full identity encoding"))?,
    })
}

fn present(path: &std::path::Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn members(path: &std::path::Path, expected: &BTreeSet<PathBuf>) -> Result<()> {
    let mut actual = BTreeSet::new();
    for child in fs::read_dir(path)? {
        if actual.len() >= expected.len() {
            return Err(invalid("tree cleanup foreign member"));
        }
        actual.insert(child?.path());
    }
    if actual != *expected {
        return Err(invalid("tree cleanup exact owner membership differs"));
    }
    Ok(())
}

fn scope(
    journal: &Journal,
    preparation: &TreeRestorePreparation,
    final_plan: &TreeNativeFinalLayoutPlan,
    max: usize,
) -> Result<Scope> {
    let (projection, _, _) = crate::tree_native_storage::initial_layout(
        &journal.connection,
        preparation,
        preparation
            .native_storage
            .as_ref()
            .ok_or(invalid("tree cleanup prewrite"))?
            .request(),
        max,
    )?;
    let root: PathBuf = journal
        .state("worktree")?
        .ok_or(invalid("tree cleanup root missing"))?
        .into();
    let parent = root.join(".sync-extend");
    let mut scope = Scope {
        directories: Vec::new(),
        files: Vec::new(),
        root: root.clone(),
        parent: parent.clone(),
        parent_key: FileKey { volume: 0, id: 0 },
        expected: final_plan
            .rows()
            .intent
            .final_native_entries
            .iter()
            .map(|(path, entry)| (path.as_str().to_owned(), entry.kind))
            .collect(),
        max,
    };
    let mut ancestors: Vec<_> = root
        .ancestors()
        .filter(|path| path.is_absolute())
        .map(std::path::Path::to_owned)
        .collect();
    ancestors.reverse();
    for path in ancestors {
        scope.directory(&path)?;
    }
    if native(
        scope
            .directories
            .last()
            .ok_or(invalid("tree cleanup root guard"))?
            .key,
    ) != projection.identity().inventory().root
    {
        return Err(invalid("tree cleanup original root changed"));
    }
    scope.parent_key = scope.directory(&parent)?;
    if native(scope.parent_key) != projection.identity().inventory().marker_directory {
        return Err(invalid("tree cleanup original parent changed"));
    }
    let marker_path = parent.join("space-id");
    let marker = LockedFile::open(&marker_path)?;
    let marker_key = marker.key()?;
    if native(marker_key) != projection.identity().inventory().marker_file {
        return Err(invalid("tree cleanup original space marker changed"));
    }
    verify_marker(
        marker.reader(),
        preparation.intent.scope.space_id.as_str().as_bytes(),
    )?;
    scope.files.push(File {
        path: marker_path,
        held: marker,
        key: marker_key,
        content: None,
    });
    for (relative, entry) in &final_plan.rows().intent.final_native_entries {
        let path = root.join(relative.as_str());
        if entry.kind == EntryKind::Directory {
            if scope.directory(&path)? != key(&entry.identity)? {
                return Err(invalid("tree cleanup completed directory changed"));
            }
        } else {
            let content = projection.context().history.manifest().entries[&entry.entry_id]
                .content
                .clone()
                .ok_or(invalid("tree cleanup completed file content"))?;
            let held = LockedFile::open(&path)?;
            if held.key()? != key(&entry.identity)? || !held.matches_path(&path)? {
                return Err(invalid("tree cleanup completed file changed"));
            }
            verify_content(held.reader(), &content)?;
            scope.files.push(File {
                path,
                key: held.key()?,
                held,
                content: Some(content),
            });
        }
    }
    scope.verify()?;
    Ok(scope)
}

fn originals(
    connection: &Connection,
    id: &EntryId,
    plan: &TreeOriginalTerminalLayoutPlan,
    bounds: sync_extend_core_model::tree_original_terminal_layout::TreeOriginalTerminalLayoutLimits,
) -> Result<BTreeMap<usize, TreeOriginalTerminalRowsLayout>> {
    let mut result = BTreeMap::new();
    for (&index, intent) in plan.intents() {
        let done: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.tree_native_original_terminals WHERE transaction_id=?1 AND step_index=?2)",
            rusqlite::params![id.as_str(), index as i64], |row| row.get(0),
        )?;
        if done {
            result.insert(
                index,
                plan_tree_original_release_layout(plan, index, intent.intended_at_ms, bounds)?,
            );
        }
    }
    Ok(result)
}

fn records(connection: &Connection, id: &EntryId) -> Result<Vec<TreeOwnerCleanupRecordLayout>> {
    connection.prepare(
        "SELECT record FROM main.tree_native_cleanup_records WHERE transaction_id=?1 ORDER BY record_index",
    )?.query_map([id.as_str()], |row| row.get::<_, String>(0))?
        .map(|row| Ok(serde_json::from_str(&row?)?)).collect()
}

impl Journal {
    #[allow(clippy::too_many_arguments)]
    fn tree_cleanup_write(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
        writes: &[TreeStorageRowValues],
        release: &[sync_extend_core_model::tree_original_terminal_layout::TreeOriginalReleasedReferenceLayout],
        verify: impl Fn() -> Result<()>,
    ) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        self.tree_owner_state(space, id, max)?;
        verify()?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(space, self.writer_capacity_limits(max)?)?;
        let mut allowed = BTreeSet::new();
        for row in writes {
            let table = disposition_state::table(row.key().table)?;
            allowed.insert((table.to_owned(), row.key().key.clone()));
            self.tree_disposition_row(row)?;
        }
        if !release.is_empty() {
            let exact = release
                .iter()
                .flat_map(|row| {
                    [
                        "tree_restore_original_objects:delete",
                        "tree_restore_original_objects:admission_delete",
                    ]
                    .map(|trigger| {
                        vec![
                            Value::Text(trigger.into()),
                            Value::Text(row.transaction_id.to_string()),
                            Value::Integer(row.step_index as i64),
                            Value::Text(row.step_execution_id.to_string()),
                            Value::Text(row.content_id.to_string()),
                            Value::Integer(i64::from(row.length)),
                        ]
                    })
                })
                .collect();
            let permit = self.tree_native_issuance.permit(exact)?;
            for row in release {
                if self.connection.execute(
                    "DELETE FROM main.tree_restore_original_objects WHERE transaction_id=?1 AND step_index=?2 AND step_execution_id=?3 AND content_id=?4 AND length=?5",
                    rusqlite::params![row.transaction_id.as_str(),row.step_index as i64,row.step_execution_id.as_str(),row.content_id.as_str(),row.length],
                )? != 1 {
                    return Err(invalid("tree cleanup exact original pin release refused"));
                }
                allowed.insert((
                    "tree_restore_original_objects".into(),
                    vec![
                        row.transaction_id.to_string(),
                        row.step_index.to_string(),
                        row.content_id.to_string(),
                    ],
                ));
            }
            permit.require_consumed()?;
        }
        self.tree_owner_state(space, id, max)?;
        let after = self
            .read_view()
            .audit_local_commit_capacity(space, self.writer_capacity_limits(max)?)?;
        let before: BTreeMap<_, _> = before
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint(),
                )
            })
            .collect();
        let after: BTreeMap<_, _> = after
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().to_owned(), row.primary_key().to_vec()),
                    row.fingerprint(),
                )
            })
            .collect();
        for item in before.keys().chain(after.keys()) {
            if !allowed.contains(item) && before.get(item) != after.get(item) {
                return Err(invalid("tree cleanup collateral physical row changed"));
            }
        }
        verify()?;
        tx.commit()?;
        Ok(())
    }

    /// The Final is immutable and never replayed. Resume only exact original
    /// disposition or confirm the already audited cleanup terminal read-only.
    pub fn resume_tree_native_cleanup(
        &self,
        space: &SpaceId,
        id: &EntryId,
        max: usize,
    ) -> Result<TreeNativeCleanupReceipt> {
        if !self.connection.is_autocommit() {
            return Err(invalid("tree cleanup refuses caller transaction"));
        }
        let _coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let (mut preparation, progress) = self.tree_owner_state(space, id, max)?;
        let committed: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.tree_native_final_commits WHERE transaction_id=?1)",
            [id.as_str()],
            |row| row.get(0),
        )?;
        if !committed {
            return Err(invalid("tree cleanup actual Final missing"));
        }
        let final_plan = final_state::plan(
            &self.connection,
            &preparation,
            &progress.records,
            &progress.layout,
            max,
        )?;
        let snapshot_id = final_plan.rows().intent.final_snapshot_id.clone();
        if preparation.state == "native_cleaned" {
            tx.commit()?;
            return Ok(TreeNativeCleanupReceipt {
                transaction: id.clone(),
                snapshot_id,
            });
        }
        let mut scope = scope(self, &preparation, &final_plan, max)?;
        let owner = &preparation
            .owner_description
            .as_ref()
            .ok_or(invalid("tree cleanup owner"))?
            .intent;
        let owner_path = scope.parent.join(&owner.published_component);
        let marker_path = owner_path.join(&owner.marker_component);
        let mut cleanup_records = records(&self.connection, id)?;
        let stage = cleanup_records.len();
        if ![0, 1, 3].contains(&stage) {
            return Err(invalid("tree cleanup durable prefix differs"));
        }
        let mut directory = if present(&owner_path)? {
            let held = LockedDirectory::open(&owner_path)?;
            if native(held.key()?) != final_plan.rows().intent.owner_directory
                || !held.matches_path(&owner_path)?
            {
                return Err(invalid("tree cleanup original owner full identity differs"));
            }
            Some(held)
        } else {
            if stage < 3 {
                return Err(invalid("tree cleanup owner absent without disposition"));
            }
            None
        };
        let mut marker = if present(&marker_path)? {
            if stage >= 3 {
                return Err(invalid(
                    "tree cleanup marker reappeared after observed absence",
                ));
            }
            let held = LockedFile::open(&marker_path)?;
            if native(held.key()?) != final_plan.rows().intent.owner_marker
                || !held.matches_path(&marker_path)?
            {
                return Err(invalid(
                    "tree cleanup original marker full identity differs",
                ));
            }
            verify_marker(
                held.reader(),
                &encode_history_record(&owner.marker_payload, MAX_OPERATION_BYTES as u64)?,
            )?;
            Some(held)
        } else {
            if stage == 0 {
                return Err(invalid("tree cleanup marker absent without disposition"));
            }
            None
        };
        let (original_plan, bounds) = disposition_state::original_plan(&final_plan, &preparation)?;
        let mut terminals = originals(&self.connection, id, &original_plan, bounds)?;
        let mut expected = BTreeSet::new();
        if marker.is_some() {
            expected.insert(marker_path.clone());
        }
        for (&index, intent) in original_plan.intents() {
            let path = owner_path.join(&intent.retained_component);
            if terminals.contains_key(&index) {
                absent(&path)?;
                continue;
            }
            let intended: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.tree_native_original_intents WHERE transaction_id=?1 AND step_index=?2)",
                rusqlite::params![id.as_str(),index as i64], |row| row.get(0),
            )?;
            if present(&path)? {
                let held = LockedFile::open(&path)?;
                let content: FileManifest = preparation
                    .original_pins
                    .as_ref()
                    .ok_or(invalid("tree cleanup original pins"))?
                    .originals[&index]
                    .original_content
                    .clone();
                if native(held.key()?) != intent.original_identity || !held.matches_path(&path)? {
                    return Err(invalid(
                        "tree cleanup retained original full identity differs",
                    ));
                }
                verify_content(held.reader(), &content)?;
                expected.insert(path.clone());
                scope.files.push(File {
                    path,
                    key: held.key()?,
                    held,
                    content: Some(content),
                });
            } else if !intended {
                return Err(invalid(
                    "tree cleanup original absent without durable disposition",
                ));
            }
        }
        if directory.is_some() {
            members(&owner_path, &expected)?;
        }
        scope.verify()?;
        tx.commit()?;
        let all = tree_original_terminal_row_values(
            &original_plan,
            final_plan.rows().committed.committed_at_ms,
            bounds,
        )?;
        for (&index, intent) in original_plan.intents() {
            if terminals.contains_key(&index) {
                continue;
            }
            self.tree_owner_state(space, id, max)?;
            scope.verify()?;
            let path = owner_path.join(&intent.retained_component);
            let intended: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.tree_native_original_intents WHERE transaction_id=?1 AND step_index=?2)",
                rusqlite::params![id.as_str(),index as i64], |row| row.get(0),
            )?;
            if !intended {
                let row = all
                    .iter()
                    .find(|row| {
                        row.key().table == TreeStorageTable::OriginalIntent
                            && row.key().key.get(1) == Some(&index.to_string())
                    })
                    .ok_or(invalid("tree cleanup original intent values"))?;
                self.tree_cleanup_write(space, id, max, std::slice::from_ref(row), &[], || {
                    scope.verify()?;
                    members(&owner_path, &expected)
                })?;
            }
            checkpoint_index("after_tree_original_disposition_intended", index);
            if let Some(file_index) = scope.files.iter().position(|file| file.path == path) {
                self.tree_owner_state(space, id, max)?;
                scope.verify()?;
                members(&owner_path, &expected)?;
                scope.files[file_index].held.delete_on_close()?;
                drop(scope.files.remove(file_index));
            }
            absent(&path)?;
            expected.remove(&path);
            checkpoint_index("after_tree_original_absent", index);
            let released = plan_tree_original_release_layout(
                &original_plan,
                index,
                intent.intended_at_ms,
                bounds,
            )?;
            let writes: Vec<_> = all
                .iter()
                .filter(|row| {
                    [
                        TreeStorageTable::OriginalAbsence,
                        TreeStorageTable::OriginalTerminal,
                    ]
                    .contains(&row.key().table)
                        && row.key().key.get(1) == Some(&index.to_string())
                })
                .cloned()
                .collect();
            self.tree_cleanup_write(space, id, max, &writes, &released.release, || {
                scope.verify()?;
                absent(&path)?;
                members(&owner_path, &expected)
            })?;
            terminals.insert(index, released);
            // The terminal SQL transaction released this exact closure.
            // Rebuild the typed remaining-pin audit before constructing later
            // cleanup phases; historical admission identities stay unchanged.
            preparation = self.tree_owner_state(space, id, max)?.0;
            checkpoint_index("after_tree_original_terminal", index);
        }
        if cleanup_records.is_empty() {
            let plan = disposition_state::cleanup_plan(
                &self.connection,
                &preparation,
                &final_plan,
                &original_plan,
                &terminals,
                &[],
                max,
            )?;
            let first = plan
                .next_record_candidate(
                    final_plan.rows().committed.committed_at_ms,
                    MAX_OPERATION_BYTES as u64,
                )?
                .ok_or(invalid("tree cleanup marker intended"))?;
            self.tree_cleanup_write(
                space,
                id,
                max,
                &[
                    tree_owner_cleanup_intent_row_values(&plan)?,
                    tree_owner_cleanup_record_row_values(&first)?,
                ],
                &[],
                || {
                    scope.verify()?;
                    members(&owner_path, &expected)
                },
            )?;
            cleanup_records.push(first);
        }
        if cleanup_records.len() == 1 {
            checkpoint("after_tree_marker_disposition_intended");
            if let Some(held) = marker.take() {
                self.tree_owner_state(space, id, max)?;
                scope.verify()?;
                members(&owner_path, &expected)?;
                held.delete_on_close()?;
                drop(held);
            }
            absent(&marker_path)?;
            expected.remove(&marker_path);
            members(&owner_path, &expected)?;
            checkpoint("after_tree_marker_absent");
            let mut plan = disposition_state::cleanup_plan(
                &self.connection,
                &preparation,
                &final_plan,
                &original_plan,
                &terminals,
                &cleanup_records,
                max,
            )?;
            let absence = plan
                .next_record_candidate(
                    final_plan.rows().committed.committed_at_ms,
                    MAX_OPERATION_BYTES as u64,
                )?
                .ok_or(invalid("tree cleanup marker absence"))?;
            cleanup_records.push(absence.clone());
            plan = disposition_state::cleanup_plan(
                &self.connection,
                &preparation,
                &final_plan,
                &original_plan,
                &terminals,
                &cleanup_records,
                max,
            )?;
            let intended = plan
                .next_record_candidate(
                    final_plan.rows().committed.committed_at_ms,
                    MAX_OPERATION_BYTES as u64,
                )?
                .ok_or(invalid("tree cleanup directory intention"))?;
            self.tree_cleanup_write(
                space,
                id,
                max,
                &[
                    tree_owner_cleanup_record_row_values(&absence)?,
                    tree_owner_cleanup_record_row_values(&intended)?,
                ],
                &[],
                || {
                    scope.verify()?;
                    absent(&marker_path)?;
                    members(&owner_path, &expected)
                },
            )?;
            cleanup_records.push(intended);
        }
        checkpoint("after_tree_directory_disposition_intended");
        if directory.is_some() {
            self.tree_owner_state(space, id, max)?;
            scope.verify()?;
            members(&owner_path, &BTreeSet::new())?;
            drop(directory.take());
            let held = LockedDirectoryMutation::open(&owner_path)?;
            if native(held.key()?) != final_plan.rows().intent.owner_directory
                || !held.matches_path(&owner_path)?
            {
                return Err(invalid("tree cleanup empty owner original handoff changed"));
            }
            members(&owner_path, &BTreeSet::new())?;
            held.delete_empty_on_close()?;
            drop(held);
        }
        absent(&owner_path)?;
        checkpoint("after_tree_directory_absent");
        let plan = disposition_state::cleanup_plan(
            &self.connection,
            &preparation,
            &final_plan,
            &original_plan,
            &terminals,
            &cleanup_records,
            max,
        )?;
        let terminal = plan
            .next_record_candidate(
                final_plan.rows().committed.committed_at_ms,
                MAX_OPERATION_BYTES as u64,
            )?
            .ok_or(invalid("tree cleanup directory terminal"))?;
        self.tree_cleanup_write(
            space,
            id,
            max,
            &[tree_owner_cleanup_record_row_values(&terminal)?],
            &[],
            || {
                scope.verify()?;
                absent(&owner_path)
            },
        )?;
        checkpoint("after_tree_owner_cleanup_complete");
        Ok(TreeNativeCleanupReceipt {
            transaction: id.clone(),
            snapshot_id,
        })
    }
}
