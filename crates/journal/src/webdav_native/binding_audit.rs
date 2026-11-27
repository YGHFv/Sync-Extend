//! Strict original binding description set. Live issuer still requires original guards.
use super::{
    budget_manifest::OriginalMainRow,
    initial_binding::{InitialBindingRole, InitialHeldBinding},
};
use crate::{JournalError, JournalStorageColumnValue as Value, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
};
use sync_extend_core_model::{
    ContentId, EntryKind, Manifest,
    tree_restore_identity::TreeNativeIdentity,
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
};

fn invalid() -> JournalError {
    JournalError::Invariant("complete exact original DAV held binding role set")
}

pub(super) fn audit(
    baseline: &Manifest,
    plan: &WebDavNativePlan,
    original: &[OriginalMainRow],
    bindings: &[InitialHeldBinding],
    expected_data: &std::path::Path,
) -> Result<()> {
    let expected_data = crate::archived_windows_path::ArchivedWindowsPath::parse(
        expected_data.to_str().ok_or_else(invalid)?,
    )?;
    let root = original
        .iter()
        .find(|row| row.table == "local_state" && row.primary_key == ["worktree"])
        .ok_or_else(invalid)?;
    let [Value::Text(key), Value::Text(root)] = root.values.as_slice() else {
        return Err(invalid());
    };
    if key != "worktree" {
        return Err(invalid());
    }
    let root = crate::archived_windows_path::ArchivedWindowsPath::parse(root)?;
    if bindings.is_empty() {
        return Err(invalid());
    }
    let marker_dir = root.join_portable(".sync-extend")?;
    let marker_file = marker_dir.join_portable("space-id")?;
    let mut by_path = BTreeMap::new();
    let mut identities = BTreeSet::<TreeNativeIdentity>::new();
    let mut role_keys = BTreeSet::new();
    let mut baseline_entries = BTreeSet::new();
    let mut actual_chunks = BTreeMap::new();
    let mut cas_base = None;
    let quarantine: BTreeSet<_> = plan
        .steps()
        .iter()
        .filter_map(|step| match &step.action {
            WebDavNativeAction::QuarantineOriginal { entry, .. }
                if entry.kind == EntryKind::Directory =>
            {
                Some(entry.entry_id.clone())
            }
            _ => None,
        })
        .collect();
    for (index, binding) in bindings.iter().enumerate() {
        let path = crate::archived_windows_path::ArchivedWindowsPath::parse(&binding.absolute_path)?;
        binding.identity.validate()?;
        if binding.index != index
            || binding.plan_hash != *plan.fingerprint()
            || binding.baseline_hash != baseline.root()?
            || !identities.insert(binding.identity.clone())
            || by_path.insert(path.clone(), binding).is_some()
        {
            return Err(invalid());
        }
        match &binding.role {
            InitialBindingRole::DataRoot => {
                if path != expected_data || !role_keys.insert("data_root") {
                    return Err(invalid());
                }
            }
            InitialBindingRole::DataAncestor => {
                if path == expected_data || !expected_data.starts_with(&path) {
                    return Err(invalid());
                }
            }
            InitialBindingRole::WorktreeRoot => {
                if path != root
                    || binding.identity != plan.inventory().root
                    || !role_keys.insert("root")
                {
                    return Err(invalid());
                }
            }
            InitialBindingRole::MarkerDirectory => {
                if path != marker_dir
                    || binding.identity != plan.inventory().marker_directory
                    || !role_keys.insert("marker_dir")
                {
                    return Err(invalid());
                }
            }
            InitialBindingRole::MarkerFile { space_id } => {
                if path != marker_file
                    || binding.identity != plan.inventory().marker_file
                    || space_id != &baseline.space_id
                    || !role_keys.insert("marker_file")
                {
                    return Err(invalid());
                }
            }
            InitialBindingRole::BaselineDirectory {
                entry,
                mutation_handle,
            } => {
                if entry.kind != EntryKind::Directory
                    || *mutation_handle != quarantine.contains(&entry.entry_id)
                    || baseline.entries.get(&entry.entry_id) != Some(entry)
                    || path != root.join_portable(entry.path.as_str())?
                    || plan
                        .inventory()
                        .entries
                        .get(&entry.path)
                        .is_none_or(|native| {
                            native.identity != binding.identity
                                || native.entry_id != entry.entry_id
                                || native.kind != entry.kind
                        })
                    || !baseline_entries.insert(entry.entry_id.clone())
                {
                    return Err(invalid());
                }
            }
            InitialBindingRole::BaselineFile { entry } => {
                if entry.kind != EntryKind::File
                    || baseline.entries.get(&entry.entry_id) != Some(entry)
                    || path != root.join_portable(entry.path.as_str())?
                    || plan
                        .inventory()
                        .entries
                        .get(&entry.path)
                        .is_none_or(|native| {
                            native.identity != binding.identity
                                || native.entry_id != entry.entry_id
                                || native.kind != entry.kind
                        })
                    || !baseline_entries.insert(entry.entry_id.clone())
                {
                    return Err(invalid());
                }
            }
            InitialBindingRole::CasChunk { content_id, length } => {
                let parent = path.parent().ok_or_else(invalid)?;
                let objects = parent.parent().ok_or_else(invalid)?;
                let base = objects.parent().ok_or_else(invalid)?;
                if path.file_name() != Some(content_id.as_str())
                    || parent.file_name()
                        != Some(&content_id.as_str()[..2])
                    || objects.file_name() != Some("objects")
                    || base.file_name() != Some("cas")
                    || cas_base.as_ref().is_some_and(|old| old != &base)
                    || base != expected_data.join_portable("cas")?
                    || actual_chunks.insert(content_id.clone(), *length).is_some()
                {
                    return Err(invalid());
                }
                cas_base = Some(base.to_owned());
            }
            InitialBindingRole::WorktreeAncestor => {
                if path == root || !root.starts_with(&path) {
                    return Err(invalid());
                }
            }
            InitialBindingRole::CasAncestor => {}
        }
    }
    if role_keys != BTreeSet::from(["root", "marker_dir", "marker_file", "data_root"])
        || baseline_entries != baseline.entries.keys().cloned().collect()
    {
        return Err(invalid());
    }
    let mut expected_chunks = BTreeMap::<ContentId, u64>::new();
    for chunk in baseline
        .entries
        .values()
        .chain(plan.final_manifest().entries.values())
        .filter_map(|entry| entry.content.as_ref())
        .flat_map(|content| &content.chunks)
    {
        if expected_chunks
            .insert(chunk.content_id.clone(), u64::from(chunk.length))
            .is_some_and(|old| old != u64::from(chunk.length))
        {
            return Err(invalid());
        }
    }
    if expected_chunks != actual_chunks {
        return Err(invalid());
    }
    for (path, binding) in &by_path {
        if let InitialBindingRole::CasAncestor = &binding.role {
            if !bindings.iter().any(|chunk| {
                matches!(chunk.role, InitialBindingRole::CasChunk { .. })
                    && crate::archived_windows_path::ArchivedWindowsPath::parse(
                        &chunk.absolute_path,
                    ).is_ok_and(|chunk| chunk.starts_with(path))
            }) {
                return Err(invalid());
            }
        }
        let expected_parent = path
            .parent()
            .map(|parent| {
                by_path
                    .get(&parent)
                    .map(|binding| binding.identity.clone())
                    .ok_or_else(invalid)
            })
            .transpose()?;
        if binding.parent_identity != expected_parent {
            return Err(invalid());
        }
    }
    Ok(())
}
