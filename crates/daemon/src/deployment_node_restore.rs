//! Prepare every original node and native parent before the first CREATE.
//! Nested callbacks retain the same original completion loans through install.
use super::{Descriptor, NodeRestoreDescriptor, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
};
use sync_extend_platform_fs::{
    held_disk_space, LockedDirectory, WindowsOriginalCloseAttempt,
    WindowsOriginalResourceCloseFailure,
};
use sync_extend_reconcile::{
    DeploymentProtectionProvider, NodeTargetRoot, OriginalDeploymentNodeCompletion,
    PreparedDeploymentNodeRestore, PreparedDeploymentTargets, RestrictedDeploymentMapping,
    RetainedInstalledDeploymentFiles,
};

#[derive(Clone)]
pub(crate) struct InstalledNode {
    pub node_id: u32,
    pub recovery: super::super::recovery::Descriptor,
}

pub(crate) struct Installed {
    pub files: RetainedInstalledDeploymentFiles,
    pub receipts: Vec<serde_json::Value>,
    pub nodes: Vec<InstalledNode>,
}

struct PreparedNode {
    original: PreparedDeploymentNodeRestore,
    descriptor: NodeRestoreDescriptor,
    data_parent: usize,
    worktree_parent: usize,
    ledger_parent: usize,
}

struct Parent {
    path: PathBuf,
    original: LockedDirectory,
}

pub(crate) struct Prepared {
    targets: Option<PreparedDeploymentTargets>,
    nodes: Vec<PreparedNode>,
    parents: Vec<Parent>,
    max_generations: u64,
}

fn same_windows_path(first: &Path, second: &Path) -> bool {
    first
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&second.as_os_str().to_string_lossy())
}

fn require_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("all selected original node target roots must be absent".into()),
    }
}

fn require_empty(path: &Path) -> Result<()> {
    if std::fs::read_dir(path)?.next().transpose()?.is_some() {
        return Err("original deployment external ledger directory must be empty".into());
    }
    Ok(())
}

fn retain_parent(
    path: &Path,
    private: bool,
    parents: &mut Vec<Parent>,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
) -> Result<usize> {
    let index = match parents
        .iter()
        .position(|parent| same_windows_path(path, &parent.path))
    {
        Some(index) => index,
        None => {
            let original = LockedDirectory::open_retaining(path).map_err(|failure| {
                if let Some(original) = failure.original_resources {
                    failures.push(original);
                }
                Box::<dyn std::error::Error>::from(failure.error)
            })?;
            parents.push(Parent {
                path: path.to_owned(),
                original,
            });
            parents.len() - 1
        }
    };
    let original = &parents[index].original;
    original.require_local_ntfs(path)?;
    original.require_case_insensitive()?;
    if !original.matches_path(path)? {
        return Err("same retained original deployment parent slot required".into());
    }
    if private {
        original.require_current_user_private()?;
    }
    let key = original.key()?;
    if parents.iter().enumerate().any(|(other, parent)| {
        other != index
            && parent.original.key().ok() == Some(key)
            && !same_windows_path(path, &parent.path)
    }) {
        return Err("original deployment native parent alias".into());
    }
    Ok(index)
}

pub(crate) fn prepare(
    descriptor: &Descriptor,
    mapping: RestrictedDeploymentMapping,
    provider: &DeploymentProtectionProvider,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
) -> Result<Prepared> {
    let targets =
        PreparedDeploymentTargets::preflight_retaining(mapping, provider).map_err(|failure| {
            let error = io::Error::other(failure.error.to_string());
            if let Err(original) = failure.close_retaining() {
                failures.push(original);
            }
            Box::<dyn std::error::Error>::from(error)
        })?;
    let mut prepared = Prepared {
        targets: Some(targets),
        nodes: Vec::new(),
        parents: Vec::new(),
        max_generations: descriptor.owner.max_generations,
    };
    let result = (|| -> Result<()> {
        let inputs = prepared
            .targets
            .as_ref()
            .ok_or("original deployment preflight absent")?
            .node_restore_inputs(provider)?;
        if inputs.len() != descriptor.node_restores.len() || inputs.len() > 64 {
            return Err(
                "complete exact original deployment restore descriptor set required".into(),
            );
        }
        let mut used = BTreeSet::new();
        let mut future_roots = Vec::<PathBuf>::new();
        for input in inputs {
            let node = input.node();
            let selected = descriptor
                .node_restores
                .iter()
                .find(|selected| selected.node_id == node.id)
                .ok_or("original deployment node restore descriptor absent")?
                .clone();
            if !used.insert(selected.node_id)
                || selected.recovery.archive_digest != node.archive_digest
                || selected.recovery.archive != node.archive_path
                || selected.recovery.expected_space != node.space_id
                || selected.recovery.expected_device != node.device_id
                || selected.recovery.worktree != input.target().worktree
                || selected.recovery.data != input.target().data_dir
                || selected.recovery.max_content_hash_bytes > descriptor.max_content_hash_bytes
            {
                return Err(
                    "original deployment node descriptor/archive/target binding differs".into(),
                );
            }
            for root in [&selected.recovery.worktree, &selected.recovery.data] {
                if future_roots.iter().any(|other| {
                    same_windows_path(root, other)
                        || root.starts_with(other)
                        || other.starts_with(root)
                }) {
                    return Err("independent original deployment node target roots required".into());
                }
                require_absent(root)?;
                future_roots.push(root.clone());
            }
            if future_roots.iter().any(|root| {
                selected.ledger_directory.starts_with(root)
                    || root.starts_with(&selected.ledger_directory)
            }) {
                return Err("original deployment ledger must be outside every target root".into());
            }
            for path in [
                &selected.recovery.worktree,
                &selected.recovery.data,
                &selected.ledger_directory,
            ] {
                let parent = if path == &selected.ledger_directory {
                    path.as_path()
                } else {
                    path.parent()
                        .ok_or("original deployment root parent absent")?
                };
                for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
                    retain_parent(ancestor, false, &mut prepared.parents, failures)?;
                }
            }
            let data_parent = retain_parent(
                selected
                    .recovery
                    .data
                    .parent()
                    .ok_or("original data parent absent")?,
                true,
                &mut prepared.parents,
                failures,
            )?;
            let worktree_parent = retain_parent(
                selected
                    .recovery
                    .worktree
                    .parent()
                    .ok_or("original worktree parent absent")?,
                true,
                &mut prepared.parents,
                failures,
            )?;
            let ledger_parent = retain_parent(
                &selected.ledger_directory,
                true,
                &mut prepared.parents,
                failures,
            )?;
            require_empty(&selected.ledger_directory)?;
            let original = input.prepare_original_node_restore(
                selected.recovery.inspection(),
                selected.recovery.ledger(),
                None,
            )?;
            prepared.nodes.push(PreparedNode {
                original,
                descriptor: selected,
                data_parent,
                worktree_parent,
                ledger_parent,
            });
        }
        // Later nodes must also be excluded from every earlier external ledger.
        for node in &prepared.nodes {
            if future_roots.iter().any(|root| {
                node.descriptor.ledger_directory.starts_with(root)
                    || root.starts_with(&node.descriptor.ledger_directory)
            }) {
                return Err("original external ledger overlaps a selected deployment root".into());
            }
        }
        prepared.nodes.sort_by_key(|node| node.descriptor.node_id);
        prepared.verify_liabilities(provider)?;
        Ok(())
    })();
    if let Err(error) = result {
        prepared.close_into(failures);
        return Err(error);
    }
    Ok(prepared)
}

impl Prepared {
    fn verify_liabilities(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<Vec<serde_json::Value>> {
        let mut totals = BTreeMap::<String, (u64, u64, u64)>::new();
        let targets = self
            .targets
            .as_ref()
            .ok_or("actual original deployment targets absent")?;
        for file in targets.future_file_liabilities(provider)? {
            add_rounded(
                &mut totals,
                file.filesystem,
                file.allocation_bytes,
                file.available_bytes,
                file.allocation_unit,
            )?;
        }
        let mut charge = |parent: usize, bytes: u64| -> Result<()> {
            let parent = self
                .parents
                .get(parent)
                .ok_or("actual original liability parent absent")?;
            let observed = held_disk_space(&parent.original, &parent.path)?;
            let unit = observed.allocation_unit;
            let rounded = bytes
                .checked_add(unit.checked_sub(1).ok_or("zero actual allocation unit")?)
                .and_then(|bytes| bytes.checked_div(unit))
                .and_then(|units| units.checked_mul(unit))
                .ok_or("original deployment per-file allocation overflow")?;
            add_rounded(
                &mut totals,
                format!("windows-volume:{}", parent.original.key()?.volume),
                rounded,
                observed.available_to_caller,
                unit,
            )
        };
        for node in &self.nodes {
            require_absent(&node.descriptor.recovery.data)?;
            require_absent(&node.descriptor.recovery.worktree)?;
            require_empty(&node.descriptor.ledger_directory)?;
            for (root, bytes) in node.original.prepared().future_file_bytes_by_root()? {
                charge(
                    match root {
                        NodeTargetRoot::Data => node.data_parent,
                        NodeTargetRoot::Worktree => node.worktree_parent,
                    },
                    bytes,
                )?;
            }
            // The shared native engine supplies every first-write and finite
            // future runtime file bound. No copied frame/owner magic numbers.
            let runtime = node
                .original
                .prepared()
                .deployment_native_runtime_liability(self.max_generations)?;
            if self.max_generations > runtime.maximum_generations {
                return Err(
                    "deployment owner generations exceed the original native budget".into(),
                );
            }
            for bytes in runtime.data_files {
                charge(node.data_parent, bytes)?;
            }
            for bytes in runtime.worktree_files {
                charge(node.worktree_parent, bytes)?;
            }
            for bytes in runtime.external_files {
                charge(node.ledger_parent, bytes)?;
            }
            let native = node.original.prepared();
            charge(node.ledger_parent, native.reserved_database_bytes())?;
            charge(node.ledger_parent, native.reserved_record_bytes())?;
            charge(node.ledger_parent, native.completion_manifest_reserve())?;
        }
        if totals
            .values()
            .any(|(allocation, available, _)| allocation > available)
        {
            return Err(
                "complete original deployment filesystem allocation exceeds available bytes".into(),
            );
        }
        Ok(totals
            .into_iter()
            .map(
                |(filesystem, (allocation_bytes, available_bytes, allocation_unit))| {
                    serde_json::json!({
                        "filesystem": filesystem, "allocation_bytes": allocation_bytes,
                        "available_bytes": available_bytes, "allocation_unit": allocation_unit,
                    })
                },
            )
            .collect())
    }

    pub(crate) fn preview(
        &self,
        provider: &DeploymentProtectionProvider,
    ) -> Result<serde_json::Value> {
        let liabilities = self.verify_liabilities(provider)?;
        let mut preview = self
            .targets
            .as_ref()
            .ok_or("original deployment targets absent")?
            .preview()?;
        preview["complete_original_filesystem_liabilities"] = liabilities.into();
        preview["original_node_restores"] = serde_json::to_value(
            self.nodes
                .iter()
                .map(|node| {
                    serde_json::json!({
                        "node_id": node.descriptor.node_id,
                        "archive_digest": node.original.archive().digest(),
                        "worktree": node.descriptor.recovery.worktree,
                        "data": node.descriptor.recovery.data,
                        "ledger_directory": node.descriptor.ledger_directory,
                    })
                })
                .collect::<Vec<_>>(),
        )?;
        Ok(preview)
    }

    pub(crate) fn close_into(self, failures: &mut Vec<WindowsOriginalResourceCloseFailure>) {
        let mut terminal = WindowsOriginalCloseAttempt::new();
        if let Some(targets) = self.targets {
            terminal.append_result(targets.close_retaining());
        }
        for parent in self.parents {
            terminal.close_directory(parent.original);
        }
        if let Err(original) = terminal.finish() {
            failures.push(original);
        }
    }

    pub(crate) fn install(
        mut self,
        provider: &DeploymentProtectionProvider,
        failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
        partial_receipt: &mut Option<serde_json::Value>,
    ) -> Result<Installed> {
        if !failures.is_empty() {
            self.close_into(failures);
            return Err("an earlier original deployment resource failure remains recorded".into());
        }
        let close_start = failures.len();
        let mut files = None;
        let mut receipts = Vec::new();
        let mut successors = BTreeMap::new();
        let mut result = self.verify_liabilities(provider).and_then(|_| {
            install_original(
                &self.nodes,
                0,
                &mut self.targets,
                Vec::new(),
                provider,
                failures,
                &mut files,
                &mut receipts,
                &mut successors,
                partial_receipt,
            )
        });
        let original_attempt_receipt = partial_receipt.take();
        let installation_receipt = match files.as_ref() {
            Some(files) => match serde_json::to_value(files.receipt()) {
                Ok(receipt) => receipt,
                Err(error) => {
                    if result.is_ok() {
                        result = Err(error.into());
                    }
                    original_attempt_receipt.unwrap_or(serde_json::Value::Null)
                }
            },
            None => original_attempt_receipt.unwrap_or(serde_json::Value::Null),
        };
        *partial_receipt = Some(serde_json::json!({
            "installation": installation_receipt,
            "original_node_restores": receipts,
        }));
        self.close_into(failures);
        if let Err(error) = result {
            if let Some(files) = files {
                if let Err(original) = files.close_retaining() {
                    failures.push(original);
                }
            }
            return Err(error);
        }
        if failures.len() != close_start {
            if let Some(files) = files {
                if let Err(original) = files.close_retaining() {
                    failures.push(original);
                }
            }
            return Err("actual original deployment preflight parent close failed".into());
        }
        receipts.sort_by_key(|receipt| receipt["node_id"].as_u64());
        let files = files.ok_or("same actual complete installed file owner absent")?;
        Ok(Installed {
            files,
            receipts,
            nodes: successors
                .into_iter()
                .map(|(node_id, recovery)| InstalledNode { node_id, recovery })
                .collect(),
        })
    }
}

fn add_rounded(
    totals: &mut BTreeMap<String, (u64, u64, u64)>,
    filesystem: String,
    allocation: u64,
    available: u64,
    unit: u64,
) -> Result<()> {
    if unit == 0 {
        return Err("actual original deployment allocation unit is zero".into());
    }
    let total = totals.entry(filesystem).or_insert((0, available, unit));
    if total.2 != unit {
        return Err("actual original filesystem allocation geometry changed".into());
    }
    total.0 = total
        .0
        .checked_add(allocation)
        .ok_or("complete original filesystem allocation overflow")?;
    total.1 = total.1.min(available);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn install_original<'proof>(
    nodes: &[PreparedNode],
    index: usize,
    targets: &mut Option<PreparedDeploymentTargets>,
    completions: Vec<OriginalDeploymentNodeCompletion<'proof>>,
    provider: &DeploymentProtectionProvider,
    failures: &mut Vec<WindowsOriginalResourceCloseFailure>,
    files: &mut Option<RetainedInstalledDeploymentFiles>,
    receipts: &mut Vec<serde_json::Value>,
    successors: &mut BTreeMap<u32, super::super::recovery::Descriptor>,
    partial_receipt: &mut Option<serde_json::Value>,
) -> Result<()> {
    if let Some(node) = nodes.get(index) {
        let output = super::super::recovery::with_prepared_original_node_restore_result(
            node.original.archive(),
            node.original.prepared(),
            &node.descriptor.recovery,
            &node.descriptor.ledger_directory,
            super::super::recovery::RestoreMode::FirstWrite,
            |original| {
                let mut live: Vec<_> = completions
                    .into_iter()
                    .map(OriginalDeploymentNodeCompletion::into_shorter_borrow)
                    .collect();
                live.push(OriginalDeploymentNodeCompletion::from_original(
                    node.descriptor.node_id,
                    original,
                )?);
                install_original(
                    nodes,
                    index + 1,
                    targets,
                    live,
                    provider,
                    failures,
                    files,
                    receipts,
                    successors,
                    partial_receipt,
                )
            },
        )?;
        let mut receipt = output.receipt;
        receipt["node_id"] = node.descriptor.node_id.into();
        receipts.push(receipt);
        successors.insert(
            node.descriptor.node_id,
            output
                .successor
                .ok_or("same original deployment first-write successor absent")?,
        );
        output.value
    } else {
        let original_targets = targets
            .take()
            .ok_or("same original deployment targets already consumed")?;
        let prepared = original_targets
            .with_original_completions_retaining(completions, provider)
            .map_err(|failure| {
                if let Err(original) = failure.original_targets.close_retaining() {
                    failures.push(original);
                }
                Box::<dyn std::error::Error>::from(failure.error)
            })?;
        let complete = prepared.install(provider).map_err(|failure| {
            *partial_receipt = serde_json::to_value(failure.original_attempt.receipt()).ok();
            if let Err(original) = failure.original_attempt.close_retaining() {
                failures.push(original);
            }
            Box::<dyn std::error::Error>::from(failure.error)
        })?;
        let receipt = match serde_json::to_value(complete.receipt()) {
            Ok(receipt) => receipt,
            Err(error) => {
                if let Err(original) = complete.close_retaining() {
                    failures.push(original);
                }
                return Err(error.into());
            }
        };
        *partial_receipt = Some(receipt);
        let retained = complete.retain_files(provider).map_err(|failure| {
            if let Err(original) = failure.original_install.close_retaining() {
                failures.push(original);
            }
            Box::<dyn std::error::Error>::from(failure.error)
        })?;
        *files = Some(retained);
        Ok(())
    }
}
