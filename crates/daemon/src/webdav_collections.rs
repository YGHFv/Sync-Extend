//! Authenticated bounded HTTP collection requests bind the actual native lifecycle.
use super::*;
use sync_extend_core_model::{
    limits::LocalLimits,
    webdav_mutation::{plan_webdav_mutation, WebDavMutation, WebDavMutationRequest},
    webdav_native::WebDavNativeLimits,
    EntryId,
};
use sync_extend_reconcile::WebDavBudgetLimits;

/// Listener-local explicit collection limits; no new product defaults are inferred.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CollectionLimits {
    max_entries: usize,
    max_operations: usize,
    max_handles: usize,
    max_actions: usize,
    max_templates: usize,
    max_binding_json: u64,
    max_manifest_json: u64,
    max_receipt_json: u64,
    max_execution_json: u64,
    max_metadata_bytes: u64,
    max_retained_bytes: u64,
    max_native_bytes: u64,
    max_failure_body_bytes: usize,
}
impl CollectionLimits {
    fn validate(&self, local: &LocalLimits) -> Result<(), u16> {
        let ceiling = sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES;
        if self.max_entries == 0
            || self.max_entries > local.max_scan_entries
            || self.max_operations == 0
            || self.max_operations > local.max_storage_entries
            || self.max_handles == 0
            || self.max_handles > local.max_storage_entries
            || self.max_actions == 0
            || self.max_actions > local.max_storage_entries
            || self.max_templates == 0
            || self.max_templates > local.max_storage_entries
            || self.max_binding_json == 0
            || self.max_binding_json > ceiling
            || self.max_manifest_json == 0
            || self.max_manifest_json > ceiling
            || self.max_receipt_json == 0
            || self.max_receipt_json > ceiling
            || self.max_execution_json == 0
            || self.max_execution_json > ceiling
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > local.max_scan_bytes
            || self.max_metadata_bytes > ceiling
            || self.max_retained_bytes > local.max_staging_bytes
            || self.max_native_bytes > local.max_staging_bytes
            || self.max_failure_body_bytes == 0
            || self.max_failure_body_bytes > 4 * 1024 * 1024
        {
            return Err(503);
        }
        Ok(())
    }
}
fn inside(path: &PortablePath, root: &PortablePath) -> bool {
    path == root
        || path
            .as_str()
            .strip_prefix(root.as_str())
            .is_some_and(|tail| tail.starts_with('/'))
}
fn authorized_path(
    authorized: &AuthorizedWebDavPath,
    path: &PortablePath,
    subtree: Option<&PortablePath>,
) -> Result<String, u16> {
    let tail = match subtree {
        Some(root) if path == root => "",
        Some(root) => path
            .as_str()
            .strip_prefix(root.as_str())
            .and_then(|tail| tail.strip_prefix('/'))
            .ok_or(403u16)?,
        None => path.as_str(),
    };
    Ok(format!("/{}/{}", authorized.export_name, tail))
}

// Keep authorization, locks, budget, request and connection explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn dispatch(
    runtime: &Runtime,
    limits: &LocalLimits,
    locks: &mut Locks,
    account: &str,
    authorized: &AuthorizedWebDavPath,
    tokens: &[String],
    request: &Request,
    local: &LocalSpace,
    baseline: WebDavBaseline,
    stream: &mut Connection,
) -> Result<(), u16> {
    if request.content_length != 0 {
        return Err(if request.method == "MKCOL" { 415 } else { 400 });
    }
    if authorized.export_root {
        return Err(405);
    }
    let policy = runtime.collection_limits.as_ref().ok_or(503u16)?;
    policy.validate(limits)?;
    let source = authorized.path.as_ref().ok_or(405u16)?.clone();
    let original = find(&baseline, Some(&source));
    let export = runtime
        .listener
        .exports
        .iter()
        .find(|export| export.name == authorized.export_name)
        .ok_or(403u16)?;
    let mut fresh_ids = BTreeMap::new();
    let mutation = match request.method.as_str() {
        "MKCOL" => {
            if original.is_some() {
                return Err(405);
            }
            WebDavMutation::Mkcol {
                destination: source.clone(),
            }
        }
        "DELETE" => {
            if original.is_none() {
                return Err(404);
            }
            if request
                .header("depth")
                .is_some_and(|value| value != "infinity")
            {
                return Err(400);
            }
            WebDavMutation::Delete {
                source: source.clone(),
            }
        }
        "MOVE" | "COPY" => {
            let original = original.ok_or(404u16)?;
            let destination = resource(
                runtime,
                account,
                request.header("destination").ok_or(400u16)?,
                true,
            )?;
            if destination.export_name != authorized.export_name
                || destination.space_id != authorized.space_id
                || destination.export_root
            {
                return Err(403);
            }
            let destination = destination.path.ok_or(405u16)?;
            if source.collision_key() == destination.collision_key() {
                return Err(403);
            }
            let overwrite = match request.header("overwrite").unwrap_or("T") {
                "T" => true,
                "F" => false,
                _ => return Err(400),
            };
            if !overwrite && find(&baseline, Some(&destination)).is_some() {
                return Err(412);
            }
            if request.method == "MOVE" {
                if request
                    .header("depth")
                    .is_some_and(|value| value != "infinity")
                {
                    return Err(400);
                }
                WebDavMutation::Move {
                    source: source.clone(),
                    destination,
                    overwrite,
                }
            } else {
                let recursive = match request.header("depth").unwrap_or("infinity") {
                    "infinity" => true,
                    "0" => false,
                    _ => return Err(400),
                };
                for entry in baseline.manifest().entries.values().filter(|entry| {
                    entry.path == source || recursive && inside(&entry.path, &source)
                }) {
                    fresh_ids.insert(
                        entry.entry_id.clone(),
                        EntryId::random().map_err(|_| 500u16)?,
                    );
                }
                if original.kind == EntryKind::File && !recursive && fresh_ids.len() != 1 {
                    return Err(500);
                }
                WebDavMutation::Copy {
                    source: source.clone(),
                    destination,
                    overwrite,
                    recursive,
                }
            }
        }
        _ => return Err(405),
    };
    let id = EntryId::random().map_err(|_| 500u16)?;
    let native_request = WebDavMutationRequest {
        transaction_id: id.clone(),
        baseline: baseline.snapshot_id().map_err(core_status)?,
        export_subtree: export.subtree.clone(),
        mutation,
        fresh_ids,
        origin_device: local.device_id.clone(),
        created_at_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| 500u16)?
            .as_millis()
            .try_into()
            .map_err(|_| 500u16)?,
        max_entries: policy.max_entries,
        max_operations: policy.max_operations,
        max_metadata_bytes: policy.max_metadata_bytes,
        max_retained_bytes: policy.max_retained_bytes,
    };
    let logical = plan_webdav_mutation(baseline.manifest(), &native_request).map_err(|_| 409u16)?;
    // Bound authorization to paths the request actually retains/removes/publishes.
    // Unchanged entries elsewhere in the space cannot spuriously expand the export.
    let paths: std::collections::BTreeMap<_, _> =
        logical
            .retained_originals()
            .iter()
            .chain(
                logical.manifest().entries.values().filter(|entry| {
                    baseline.manifest().entries.get(&entry.entry_id) != Some(*entry)
                }),
            )
            .map(|entry| (entry.path.clone(), entry.kind))
            .collect();
    for (path, kind) in &paths {
        let target = authorized_path(authorized, path, export.subtree.as_ref())?;
        let write = match &native_request.mutation {
            WebDavMutation::Copy { destination, .. } => inside(path, destination),
            _ => true,
        };
        let actual = runtime
            .listener
            .authorize(account, &target, write)
            .map_err(|_| 403u16)?;
        if write && !locks.allowed(account, &actual, tokens, *kind == EntryKind::Directory) {
            return Err(423);
        }
    }
    let parked = logical
        .retained_originals()
        .iter()
        .filter(|entry| match &native_request.mutation {
            WebDavMutation::Mkcol { .. } => false,
            WebDavMutation::Copy { destination, .. } => inside(&entry.path, destination),
            _ => true,
        })
        .map(|entry| entry.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let desired = logical
        .manifest()
        .entries
        .values()
        .filter(|entry| {
            parked.contains(&entry.path)
                || baseline.manifest().entries.get(&entry.entry_id) != Some(*entry)
        })
        .count();
    let actions = parked
        .len()
        .checked_mul(2)
        .and_then(|value| value.checked_add(desired))
        .and_then(|value| value.checked_add(1))
        .ok_or(507u16)?;
    let records = actions.checked_mul(2).ok_or(507u16)?;
    if actions > policy.max_actions || records > limits.max_storage_entries {
        return Err(507);
    }
    let total = (records as u64)
        .checked_mul(policy.max_execution_json)
        .ok_or(507u16)?;
    if total > sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES {
        return Err(507);
    }
    let status = if request.method == "DELETE" || logical.target_existed() {
        204
    } else {
        201
    };
    // Release preliminary observation parents; admission now captures and retains its
    // own exact native originals and verifies the unchanged baseline before any write.
    drop(baseline);
    let mut held = local
        .admit_complete_webdav(
            &native_request,
            WebDavNativeLimits {
                max_bindings: policy.max_handles,
                max_actions: policy.max_actions,
                max_metadata_bytes: policy.max_metadata_bytes,
                max_staging_bytes: policy.max_native_bytes,
            },
            WebDavBudgetLimits {
                max_templates: policy.max_templates,
                max_bindings: policy.max_handles,
                max_binding_json: policy.max_binding_json,
                max_manifest_json: policy.max_manifest_json,
                execution_records: records,
                max_execution_record_json: policy.max_execution_json,
                max_total_execution_json: total,
            },
            policy.max_handles,
            policy.max_receipt_json,
        )
        .map_err(core_status)?;
    let result = (|| -> Result<WebDavCommit, ReconcileError> {
        held.activate(&EntryId::random()?)?;
        held.create_initial_owner()?;
        held.execute_collection_actions()?;
        held.commit_collection_final()?;
        held.dispose_collection_originals()?;
        held.finish_collection_cleanup()?;
        held.verify_originals()?;
        if !held.execution().final_committed
            || held.execution().future_rows != 0
            || held.execution().future_bytes != 0
            || held.execution().unresolved_activation
        {
            return Err(ReconcileError::Invariant(
                "actual HTTP collection terminal incomplete",
            ));
        }
        Ok(WebDavCommit {
            transaction_id: id.clone(),
            snapshot_id: held.native_plan().final_manifest().root()?,
            local_committed: true,
            remote_backup_complete: false,
        })
    })();
    let native_failed_path = held.failed_native_path().cloned();
    let native_failed_status = held.failed_native_status();
    drop(held);

    match result {
        Ok(commit) => committed(stream, status, &commit),
        Err(error) => {
            let status = core_status(error);
            if let Some(path) = native_failed_path {
                use sync_extend_core_model::webdav_partial_response::{
                    describe_webdav_collection_failures, WebDavCollectionPathFailure,
                };
                let selected = paths.keys().cloned().collect();
                let response = describe_webdav_collection_failures(
                    &id,
                    &authorized.export_name,
                    export.subtree.as_ref(),
                    &selected,
                    &[WebDavCollectionPathFailure {
                        path,
                        failure: native_failed_status.ok_or(500u16)?,
                    }],
                    1,
                    policy.max_failure_body_bytes,
                )
                .map_err(|_| 500u16)?;
                return http::response(
                    stream,
                    207,
                    response.body().as_bytes(),
                    &[
                        ("Content-Type", response.content_type().into()),
                        ("X-SyncExtend-Transaction", id.to_string()),
                        ("X-SyncExtend-Remote-Backup-Complete", "false".into()),
                    ],
                    false,
                )
                .map_err(|_| 500u16);
            }
            // Preserve the actual transaction ID for durable inspection. No invented
            // per-path 207 successes/failures or remote backup receipt is returned.
            http::response(
                stream,
                status,
                b"collection transaction retained; inspect current state",
                &[
                    ("X-SyncExtend-Transaction", id.to_string()),
                    ("X-SyncExtend-Remote-Backup-Complete", "false".into()),
                ],
                false,
            )
            .map_err(|_| 500u16)
        }
    }
}
