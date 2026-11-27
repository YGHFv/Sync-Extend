//! Semantic archive verifier after framing; original identity protection is explicit.
use super::{
    file_content::FileClosure,
    layout::{ArchiveBounds, ArchiveRole, FramedNodeArchive},
};
use crate::{ReconcileError, Result};
use sync_extend_core_model::{config::Config, ContentId, DeviceId, Operation, SpaceId};
use sync_extend_journal::{JournalBackupImage, NodeInspectionBounds};
use sync_extend_transport::PeerIdentity;

pub struct VerifiedNodeStateArchive {
    pub(super) archive: FramedNodeArchive,
    space: SpaceId,
    device: DeviceId,
    schema: u32,
    original_worktree: std::path::PathBuf,
    original_config_data: Option<std::path::PathBuf>,
    pub(crate) inspected_bounds: NodeInspectionBounds,
    pub(crate) journal_digest: ContentId,
    pub(crate) audited_rows: Vec<sync_extend_journal::JournalStoredRow>,
}

impl VerifiedNodeStateArchive {
    pub fn space(&self) -> &SpaceId {
        &self.space
    }

    pub fn device(&self) -> &DeviceId {
        &self.device
    }

    pub fn schema(&self) -> u32 {
        self.schema
    }

    /// Original identity scope is informational; it cannot authorize any target path.
    pub fn original_worktree(&self) -> &std::path::Path {
        &self.original_worktree
    }

    pub fn original_config_data(&self) -> Option<&std::path::Path> {
        self.original_config_data.as_deref()
    }

    pub fn digest(&self) -> &ContentId {
        self.archive.digest()
    }

    pub fn bytes(&self) -> &[u8] {
        self.archive.bytes()
    }

    pub(crate) fn journal_bytes(&self) -> Result<&[u8]> {
        self.archive
            .section(&ArchiveRole::Journal)
            .ok_or(ReconcileError::Invariant("node Journal image absent"))
    }
}

impl FramedNodeArchive {
    /// Validate all original semantic fields before the caller creates a target.
    /// `decode_identity` must use the actual platform-protected secret loader.
    fn verify_node_state_inner(
        self,
        bounds: ArchiveBounds,
        inspection: NodeInspectionBounds,
        max_content_hash_bytes: u64,
        decode_identity: impl FnOnce(&[u8]) -> Result<DeviceId>,
    ) -> Result<VerifiedNodeStateArchive> {
        let bytes = self
            .section(&ArchiveRole::Journal)
            .ok_or(ReconcileError::Invariant("node Journal image absent"))?;
        let digest = ContentId::hash(bytes);
        let journal_limit = usize::try_from(bounds.archive_bytes.min(256 * 1024 * 1024))
            .map_err(|_| ReconcileError::ResourceLimit("node Journal byte bound"))?;
        let secret = self
            .section(&ArchiveRole::DeviceSecret)
            .ok_or(ReconcileError::Invariant("node protected identity absent"))?;
        let device = decode_identity(secret)?;
        if device != *self.device_id() {
            return Err(ReconcileError::Invariant(
                "node original device or schema differs",
            ));
        }
        let mut original_worktree = None;
        let mut original_config_data: Option<std::path::PathBuf> = None;
        let mut audited_image_rows = None;
        let mut protected = std::collections::BTreeSet::new();
        let mut files = FileClosure::new(
            inspection.capacity.inventory.max_rows,
            max_content_hash_bytes,
        )?;
        let (actual_schema, ()) = JournalBackupImage::inspect_current_node_image_with_audit_rows(
            bytes,
            digest.as_str(),
            journal_limit,
            self.space_id(),
            inspection,
            |database, audited_rows, references| -> sync_extend_journal::Result<()> {
                let pending_file = JournalBackupImage::verify_recovered_node_local_state(
                    audited_rows,
                    self.space_id(),
                    inspection,
                )?;
                let state = database
                    .prepare(
                        "SELECT key,value FROM main.local_state
                         WHERE key IN ('space_id','device_id','worktree') ORDER BY key",
                    )?
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<std::result::Result<std::collections::BTreeMap<_, _>, _>>()?;
                if state.len() != 3
                    || state.get("space_id") != Some(&self.space_id().to_string())
                    || state.get("device_id") != Some(&device.to_string())
                    || !state.contains_key("worktree")
                {
                    return Err(sync_extend_journal::JournalError::Invariant(
                        "node original Journal identity differs",
                    ));
                }
                let worktree = std::path::PathBuf::from(state.get("worktree").ok_or(
                    sync_extend_journal::JournalError::Invariant(
                        "node original worktree state absent",
                    ),
                )?);
                if !worktree.is_absolute() {
                    return Err(sync_extend_journal::JournalError::Invariant(
                        "node original Journal worktree is not absolute",
                    ));
                }
                original_worktree = Some(worktree);
                let mut statement = database.prepare(
                "SELECT op_id,space_id,origin_device_id,origin_seq,payload,state FROM operations")?;
                let rows = statement.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                })?;
                for row in rows {
                    let (id, space, origin, sequence, payload, state) = row?;
                    let operation: Operation = serde_json::from_str(&payload)?;
                    operation.validate()?;
                    if id != operation.op_id.as_str()
                        || space != operation.payload.space_id.as_str()
                        || origin != operation.payload.origin_device_id.as_str()
                        || sequence
                            != i64::try_from(operation.payload.origin_seq).map_err(|_| {
                                sync_extend_journal::JournalError::Invariant(
                                    "node original operation sequence",
                                )
                            })?
                        || space != self.space_id().as_str()
                        || !matches!(state.as_str(), "pending" | "received" | "materialized")
                    {
                        return Err(sync_extend_journal::JournalError::Invariant(
                            "node original operation values differ",
                        ));
                    }
                }

                let mut snapshots = std::collections::BTreeMap::new();
                let mut statement =
                    database.prepare("SELECT snapshot_id,space_id,manifest FROM snapshots")?;
                let rows = statement.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                for row in rows {
                    let (id, space, json) = row?;
                    let manifest: sync_extend_core_model::Manifest = serde_json::from_str(&json)?;
                    manifest.validate()?;
                    if manifest.space_id != *self.space_id()
                        || space != self.space_id().as_str()
                        || manifest.root()?.as_str() != id
                    {
                        return Err(sync_extend_journal::JournalError::Invariant(
                            "node snapshot root or space differs",
                        ));
                    }
                    snapshots.insert(id, manifest);
                }
                let currents = database
                    .prepare("SELECT space_id,snapshot_id FROM current_manifests")?
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                match (self.snapshot_id(), currents.as_slice()) {
                    (None, []) => {}
                    (Some(expected), [(space, root)])
                        if space == self.space_id().as_str()
                            && root == expected.as_str()
                            && snapshots.contains_key(root) => {}
                    _ => {
                        return Err(sync_extend_journal::JournalError::Invariant(
                            "node current snapshot pointer differs",
                        ))
                    }
                }
                // The original typed audit validates pruning records and retention rules.
                let pruned = database
                    .prepare("SELECT snapshot_id FROM main.snapshot_prunings")?
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
                let mut expected = std::collections::BTreeMap::new();
                let mut visits = 0usize;
                for (root, manifest) in &snapshots {
                    let mut pins = std::collections::BTreeSet::new();
                    for chunk in manifest
                        .entries
                        .values()
                        .filter_map(|entry| entry.content.as_ref())
                        .flat_map(|file| &file.chunks)
                    {
                        visits = visits
                            .checked_add(1)
                            .filter(|count| *count <= inspection.capacity.inventory.max_rows)
                            .ok_or(sync_extend_journal::JournalError::Invariant(
                                "node snapshot chunk visit bound",
                            ))?;
                        if !pruned.contains(root) {
                            pins.insert(chunk.content_id.clone());
                        }
                    }
                    if !pruned.contains(root) {
                        for file in manifest
                            .entries
                            .values()
                            .filter_map(|entry| entry.content.as_ref())
                        {
                            files.add(file)?;
                        }
                    }
                    expected.insert(root.clone(), pins);
                }
                let mut actual = std::collections::BTreeMap::new();
                let mut statement =
                    database.prepare("SELECT snapshot_id,content_id FROM snapshot_objects")?;
                let rows = statement.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                for row in rows {
                    let (root, id) = row?;
                    let expected_pins =
                        expected
                            .get(&root)
                            .ok_or(sync_extend_journal::JournalError::Invariant(
                                "node snapshot pin has no original manifest",
                            ))?;
                    let id: ContentId = id.parse()?;
                    if !actual
                        .entry(root.clone())
                        .or_insert_with(std::collections::BTreeSet::new)
                        .insert(id.clone())
                    {
                        return Err(sync_extend_journal::JournalError::Invariant(
                            "node duplicate snapshot pin",
                        ));
                    }
                    if !expected_pins.contains(&id) {
                        return Err(sync_extend_journal::JournalError::Invariant(
                            "node snapshot pin unrelated to retained manifest",
                        ));
                    }
                }
                for (root, expected_pins) in &expected {
                    if actual.remove(root).unwrap_or_default() != *expected_pins {
                        return Err(sync_extend_journal::JournalError::Invariant(
                            "node complete snapshot pins differ",
                        ));
                    }
                }
                if !actual.is_empty() {
                    return Err(sync_extend_journal::JournalError::Invariant(
                        "node snapshot pin owner absent",
                    ));
                }
                // Parse original audited intents; active lease/reference payloads are
                // supported without fabricating a new owner or dropping their pins.
                let mut leases = database.prepare("SELECT intent,state FROM main.read_leases")?;
                let rows = leases.query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?;
                for row in rows {
                    let (json, state) = row?;
                    if state == "active" {
                        let intent: sync_extend_journal::ReadLeaseIntent =
                            serde_json::from_str(&json)?;
                        files.add(intent.entry.content.as_ref().ok_or(
                            sync_extend_journal::JournalError::Invariant(
                                "node active lease original content absent",
                            ),
                        )?)?;
                    }
                }
                // Reference state is derived by the original Journal from
                // exact intent/hash/pins and audited terminal adapters.
                for owner in references {
                    if owner.state == "reserved" {
                        for file in &owner.intent.scope.files {
                            files.add(file)?;
                        }
                    }
                }
                // All owner rows above were already checked by the original complete audit.
                let mut query = database.prepare(
                "SELECT content_id FROM snapshot_objects UNION SELECT content_id FROM publication_objects
                UNION SELECT content_id FROM mutation_objects UNION SELECT content_id FROM read_lease_objects
                UNION SELECT content_id FROM reference_reservation_objects
                UNION SELECT content_id FROM conflict_resolution_objects
                UNION SELECT content_id FROM conflict_resolution_native_history_objects
                UNION SELECT content_id FROM tree_restore_objects UNION SELECT content_id FROM tree_restore_original_objects")?;
                let rows = query.query_map([], |row| row.get::<_, String>(0))?;
                for row in rows {
                    let id: ContentId = row?.parse()?;
                    protected.insert(id);
                }
                if let Some(file) = pending_file {
                    files.add(&file)?;
                    protected.extend(file.chunks.into_iter().map(|chunk| chunk.content_id));
                }
                files.verify(&self, &protected)?;
                audited_image_rows = Some(audited_rows.to_vec());
                Ok(())
            },
        )?;
        if actual_schema != self.source_schema() {
            return Err(ReconcileError::Invariant("node original schema differs"));
        }
        for id in protected {
            let bytes = self
                .section(&ArchiveRole::CasObject {
                    content_id: id.clone(),
                })
                .ok_or(ReconcileError::Invariant(
                    "node protected CAS content absent",
                ))?;
            if ContentId::hash(bytes) != id {
                return Err(ReconcileError::Invariant(
                    "node protected CAS content differs",
                ));
            }
        }
        for role in self.roles() {
            match role {
                ArchiveRole::PeerApproval { device_id } => {
                    let peer: PeerIdentity = serde_json::from_slice(
                        self.section(role)
                            .ok_or(ReconcileError::Invariant("node peer bytes absent"))?,
                    )?;
                    peer.validate()
                        .map_err(|_| ReconcileError::Invariant("node peer approval invalid"))?;
                    if peer.space_id != *self.space_id()
                        || peer.device_id != *device_id
                        || peer.device_id == device
                    {
                        return Err(ReconcileError::Invariant(
                            "node peer approval scope differs",
                        ));
                    }
                }
                ArchiveRole::ExplicitConfig { .. } => {
                    let config: Config = serde_json::from_slice(
                        self.section(role)
                            .ok_or(ReconcileError::Invariant("node config bytes absent"))?,
                    )?;
                    config.validate()?;
                    if config.webdav.credential_ref.is_some()
                        || config.webdav.tls_certificate.is_some()
                        || config.webdav.tls_key.is_some()
                    {
                        return Err(ReconcileError::Invariant(
                            "node config references require separately captured protected artifacts",
                        ));
                    }
                    let worktree_scope_matches = config
                        .worktree
                        .as_deref()
                        .zip(original_worktree.as_deref())
                        .is_some_and(|(worktree, original)| {
                            crate::path_comparison::path_equal(worktree, original)
                        });
                    if !worktree_scope_matches
                        || config.worktree.as_ref().is_none_or(|worktree| {
                            crate::path_comparison::path_within(&config.data_dir, worktree)
                                || crate::path_comparison::path_within(worktree, &config.data_dir)
                        })
                    {
                        return Err(ReconcileError::Invariant(
                            "node config original Journal worktree scope differs",
                        ));
                    }
                    match &original_config_data {
                        Some(data)
                            if !crate::path_comparison::path_equal(data, &config.data_dir) =>
                        {
                            return Err(ReconcileError::Invariant(
                                "node original config data roots disagree",
                            ));
                        }
                        None => original_config_data = Some(config.data_dir),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        Ok(VerifiedNodeStateArchive {
            space: self.space_id().clone(),
            schema: self.source_schema(),
            device,
            original_worktree: original_worktree.ok_or(ReconcileError::Invariant(
                "node verified original worktree absent",
            ))?,
            original_config_data,
            inspected_bounds: inspection,
            journal_digest: digest,
            audited_rows: audited_image_rows.ok_or(ReconcileError::Invariant(
                "node recovered archive summary absent",
            ))?,
            archive: self,
        })
    }
}

impl FramedNodeArchive {
    /// Verify using the actual platform's protected stored identity mechanism.
    /// Complete original Journal audits precede archive-specific checks.
    pub fn verify_node_state(
        self,
        bounds: ArchiveBounds,
        inspection: NodeInspectionBounds,
        max_content_hash_bytes: u64,
    ) -> Result<VerifiedNodeStateArchive> {
        self.verify_node_state_inner(bounds, inspection, max_content_hash_bytes, |stored| {
            let secret = crate::identity::decode_stored_backup(stored)?;
            let key = ed25519_dalek::SigningKey::from_bytes(&secret);
            Ok(DeviceId::from_public_key(key.verifying_key().as_bytes()))
        })
    }
}
