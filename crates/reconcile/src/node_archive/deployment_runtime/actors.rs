//! Actor mutations rederive the original account/path grant from the same
//! retained installation and borrow only its actual fresh recovered node.
use super::DeploymentRun;
use crate::{ReconcileError, Result};
use sync_extend_core_model::{
    webdav::AuthorizedWebDavPath, EntryKind, Manifest, PortablePath, SnapshotId, SpaceId,
};

impl DeploymentRun<'_> {
    fn gateway_mutation_baseline(
        &self,
        account: &str,
        target: &str,
        expected: &SnapshotId,
    ) -> Result<(u32, AuthorizedWebDavPath, Manifest)> {
        self.verify()?;
        let gateway = self.files.gateway_configuration(self.provider)?;
        let authorized = gateway.listener.authorize(account, target, true)?;
        if authorized.export_root
            || authorized.path.is_none()
            || !authorized.allow_native_windows_writes
        {
            return Err(ReconcileError::Invariant(
                "original gateway grant does not authorize this native entry mutation",
            ));
        }
        let id = self.node_id(&authorized.space_id)?;
        let manifest = self.manifest(&authorized.space_id)?;
        if manifest.root()? != *expected {
            return Err(ReconcileError::Invariant(
                "same original gateway request baseline changed",
            ));
        }
        self.verify()?;
        Ok((id, authorized, manifest))
    }

    fn verify_gateway_mutation(
        &self,
        space: &SpaceId,
        original_result: Result<SnapshotId>,
    ) -> Result<SnapshotId> {
        // Preserve the actual mutation error before any later verification.
        let committed = original_result?;
        self.verify()?;
        if self.manifest(space)?.root()? != committed {
            return Err(ReconcileError::Invariant(
                "same recovered gateway native commit root differs",
            ));
        }
        Ok(committed)
    }

    /// PUT derives create versus replace from the same request baseline. The
    /// actual node enforces original creators, native/CAS budgets and history.
    pub fn gateway_authorized_put(
        &mut self,
        account: &str,
        target: &str,
        expected: &SnapshotId,
        bytes: &[u8],
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let (id, authorized, manifest) =
            self.gateway_mutation_baseline(account, target, expected)?;
        if bytes.len() as u64 > authorized.max_upload_bytes {
            return Err(ReconcileError::ResourceLimit(
                "original gateway upload grant bytes",
            ));
        }
        let path = authorized
            .path
            .as_ref()
            .expect("entry path checked before original node mutation");
        let previous = manifest.entries.values().find(|entry| &entry.path == path);
        if previous.is_some_and(|entry| entry.kind != EntryKind::File) {
            return Err(ReconcileError::Invariant(
                "gateway PUT requires an absent path or original file",
            ));
        }
        let node = self
            .nodes
            .get_mut(&id)
            .expect("same complete fresh node binding verified");
        let result = if previous.is_some() {
            node.replace_file_bytes(path, bytes, timestamp)
        } else {
            node.create_file(path, bytes, timestamp)
        };
        self.verify_gateway_mutation(&authorized.space_id, result)
    }

    pub fn gateway_authorized_mkdir(
        &mut self,
        account: &str,
        target: &str,
        expected: &SnapshotId,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let (id, authorized, manifest) =
            self.gateway_mutation_baseline(account, target, expected)?;
        let path = authorized
            .path
            .as_ref()
            .expect("checked original entry path");
        if manifest.entries.values().any(|entry| &entry.path == path) {
            return Err(ReconcileError::Invariant(
                "gateway MKCOL destination already exists in original baseline",
            ));
        }
        let result = self
            .nodes
            .get_mut(&id)
            .expect("checked fresh node")
            .create_directory(path, timestamp);
        self.verify_gateway_mutation(&authorized.space_id, result)
    }

    pub fn gateway_authorized_delete(
        &mut self,
        account: &str,
        target: &str,
        expected: &SnapshotId,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let (id, authorized, manifest) =
            self.gateway_mutation_baseline(account, target, expected)?;
        let path = authorized
            .path
            .as_ref()
            .expect("checked original entry path");
        let entry = manifest
            .entries
            .values()
            .find(|entry| &entry.path == path)
            .ok_or(ReconcileError::Invariant(
                "gateway DELETE original entry absent",
            ))?;
        if entry.kind == EntryKind::Directory && has_children(&manifest, path) {
            return Err(ReconcileError::Invariant(
                "recovered recursive collection deletion requires its complete native contract",
            ));
        }
        let node = self.nodes.get_mut(&id).expect("checked fresh node");
        let result = match entry.kind {
            EntryKind::File => node.delete_file(path, timestamp),
            EntryKind::Directory => node.delete_created_empty_directory(path, timestamp),
        };
        self.verify_gateway_mutation(&authorized.space_id, result)
    }

    pub fn gateway_authorized_copy(
        &mut self,
        account: &str,
        source_target: &str,
        destination_target: &str,
        expected: &SnapshotId,
        overwrite: bool,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let (id, source, manifest) =
            self.gateway_mutation_baseline(account, source_target, expected)?;
        let (_, destination, _) =
            self.gateway_mutation_baseline(account, destination_target, expected)?;
        verify_same_export(&source, &destination)?;
        let source_path = source.path.as_ref().expect("checked source path");
        let destination_path = destination.path.as_ref().expect("checked destination path");
        let source_entry = manifest
            .entries
            .values()
            .find(|entry| &entry.path == source_path)
            .ok_or(ReconcileError::Invariant(
                "gateway COPY original source absent",
            ))?;
        if source_entry.kind != EntryKind::File {
            return Err(ReconcileError::Invariant(
                "recovered collection copy requires its complete native contract",
            ));
        }
        let destination_entry = manifest
            .entries
            .values()
            .find(|entry| &entry.path == destination_path);
        if destination_entry.is_some_and(|entry| !overwrite || entry.kind != EntryKind::File) {
            return Err(ReconcileError::Invariant(
                "gateway COPY original destination precondition refused",
            ));
        }
        let node = self.nodes.get_mut(&id).expect("checked fresh node");
        let result = if destination_entry.is_some() {
            node.replace_file(destination_path, source_path, timestamp)
        } else {
            node.copy_file(destination_path, source_path, timestamp)
        };
        self.verify_gateway_mutation(&source.space_id, result)
    }

    pub fn gateway_authorized_move(
        &mut self,
        account: &str,
        source_target: &str,
        destination_target: &str,
        expected: &SnapshotId,
        timestamp: u64,
    ) -> Result<SnapshotId> {
        let (id, source, manifest) =
            self.gateway_mutation_baseline(account, source_target, expected)?;
        let (_, destination, _) =
            self.gateway_mutation_baseline(account, destination_target, expected)?;
        verify_same_export(&source, &destination)?;
        let source_path = source.path.as_ref().expect("checked source path");
        let destination_path = destination.path.as_ref().expect("checked destination path");
        let entry = manifest
            .entries
            .values()
            .find(|entry| &entry.path == source_path)
            .ok_or(ReconcileError::Invariant(
                "gateway MOVE original source absent",
            ))?;
        if manifest
            .entries
            .values()
            .any(|entry| &entry.path == destination_path)
            || entry.kind == EntryKind::Directory && has_children(&manifest, source_path)
        {
            return Err(ReconcileError::Invariant(
                "recovered replacing or recursive MOVE requires its complete native contract",
            ));
        }
        let node = self.nodes.get_mut(&id).expect("checked fresh node");
        let result = match entry.kind {
            EntryKind::File => node.move_file(source_path, destination_path, timestamp),
            EntryKind::Directory => {
                node.move_created_empty_directory(source_path, destination_path, timestamp)
            }
        };
        self.verify_gateway_mutation(&source.space_id, result)
    }
}

fn has_children(manifest: &Manifest, path: &PortablePath) -> bool {
    let prefix = format!("{}/", path.as_str());
    manifest
        .entries
        .values()
        .any(|entry| entry.path.as_str().starts_with(&prefix))
}

fn verify_same_export(
    source: &AuthorizedWebDavPath,
    destination: &AuthorizedWebDavPath,
) -> Result<()> {
    if source.listener_id != destination.listener_id
        || source.export_name != destination.export_name
        || source.space_id != destination.space_id
        || source.path == destination.path
    {
        return Err(ReconcileError::Invariant(
            "gateway mutation requires distinct paths in the same original export",
        ));
    }
    Ok(())
}
