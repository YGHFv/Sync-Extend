//! Initial owner objects exist only after actual CREATE under original held parent.
use super::receipt_protocol::{ReceiptEvidence, ReceiptScope};
use crate::{JournalError, Result};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{ContentId, tree_restore_identity::TreeNativeIdentity};
use sync_extend_platform_fs::{
    FileKey, LockedDirectory, LockedDirectoryMutation, OwnedFileCreation, SealedOriginalFile,
};

pub(super) enum Marker {
    Created(OwnedFileCreation),
    Written(OwnedFileCreation),
    Sealed(SealedOriginalFile),
}

pub(super) struct InitialNativeOwner {
    root: PathBuf,
    scope: ReceiptScope,
    pub staging: Option<LockedDirectoryMutation>,
    pub owner: Option<LockedDirectoryMutation>,
    marker: Option<Marker>,
}

fn invalid() -> JournalError {
    JournalError::Invariant("original held initial DAV owner lineage")
}
fn identity(key: FileKey) -> TreeNativeIdentity {
    TreeNativeIdentity {
        volume_serial: key.volume,
        file_id: format!("{:032x}", key.id),
    }
}

impl InitialNativeOwner {
    pub(super) fn new(root: &Path, scope: &ReceiptScope) -> Self {
        Self {
            root: root.into(),
            scope: scope.clone(),
            staging: None,
            owner: None,
            marker: None,
        }
    }
    pub(super) fn observe_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        self.verify()?;
        self.observe_marker_file(path)
    }
    pub(super) fn observe_file_with_collections(
        &self,
        path: &Path,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        self.verify_with_collections(collections)?;
        self.observe_marker_file(path)
    }
    fn observe_marker_file(
        &self,
        path: &Path,
    ) -> Result<Option<crate::NativePublicationFileObservation>> {
        let expected = self
            .root
            .join(".sync-tmp")
            .join(self.owner_component())
            .join("owner-marker");
        let ordinary = |path: &Path| {
            path.to_str()
                .and_then(|value| value.strip_prefix(r"\\?\"))
                .map(Path::new)
                .unwrap_or(path)
                .to_owned()
        };
        if ordinary(path) != ordinary(&expected) {
            return Ok(None);
        }
        let reader = match self.marker.as_ref().ok_or_else(invalid)? {
            Marker::Created(marker) | Marker::Written(marker) => marker.reader(),
            Marker::Sealed(marker) => marker.reader(),
        };
        if !sync_extend_platform_fs::regular_file_matches_path(reader, path)? {
            return Err(invalid());
        }
        let key = FileKey::from_file(reader)?;
        Ok(Some(crate::NativePublicationFileObservation {
            metadata: reader.metadata()?,
            physical_identity: ContentId::hash(
                format!("windows:{}:{}", key.volume, key.id).as_bytes(),
            ),
            content: None,
        }))
    }
    fn owner_component(&self) -> String {
        format!("dav-{}.owner", self.scope.transaction_id)
    }
    fn marker_bytes(&self) -> Vec<u8> {
        format!(
            "{}:{}",
            self.scope.transaction_id, self.scope.description_hash
        )
        .into_bytes()
    }
    pub(super) fn staging_intent(&self, parent: &LockedDirectory) -> Result<ReceiptEvidence> {
        if self.staging.is_some() || !parent.matches_path(&self.root)? {
            return Err(invalid());
        }
        Ok(ReceiptEvidence::DirectoryIntent {
            parent: identity(parent.key()?),
            component: ".sync-tmp".into(),
        })
    }
    pub(super) fn create_staging(&mut self, parent: &LockedDirectory) -> Result<ReceiptEvidence> {
        if self.staging.is_some() {
            return Err(invalid());
        }
        let held = parent.create_new_staging_directory()?;
        let proof = held.original_creation()?;
        let evidence = ReceiptEvidence::DirectoryCreated {
            parent: identity(proof.parent_key()?),
            original: identity(proof.key()?),
            component: proof.created_component().into(),
        };
        self.staging = Some(held);
        Ok(evidence)
    }
    pub(super) fn owner_intent(&self) -> Result<ReceiptEvidence> {
        if self.owner.is_some() {
            return Err(invalid());
        }
        Ok(ReceiptEvidence::DirectoryIntent {
            parent: identity(self.staging.as_ref().ok_or_else(invalid)?.key()?),
            component: self.owner_component(),
        })
    }
    pub(super) fn create_owner(&mut self) -> Result<ReceiptEvidence> {
        if self.owner.is_some() {
            return Err(invalid());
        }
        let held = self
            .staging
            .as_ref()
            .ok_or_else(invalid)?
            .create_new_publication_directory(&self.owner_component())?;
        let proof = held.original_creation()?;
        let evidence = ReceiptEvidence::DirectoryCreated {
            parent: identity(proof.parent_key()?),
            original: identity(proof.key()?),
            component: proof.created_component().into(),
        };
        self.owner = Some(held);
        Ok(evidence)
    }
    pub(super) fn marker_intent(&self) -> Result<ReceiptEvidence> {
        if self.marker.is_some() {
            return Err(invalid());
        }
        let bytes = self.marker_bytes();
        Ok(ReceiptEvidence::MarkerIntent {
            parent: identity(self.owner.as_ref().ok_or_else(invalid)?.key()?),
            component: "owner-marker".into(),
            content_hash: ContentId::hash(&bytes),
            length: bytes.len() as u64,
        })
    }
    pub(super) fn create_marker(&mut self) -> Result<ReceiptEvidence> {
        if self.marker.is_some() {
            return Err(invalid());
        }
        let bytes = Vec::<u8>::new();
        let held = self
            .owner
            .as_ref()
            .ok_or_else(invalid)?
            .create_new_file("owner-marker")?;
        let proof = held.original_creation()?;
        let evidence = ReceiptEvidence::MarkerCreated {
            parent: identity(proof.parent_key()?),
            original: identity(proof.key()?),
            component: proof.created_component().into(),
            content_hash: ContentId::hash(&bytes),
            length: bytes.len() as u64,
        };
        // Keep the exact writer private; never export it to external code.
        self.marker = Some(Marker::Created(held));
        Ok(evidence)
    }
    pub(super) fn write_intent(&self) -> Result<ReceiptEvidence> {
        let Some(Marker::Created(marker)) = &self.marker else {
            return Err(invalid());
        };
        let proof = marker.original_creation()?;
        let bytes = self.marker_bytes();
        Ok(ReceiptEvidence::MarkerWrite {
            parent: identity(proof.parent_key()?),
            original: identity(proof.key()?),
            component: proof.created_component().into(),
            content_hash: ContentId::hash(&bytes),
            length: bytes.len() as u64,
        })
    }
    pub(super) fn write_marker(&mut self) -> Result<ReceiptEvidence> {
        let Some(Marker::Created(mut marker)) = self.marker.take() else {
            return Err(invalid());
        };
        let bytes = self.marker_bytes();
        marker.writer().write_all(&bytes)?;
        super::checkpoint("webdav_marker_bytes_written");
        marker.writer().sync_all()?;
        super::checkpoint("webdav_marker_bytes_synced");
        let proof = marker.original_creation()?;
        let evidence = ReceiptEvidence::MarkerWrite {
            parent: identity(proof.parent_key()?),
            original: identity(proof.key()?),
            component: proof.created_component().into(),
            content_hash: ContentId::hash(&bytes),
            length: bytes.len() as u64,
        };
        self.marker = Some(Marker::Written(marker));
        Ok(evidence)
    }
    pub(super) fn close_intent(&self) -> Result<ReceiptEvidence> {
        let Some(Marker::Written(marker)) = &self.marker else {
            return Err(invalid());
        };
        let proof = marker.original_creation()?;
        let bytes = self.marker_bytes();
        Ok(ReceiptEvidence::MarkerClose {
            parent: identity(proof.parent_key()?),
            original: identity(proof.key()?),
            component: proof.created_component().into(),
            content_hash: ContentId::hash(&bytes),
            length: bytes.len() as u64,
        })
    }
    pub(super) fn seal_marker(&mut self) -> Result<ReceiptEvidence> {
        let Some(Marker::Written(marker)) = self.marker.take() else {
            return Err(invalid());
        };
        let held = marker.seal_original()?;
        let bytes = self.marker_bytes();
        let evidence = ReceiptEvidence::MarkerClose {
            parent: identity(held.parent_key()?),
            original: identity(held.key()?),
            component: held.created_component().into(),
            content_hash: ContentId::hash(&bytes),
            length: bytes.len() as u64,
        };
        self.marker = Some(Marker::Sealed(held));
        Ok(evidence)
    }
    /// Verify exact own private prefix and reject every foreign child.
    pub(super) fn verify(&self) -> Result<()> {
        self.verify_inner(None)
    }
    pub(super) fn retained_handle_count(&self) -> usize {
        (usize::from(self.staging.is_some())
            + usize::from(self.owner.is_some())
            + usize::from(self.marker.is_some()))
            * 2
    }
    pub(super) fn marker_bytes_present(&self) -> Result<u64> {
        let bytes = match &self.marker {
            Some(Marker::Created(marker)) | Some(Marker::Written(marker)) => {
                marker.reader().metadata()?.len()
            }
            Some(Marker::Sealed(marker)) => marker.reader().metadata()?.len(),
            None => 0,
        };
        Ok(bytes)
    }
    pub(super) fn verify_with_collections(
        &self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<()> {
        collections.verify().map_err(|_| invalid())?;
        let members = collections.owner_members(self.marker.is_some());
        self.verify_inner(Some(&members))
    }
    fn verify_inner(
        &self,
        collection_members: Option<&std::collections::BTreeSet<std::ffi::OsString>>,
    ) -> Result<()> {
        let stage_path = self.root.join(".sync-tmp");
        let Some(staging) = &self.staging else {
            match fs::symlink_metadata(&stage_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                _ => return Err(invalid()),
            }
        };
        staging.original_creation()?.verify()?;
        if !staging.matches_path(&stage_path)? {
            return Err(invalid());
        }
        let names = fs::read_dir(&stage_path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let Some(owner) = &self.owner else {
            if !names.is_empty() {
                return Err(invalid());
            }
            return Ok(());
        };
        let component = self.owner_component();
        if names != [std::ffi::OsString::from(&component)] {
            return Err(invalid());
        }
        owner.original_creation()?.verify()?;
        let owner_path = stage_path.join(&component);
        if !owner.matches_path(&owner_path)?
            || owner.original_creation()?.parent_key()? != staging.key()?
        {
            return Err(invalid());
        }
        let names = fs::read_dir(&owner_path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        let Some(marker) = &self.marker else {
            let actual = names.into_iter().collect::<std::collections::BTreeSet<_>>();
            let expected = collection_members.cloned().unwrap_or_default();
            if actual != expected {
                return Err(invalid());
            }
            return Ok(());
        };
        let expected = match collection_members {
            Some(members) => members.clone(),
            None => std::collections::BTreeSet::from([std::ffi::OsString::from("owner-marker")]),
        };
        if names.into_iter().collect::<std::collections::BTreeSet<_>>() != expected {
            return Err(invalid());
        }
        let (reader, parent) = match marker {
            Marker::Created(marker) | Marker::Written(marker) => {
                marker.original_creation()?.verify()?;
                (marker.reader(), marker.original_creation()?.parent_key()?)
            }
            Marker::Sealed(marker) => {
                marker.verify_original()?;
                (marker.reader(), marker.parent_key()?)
            }
        };
        if parent != owner.key()?
            || !sync_extend_platform_fs::regular_file_matches_path(
                reader,
                &owner_path.join("owner-marker"),
            )?
        {
            return Err(invalid());
        }
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader.take(98).read_to_end(&mut bytes)?;
        let expected = match marker {
            Marker::Created(_) => Vec::new(),
            Marker::Written(_) | Marker::Sealed(_) => self.marker_bytes(),
        };
        if bytes != expected {
            return Err(invalid());
        }
        Ok(())
    }
}

impl InitialNativeOwner {
    pub(super) fn marker_removal_intent(
        &self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<ReceiptEvidence> {
        self.verify_with_collections(collections)?;
        let Some(Marker::Sealed(marker)) = &self.marker else {
            return Err(invalid());
        };
        Ok(ReceiptEvidence::InternalRemoval {
            original: identity(marker.key()?),
            parent: identity(marker.parent_key()?),
            component: "owner-marker".into(),
        })
    }
    pub(super) fn remove_marker(
        &mut self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<()> {
        self.verify_with_collections(collections)?;
        let Some(Marker::Sealed(marker)) = self.marker.take() else {
            return Err(invalid());
        };
        let path = self
            .root
            .join(".sync-tmp")
            .join(self.owner_component())
            .join("owner-marker");
        marker.delete_on_close()?;
        super::checkpoint("webdav_cleanup_marker_delete_requested");
        drop(marker);
        super::checkpoint("webdav_cleanup_marker_handle_closed");
        require_absent(&path)?;
        self.verify_with_collections(collections)?;
        super::checkpoint("webdav_cleanup_marker_absence_verified");
        Ok(())
    }
    pub(super) fn owner_removal_intent(
        &self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<ReceiptEvidence> {
        self.verify_with_collections(collections)?;
        if self.marker.is_some() || !collections.owner_members(false).is_empty() {
            return Err(invalid());
        }
        let owner = self.owner.as_ref().ok_or_else(invalid)?;
        let proof = owner.original_creation()?;
        Ok(ReceiptEvidence::InternalRemoval {
            original: identity(proof.key()?),
            parent: identity(proof.parent_key()?),
            component: proof.created_component().into(),
        })
    }
    pub(super) fn remove_owner(
        &mut self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<()> {
        self.owner_removal_intent(collections)?;
        let owner = self.owner.take().ok_or_else(invalid)?;
        let path = self.root.join(".sync-tmp").join(self.owner_component());
        owner.delete_empty_on_close()?;
        super::checkpoint("webdav_cleanup_owner_delete_requested");
        drop(owner);
        super::checkpoint("webdav_cleanup_owner_handle_closed");
        require_absent(&path)?;
        self.verify_with_collections(collections)?;
        super::checkpoint("webdav_cleanup_owner_absence_verified");
        Ok(())
    }
    pub(super) fn staging_removal_intent(
        &self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<ReceiptEvidence> {
        self.verify_with_collections(collections)?;
        if self.owner.is_some() || self.marker.is_some() {
            return Err(invalid());
        }
        let staging = self.staging.as_ref().ok_or_else(invalid)?;
        let proof = staging.original_creation()?;
        Ok(ReceiptEvidence::InternalRemoval {
            original: identity(proof.key()?),
            parent: identity(proof.parent_key()?),
            component: proof.created_component().into(),
        })
    }
    pub(super) fn remove_staging(
        &mut self,
        collections: &super::held_collections::HeldCollections,
    ) -> Result<()> {
        self.staging_removal_intent(collections)?;
        let staging = self.staging.take().ok_or_else(invalid)?;
        staging.delete_empty_on_close()?;
        super::checkpoint("webdav_cleanup_staging_delete_requested");
        drop(staging);
        super::checkpoint("webdav_cleanup_staging_handle_closed");
        require_absent(&self.root.join(".sync-tmp"))?;
        self.verify_with_collections(collections)?;
        super::checkpoint("webdav_cleanup_staging_absence_verified");
        Ok(())
    }
}
fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3)) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(invalid()),
    }
}
