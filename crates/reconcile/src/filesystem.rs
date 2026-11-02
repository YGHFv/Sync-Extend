use crate::{check_ancestors, ReconcileError, Result};
use same_file::Handle;
use std::{
    fs::{self, File, Metadata},
    path::Path,
};
use sync_extend_cas::is_reparse;
use sync_extend_core_model::ContentId;

pub(crate) struct PathIdentity {
    handle: Handle,
    pub(crate) physical: ContentId,
}

impl PathIdentity {
    pub(crate) fn capture(path: &Path) -> Result<Self> {
        check_ancestors(path)?;
        let handle = Handle::from_path(path)?;
        let physical = physical_identity(path)?;
        let identity = Self { handle, physical };
        identity.verify(path)?;
        Ok(identity)
    }

    pub(crate) fn verify(&self, path: &Path) -> Result<()> {
        check_ancestors(path)?;
        if self.handle != Handle::from_path(path)? || self.physical != physical_identity(path)? {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }
}

pub(crate) struct ObservedFile {
    pub(crate) file: File,
    pub(crate) identity: PathIdentity,
    pub(crate) metadata: Metadata,
}

impl ObservedFile {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        check_ancestors(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(ReconcileError::Invariant(
                "expected a regular non-link file",
            ));
        }
        let physical = physical_identity(path)?;
        let file = File::open(path)?;
        let handle = Handle::from_file(file.try_clone()?)?;
        let observed = Self {
            file,
            identity: PathIdentity { handle, physical },
            metadata,
        };
        observed.verify(path)?;
        Ok(observed)
    }

    pub(crate) fn verify(&self, path: &Path) -> Result<()> {
        self.identity.verify(path)?;
        if !same_metadata(&self.metadata, &self.file.metadata()?)
            || !same_metadata(&self.metadata, &fs::symlink_metadata(path)?)
        {
            return Err(ReconcileError::Unstable);
        }
        Ok(())
    }
}

pub(crate) fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    a.len() == b.len()
        && a.modified()
            .ok()
            .zip(b.modified().ok())
            .is_some_and(|(a, b)| a == b)
        && a.file_type() == b.file_type()
        && !b.file_type().is_symlink()
        && !is_reparse(b)
}

pub(crate) fn physical_identity(path: &Path) -> Result<ContentId> {
    check_ancestors(path)?;
    let id = file_id::get_file_id(path)?;
    let text = match id {
        file_id::FileId::Inode {
            device_id,
            inode_number,
        } => format!("inode:{device_id}:{inode_number}"),
        file_id::FileId::HighRes {
            volume_serial_number,
            file_id,
        } => format!("windows:{volume_serial_number}:{file_id}"),
        file_id::FileId::LowRes { .. } => {
            return Err(ReconcileError::Invariant(
                "high-resolution Windows file identity is unavailable",
            ))
        }
    };
    Ok(ContentId::hash(text.as_bytes()))
}
