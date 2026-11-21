//! Independent ordinary control-root gates. Marker presence can only refuse.
use super::budget_error;
use crate::Result;
use std::path::Path;

pub(crate) fn require_platform() -> Result<()> {
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    {
        Ok(())
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
    {
        Err(budget_error(
            "application-frame ledger requires a certified platform",
        ))
    }
}

pub(crate) fn require_readonly_platform() -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // This precedes policy/ledger/root IO. The unpublished N05b reader is
        // deliberately not an authority for this separate ledger.
        Err(budget_error(
            "read-only application-frame status is Unsupported on this platform",
        ))
    }
}

pub(crate) fn require_legacy_absent(control_root: &Path) -> Result<()> {
    let path = super::TransportAttemptPolicy::fixed_ledger_path(control_root);
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(budget_error(
            "initialized application-frame ledger requires its explicit policy",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(budget_error(error)),
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::{SignedTransportAttemptPolicy, TransportAttemptPolicy};
    use rusqlite::Connection;
    use std::{
        fs::{File, OpenOptions},
        os::windows::fs::OpenOptionsExt,
        path::PathBuf,
    };
    use sync_extend_platform_fs::{FileKey, LockedDirectory};

    pub(crate) struct WindowsRoots {
        data: Vec<(PathBuf, LockedDirectory)>,
        control: Vec<(PathBuf, LockedDirectory)>,
        control_path: PathBuf,
    }

    fn lineage(path: &Path) -> Result<Vec<(PathBuf, LockedDirectory)>> {
        let mut held = Vec::new();
        for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let directory = LockedDirectory::open(ancestor).map_err(budget_error)?;
            if !directory.matches_path(ancestor).map_err(budget_error)? {
                return Err(budget_error("control directory original slot differs"));
            }
            held.push((ancestor.to_path_buf(), directory));
        }
        Ok(held)
    }

    fn marker(path: &Path) -> Result<bool> {
        match std::fs::symlink_metadata(path.join("journal.sqlite.metadata-owner")) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(budget_error(error)),
        }
    }

    impl WindowsRoots {
        pub(crate) fn hold(data_root: &Path, control_root: &Path) -> Result<Self> {
            let result = Self {
                data: lineage(data_root)?,
                control: lineage(control_root)?,
                control_path: control_root.to_path_buf(),
            };
            result.verify()?;
            Ok(result)
        }

        fn parent(&self) -> Result<&LockedDirectory> {
            self.control
                .last()
                .map(|(_, directory)| directory)
                .ok_or_else(|| budget_error("retained control parent absent"))
        }

        pub(crate) fn verify(&self) -> Result<()> {
            for (path, directory) in self.data.iter().chain(&self.control) {
                if !directory.matches_path(path).map_err(budget_error)? {
                    return Err(budget_error("retained data/control directory was replaced"));
                }
            }
            let parent = self.parent()?;
            parent
                .require_local_ntfs(&self.control_path)
                .map_err(budget_error)?;
            parent
                .require_current_user_private()
                .map_err(budget_error)?;
            for (path, _) in &self.control {
                if marker(path)? {
                    return Err(budget_error(
                        "control root cannot be owned metadata or its subtree",
                    ));
                }
            }
            let (data_path, data) = self
                .data
                .last()
                .ok_or_else(|| budget_error("retained data directory absent"))?;
            if marker(data_path)? {
                let original = data.key().map_err(budget_error)?;
                for (_, directory) in &self.control {
                    if directory.key().map_err(budget_error)? == original {
                        return Err(budget_error(
                            "control directory aliases owned data metadata",
                        ));
                    }
                }
            }
            Ok(())
        }
    }

    pub(crate) struct WindowsFiles {
        roots: WindowsRoots,
        path: PathBuf,
        main: File,
        original_key: FileKey,
        wal: Option<(PathBuf, File, FileKey)>,
        maximum: u64,
    }

    fn open_file(path: &Path, writable: bool) -> Result<File> {
        OpenOptions::new()
            .read(true)
            .write(writable)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(path)
            .map_err(budget_error)
    }

    fn verify_slot(file: &File, path: &Path, maximum: u64) -> Result<()> {
        let metadata = file.metadata().map_err(budget_error)?;
        if metadata.len() > maximum
            || !sync_extend_platform_fs::regular_file_matches_path(file, path)
                .map_err(budget_error)?
        {
            return Err(budget_error(
                "control ledger file identity/size/link differs",
            ));
        }
        Ok(())
    }

    impl WindowsFiles {
        pub(crate) fn open(
            roots: WindowsRoots,
            signed: &SignedTransportAttemptPolicy,
            fresh: bool,
        ) -> Result<Self> {
            roots.verify()?;
            let policy = &signed.policy;
            let maximum = policy.max_file_bytes()?;
            let mut wal = None;
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let path = PathBuf::from(format!("{}{suffix}", policy.ledger_path.display()));
                match std::fs::symlink_metadata(&path) {
                    Ok(_) if fresh || matches!(suffix, "-shm" | "-journal") => {
                        return Err(budget_error(
                            "fresh/unsupported ledger sidecar already exists",
                        ));
                    }
                    Ok(_) => {
                        let file = open_file(&path, false)?;
                        verify_slot(&file, &path, maximum)?;
                        if suffix.is_empty() {
                            sync_extend_platform_fs::verify_current_user_private_file(&file)
                                .map_err(budget_error)?;
                        } else {
                            roots
                                .parent()?
                                .verify_current_user_private_child_file(&file)
                                .map_err(budget_error)?;
                            let key = FileKey::from_file(&file).map_err(budget_error)?;
                            wal = Some((path.clone(), file, key));
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(budget_error(error)),
                }
            }
            let original_key = if fresh {
                let creator = roots
                    .parent()?
                    .create_new_current_user_file(super::super::policy::FILE_NAME)
                    .map_err(budget_error)?;
                let original = creator.key().map_err(budget_error)?;
                // SQLite needs a compatible RW open. This is explicitly a new
                // writable state file, not a retained-original readonly claim.
                drop(creator);
                original
            } else {
                let held = open_file(&policy.ledger_path, true)?;
                verify_slot(&held, &policy.ledger_path, maximum)?;
                sync_extend_platform_fs::verify_current_user_private_file(&held)
                    .map_err(budget_error)?;
                FileKey::from_file(&held).map_err(budget_error)?
            };
            let main = open_file(&policy.ledger_path, true)?;
            verify_slot(&main, &policy.ledger_path, maximum)?;
            sync_extend_platform_fs::verify_current_user_private_file(&main)
                .map_err(budget_error)?;
            if FileKey::from_file(&main).map_err(budget_error)? != original_key {
                return Err(budget_error(
                    "fresh main changed across original CREATE handoff",
                ));
            }
            Ok(Self {
                roots,
                path: TransportAttemptPolicy::fixed_ledger_path(&policy.control_root),
                main,
                original_key,
                wal,
                maximum,
            })
        }

        pub(crate) fn verify_main(&self, connection: &Connection) -> Result<()> {
            self.roots.verify()?;
            verify_slot(&self.main, &self.path, self.maximum)?;
            sync_extend_platform_fs::verify_current_user_private_file(&self.main)
                .map_err(budget_error)?;
            if FileKey::from_file(&self.main).map_err(budget_error)? != self.original_key
                || sync_extend_platform_fs::sqlite_main_file_identity(connection)
                    .map_err(budget_error)?
                    != self.original_key
            {
                return Err(budget_error("actual SQLite main HANDLE differs"));
            }
            Ok(())
        }

        pub(crate) fn verify(&mut self, connection: &Connection) -> Result<()> {
            self.verify_main(connection)?;
            for suffix in ["-shm", "-journal"] {
                match std::fs::symlink_metadata(format!("{}{suffix}", self.path.display())) {
                    Ok(_) => {
                        return Err(budget_error("exclusive WAL has no SHM/rollback authority"))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(budget_error(error)),
                }
            }
            let wal_path = PathBuf::from(format!("{}-wal", self.path.display()));
            match std::fs::symlink_metadata(&wal_path) {
                Ok(_) => {
                    if self.wal.is_none() {
                        let file = open_file(&wal_path, false)?;
                        verify_slot(&file, &wal_path, self.maximum)?;
                        self.roots
                            .parent()?
                            .verify_current_user_private_child_file(&file)
                            .map_err(budget_error)?;
                        let key = FileKey::from_file(&file).map_err(budget_error)?;
                        self.wal = Some((wal_path.clone(), file, key));
                    }
                    let (path, file, key) = self.wal.as_ref().expect("retained WAL");
                    verify_slot(file, path, self.maximum)?;
                    self.roots
                        .parent()?
                        .verify_current_user_private_child_file(file)
                        .map_err(budget_error)?;
                    if FileKey::from_file(file).map_err(budget_error)? != *key
                        || sync_extend_platform_fs::sqlite_wal_file_identity(connection)
                            .map_err(budget_error)?
                            != *key
                    {
                        return Err(budget_error("actual SQLite WAL HANDLE differs"));
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && self.wal.is_none() => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(budget_error("retained WAL fixed slot disappeared"));
                }
                Err(error) => return Err(budget_error(error)),
            }
            Ok(())
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::{WindowsFiles, WindowsRoots};
