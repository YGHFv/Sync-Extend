//! Bounded ordinary configuration reads, with exact guarded Windows file handles.
#[cfg(windows)]
use std::io;
use std::{
    fs,
    io::Read,
    path::{Component, Path},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    if maximum == 0
        || maximum > sync_extend_transport::MAX_CONTROL_BYTES
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("exact absolute bounded configuration path required".into());
    }
    #[cfg(windows)]
    let _parents = path
        .parent()
        .ok_or_else(|| io::Error::other("configuration parent required"))?
        .ancestors()
        .filter(|ancestor| ancestor.is_absolute())
        .map(sync_extend_platform_fs::LockedDirectory::open)
        .collect::<io::Result<Vec<_>>>()?;
    #[cfg(unix)]
    for ancestor in path.ancestors() {
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err("configuration symlink path refused".into());
        }
    }
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > maximum as u64 {
        return Err("regular bounded configuration file required".into());
    }
    #[cfg(windows)]
    let held = sync_extend_platform_fs::GuardedReadFile::open(path)?;
    #[cfg(windows)]
    let file = held.reader();
    #[cfg(not(windows))]
    let held = fs::File::open(path)?;
    #[cfg(not(windows))]
    let file = &held;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() > maximum as u64 {
        return Err("opened configuration file exceeds bound".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.mode() & 0o077 != 0
            || opened.nlink() != 1
            || before.dev() != opened.dev()
            || before.ino() != opened.ino()
        {
            return Err("private single-link unchanged configuration file required".into());
        }
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("configuration file grew beyond bound".into());
    }
    #[cfg(windows)]
    held.verify_single_link()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = fs::symlink_metadata(path)?;
        let retained = file.metadata()?;
        if !after.is_file()
            || after.file_type().is_symlink()
            || after.dev() != opened.dev()
            || after.ino() != opened.ino()
            || retained.nlink() != 1
            || retained.len() != opened.len()
            || retained.mtime() != opened.mtime()
            || retained.mtime_nsec() != opened.mtime_nsec()
            || retained.ctime() != opened.ctime()
            || retained.ctime_nsec() != opened.ctime_nsec()
        {
            return Err("configuration file changed while read".into());
        }
    }
    Ok(bytes)
}
