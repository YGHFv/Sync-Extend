//! Platform path comparison: exact authority, conservative overlap rejection.
#[cfg(windows)]
use std::path::Component;
use std::path::Path;

// Compare drive and ordinary components the same way for both slash
// spellings and when the original is an extended-length Windows path.
#[cfg(windows)]
pub(crate) fn path_components(value: &Path) -> Vec<String> {
    value
        .components()
        .map(|part| match part {
            Component::Prefix(prefix) => match prefix.kind() {
                std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter) => {
                    format!("{}:", char::from(letter.to_ascii_uppercase()))
                }
                _ => prefix.as_os_str().to_string_lossy().to_uppercase(),
            },
            Component::Normal(name) => name
                .to_string_lossy()
                .trim_end_matches([' ', '.'])
                .to_uppercase(),
            _ => part.as_os_str().to_string_lossy().into_owned(),
        })
        .collect()
}

// Unix paths are case- and trailing-character-sensitive, so components are
// compared exactly rather than folded through Windows rules.
#[cfg(not(windows))]
pub(crate) fn path_components(value: &Path) -> Vec<String> {
    value
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect()
}

pub(crate) fn path_equal(left: &Path, right: &Path) -> bool {
    // Equality grants access to a selected artifact/root. Only the drive
    // prefix has two equivalent spellings; ordinary components must retain
    // their original OsStr bytes. Unicode case expansion and Win32 trailing
    // character trimming are useful for conservative alias rejection, but
    // cannot establish that two selected paths identify the same object.
    #[cfg(windows)]
    {
        let mut left = left.components();
        let mut right = right.components();
        loop {
            match (left.next(), right.next()) {
                (None, None) => return true,
                (Some(Component::Prefix(a)), Some(Component::Prefix(b))) => {
                    use std::path::Prefix::{Disk, VerbatimDisk};
                    match (a.kind(), b.kind()) {
                        (Disk(a) | VerbatimDisk(a), Disk(b) | VerbatimDisk(b))
                            if a.eq_ignore_ascii_case(&b) => {}
                        _ if a == b => {}
                        _ => return false,
                    }
                }
                (Some(a), Some(b)) if a == b => {}
                _ => return false,
            }
        }
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

pub(crate) fn path_within(path: &Path, parent: &Path) -> bool {
    #[cfg(windows)]
    {
        // Used only to reject overlapping roots, never to grant access.
        path_components(path).starts_with(&path_components(parent))
    }
    #[cfg(not(windows))]
    {
        path.starts_with(parent)
    }
}
