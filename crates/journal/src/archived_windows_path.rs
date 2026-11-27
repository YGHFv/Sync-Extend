//! Host-independent paths captured by the Windows native DAV producer.
//! This is a lexical description only: it never opens or canonicalizes a path.
use crate::{JournalError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ArchivedWindowsPath {
    root: String,
    parts: Vec<String>,
}

fn invalid() -> JournalError {
    JournalError::Invariant("exact archived Windows absolute path")
}

impl ArchivedWindowsPath {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value.is_empty() || value.len() > 32_768 || value.contains('\0') {
            return Err(invalid());
        }
        // The original native adapter admits fixed local volumes. UNC shares,
        // device namespaces, drive-relative paths and rooted-relative paths
        // cannot be descriptions from that adapter.
        let tail = value.strip_prefix(r"\\?\").unwrap_or(value);
        let root_len = if tail.as_bytes().get(0).is_some_and(u8::is_ascii_alphabetic)
            && tail.as_bytes().get(1..3) == Some(b":\\")
        {
            3
        } else if let Some(guid) = tail.strip_prefix("Volume{") {
            let end = guid.find('}').ok_or_else(invalid)?;
            let id = &guid[..end];
            if !value.starts_with(r"\\?\")
                || id.len() != 36
                || !id.bytes().enumerate().all(|(i, byte)| {
                    if [8, 13, 18, 23].contains(&i) { byte == b'-' }
                    else { byte.is_ascii_hexdigit() }
                })
                || guid.as_bytes().get(end + 1) != Some(&b'\\')
            {
                return Err(invalid());
            }
            7 + end + 2
        } else {
            return Err(invalid());
        };
        let prefix_len = value.len() - tail.len();
        let boundary = prefix_len + root_len;
        let root = value[..boundary].to_owned();
        let rest = &value[boundary..];
        let parts = if rest.is_empty() { Vec::new() } else {
            rest.split('\\').map(|part| {
                if part.is_empty() || part == "." || part == ".."
                    || part.bytes().any(|byte| matches!(byte, b'/' | b':' | b'\0'))
                {
                    return Err(invalid());
                }
                Ok(part.to_owned())
            }).collect::<Result<Vec<_>>>()?
        };
        Ok(Self { root, parts })
    }

    pub(crate) fn parent(&self) -> Option<Self> {
        if self.parts.is_empty() { return None; }
        let mut parent = self.clone();
        parent.parts.pop();
        Some(parent)
    }

    pub(crate) fn starts_with(&self, parent: &Self) -> bool {
        self.root == parent.root && self.parts.starts_with(&parent.parts)
    }

    pub(crate) fn file_name(&self) -> Option<&str> {
        self.parts.last().map(String::as_str)
    }

    pub(crate) fn join_portable(&self, value: &str) -> Result<Self> {
        let mut joined = self.clone();
        for part in value.split('/') {
            if part.is_empty() || part == "." || part == ".."
                || part.bytes().any(|byte| matches!(byte, b'\\' | b':' | b'\0'))
            {
                return Err(invalid());
            }
            joined.parts.push(part.to_owned());
        }
        Ok(joined)
    }

    pub(crate) fn ancestor_count(&self) -> usize {
        self.parts.len() + 1
    }
}
