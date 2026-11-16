//! Exact local SQLite URI with share-zero original-main open and no CREATE.
use std::{
    io,
    path::{Component, Path},
};
pub(super) fn original_sqlite_uri(path: &Path) -> io::Result<String> {
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::other("SQLite local path encoding"))?;
    if !path.is_absolute()
        || value.len() > 4096
        || value.starts_with("\\\\")
        || value.as_bytes().get(1) != Some(&b':')
        || !value.as_bytes()[0].is_ascii_alphabetic()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(io::Error::other(
            "explicit normalized local drive SQLite path required",
        ));
    }
    let mut output = String::from("file:/");
    for byte in value.replace('\\', "/").bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(output, "%{byte:02X}").map_err(|_| io::Error::other("SQLite URI encoding"))?;
        }
    }
    output.push_str("?mode=rw&exclusive=1");
    Ok(output)
}
