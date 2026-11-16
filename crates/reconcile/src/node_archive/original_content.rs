//! Retain original CREATE read/delete access without a pathname or sharing handoff.
pub(super) trait OriginalContentReader {
    fn reader(&self) -> &std::fs::File;
    fn verify_identity(&self) -> std::io::Result<()>;
}
impl OriginalContentReader for sync_extend_platform_fs::ReleasedOriginalReadFile {
    fn reader(&self) -> &std::fs::File {
        self.reader()
    }
    fn verify_identity(&self) -> std::io::Result<()> {
        self.verify_identity()
    }
}
pub(super) enum OriginalContent {
    Read(sync_extend_platform_fs::ReleasedOriginalReadFile),
    Sealed(sync_extend_platform_fs::SealedOriginalFile),
}
impl OriginalContent {
    pub(super) fn reader(&self) -> &std::fs::File {
        match self {
            Self::Read(file) => file.reader(),
            Self::Sealed(file) => file.reader(),
        }
    }
    pub(super) fn original_key(&self) -> std::io::Result<sync_extend_platform_fs::FileKey> {
        match self {
            Self::Read(file) => file.original_key(),
            Self::Sealed(file) => file.key(),
        }
    }
    pub(super) fn original_parent_key(&self) -> std::io::Result<sync_extend_platform_fs::FileKey> {
        match self {
            Self::Read(file) => file.original_parent_key(),
            Self::Sealed(file) => file.parent_key(),
        }
    }
    pub(super) fn matches_path(&self, path: &std::path::Path) -> std::io::Result<bool> {
        match self {
            Self::Read(file) => file.matches_path(path),
            Self::Sealed(file) => file.matches_path(path),
        }
    }
    pub(super) fn verify_identity(&self) -> std::io::Result<()> {
        match self {
            Self::Read(file) => file.verify_identity(),
            Self::Sealed(file) => file.verify_original(),
        }
    }
}
impl OriginalContentReader for OriginalContent {
    fn reader(&self) -> &std::fs::File {
        self.reader()
    }
    fn verify_identity(&self) -> std::io::Result<()> {
        self.verify_identity()
    }
}
