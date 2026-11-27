//! Current-namespace Unix originals, separate from private ext4 storage authority.
//! Directory acquisition and actual O_EXCL file creation have distinct types.
mod namespace;
mod originals;
mod sealed;
pub use sealed::{SealedUnixNativeFile, UnixNativeFileSealFailure};
mod sqlite;
pub use namespace::{OriginalUnixNamespace, OriginalUnixNamespaceCloseFailure};
pub use originals::{
    AcquiredUnixChildDirectory, AcquiredUnixChildDirectoryFailure, FailedUnixNativeFileCreation,
    FreshUnixNativeFile, FreshUnixNativeFileFailure, OriginalUnixCasSentinel,
    OriginalUnixNativeRoot, OriginalUnixWriterLock,
};
pub use sqlite::{
    FreshUnixNativeSqliteIo, FreshUnixNativeSqliteIoFailure, FreshUnixSqliteOpenScope,
    OriginalUnixSqliteSessionBinding, OriginalUnixSqliteSessionLoan,
};
