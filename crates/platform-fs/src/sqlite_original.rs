use super::verify_regular_file;
#[path = "sqlite_original/bounded_io.rs"]
mod bounded_io;
#[path = "sqlite_original/readonly_vfs.rs"]
mod readonly_vfs;
#[path = "sqlite_original/scoped_vfs.rs"]
mod scoped_vfs;
pub use readonly_vfs::{
    OriginalReadonlySqliteCloseFailure, OriginalReadonlySqliteConnection,
    OriginalReadonlySqliteOpenFailure,
};
#[path = "sqlite_original/uri.rs"]
mod uri;
pub use scoped_vfs::{
    OriginalSqliteConnection, OriginalSqliteOpenFailure, OriginalSqliteQuery,
    OriginalSqliteReadBudget, OriginalSqliteResourceCloseFailure, OriginalSqliteRows,
    OriginalSqliteStatement, OriginalSqliteValue,
};

pub(super) use scoped_vfs::execute_fresh_planned_history;
pub(super) use scoped_vfs::execute_fresh_retention_metadata;
