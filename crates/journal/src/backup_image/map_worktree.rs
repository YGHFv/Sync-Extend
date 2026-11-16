//! Bounded owned memory image mapping; never changes live Journal or creates a target.
use crate::{JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use std::path::Path;
use sync_extend_core_model::{ContentId, SpaceId};

/// This fragment is registered only after the conservative portability module.
impl JournalBackupImage {
    /// Caller supplies explicit original scope and desired absolute new worktree.
    /// Mapping grants no filesystem permission, creator adoption or restart authority.
    pub fn mapped_portable_worktree_image(
        &self,
        space: &SpaceId,
        original_worktree: &Path,
        new_worktree: &Path,
        bounds: NodeInspectionBounds,
        max_image_bytes: usize,
    ) -> Result<Self> {
        let scope = self.portable_node_scope(space, bounds)?;
        if scope.original_worktree() != original_worktree
            || !new_worktree.is_absolute()
            || new_worktree.as_os_str().is_empty()
        {
            return Err(JournalError::Invariant(
                "exact explicit portable node original/new worktree required",
            ));
        }
        let replacement = new_worktree.to_str().ok_or(JournalError::Invariant(
            "new worktree path encoding unavailable",
        ))?;
        if replacement.len() > 32_768 {
            return Err(JournalError::Invariant("new worktree path byte limit"));
        }
        super::limit(max_image_bytes)?;
        let mut memory = rusqlite::Connection::open_in_memory()?;
        memory.deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(self.bytes()),
            self.bytes().len(),
            false,
        )?;
        super::readonly::configure_inspection(&mut memory, bounds)?;
        // Mutation applies only to the new independent owned memory image.
        memory.pragma_update(None, "query_only", false)?;
        if super::validate(&memory)? != self.schema_version() {
            return Err(JournalError::Invariant(
                "node original mapped source catalog differs",
            ));
        }
        let transaction = memory.unchecked_transaction()?;
        let original_view = crate::JournalReadView {
            connection: &memory,
        };
        let before = original_view.audit_original_provenance_capacity(
            space,
            bounds.max_entries,
            bounds.capacity,
        )?;
        let changed = transaction.execute(
            "UPDATE main.local_state SET value=?1 WHERE key='worktree' AND value=?2",
            [
                replacement,
                original_worktree.to_str().ok_or(JournalError::Invariant(
                    "original worktree path encoding unavailable",
                ))?,
            ],
        )?;
        if changed != 1 {
            return Err(JournalError::Invariant(
                "portable node mapping must change exact original one row",
            ));
        }
        let after = original_view.audit_original_provenance_capacity(
            space,
            bounds.max_entries,
            bounds.capacity,
        )?;
        let mut altered = 0;
        if before.rows.len() != after.rows.len() {
            return Err(JournalError::Invariant(
                "node mapping physical row count differs",
            ));
        }
        for (old, new) in before.rows.iter().zip(&after.rows) {
            if old.table() == "local_state" && old.primary_key() == ["worktree"] {
                let expected = [
                    crate::JournalStorageColumn {
                        name: "key".into(),
                        value: crate::JournalStorageColumnValue::Text("worktree".into()),
                    },
                    crate::JournalStorageColumn {
                        name: "value".into(),
                        value: crate::JournalStorageColumnValue::Text(replacement.into()),
                    },
                ];
                if new.table() != old.table()
                    || new.primary_key() != old.primary_key()
                    || new.columns() != expected
                {
                    return Err(JournalError::Invariant(
                        "node mapping original worktree column differs",
                    ));
                }
                altered += 1;
            } else if old != new {
                return Err(JournalError::Invariant(
                    "node mapping changed another original Journal row",
                ));
            }
        }
        if altered != 1 {
            return Err(JournalError::Invariant(
                "node mapping original worktree key absent",
            ));
        }
        transaction.commit()?;
        let pages: i64 = memory.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size: i64 = memory.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let bytes = u64::try_from(pages)
            .ok()
            .and_then(|pages| {
                u64::try_from(page_size)
                    .ok()
                    .and_then(|page_size| pages.checked_mul(page_size))
            })
            .ok_or(JournalError::Invariant(
                "node mapped image page bound overflow",
            ))?;
        if bytes > max_image_bytes as u64 {
            return Err(JournalError::Invariant(
                "node mapped image exceeds explicit bound",
            ));
        }
        let output = memory.serialize(rusqlite::MAIN_DB)?.to_vec();
        let digest = ContentId::hash(&output);
        let (version, ()) = JournalBackupImage::inspect_current_node_image(
            &output,
            digest.as_str(),
            max_image_bytes,
            space,
            bounds,
            |_| Ok(()),
        )?;
        Ok(Self {
            bytes: output,
            schema_version: version,
            digest: digest.to_string(),
        })
    }
}
