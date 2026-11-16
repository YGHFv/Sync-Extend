//! Current manifest comes only from the original bounded audited Journal section.
use super::{ArchiveRole, VerifiedNodeStateArchive};
use crate::{ReconcileError, Result};
use rusqlite::OptionalExtension;
use sync_extend_core_model::{ContentId, Manifest};
use sync_extend_journal::{JournalBackupImage, JournalError, NodeInspectionBounds};

impl VerifiedNodeStateArchive {
    pub(super) fn current_node_manifest(&self, bounds: NodeInspectionBounds) -> Result<Manifest> {
        let bytes =
            self.archive
                .section(&ArchiveRole::Journal)
                .ok_or(ReconcileError::Invariant(
                    "node original Journal section absent",
                ))?;
        let digest = ContentId::hash(bytes);
        let (version, manifest) = JournalBackupImage::inspect_current_node_image(
            bytes,
            digest.as_str(),
            bytes.len(),
            self.space(),
            bounds,
            |database| {
                let rows = database
                    .prepare(
                        "SELECT space_id,snapshot_id FROM main.current_manifests ORDER BY space_id",
                    )?
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let root = match rows.as_slice() {
                    [(space, root)]
                        if space == self.space().as_str()
                            && self
                                .archive
                                .snapshot_id()
                                .is_some_and(|expected| expected.as_str() == root) =>
                    {
                        root
                    }
                    _ => {
                        return Err(JournalError::Invariant(
                            "exact original current node pointer required",
                        ))
                    }
                };
                let stored: Option<String> = database
                    .query_row(
                        "SELECT manifest FROM main.snapshots WHERE snapshot_id=?1 AND space_id=?2
                        AND state='materialized'
                        AND NOT EXISTS(SELECT 1 FROM main.snapshot_prunings WHERE snapshot_id=?1)",
                        rusqlite::params![root, self.space().as_str()],
                        |row| row.get(0),
                    )
                    .optional()?;
                let manifest: Manifest = serde_json::from_str(&stored.ok_or(
                    JournalError::Invariant("original current node snapshot absent or pruned"),
                )?)?;
                manifest.validate()?;
                if manifest.space_id != *self.space() || manifest.root()?.as_str() != root {
                    return Err(JournalError::Invariant(
                        "original current node manifest root differs",
                    ));
                }
                Ok(manifest)
            },
        )?;
        if version != self.schema() {
            return Err(ReconcileError::Invariant(
                "current node original schema differs",
            ));
        }
        Ok(manifest)
    }
}
