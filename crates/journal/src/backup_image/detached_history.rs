//! Preserve original history as inert evidence while explicitly mapping client metadata.
//! This distinct image cannot enter the conservative portable native restore API.
use crate::{JournalBackupImage, JournalError, NodeInspectionBounds, Result};
use std::path::{Component, Path, PathBuf};
use sync_extend_core_model::{ContentId, SpaceId};

#[derive(Clone, serde::Serialize)]
pub struct OriginalNodeHistoryMappingEvidence {
    format_version: u32,
    space: SpaceId,
    source_image: ContentId,
    mapped_image: ContentId,
    original_worktree: PathBuf,
    mapped_worktree: PathBuf,
    immutable_history_inventory: ContentId,
    source_rows: usize,
}

impl OriginalNodeHistoryMappingEvidence {
    pub fn source_image(&self) -> &ContentId {
        &self.source_image
    }
    pub fn mapped_image(&self) -> &ContentId {
        &self.mapped_image
    }
    pub fn immutable_history_inventory(&self) -> &ContentId {
        &self.immutable_history_inventory
    }
}

/// Original receipts, native keys, signatures, pins and pending attempts remain
/// values in immutable images. They are never converted to live capabilities.
pub struct DetachedOriginalNodeHistory {
    original: JournalBackupImage,
    mapped: JournalBackupImage,
    evidence: OriginalNodeHistoryMappingEvidence,
}

fn explicit_root(path: &Path) -> Result<&str> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(JournalError::Invariant(
            "explicit normalized history mapping root required",
        ));
    }
    let value = path
        .to_str()
        .ok_or(JournalError::Invariant("history root encoding"))?;
    if value.len() > 32_768 || value.contains('\0') {
        return Err(JournalError::Invariant("history root byte bound"));
    }
    Ok(value)
}

fn inventory_without_root(rows: &[crate::JournalStoredRow]) -> Result<ContentId> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"sync-extend.detached-original-history.v1");
    for row in rows {
        if row.table() != "local_state" || row.primary_key() != ["worktree"] {
            hash.update(row.fingerprint().as_str().as_bytes());
        }
    }
    Ok(ContentId::from_hasher(&hash))
}

impl JournalBackupImage {
    /// A separate audit-only contract preserves every non-root persisted value.
    /// Active histories remain active evidence; this grants no resume, GC,
    /// reference release, cleanup, new native identity or normal Journal access.
    pub fn map_detached_original_history(
        self,
        space: &SpaceId,
        original_worktree: &Path,
        new_worktree: &Path,
        bounds: NodeInspectionBounds,
        max_image_bytes: usize,
        max_combined_image_bytes: usize,
    ) -> Result<DetachedOriginalNodeHistory> {
        let original_value = explicit_root(original_worktree)?;
        let replacement = explicit_root(new_worktree)?;
        super::limit(max_image_bytes)?;
        if self.bytes().len() > max_image_bytes
            || max_combined_image_bytes == 0
            || max_combined_image_bytes > 512 * 1024 * 1024
            || self
                .bytes()
                .len()
                .checked_mul(2)
                .is_none_or(|bytes| bytes > max_combined_image_bytes)
        {
            return Err(JournalError::Invariant(
                "detached original and mapped aggregate image budget",
            ));
        }
        let before = self.with_audited_readonly(space, bounds, |connection| {
            let actual_space: String = connection.query_row(
                "SELECT value FROM main.local_state WHERE key='space_id'",
                [],
                |row| row.get(0),
            )?;
            let actual_root: String = connection.query_row(
                "SELECT value FROM main.local_state WHERE key='worktree'",
                [],
                |row| row.get(0),
            )?;
            if actual_space != space.as_str() || actual_root != original_value {
                return Err(JournalError::Invariant(
                    "detached mapping original client scope differs",
                ));
            }
            crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            }
            .audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )
        })?;
        let history = inventory_without_root(&before.rows)?;
        let mut memory = rusqlite::Connection::open_in_memory()?;
        memory.deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(self.bytes()),
            self.bytes().len(),
            false,
        )?;
        super::readonly::configure_inspection(&mut memory, bounds)?;
        memory.pragma_update(None, "query_only", false)?;
        let transaction = memory.unchecked_transaction()?;
        if transaction.execute(
            "UPDATE main.local_state SET value=?1 WHERE key='worktree' AND value=?2",
            [replacement, original_value],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "detached mapping exact original root update",
            ));
        }
        let after = crate::JournalReadView {
            connection: &memory,
            dav_read_charge_cache: None,
        }
        .audit_original_provenance_capacity(space, bounds.max_entries, bounds.capacity)?;
        if before.rows.len() != after.rows.len() || history != inventory_without_root(&after.rows)?
        {
            return Err(JournalError::Invariant(
                "detached original history inventory changed",
            ));
        }
        let mut changed = 0;
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
                        "detached mapped root exact columns",
                    ));
                }
                changed += 1;
            } else if old != new {
                return Err(JournalError::Invariant(
                    "detached mapping changed immutable history",
                ));
            }
        }
        if changed != 1 {
            return Err(JournalError::Invariant("detached original root row absent"));
        }
        transaction.commit()?;
        let pages: i64 = memory.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let page_size: i64 = memory.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let length = u64::try_from(pages)
            .ok()
            .and_then(|pages| {
                u64::try_from(page_size)
                    .ok()
                    .and_then(|size| pages.checked_mul(size))
            })
            .ok_or(JournalError::Invariant(
                "detached mapped page byte overflow",
            ))?;
        if length > max_image_bytes as u64
            || length
                .checked_add(self.bytes().len() as u64)
                .is_none_or(|bytes| bytes > max_combined_image_bytes as u64)
        {
            return Err(JournalError::Invariant(
                "detached mapped aggregate physical byte budget",
            ));
        }
        let output = memory.serialize(rusqlite::MAIN_DB)?.to_vec();
        let digest = ContentId::hash(&output);
        let mapped = JournalBackupImage::from_current_node_image(
            output,
            digest.as_str(),
            max_image_bytes,
            space,
            bounds,
        )?;
        let evidence = OriginalNodeHistoryMappingEvidence {
            format_version: 1,
            space: space.clone(),
            source_image: ContentId::hash(self.bytes()),
            mapped_image: digest,
            original_worktree: original_worktree.into(),
            mapped_worktree: new_worktree.into(),
            immutable_history_inventory: history,
            source_rows: before.rows.len(),
        };
        Ok(DetachedOriginalNodeHistory {
            original: self,
            mapped,
            evidence,
        })
    }
}

impl DetachedOriginalNodeHistory {
    pub fn evidence(&self) -> &OriginalNodeHistoryMappingEvidence {
        &self.evidence
    }
    /// The complete original source remains available for immutable archival.
    pub fn original_image_bytes(&self) -> &[u8] {
        self.original.bytes()
    }
    /// Borrowed readonly inspection only, using the original audit and budgets.
    pub fn inspect_mapped_history<T>(
        &self,
        bounds: NodeInspectionBounds,
        inspect: impl FnOnce(&rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.mapped
            .with_audited_readonly(&self.evidence.space, bounds, inspect)
    }
}

/// Pending immutable histories cannot update even independent runtime metadata.
/// The desired root is only a separate explicit observation. It admits no
/// access, resume, reference release, cleanup or reconstruction of old owners.
pub struct RetainedOriginalNodeHistory {
    original: JournalBackupImage,
    space: SpaceId,
    original_worktree: PathBuf,
    desired_worktree: PathBuf,
    inventory: ContentId,
}

impl JournalBackupImage {
    pub fn bind_retained_original_history(
        self,
        space: &SpaceId,
        original_worktree: &Path,
        desired_worktree: &Path,
        bounds: NodeInspectionBounds,
    ) -> Result<RetainedOriginalNodeHistory> {
        let original_root = explicit_root(original_worktree)?;
        explicit_root(desired_worktree)?;
        let inventory = self.with_audited_readonly(space, bounds, |connection| {
            let actual: String = connection.query_row(
                "SELECT value FROM main.local_state WHERE key='worktree'",
                [],
                |row| row.get(0),
            )?;
            if actual != original_root {
                return Err(JournalError::Invariant("retained original root differs"));
            }
            let audit = crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            }
            .audit_original_provenance_capacity(
                space,
                bounds.max_entries,
                bounds.capacity,
            )?;
            inventory_without_root(&audit.rows)
        })?;
        Ok(RetainedOriginalNodeHistory {
            original: self,
            space: space.clone(),
            original_worktree: original_worktree.into(),
            desired_worktree: desired_worktree.into(),
            inventory,
        })
    }
}
impl RetainedOriginalNodeHistory {
    pub fn original_image_bytes(&self) -> &[u8] {
        self.original.bytes()
    }
    pub fn original_worktree(&self) -> &Path {
        &self.original_worktree
    }
    pub fn desired_worktree(&self) -> &Path {
        &self.desired_worktree
    }
    pub fn immutable_history_inventory(&self) -> &ContentId {
        &self.inventory
    }
    pub fn inspect_original_history<T>(
        &self,
        bounds: NodeInspectionBounds,
        inspect: impl FnOnce(&rusqlite::Connection) -> Result<T>,
    ) -> Result<T> {
        self.original
            .with_audited_readonly(&self.space, bounds, inspect)
    }
}

/// Observation from the original GC protection predicate, not authority to GC
/// or release a pin. The source digest and explicit content ID remain bound.
#[derive(Clone, serde::Serialize)]
pub struct OriginalHistoryContentReference {
    source_image: ContentId,
    content_id: ContentId,
    protected: bool,
}
impl OriginalHistoryContentReference {
    pub fn source_image(&self) -> &ContentId {
        &self.source_image
    }
    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }
    pub fn protected(&self) -> bool {
        self.protected
    }
}
impl RetainedOriginalNodeHistory {
    pub fn original_read_leases(
        &self,
        bounds: NodeInspectionBounds,
    ) -> Result<Vec<crate::ReadLease>> {
        self.inspect_original_history(bounds, |connection| {
            crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            }
            .read_leases(&self.space)
        })
    }
    /// Read-only bounded explicit content queries reuse the original GC policy.
    /// A released lease can remain snapshot-protected; no release is inferred.
    pub fn observe_original_content_references(
        &self,
        content: &[ContentId],
        bounds: NodeInspectionBounds,
    ) -> Result<Vec<OriginalHistoryContentReference>> {
        if content.len() > bounds.max_entries
            || content
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != content.len()
        {
            return Err(JournalError::Invariant(
                "explicit original content reference inventory",
            ));
        }
        self.inspect_original_history(bounds, |connection| {
            let view = crate::JournalReadView {
                connection,
                dav_read_charge_cache: None,
            };
            let source_image = ContentId::hash(self.original.bytes());
            content
                .iter()
                .map(|content_id| {
                    Ok(OriginalHistoryContentReference {
                        source_image: source_image.clone(),
                        content_id: content_id.clone(),
                        protected: view.gc_protected(content_id)?,
                    })
                })
                .collect()
        })
    }
}

impl RetainedOriginalNodeHistory {
    /// Read original signer proofs under an explicitly approved key. The
    /// original signature domain, operation, sequence and hashes remain exact.
    /// This neither approves a new signer nor creates an applied/native claim.
    pub fn original_signed_provenance(
        &self,
        approved_key: &[u8; 32],
        max_proofs: usize,
        max_bytes: usize,
        bounds: NodeInspectionBounds,
    ) -> Result<Vec<crate::RemotePublicationProof>> {
        if max_proofs == 0
            || max_proofs > bounds.max_entries
            || max_bytes == 0
            || max_bytes > 16 * 1024 * 1024
        {
            return Err(JournalError::Invariant(
                "original signed history explicit bounds",
            ));
        }
        self.inspect_original_history(bounds, |connection| {
            let proofs = crate::original_provenance::audit(connection)?;
            let mut result = Vec::new();
            let mut bytes = 0usize;
            for proof in proofs {
                if proof.public_key != *approved_key {
                    continue;
                }
                if proof.operation.payload.space_id != self.space {
                    return Err(JournalError::Invariant("original signed history space"));
                }
                proof.verify()?;
                bytes = bytes
                    .checked_add(serde_json::to_vec(&proof)?.len())
                    .filter(|bytes| *bytes <= max_bytes)
                    .ok_or(JournalError::Invariant(
                        "original signed history aggregate bytes",
                    ))?;
                if result.len() >= max_proofs {
                    return Err(JournalError::Invariant(
                        "original signed history aggregate count",
                    ));
                }
                result.push(proof);
            }
            Ok(result)
        })
    }
}
