//! Exact original owner/path/snapshot mapping. This conservative contract
//! supports a current-user private DACL and never adopts foreign ACLs.
use super::VerifiedNodeStateArchive;
use crate::{ReconcileError, Result};
use std::path::{Component, Path, PathBuf};
use sync_extend_core_model::{ContentId, PortablePath, SnapshotId};
use sync_extend_journal::NodeInspectionBounds;
use sync_extend_platform_fs::{GuardedReadFile, LockedDirectory};

#[derive(serde::Serialize)]
pub struct ExplicitAclMappingEvidence {
    pub archive_digest: ContentId,
    pub source_snapshot: SnapshotId,
    pub original_path: PathBuf,
    pub mapped_path: PathBuf,
    pub original_object: ContentId,
    pub original_content: ContentId,
    pub owner_digest: ContentId,
    pub acl_digest: ContentId,
    pub mapping_digest: ContentId,
    pub source_handle_verified: bool,
    pub current_user_only: bool,
    pub installed: bool,
}
pub struct ExplicitOriginalAclMapping {
    source: GuardedReadFile,
    ancestors: Vec<LockedDirectory>,
    original: PathBuf,
    owner: Vec<u8>,
    acl: Vec<u8>,
    content: ContentId,
    maximum: u64,
    evidence: ExplicitAclMappingEvidence,
}
fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path.as_os_str().len() <= 32768
        && !path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
}
impl VerifiedNodeStateArchive {
    /// The original path and snapshot must name the exact archived file. A
    /// caller JSON ACL or owner identifier is deliberately not accepted.
    pub fn map_explicit_original_acl(
        &self,
        path: &PortablePath,
        source: &Path,
        snapshot: &SnapshotId,
        mapped_worktree: &Path,
        bounds: NodeInspectionBounds,
        maximum: u64,
    ) -> Result<ExplicitOriginalAclMapping> {
        if !normalized(source)
            || !normalized(mapped_worktree)
            || maximum == 0
            || maximum > 64 * 1024 * 1024
            || source != self.original_worktree().join(path.as_str())
            || mapped_worktree == self.original_worktree()
        {
            return Err(ReconcileError::Invariant(
                "ACL mapping exact original path and new root required",
            ));
        }
        let manifest = self.current_node_manifest(bounds)?;
        if manifest.root()? != *snapshot {
            return Err(ReconcileError::Invariant(
                "ACL mapping original archived snapshot differs",
            ));
        }
        let entry = manifest.entries.values().find(|e| e.path == *path).ok_or(
            ReconcileError::Invariant("ACL mapping original archived path absent"),
        )?;
        let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
            "ACL mapping requires original regular-file snapshot",
        ))?;
        if content.length > maximum {
            return Err(ReconcileError::ResourceLimit(
                "ACL mapping original snapshot byte bound",
            ));
        }
        let ancestors = source
            .parent()
            .ok_or(ReconcileError::Invariant("ACL mapping original parent"))?
            .ancestors()
            .filter(|p| p.is_absolute())
            .map(LockedDirectory::open)
            .collect::<std::io::Result<Vec<_>>>()?;
        let file = GuardedReadFile::open(source)?;
        file.verify_single_link()?;
        let (owner, acl) =
            sync_extend_platform_fs::capture_current_user_private_acl(file.reader())?;
        let mapped_path = mapped_worktree.join(path.as_str());
        let original_object = ContentId::hash(file.key()?.to_string().as_bytes());
        let owner_digest = ContentId::hash(&owner);
        let acl_digest = ContentId::hash(&acl);
        let mapping_digest = ContentId::hash(&serde_json::to_vec(&(
            1u32,
            self.digest(),
            snapshot,
            path,
            source,
            &mapped_path,
            &original_object,
            &content.content_id,
            &owner_digest,
            &acl_digest,
        ))?);
        let result = ExplicitOriginalAclMapping {
            source: file,
            ancestors,
            original: source.to_owned(),
            owner,
            acl,
            content: content.content_id.clone(),
            maximum,
            evidence: ExplicitAclMappingEvidence {
                archive_digest: self.digest().clone(),
                source_snapshot: snapshot.clone(),
                original_path: source.to_owned(),
                mapped_path,
                original_object,
                original_content: content.content_id.clone(),
                owner_digest,
                acl_digest,
                mapping_digest,
                source_handle_verified: true,
                current_user_only: true,
                installed: false,
            },
        };
        result.verify()?;
        Ok(result)
    }
}
impl ExplicitOriginalAclMapping {
    pub fn verify(&self) -> Result<()> {
        self.source.verify_single_link()?;
        if !sync_extend_platform_fs::regular_file_matches_path(
            self.source.reader(),
            &self.original,
        )? || ContentId::hash(self.source.key()?.to_string().as_bytes())
            != self.evidence.original_object
            || self.ancestors.is_empty()
        {
            return Err(ReconcileError::Invariant(
                "ACL mapping original held source identity changed",
            ));
        }
        use std::os::windows::fs::FileExt;
        let file = self.source.reader();
        let length = file.metadata()?.len();
        if length > self.maximum {
            return Err(ReconcileError::ResourceLimit(
                "ACL original stable content budget",
            ));
        }
        let mut bytes = vec![0; length as usize];
        let mut offset = 0;
        while offset < bytes.len() {
            let n = file.seek_read(&mut bytes[offset..], offset as u64)?;
            if n == 0 {
                return Err(ReconcileError::Invariant(
                    "ACL original stable snapshot bytes",
                ));
            }
            offset += n;
        }
        if ContentId::hash(&bytes) != self.content
            || sync_extend_platform_fs::capture_current_user_private_acl(file)?
                != (self.owner.clone(), self.acl.clone())
        {
            return Err(ReconcileError::Invariant(
                "ACL original owner snapshot content changed",
            ));
        }
        Ok(())
    }
    pub fn evidence(&self) -> &ExplicitAclMappingEvidence {
        &self.evidence
    }
}
