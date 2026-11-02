use crate::{check_ancestors, fault::checkpoint, now_ms, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    path::Path,
};
use sync_extend_cas::sync_directory;
use sync_extend_core_model::*;
use sync_extend_journal::{read_lease_expiry, ReadLease, ReadLeaseIntent};

#[derive(Serialize)]
pub struct LeasedExportResult {
    pub lease_id: EntryId,
    pub snapshot_id: SnapshotId,
    pub bytes: u64,
    pub local_export_complete: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub fn read_leases(&self) -> Result<Vec<ReadLease>> {
        self.verify_root()?;
        Ok(self
            .journal
            .read_leases(&self.space_id, self.limits.max_storage_entries)?)
    }

    pub fn acquire_read_lease(
        &mut self,
        snapshot: &SnapshotId,
        path: &PortablePath,
        ttl_secs: u64,
    ) -> Result<ReadLease> {
        self.verify_root()?;
        self.journal
            .check_storage_metadata_limit(self.limits.max_storage_entries)?;
        read_lease_expiry(now_ms()?, ttl_secs)?;
        let manifest = self.journal.snapshot(&self.space_id, snapshot)?;
        let entry = manifest
            .entries
            .values()
            .find(|e| &e.path == path)
            .ok_or(ReconcileError::Invariant("read lease file not in snapshot"))?;
        let content = entry.content.as_ref().ok_or(ReconcileError::Invariant(
            "read lease requires a regular file",
        ))?;
        self.check_read_lease_limits(content)?;
        self.cas.verify(content)?;
        checkpoint("before_read_lease_acquire");
        let now = now_ms()?;
        let expires = read_lease_expiry(now, ttl_secs)?;
        let intent = ReadLeaseIntent {
            format_version: FORMAT_VERSION,
            lease_id: EntryId::random()?,
            space_id: self.space_id.clone(),
            snapshot_id: snapshot.clone(),
            entry: entry.clone(),
            created_at_ms: now,
            initial_expires_at_ms: expires,
        };
        let lease = self
            .journal
            .acquire_read_lease(&intent, self.limits.max_storage_entries)?;
        checkpoint("after_read_lease_acquire");
        Ok(lease)
    }

    pub fn renew_read_lease(&mut self, id: &EntryId, ttl_secs: u64) -> Result<ReadLease> {
        self.verify_root()?;
        checkpoint("before_read_lease_renew");
        let lease = self.journal.renew_read_lease(
            &self.space_id,
            id,
            now_ms()?,
            ttl_secs,
            self.limits.max_storage_entries,
        )?;
        checkpoint("after_read_lease_renew");
        Ok(lease)
    }

    pub fn release_read_lease(&mut self, id: &EntryId) -> Result<ReadLease> {
        self.verify_root()?;
        checkpoint("before_read_lease_release");
        let lease = self
            .journal
            .release_read_lease(&self.space_id, id, now_ms()?)?;
        checkpoint("after_read_lease_release");
        Ok(lease)
    }

    pub fn recover_read_leases(&mut self) -> Result<Vec<ReadLease>> {
        self.verify_root()?;
        checkpoint("before_read_lease_expire");
        let leases = self.journal.expire_read_leases(
            &self.space_id,
            now_ms()?,
            self.limits.max_storage_entries,
        )?;
        checkpoint("after_read_lease_expire");
        Ok(leases)
    }

    pub fn export_leased(&mut self, id: &EntryId, output: &Path) -> Result<LeasedExportResult> {
        self.verify_root()?;
        check_ancestors(output)?;
        let parent = fs::canonicalize(output.parent().ok_or(ReconcileError::Invariant(
            "leased export requires an external parent",
        ))?)?;
        if parent.starts_with(&self.worktree) || parent.starts_with(&self.data_dir) {
            return Err(ReconcileError::Invariant(
                "leased export must be outside worktree and data",
            ));
        }
        let name =
            output
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ReconcileError::Invariant(
                    "leased export requires a UTF-8 filename",
                ))?;
        PortablePath::new(name)?;
        let output = parent.join(name);
        #[cfg(windows)]
        let _parents = crate::guarded_mutation::directory_chain(&parent)?;
        let parent_identity = crate::filesystem::PathIdentity::capture(&parent)?;
        checkpoint("before_leased_read");
        let lease = self.journal.admit_leased_read(
            &self.space_id,
            id,
            now_ms()?,
            self.limits.max_storage_entries,
        )?;
        let content = lease
            .intent
            .entry
            .content
            .as_ref()
            .ok_or(ReconcileError::Invariant("read lease content missing"))?;
        self.check_read_lease_limits(content)?;
        self.cas.verify(content)?;
        checkpoint("after_leased_read_admission");
        parent_identity.verify(&parent)?;
        check_ancestors(&output)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.share_mode(0);
        }
        let mut file = options.open(&output)?;
        checkpoint("after_leased_export_create");
        self.cas.write_file(content, &mut file)?;
        file.sync_all()?;
        parent_identity.verify(&parent)?;
        sync_directory(&parent)?;
        checkpoint("after_leased_export");
        Ok(LeasedExportResult {
            lease_id: id.clone(),
            snapshot_id: lease.intent.snapshot_id,
            bytes: content.length,
            local_export_complete: true,
            remote_backup_complete: false,
        })
    }

    fn check_read_lease_limits(&self, content: &FileManifest) -> Result<()> {
        if content.length > self.limits.max_file_bytes
            || content.chunks.len() > self.limits.max_scan_chunks
        {
            return Err(ReconcileError::ResourceLimit("leased read content budget"));
        }
        Ok(())
    }
}
