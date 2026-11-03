use crate::{scan, LocalSpace, ReconcileError, Result};
use std::collections::BTreeMap;
use sync_extend_core_model::{persisted_rename::*, *};

fn epoch() -> ContentId {
    #[cfg(windows)]
    let name = b"local-windows-full-file-id-v1-not-journal-continuity".as_slice();
    #[cfg(unix)]
    let name = b"local-unix-device-inode-v1-not-journal-continuity".as_slice();
    #[cfg(not(any(windows, unix)))]
    let name = b"unsupported-local-identity-v1".as_slice();
    ContentId::hash(name)
}

fn observation(path: &PortablePath, entry: &scan::ScannedEntry) -> RenamePathObservation {
    RenamePathObservation {
        path: path.clone(),
        kind: entry.kind,
        content: entry.content.clone(),
        physical_identity: entry.physical_identity.clone(),
        single_link: entry.single_link,
    }
}

impl LocalSpace {
    fn observation_scope(&self, manifest: &Manifest) -> Result<RenameObservationScope> {
        Ok(RenameObservationScope {
            format_version: FORMAT_VERSION,
            space_id: self.space_id.clone(),
            prior_snapshot: manifest.root()?,
            local_root_identity: self.root_identity.physical.clone(),
            platform_epoch: epoch(),
        })
    }

    pub(crate) fn persisted_rename_candidates(
        &self,
        prior: &Manifest,
        scanned: &scan::Scan,
    ) -> Result<BTreeMap<PortablePath, EntryId>> {
        let Some(map) = self
            .journal
            .rename_observation(&self.space_id, self.limits.max_storage_entries)?
        else {
            return Ok(BTreeMap::new());
        };
        let current: Vec<_> = scanned
            .iter()
            .map(|(path, e)| observation(path, e))
            .collect();
        Ok(plan_persisted_rename(
            prior,
            &map,
            &self.observation_scope(prior)?,
            &current,
            true,
            self.limits.max_scan_entries,
        )?
        .candidates()
        .clone())
    }

    pub(crate) fn scan_observations(
        &self,
        manifest: &Manifest,
        scanned: &scan::Scan,
    ) -> Result<RenameObservationMap> {
        let entries = manifest
            .entries
            .values()
            .map(|entry| {
                let observed = scanned.get(&entry.path).ok_or(ReconcileError::Unstable)?;
                if observed.kind != entry.kind || observed.content != entry.content {
                    return Err(ReconcileError::Unstable);
                }
                Ok(PriorRenameObservation {
                    entry_id: entry.entry_id.clone(),
                    observed: observation(&entry.path, observed),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RenameObservationMap {
            scope: self.observation_scope(manifest)?,
            entries,
        })
    }
}
