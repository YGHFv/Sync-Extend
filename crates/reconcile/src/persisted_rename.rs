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
        local_metadata: entry.metadata.clone(),
    }
}

impl LocalSpace {
    /// Retain immutable logical metadata only for a physically bound local
    /// observation whose supported projection is still present. Content equality
    /// alone cannot make a same-byte replacement inherit the remote metadata.
    pub(crate) fn scan_with_logical_metadata(
        &self,
        prior: &Manifest,
        scanned: &scan::Scan,
    ) -> Result<(scan::Scan, std::collections::BTreeSet<EntryId>)> {
        let mut result = scanned.clone();
        let mut replacements = std::collections::BTreeSet::new();
        let map = self
            .journal
            .rename_observation(&self.space_id, self.limits.max_storage_entries)?;
        let scope = self.observation_scope(prior)?;
        let valid_map = map.as_ref().filter(|map| map.scope == scope);
        if let Some(map) = valid_map {
            map.validate(prior, self.limits.max_scan_entries)?;
        }
        let persisted: BTreeMap<_, _> = valid_map
            .into_iter()
            .flat_map(|map| &map.entries)
            .map(|row| (&row.entry_id, &row.observed))
            .collect();
        let mut by_identity = BTreeMap::new();
        for (path, observed) in scanned {
            if observed.kind != EntryKind::File || !observed.single_link {
                continue;
            }
            if by_identity
                .insert(observed.physical_identity.clone(), path.clone())
                .is_some()
            {
                return Err(ReconcileError::Invariant(
                    "ambiguous physical metadata observation",
                ));
            }
        }
        let mut pending = Vec::new();
        for entry in prior.entries.values() {
            let Some(logical) = &entry.metadata else {
                continue;
            };
            if let Some(row) = persisted.get(&entry.entry_id) {
                // A current captured record is authoritative for change detection:
                // do not fall back to older Final evidence after a local edit.
                if row.local_metadata.is_some() {
                    if scanned.get(&entry.path).is_some_and(|observed| {
                        observed.kind == entry.kind
                            && observed.physical_identity != row.physical_identity
                    }) {
                        replacements.insert(entry.entry_id.clone());
                    }
                    if let Some(path) = by_identity.get(&row.physical_identity) {
                        let observed = result.get_mut(path).ok_or(ReconcileError::Unstable)?;
                        let platform = if cfg!(windows) {
                            PortableMetadataProjectionPlatform::Windows
                        } else {
                            PortableMetadataProjectionPlatform::Unix
                        };
                        if preserves_logical_metadata(
                            entry,
                            row,
                            &observation(path, observed),
                            platform,
                        )? {
                            observed.metadata = Some(logical.clone());
                        }
                    }
                    continue;
                }
            }
            if scanned.get(&entry.path).is_none_or(|observed| {
                observed.kind == entry.kind
                    && observed.content == entry.content
                    && observed.metadata != entry.metadata
            }) {
                pending.push(entry);
            }
        }
        if !pending.is_empty() {
            #[cfg(windows)]
            let finals = self
                .journal
                .remote_metadata_final_identities(&self.space_id, &self.root_identity.physical)?;
            #[cfg(not(windows))]
            let finals: Vec<(Entry, ContentId)> = Vec::new();
            let mut indexed: BTreeMap<EntryId, BTreeMap<ContentId, Entry>> = BTreeMap::new();
            for (entry, identity) in finals {
                if indexed
                    .entry(entry.entry_id.clone())
                    .or_default()
                    .insert(identity, entry.clone())
                    .is_some_and(|prior| prior != entry)
                {
                    return Err(ReconcileError::Invariant(
                        "ambiguous original metadata Final",
                    ));
                }
            }
            for entry in pending {
                let Some(originals) = indexed.get(&entry.entry_id) else {
                    continue;
                };
                let matching: Vec<_> = originals
                    .iter()
                    .filter(|(_, original)| {
                        original.content == entry.content && original.metadata == entry.metadata
                    })
                    .filter_map(|(identity, _)| by_identity.get(identity))
                    .collect();
                if matching.len() > 1 {
                    return Err(ReconcileError::Invariant(
                        "ambiguous physical metadata Final identity",
                    ));
                }
                let Some(path) = matching.first() else {
                    continue;
                };
                let Some(observed) = result.get_mut(*path) else {
                    continue;
                };
                let logical = entry.metadata.as_ref().ok_or(ReconcileError::Unstable)?;
                if observed.single_link
                    && observed.kind == entry.kind
                    && observed.content == entry.content
                    && originals
                        .get(&observed.physical_identity)
                        .is_some_and(|original| {
                            original.content == entry.content && original.metadata == entry.metadata
                        })
                    && observed.metadata.as_ref().is_some_and(|actual| {
                        crate::filesystem::projected_metadata_matches(logical, actual)
                            .unwrap_or(false)
                    })
                {
                    observed.metadata = Some(logical.clone());
                }
            }
        }
        Ok((result, replacements))
    }

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
