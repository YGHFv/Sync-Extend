//! Original signature and received-to-applied plan, distinct from local authoring.
use crate::{Journal, JournalError, PublicationCompletion, PublicationIntent, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePublicationProof {
    pub public_key: [u8; 32],
    pub operation: Operation,
    pub signature: Vec<u8>,
}
impl RemotePublicationProof {
    /// Verify the original transport signed-operation domain, not a receiver signature.
    pub fn verify(&self) -> Result<()> {
        self.operation.validate()?;
        if DeviceId::from_public_key(&self.public_key) != self.operation.payload.origin_device_id {
            return Err(JournalError::Invariant(
                "remote original public key differs",
            ));
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| JournalError::Invariant("remote original signature length"))?;
        let key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| JournalError::Invariant("remote original signing key"))?;
        let digest = blake3::derive_key(
            "SyncExtend signed operation v1",
            &serde_json::to_vec(&self.operation)?,
        );
        key.verify_strict(&digest, &signature)
            .map_err(|_| JournalError::Invariant("remote original signature invalid"))?;
        Ok(())
    }
}
impl PublicationCompletion {
    pub fn from_remote(baseline: &Manifest, proof: &RemotePublicationProof) -> Result<Self> {
        proof.verify()?;
        baseline.validate()?;
        let operation = &proof.operation;
        let payload = &operation.payload;
        let Change::Put { entry } = &payload.change else {
            return Err(JournalError::Invariant(
                "remote native apply supports new file Put only",
            ));
        };
        if payload.space_id != baseline.space_id
            || entry.kind != EntryKind::File
            || baseline.entries.contains_key(&entry.entry_id)
            || baseline.tombstones.contains_key(&entry.entry_id)
            || baseline
                .entries
                .values()
                .any(|old| old.path.collision_key() == entry.path.collision_key())
            || !baseline.version_vector.dominates(&payload.causal)
            || baseline
                .version_vector
                .get(&payload.origin_device_id)
                .checked_add(1)
                != Some(payload.origin_seq)
            || baseline.entries.len() >= limits::MAX_ENTRIES
        {
            return Err(JournalError::Invariant(
                "remote new Put baseline, causal dependency or path conflict",
            ));
        }
        let mut manifest = baseline.clone();
        manifest
            .entries
            .insert(entry.entry_id.clone(), entry.clone());
        manifest
            .version_vector
            .observe(payload.origin_device_id.clone(), payload.origin_seq);
        manifest.validate()?;
        let mut protected_objects = std::collections::BTreeMap::new();
        for chunk in manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
            .flat_map(|content| &content.chunks)
        {
            if protected_objects
                .insert(chunk.content_id.clone(), chunk.length)
                .is_some_and(|length| length != chunk.length)
            {
                return Err(JournalError::Invariant(
                    "remote completion chunk length differs",
                ));
            }
        }
        let completion = Self {
            baseline: baseline.clone(),
            manifest,
            operations: vec![operation.clone()],
            timestamp_ms: payload.created_at_ms,
            protected_objects,
        };
        completion.charge()?;
        Ok(completion)
    }
}
impl Journal {
    /// Distinct original remote admission; no own-origin Put or receive-cursor advance.
    pub fn begin_remote_native_publication(&mut self, intent: &PublicationIntent) -> Result<()> {
        if intent.remote.is_none() || !intent.native_only {
            return Err(JournalError::Invariant(
                "remote publication original proof missing",
            ));
        }
        self.begin_admitted_publication(intent)
    }

    pub(crate) fn require_remote_publication_received(
        &self,
        intent: &PublicationIntent,
    ) -> Result<()> {
        let proof = intent
            .remote
            .as_ref()
            .ok_or(JournalError::Invariant("remote publication proof missing"))?;
        proof.verify()?;
        if self.state("device_id")?.as_deref()
            == Some(proof.operation.payload.origin_device_id.as_str())
        {
            return Err(JournalError::Invariant(
                "remote publication refuses own origin",
            ));
        }
        let (payload, state): (String, String) = self.connection.query_row(
            "SELECT payload,state FROM main.operations WHERE op_id=?1",
            [proof.operation.op_id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if payload != serde_json::to_string(&proof.operation)? || state != "received" {
            return Err(JournalError::Invariant(
                "remote publication requires exact original received operation",
            ));
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn commit_remote_publication_sql(
        &self,
        tx: &rusqlite::Transaction<'_>,
        intent: &PublicationIntent,
    ) -> Result<SnapshotId> {
        self.require_remote_publication_received(intent)?;
        intent.validate()?;
        let completion = intent.completion.as_ref().ok_or(JournalError::Invariant(
            "remote original completion missing",
        ))?;
        let proof = intent.remote.as_ref().unwrap();
        let current = self
            .current(&intent.space_id)?
            .ok_or(JournalError::Invariant("remote applied baseline missing"))?;
        if current != completion.baseline
            || current.root()? != intent.baseline_root
            || self.outstanding_publications(&intent.space_id)?.len() != 1
            || !self.outstanding_mutations(&intent.space_id)?.is_empty()
        {
            return Err(JournalError::Invariant(
                "remote original final baseline or owner changed",
            ));
        }
        let manifest = &completion.manifest;
        let root = manifest.root()?;
        self.require_unpruned_root(&root)?;
        let original = serde_json::to_string(&proof.operation)?;
        if tx.execute(
            "UPDATE main.operations SET state='materialized'
            WHERE op_id=?1 AND payload=?2 AND state='received'",
            rusqlite::params![proof.operation.op_id.as_str(), original],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "remote original received update missing",
            ));
        }
        let json = serde_json::to_string(manifest)?;
        tx.execute(
            "INSERT INTO main.snapshots VALUES (?1,?2,?3,?4,'materialized',0)",
            rusqlite::params![
                root.as_str(),
                intent.space_id.as_str(),
                json,
                completion.timestamp_ms as i64
            ],
        )?;
        if tx.execute(
            "UPDATE main.current_manifests SET snapshot_id=?1
            WHERE space_id=?2 AND snapshot_id=?3",
            rusqlite::params![
                root.as_str(),
                intent.space_id.as_str(),
                intent.baseline_root.as_str()
            ],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "remote original current handoff missing",
            ));
        }
        crate::pin_snapshot(tx, root.as_str(), manifest)?;
        if tx.execute(
            "UPDATE main.publications SET state='committed',committed_snapshot=?1
            WHERE transaction_id=?2 AND state='preparing'",
            rusqlite::params![root.as_str(), intent.transaction_id.as_str()],
        )? != 1
        {
            return Err(JournalError::Invariant(
                "remote original publication final missing",
            ));
        }
        tx.execute(
            "DELETE FROM main.publication_objects WHERE transaction_id=?1",
            [intent.transaction_id.as_str()],
        )?;
        tx.execute(
            "DELETE FROM main.rename_observations WHERE space_id=?1",
            [intent.space_id.as_str()],
        )?;
        Ok(root)
    }
}
