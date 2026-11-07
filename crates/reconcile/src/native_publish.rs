use crate::{fault::checkpoint, scan, LocalSpace, ReconcileError, Result};
use serde::Serialize;
use std::{io::Write, path::Path};
use sync_extend_core_model::{EntryId, PortablePath, SnapshotId};
use sync_extend_journal::{NativePublicationObservation, NativePublicationStage as Stage};

/// Local-only outcome; pending creator/forward/cleanup is never reported as done.
#[derive(Serialize)]
pub struct NativePublishResult {
    pub transaction_id: EntryId,
    pub requested_path: PortablePath,
    pub published_path: PortablePath,
    pub conflict_copy: bool,
    pub snapshot_id: Option<SnapshotId>,
    pub stage: Stage,
    pub local_committed: bool,
    pub native_cleanup_complete: bool,
    pub pending_reason: Option<String>,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub fn publish_native_file(
        &mut self,
        source: &Path,
        path: PortablePath,
    ) -> Result<NativePublishResult> {
        // Do not let legacy recovery interpret a previously selected native intent.
        self.recover()?;
        self.scan_without_recovery()?;
        let content = self.import_source(source)?;
        let peak = content
            .length
            .checked_mul(17)
            .and_then(|n| n.checked_add(32))
            .ok_or(ReconcileError::ResourceLimit(
                "native internal reservation overflow",
            ))?;
        self.reserve_internal_worktree(peak)?;
        let id = self.begin_content_selected(
            path,
            content,
            None,
            EntryId::random()?,
            EntryId::random()?,
            true,
        )?;
        checkpoint("after_native_selection");
        let outcome = self.create_native_pipeline(&id, peak);
        self.native_publish_result(&id, outcome.err().map(|error| error.to_string()))
    }

    fn create_native_pipeline(&mut self, id: &EntryId, peak: u64) -> Result<()> {
        self.verify_root()?;
        self.require_no_mutation()?;
        self.reserve_internal_worktree(peak)?;
        let publication = self.journal.publication(id)?;
        self.check_publication_limits(&publication.intent.content)?;
        self.cas.verify(&publication.intent.content)?;
        let mut creation = self.journal.begin_native_publication_creation(id, peak)?;
        checkpoint("after_native_creators");
        self.reserve_native_internal_worktree(&creation.file_view())?;
        creation.marker_writer().write_all(id.as_str().as_bytes())?;
        checkpoint("after_native_marker");
        self.reserve_native_internal_worktree(&creation.file_view())?;
        self.cas
            .write_file(&publication.intent.content, creation.payload_writer())?;
        checkpoint("after_native_payload");
        self.reserve_native_internal_worktree(&creation.file_view())?;
        let ready = self.journal.seal_native_publication_creation(creation)?;
        checkpoint("after_native_seal");
        let ready = self.journal.record_native_publication_ready(ready)?;
        checkpoint("after_native_ready");
        self.reserve_native_internal_worktree(&ready.file_view())?;
        self.verify_root()?;
        self.cas.verify(&publication.intent.content)?;
        let observation = self.journal.publish_native_publication_ready(ready)?;
        checkpoint("after_native_observed");
        self.complete_native_pipeline(observation)
    }

    fn complete_native_pipeline(
        &mut self,
        observation: NativePublicationObservation,
    ) -> Result<()> {
        let id = observation.transaction_id().clone();
        self.verify_root()?;
        self.require_no_mutation()?;
        self.reserve_native_internal_worktree(&observation.file_view())?;
        let intent = self.journal.publication(&id)?.intent;
        if intent.space_id != self.space_id {
            return Err(ReconcileError::Invariant(
                "native publication belongs to another space",
            ));
        }
        let completion = intent.completion.as_ref().ok_or(ReconcileError::Invariant(
            "native publication original completion missing",
        ))?;
        let first = scan::scan_native(
            &self.worktree,
            &self.cas,
            &self.limits,
            &observation.file_view(),
        )?;
        checkpoint("after_native_first_scan");
        let second = scan::scan_native(
            &self.worktree,
            &self.cas,
            &self.limits,
            &observation.file_view(),
        )?;
        if first != second
            || second.len() != completion.manifest.entries.len()
            || completion.manifest.entries.values().any(|entry| {
                second
                    .get(&entry.path)
                    .is_none_or(|seen| seen.kind != entry.kind || seen.content != entry.content)
            })
        {
            return Err(ReconcileError::Unstable);
        }
        for content in completion
            .manifest
            .entries
            .values()
            .filter_map(|entry| entry.content.as_ref())
        {
            self.cas.verify(content)?;
        }
        self.verify_root()?;
        self.reserve_native_internal_worktree(&observation.file_view())?;
        checkpoint("before_native_final");
        let last = scan::scan_native(
            &self.worktree,
            &self.cas,
            &self.limits,
            &observation.file_view(),
        )?;
        if last != second {
            return Err(ReconcileError::Unstable);
        }
        observation.verify_content()?;
        self.verify_root()?;
        // Two scans are cooperative observation, not exclusion of unrelated writers.
        self.journal.finalize_native_publication(observation)?;
        checkpoint("after_native_final");
        self.journal.cleanup_native_publication(&id)?;
        checkpoint("after_native_cleanup");
        Ok(())
    }

    pub fn recover_native_publications(&mut self) -> Result<Vec<NativePublishResult>> {
        self.verify_root()?;
        self.require_no_mutation()?;
        let publications = self.journal.outstanding_publications(&self.space_id)?;
        let mut results = Vec::new();
        for publication in publications {
            let id = publication.intent.transaction_id;
            let stage = self.journal.audit_native_publication_stage(&id)?;
            if stage == Stage::Legacy {
                continue;
            }
            let outcome = match stage {
                Stage::Selected | Stage::Creating => Err(ReconcileError::Invariant(
                    "incomplete native creation preserved; no receiptless CREATE or writer retry",
                )),
                Stage::Ready => (|| {
                    self.check_publication_limits(&publication.intent.content)?;
                    let ready = self.journal.reopen_native_publication_ready(&id)?;
                    self.reserve_native_internal_worktree(&ready.file_view())?;
                    self.cas.verify(&publication.intent.content)?;
                    let observation = self.journal.publish_native_publication_ready(ready)?;
                    self.complete_native_pipeline(observation)
                })(),
                Stage::Publishing | Stage::Observed => (|| {
                    self.check_publication_limits(&publication.intent.content)?;
                    // Reopen performs exact receipt/content/parent checks before rename.
                    let held = self.journal.reopen_native_publication_forward_guard(&id)?;
                    self.reserve_native_internal_worktree(&held.file_view())?;
                    self.cas.verify(&publication.intent.content)?;
                    let observation = self.journal.resume_native_publication_forward(held)?;
                    self.complete_native_pipeline(observation)
                })(),
                Stage::Final => (|| {
                    self.journal.native_publication_final_snapshot(&id)?;
                    self.journal.cleanup_native_publication(&id)?;
                    Ok(())
                })(),
                Stage::Cleanup => Ok(()),
                Stage::Legacy => unreachable!(),
            };
            results.push(
                self.native_publish_result(&id, outcome.err().map(|error| error.to_string()))?,
            );
        }
        Ok(results)
    }

    fn native_publish_result(
        &self,
        id: &EntryId,
        pending_reason: Option<String>,
    ) -> Result<NativePublishResult> {
        let stage = self.journal.audit_native_publication_stage(id)?;
        let publication = self.journal.publication(id)?;
        let final_history = matches!(stage, Stage::Final | Stage::Cleanup);
        let snapshot_id = if final_history {
            Some(self.journal.native_publication_final_snapshot(id)?)
        } else {
            None
        };
        Ok(NativePublishResult {
            transaction_id: id.clone(),
            conflict_copy: publication.intent.target_path != publication.intent.requested_path,
            requested_path: publication.intent.requested_path,
            published_path: publication.intent.target_path,
            snapshot_id,
            stage,
            local_committed: final_history,
            native_cleanup_complete: stage == Stage::Cleanup,
            pending_reason,
            remote_backup_complete: false,
        })
    }
}
