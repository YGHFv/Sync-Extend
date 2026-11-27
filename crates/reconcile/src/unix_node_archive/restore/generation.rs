//! The actual runtime closes before its retained creator receives a terminal.
//! This record describes that one generation and grants no reopen authority.
use super::super::{completion_frames, generation_budget as budget};
use super::*;
use sync_extend_core_model::ContentId;
use sync_extend_platform_fs::OriginalUnixCloseFrames;

const NAME: &str = "unix-generation-0000.frames";

impl OriginalUnixRestoredNode<'_, '_> {
    fn generation_record(&mut self) -> Result<budget::Record> {
        self.verify()?;
        if !self.completed || self.generation_frames.is_some() {
            return Err(ReconcileError::Invariant(
                "one completed original Unix generation",
            ));
        }
        let observed = self
            .journal
            .as_mut()
            .expect("verified original Journal")
            .observe_original_session()?;
        if observed.root != self.plan.manifest.root()? || observed.local_turns != 0 {
            return Err(ReconcileError::Invariant(
                "restored generation manifest frontier differs",
            ));
        }
        let mut objects = Vec::new();
        let count = self
            .files
            .len()
            .checked_add(self.directories.len())
            .and_then(|count| count.checked_add(self.locks.len() + 1))
            .filter(|count| *count <= budget::MAX_OBJECTS)
            .ok_or(ReconcileError::ResourceLimit(
                "complete Unix generation members",
            ))?;
        objects
            .try_reserve_exact(count)
            .map_err(|_| ReconcileError::ResourceLimit("Unix generation member allocation"))?;
        for (slot, directory) in &self.directories {
            objects.push(budget::Object {
                role: if slot.data {
                    "data_directory"
                } else {
                    "work_directory"
                }
                .into(),
                path: slot.parts.join("/"),
                original: budget::Key::observed(directory.key()?),
                parent: budget::Key::observed(directory.parent_key()?),
                bytes: 0,
                digest: None,
                projected_metadata: None,
            });
        }
        for (slot, file) in &self.files {
            let planned = &self.plan.files[slot];
            objects.push(budget::Object {
                role: if slot.data { "data_file" } else { "work_file" }.into(),
                path: slot.parts.join("/"),
                original: budget::Key::observed(file.key()?),
                parent: budget::Key::observed(file.parent_key()?),
                bytes: file.bytes()?,
                digest: Some(planned.digest.clone()),
                projected_metadata: planned.projected.clone(),
            });
        }
        if self.locks.len() != 2 {
            return Err(ReconcileError::Invariant(
                "complete original Unix writer locks",
            ));
        }
        for (index, lock) in self.locks.iter().enumerate() {
            objects.push(budget::Object {
                role: if index == 0 { "data_lock" } else { "work_lock" }.into(),
                path: if index == 0 {
                    "writer.lock"
                } else {
                    ".sync-extend/writer.lock"
                }
                .into(),
                original: budget::Key::observed(lock.key()?),
                parent: budget::Key::observed(lock.parent_key()?),
                bytes: 0,
                digest: Some(ContentId::hash(&[])),
                projected_metadata: None,
            });
        }
        let intent = self.intent.as_ref().expect("verified restore intent");
        objects.push(budget::Object {
            role: "restore_intent".into(),
            path: "unix-restore.intent".into(),
            original: budget::Key::observed(intent.key()?),
            parent: budget::Key::observed(intent.parent_key()?),
            bytes: intent.bytes()?,
            digest: Some(ContentId::hash(&self.intent_bytes)),
            projected_metadata: None,
        });
        let data = self.data.as_ref().expect("verified data root").key()?;
        if observed.keys[1] != data {
            return Err(ReconcileError::Invariant(
                "original generation data parent differs",
            ));
        }
        Ok(budget::Record {
            version: 1,
            sequence: 0,
            phase: "close_intended".into(),
            generation: 0,
            turns: observed.local_turns,
            archive: self.plan.archive.digest().clone(),
            source: self
                .plan
                .native_projection
                .as_ref()
                .map(|source| source.source_digest().clone()),
            predecessor: None,
            space: self.plan.archive.space().clone(),
            root: observed.root,
            rows: observed.rows,
            namespace: budget::Key::observed(observed.keys[0]),
            data: budget::Key::observed(data),
            worktree: budget::Key::observed(
                self.worktree.as_ref().expect("verified worktree").key()?,
            ),
            database: std::array::from_fn(|index| budget::Key::observed(observed.keys[index + 2])),
            objects,
            runtime_closed_descriptors: None,
        })
    }
}

impl<'archive, 'namespace> OriginalUnixRestoredNode<'archive, 'namespace> {
    /// Close the actual restored generation, recording its exact membership on
    /// one original creator. A failed close leaves an intended-only record.
    pub fn close_with_generation_record(
        mut self,
    ) -> std::result::Result<
        ClosedOriginalUnixRestore,
        OriginalUnixRestoreFailure<'archive, 'namespace>,
    > {
        let result = (|| -> Result<_> {
            let mut record = self.generation_record()?;
            budget::require_future_close(&record, &[], 0)?;
            if self
                .plan
                .total_bytes
                .checked_add(completion_frames::MAX_FRAME_BYTES as u64)
                .is_none_or(|bytes| bytes > self.plan.bounds.maximum_total_bytes)
                || self.plan.files.len() + self.plan.directories.len() + 9
                    > self.plan.bounds.maximum_creations
            {
                return Err(ReconcileError::ResourceLimit(
                    "Unix generation creator reserved before effects",
                ));
            }
            let intended = budget::encode(&record)?;
            let first = completion_frames::intended(budget::HEADER, &intended)?;
            record.sequence = 1;
            record.phase = "runtime_closed".into();
            record.runtime_closed_descriptors = Some(u64::MAX);
            let maximum = completion_frames::terminal(&intended, &budget::encode(&record)?)?.len();
            let creator = self.create_file(
                &Slot::new(true, &[NAME]),
                completion_frames::MAX_FRAME_BYTES as u64,
            )?;
            self.generation_frames = Some(
                match OriginalUnixCloseFrames::begin(creator, &first, maximum) {
                    Ok(frames) => frames,
                    Err(mut failure) => {
                        let error = io_error(&failure.error);
                        if let Some(original) = failure.original.take() {
                            self.pending.push(original);
                        }
                        return Err(error);
                    }
                },
            );
            Ok((record, intended, first))
        })();
        let (mut record, intended, first) = match result {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(OriginalUnixRestoreFailure {
                    error,
                    original: Some(self),
                    original_close: None,
                })
            }
        };
        // The record creator retains the same data parent. Close all runtime
        // resources first, preserving that parent and creator for the append.
        let data = self.data.take();
        let frames = self.generation_frames.take();
        let mut runtime = UnixOriginalCloseAttempt::new();
        self.close_resources(&mut runtime);
        self.data = data;
        self.generation_frames = frames;
        let closed = match runtime.finish() {
            Ok(closed) => closed,
            Err(original_close) => {
                return Err(OriginalUnixRestoreFailure {
                    error: ReconcileError::Invariant("Unix generation runtime close failed"),
                    original: Some(self),
                    original_close: Some(original_close),
                })
            }
        };
        record.runtime_closed_descriptors = Some(closed.actual_closed_descriptors() as u64);
        let mut completed = UnixOriginalCloseAttempt::new();
        completed.append_result(Ok(closed));
        let append = (|| -> Result<ContentId> {
            let terminal = completion_frames::terminal(&intended, &budget::encode(&record)?)?;
            let mut bytes = first;
            bytes.extend_from_slice(&terminal);
            budget::decode(&bytes)?;
            self.generation_frames
                .as_mut()
                .expect("same generation creator")
                .append_terminal_and_sync(&terminal)?;
            Ok(ContentId::hash(&bytes))
        })();
        let digest = match append {
            Ok(digest) => digest,
            Err(error) => {
                self.close_resources(&mut completed);
                return Err(OriginalUnixRestoreFailure {
                    error,
                    original: Some(self),
                    original_close: completed.finish().err(),
                });
            }
        };
        self.close_resources(&mut completed);
        match completed.finish() {
            Ok(resources) => Ok(ClosedOriginalUnixRestore {
                resources,
                archive_digest: self.plan.archive.digest().clone(),
                generation: Some((self.plan.data.join(NAME), digest)),
            }),
            Err(original_close) => Err(OriginalUnixRestoreFailure {
                error: ReconcileError::Invariant("Unix generation record creator close failed"),
                original: Some(self),
                original_close: Some(original_close),
            }),
        }
    }
}
