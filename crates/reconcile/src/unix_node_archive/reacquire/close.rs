use super::*;

pub struct ClosedReacquiredUnixGeneration {
    resources: ClosedUnixOriginalResources,
    path: std::path::PathBuf,
    digest: ContentId,
    generation: u32,
}
impl ClosedReacquiredUnixGeneration {
    pub fn actual_closed_descriptors(&self) -> usize {
        self.resources.actual_closed_descriptors()
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn digest(&self) -> &ContentId {
        &self.digest
    }
}

impl<'a, 'n> ReacquiredOriginalUnixNode<'a, 'n> {
    pub(super) fn require_next_close_budget(
        &self,
        current: &budget::Record,
        additional: &[budget::Object],
        turns: u32,
    ) -> Result<()> {
        let mut next = current.clone();
        next.generation = next
            .generation
            .checked_add(1)
            .filter(|n| *n < budget::MAX_GENERATIONS)
            .ok_or(ReconcileError::ResourceLimit(
                "future Unix generation count",
            ))?;
        next.predecessor = Some(self.record_digest.clone());
        let prior = self.record_file.as_ref().ok_or(ReconcileError::Invariant(
            "future generation original record absent",
        ))?;
        next.objects.push(budget::Object {
            role: "generation_record".into(),
            path: format!("unix-generation-{:04}.frames", current.generation),
            original: budget::Key::observed(prior.key()?),
            parent: budget::Key::observed(prior.parent_key()?),
            bytes: prior.bytes()?,
            digest: Some(self.record_digest.clone()),
            projected_metadata: None,
        });
        let held = next.objects.iter().chain(additional).try_fold(0u64, |sum, object| {
            sum.checked_add(object.bytes)
                .filter(|bytes| *bytes <= self.bounds.maximum_total_bytes)
                .ok_or(ReconcileError::ResourceLimit("configured Unix generation byte budget"))
        })?;
        let _ = held;
        if next.objects.len().checked_add(additional.len()).and_then(|n| n.checked_add(10))
            .is_none_or(|n| n > self.bounds.maximum_creations)
        {
            return Err(ReconcileError::ResourceLimit("configured Unix generation creator budget"));
        }
        budget::require_future_close(&next, additional, turns)
    }
    pub fn close_next_generation(
        mut self,
    ) -> std::result::Result<ClosedReacquiredUnixGeneration, UnixGenerationReacquireFailure<'a, 'n>>
    {
        let prepared = (|| -> Result<_> {
            self.verify()?;
            self.require_next_close_budget(&self.record, &[], 0)?;
            let generation = self
                .record
                .generation
                .checked_add(1)
                .filter(|n| *n < budget::MAX_GENERATIONS)
                .ok_or(ReconcileError::ResourceLimit("Unix generation count"))?;
            let previous = self.record_file.as_ref().expect("verified original record");
            let prior = budget::Object {
                role: "generation_record".into(),
                path: format!("unix-generation-{:04}.frames", self.record.generation),
                original: budget::Key::observed(previous.key()?),
                parent: budget::Key::observed(previous.parent_key()?),
                bytes: previous.bytes()?,
                digest: Some(self.record_digest.clone()),
                projected_metadata: None,
            };
            let mut record = self.record.clone();
            record.generation = generation;
            record.predecessor = Some(self.record_digest.clone());
            record.sequence = 0;
            record.phase = "close_intended".into();
            record.runtime_closed_descriptors = None;
            budget::require_future_close(&record, std::slice::from_ref(&prior), 0)?;
            record.objects.push(prior);
            let intended = budget::encode(&record)?;
            let first = completion_frames::intended(budget::HEADER, &intended)?;
            record.sequence = 1;
            record.phase = "runtime_closed".into();
            record.runtime_closed_descriptors = Some(u64::MAX);
            let maximum = completion_frames::terminal(&intended, &budget::encode(&record)?)?.len();
            let name = format!("unix-generation-{generation:04}.frames");
            let file = self
                .root(true)
                .create_file(&name, completion_frames::MAX_FRAME_BYTES as u64)
                .map_err(|f| {
                    let e = io(&f.error);
                    self.create_failures.push(f);
                    e
                })?;
            self.frame = Some(
                OriginalUnixCloseFrames::begin(file, &first, maximum).map_err(|mut f| {
                    let e = io(&f.error);
                    if let Some(v) = f.original.take() {
                        self.creations.push(v);
                    }
                    e
                })?,
            );
            Ok((record, intended, first, self.root(true).path().join(name)))
        })();
        let (mut record, intended, first, path) = match prepared {
            Ok(v) => v,
            Err(error) => {
                return Err(UnixGenerationReacquireFailure {
                    error,
                    original: Some(self),
                    original_close: None,
                })
            }
        };
        let data = self.data.take();
        let frame = self.frame.take();
        let mut runtime = UnixOriginalCloseAttempt::new();
        self.close_resources(&mut runtime);
        self.data = data;
        self.frame = frame;
        let closed = match runtime.finish() {
            Ok(v) => v,
            Err(f) => {
                return Err(UnixGenerationReacquireFailure {
                    error: ReconcileError::Invariant("Unix next generation runtime close failed"),
                    original: Some(self),
                    original_close: Some(f),
                })
            }
        };
        record.runtime_closed_descriptors = Some(closed.actual_closed_descriptors() as u64);
        let mut terminal_close = UnixOriginalCloseAttempt::new();
        terminal_close.append_result(Ok(closed));
        let appended = (|| -> Result<_> {
            let terminal = completion_frames::terminal(&intended, &budget::encode(&record)?)?;
            let mut bytes = first;
            bytes.extend_from_slice(&terminal);
            budget::decode(&bytes)?;
            self.frame
                .as_mut()
                .expect("actual same frame creator")
                .append_terminal_and_sync(&terminal)?;
            Ok(ContentId::hash(&bytes))
        })();
        self.close_resources(&mut terminal_close);
        let finished = terminal_close.finish();
        match (appended, finished) {
            (Ok(digest), Ok(resources)) => Ok(ClosedReacquiredUnixGeneration {
                resources,
                path,
                digest,
                generation: record.generation,
            }),
            (appended, finished) => Err(UnixGenerationReacquireFailure {
                error: appended.err().unwrap_or(ReconcileError::Invariant(
                    "Unix next generation creator close failed",
                )),
                original: Some(self),
                original_close: finished.err(),
            }),
        }
    }
}
