//! End actual native owners and callback loans before releasing their whole scope.
use crate::ReconcileError;
use sync_extend_platform_fs::ClosedWindowsOriginalResources;

pub(super) trait OriginalNodePendingResourceClose<'scope>: 'scope {
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        super::OriginalNodeResourceCloseFailure<'scope>,
    >;
}

pub(super) enum OriginalNodeJournalToClose {
    Read(sync_extend_journal::Journal),
    Write(sync_extend_journal::OriginalJournalWriteTransition),
    ReadOpenFailure(sync_extend_journal::OriginalReadonlyJournalOpenFailure),
    ReadFailure(sync_extend_journal::OriginalReadonlyJournalCloseFailure),
    WriteFailure(sync_extend_journal::OriginalJournalWriteResourceCloseFailure),
    TransitionFailure(sync_extend_journal::OriginalJournalTransitionFailure),
    TransitionResourceFailure(sync_extend_journal::OriginalJournalTransitionResourceCloseFailure),
    Group(Vec<OriginalNodeJournalToClose>),
}

impl OriginalNodeJournalToClose {
    fn has_retained_originals(&self) -> bool {
        match self {
            Self::Read(_) | Self::Write(_) | Self::TransitionFailure(_) => true,
            Self::ReadOpenFailure(original) => original.has_retained_originals(),
            Self::ReadFailure(original) => original.has_retained_originals(),
            Self::WriteFailure(original) => original.has_retained_originals(),
            Self::TransitionResourceFailure(original) => original.has_retained_originals(),
            Self::Group(originals) => originals.iter().any(Self::has_retained_originals),
        }
    }
}

pub(super) enum OriginalNodeCasReadersToClose {
    Read(crate::original_managed_cas::OriginalManagedCasReadResources),
    Failure(crate::original_managed_cas::OriginalManagedCasResourceCloseFailure),
    PreparationFailure(crate::original_managed_cas::OriginalManagedCasReadPreparationFailure),
}

impl OriginalNodeCasReadersToClose {
    fn has_retained_originals(&self) -> bool {
        match self {
            Self::Read(_) => true,
            Self::Failure(original) => original.has_retained_originals(),
            Self::PreparationFailure(original) => original.has_retained_originals(),
        }
    }
}

pub(super) struct OriginalNodeOwnedResourceGroups<'scope> {
    pub(super) journals: Vec<OriginalNodeJournalToClose>,
    pub(super) cas: Vec<sync_extend_cas::Cas>,
    pub(super) cas_readers: Vec<OriginalNodeCasReadersToClose>,
    pub(super) pending: Vec<Box<dyn OriginalNodePendingResourceClose<'scope>>>,
}

impl<'scope> OriginalNodeOwnedResourceGroups<'scope> {
    pub(super) fn new() -> Self {
        Self {
            journals: Vec::new(),
            cas: Vec::new(),
            cas_readers: Vec::new(),
            pending: Vec::new(),
        }
    }

    pub(super) fn fail(
        self,
        error: ReconcileError,
    ) -> OriginalNodeScopedResourceCloseFailure<'scope> {
        let Self {
            journals,
            cas,
            cas_readers,
            pending,
        } = self;
        let mut original = OriginalNodeScopedResourceClose {
            journal: (!journals.is_empty()).then_some(OriginalNodeJournalToClose::Group(journals)),
            cas,
            cas_readers,
            pending: Some(Box::new(OriginalNodePendingResourceGroup {
                originals: pending,
            })),
            resources: None,
            first_error: Some(reported(&error)),
            already_closed: Vec::new(),
        };
        original.close_remaining();
        OriginalNodeScopedResourceCloseFailure {
            error,
            original: Some(Box::new(original)),
        }
    }
}

struct OriginalNodePendingResourceGroup<'scope> {
    originals: Vec<Box<dyn OriginalNodePendingResourceClose<'scope>>>,
}

impl<'scope> OriginalNodePendingResourceClose<'scope> for OriginalNodePendingResourceGroup<'scope> {
    fn close(
        self: Box<Self>,
    ) -> std::result::Result<
        ClosedWindowsOriginalResources,
        super::OriginalNodeResourceCloseFailure<'scope>,
    > {
        let mut complete = super::OriginalNodeResourceCloseAttempt::new();
        let Self { originals } = *self;
        for original in originals {
            match original.close() {
                Ok(closed) => complete.append_closed(closed),
                Err(original) => complete.append_failure(original),
            }
        }
        complete.finish()
    }
}

struct OriginalNodeScopedResourceClose<'scope> {
    journal: Option<OriginalNodeJournalToClose>,
    cas: Vec<sync_extend_cas::Cas>,
    cas_readers: Vec<OriginalNodeCasReadersToClose>,
    pending: Option<Box<dyn OriginalNodePendingResourceClose<'scope>>>,
    resources: Option<super::OriginalNodeResourceCloseFailure<'scope>>,
    first_error: Option<ReconcileError>,
    already_closed: Vec<ClosedWindowsOriginalResources>,
}

/// All same actual native failures and protective scope remain together.
/// Retry ends resources only; an earlier failure can never become a clean
/// completion, installed runtime, or restart permission.
pub struct OriginalNodeScopedResourceCloseFailure<'scope> {
    pub error: ReconcileError,
    original: Option<Box<OriginalNodeScopedResourceClose<'scope>>>,
}

impl std::fmt::Debug for OriginalNodeScopedResourceCloseFailure<'_> {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("OriginalNodeScopedResourceCloseFailure")
            .field("error", &self.error)
            .field("has_retained_originals", &self.has_retained_originals())
            .finish()
    }
}

fn reported(error: &impl std::fmt::Display) -> ReconcileError {
    ReconcileError::Io(std::io::Error::other(error.to_string()))
}

impl OriginalNodeScopedResourceClose<'_> {
    fn has_retained_originals(&self) -> bool {
        let journal = self
            .journal
            .as_ref()
            .is_some_and(OriginalNodeJournalToClose::has_retained_originals);
        let readers = self
            .cas_readers
            .iter()
            .any(OriginalNodeCasReadersToClose::has_retained_originals);
        journal
            || readers
            || !self.cas.is_empty()
            || self.pending.is_some()
            || self
                .resources
                .as_ref()
                .is_some_and(|original| original.has_retained_originals())
    }

    fn close_remaining(&mut self) {
        if let Some(journal) = self.journal.take() {
            let result = match journal {
                OriginalNodeJournalToClose::Read(journal) => {
                    match journal.close_original_readonly_resources_retaining() {
                        Ok(closed) => {
                            self.already_closed.push(closed);
                            None
                        }
                        Err(original) => {
                            self.first_error
                                .get_or_insert_with(|| reported(&original.error));
                            Some(OriginalNodeJournalToClose::ReadFailure(original))
                        }
                    }
                }
                OriginalNodeJournalToClose::Write(journal) => {
                    match journal.close_original_resources_retaining() {
                        Ok(closed) => {
                            self.already_closed.push(closed);
                            None
                        }
                        Err(original) => {
                            self.first_error
                                .get_or_insert_with(|| reported(&original.error));
                            Some(OriginalNodeJournalToClose::WriteFailure(original))
                        }
                    }
                }
                OriginalNodeJournalToClose::ReadFailure(original) => Some(
                    OriginalNodeJournalToClose::ReadFailure(original.close_remaining()),
                ),
                OriginalNodeJournalToClose::ReadOpenFailure(original) => {
                    self.first_error
                        .get_or_insert_with(|| reported(&original.error));
                    Some(OriginalNodeJournalToClose::ReadOpenFailure(
                        original.close_remaining(),
                    ))
                }
                OriginalNodeJournalToClose::WriteFailure(original) => Some(
                    OriginalNodeJournalToClose::WriteFailure(original.close_remaining()),
                ),
                OriginalNodeJournalToClose::TransitionFailure(original) => {
                    self.first_error
                        .get_or_insert_with(|| reported(&original.resource_error()));
                    Some(OriginalNodeJournalToClose::TransitionResourceFailure(
                        original.close_original_resources_retaining(),
                    ))
                }
                OriginalNodeJournalToClose::TransitionResourceFailure(original) => {
                    Some(OriginalNodeJournalToClose::TransitionResourceFailure(
                        original.close_remaining(),
                    ))
                }
                OriginalNodeJournalToClose::Group(originals) => {
                    let mut remaining = Vec::new();
                    for journal in originals {
                        let mut original = OriginalNodeScopedResourceClose {
                            journal: Some(journal),
                            cas: Vec::new(),
                            cas_readers: Vec::new(),
                            pending: None,
                            resources: None,
                            first_error: None,
                            already_closed: Vec::new(),
                        };
                        original.close_remaining();
                        if let Some(error) = original.first_error {
                            self.first_error.get_or_insert(error);
                        }
                        self.already_closed.append(&mut original.already_closed);
                        if let Some(journal) = original.journal {
                            remaining.push(journal);
                        }
                    }
                    (!remaining.is_empty()).then_some(OriginalNodeJournalToClose::Group(remaining))
                }
            };
            self.journal = result;
        }
        let journal_still_owns = self
            .journal
            .as_ref()
            .is_some_and(OriginalNodeJournalToClose::has_retained_originals);
        if journal_still_owns {
            return;
        }
        // Consuming Cas ends its own three Arc callback loans. The reader
        // owner's actual Arc::try_unwrap gate independently verifies this.
        self.cas.clear();
        let mut remaining = Vec::new();
        for readers in self.cas_readers.drain(..) {
            let readers = match readers {
                OriginalNodeCasReadersToClose::Read(readers) => match readers.close_retaining() {
                    Ok(closed) => {
                        self.already_closed.push(closed);
                        None
                    }
                    Err(original) => {
                        self.first_error
                            .get_or_insert_with(|| reported(&original.error));
                        Some(OriginalNodeCasReadersToClose::Failure(original))
                    }
                },
                OriginalNodeCasReadersToClose::Failure(original) => Some(
                    OriginalNodeCasReadersToClose::Failure(original.close_remaining()),
                ),
                OriginalNodeCasReadersToClose::PreparationFailure(original) => {
                    self.first_error
                        .get_or_insert_with(|| reported(&original.error));
                    Some(OriginalNodeCasReadersToClose::PreparationFailure(
                        original.close_remaining(),
                    ))
                }
            };
            if let Some(readers) = readers {
                remaining.push(readers);
            }
        }
        self.cas_readers = remaining;
        if self
            .cas_readers
            .iter()
            .any(OriginalNodeCasReadersToClose::has_retained_originals)
        {
            return;
        }
        if let Some(pending) = self.pending.take() {
            match pending.close() {
                Ok(closed) => self.already_closed.push(closed),
                Err(original) => {
                    self.first_error
                        .get_or_insert_with(|| reported(&original.error));
                    self.resources = Some(original);
                }
            }
        } else if let Some(original) = self.resources.take() {
            self.resources = Some(original.close_remaining());
        }
    }
}

pub(super) fn fail_original_scoped_resources<'scope>(
    error: ReconcileError,
    journal: Option<OriginalNodeJournalToClose>,
    cas: Option<sync_extend_cas::Cas>,
    cas_readers: Option<OriginalNodeCasReadersToClose>,
    pending: impl OriginalNodePendingResourceClose<'scope>,
) -> OriginalNodeScopedResourceCloseFailure<'scope> {
    let mut original = OriginalNodeOwnedResourceGroups::new();
    original.journals.extend(journal);
    original.cas.extend(cas);
    original.cas_readers.extend(cas_readers);
    original.pending.push(Box::new(pending));
    original.fail(error)
}

pub(super) fn close_original_scoped_resources<'scope>(
    journal: Option<OriginalNodeJournalToClose>,
    cas: sync_extend_cas::Cas,
    cas_readers: crate::original_managed_cas::OriginalManagedCasReadResources,
    pending: impl OriginalNodePendingResourceClose<'scope>,
) -> std::result::Result<
    ClosedWindowsOriginalResources,
    OriginalNodeScopedResourceCloseFailure<'scope>,
> {
    let mut original = OriginalNodeScopedResourceClose {
        journal,
        cas: vec![cas],
        cas_readers: vec![OriginalNodeCasReadersToClose::Read(cas_readers)],
        pending: Some(Box::new(pending)),
        resources: None,
        first_error: None,
        already_closed: Vec::new(),
    };
    original.close_remaining();
    if let Some(error) = &original.first_error {
        return Err(OriginalNodeScopedResourceCloseFailure {
            error: reported(error),
            original: Some(Box::new(original)),
        });
    }
    if original.has_retained_originals() {
        return Err(OriginalNodeScopedResourceCloseFailure {
            error: ReconcileError::Invariant("original whole resource terminal remains incomplete"),
            original: Some(Box::new(original)),
        });
    }
    let mut complete = super::OriginalNodeResourceCloseAttempt::new();
    for closed in original.already_closed {
        complete.append_closed(closed);
    }
    Ok(complete
        .finish()
        .expect("aggregate contains only actual successful resource terminals"))
}

impl OriginalNodeScopedResourceCloseFailure<'_> {
    pub fn has_retained_originals(&self) -> bool {
        self.original
            .as_ref()
            .is_some_and(|original| original.has_retained_originals())
    }

    pub fn close_remaining(mut self) -> Self {
        if let Some(original) = &mut self.original {
            original.close_remaining();
        }
        self
    }

    pub fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }

    pub fn retain_and_report(self) -> ReconcileError {
        let reported = reported(&self.error);
        self.retain_until_process_exit();
        reported
    }
}

impl Drop for OriginalNodeScopedResourceCloseFailure<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original.take() {
            if original.has_retained_originals() {
                let _ = Box::leak(original);
            }
        }
    }
}
