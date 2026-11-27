use super::*;
impl ReacquiredOriginalUnixNode<'_, '_> {
    pub(super) fn verify_predecessors(&self) -> Result<()> {
        let mut current = self.record.clone();
        while current.generation > 0 {
            let index = current.generation - 1;
            let name = format!("unix-generation-{index:04}.frames");
            let slot = Slot::new(true, &[&name]);
            let object = current
                .objects
                .iter()
                .find(|o| o.role == "generation_record" && o.path == name)
                .ok_or(ReconcileError::Invariant(
                    "Unix immediate predecessor member absent",
                ))?;
            let file = self.observed.get(&slot).ok_or(ReconcileError::Invariant(
                "Unix predecessor lacks actual original observation",
            ))?;
            let bytes = file.read_bounded()?;
            let digest = ContentId::hash(&bytes);
            if current.predecessor.as_ref() != Some(&digest)
                || object.digest.as_ref() != Some(&digest)
            {
                return Err(ReconcileError::Invariant(
                    "Unix predecessor digest binding differs",
                ));
            }
            let previous = budget::decode(&bytes)?;
            if previous.generation != index
                || previous.archive != current.archive
                || previous.space != current.space
                || previous.source != current.source
                || previous.namespace != current.namespace
                || previous.data != current.data
                || previous.worktree != current.worktree
                || previous.database != current.database
                || previous.turns > current.turns
            {
                return Err(ReconcileError::Invariant(
                    "Unix predecessor original generation binding differs",
                ));
            }
            // Protected data/receipt/intent ancestry is append-only. Worktree
            // captures may change only through later fixed local commits.
            for old in &previous.objects {
                if old.role.starts_with("work_") {
                    continue;
                }
                let next = current
                    .objects
                    .iter()
                    .find(|o| o.path == old.path && !o.role.starts_with("work_"))
                    .ok_or(ReconcileError::Invariant(
                        "Unix generation lost protected predecessor member",
                    ))?;
                if serde_json::to_vec(old)? != serde_json::to_vec(next)? {
                    return Err(ReconcileError::Invariant(
                        "Unix protected predecessor member changed",
                    ));
                }
            }
            if previous.turns == current.turns
                && (previous.rows != current.rows || previous.root != current.root)
            {
                return Err(ReconcileError::Invariant(
                    "Unix generation changed without committed local turn",
                ));
            }
            current = previous;
        }
        if current.predecessor.is_some()
            || current.turns != 0
            || current.root
                != self
                    .archive
                    .current_node_manifest(self.inspection)?
                    .root()?
        {
            return Err(ReconcileError::Invariant(
                "original Unix generation zero lineage differs",
            ));
        }
        Ok(())
    }
}
