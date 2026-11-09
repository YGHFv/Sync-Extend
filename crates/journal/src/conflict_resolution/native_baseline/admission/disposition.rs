//! Whole target retained while only exact quarantine originals are disposed.
use super::creators::owner_path;
use super::*;
use sync_extend_core_model::conflict_native_layout::ConflictNativeActionKind;

fn absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(invalid(
            "conflict disposition original slot still present or foreign",
        )),
        Err(e) => Err(e.into()),
    }
}

impl Journal {
    /// Dispose exact non-reused original files only; owner/base remain retained.
    pub fn dispose_conflict_native_originals(
        &mut self,
        observed: ConflictNativeObservation,
    ) -> Result<ConflictNativeExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict disposition caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let mut execution = observed.held;
        let admission = &execution.held.admission;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let state = self.conflict_forward_state(&execution)?;
        if !state.contains("phase/history_handoff") {
            return Err(invalid(
                "conflict disposition complete history handoff absent",
            ));
        }
        tx.commit()?;
        if state.contains("phase/files_cleaned") {
            return Ok(execution);
        }
        let entries = admission
            .selected
            .layout
            .actions
            .iter()
            .filter(|action| {
                matches!(
                    action.kind,
                    ConflictNativeActionKind::QuarantineOriginal
                        | ConflictNativeActionKind::ReplaceOriginal
                )
            })
            .map(|action| action.entry_id.clone())
            .collect::<Vec<_>>();
        for entry in entries {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            self.conflict_forward_state(&execution)?;
            tx.commit()?;
            let admission = &execution.held.admission;
            let action = admission
                .selected
                .layout
                .actions
                .iter()
                .find(|a| a.entry_id == entry)
                .ok_or(invalid("conflict disposition original action missing"))?;
            let baseline = action
                .baseline
                .as_ref()
                .ok_or(invalid("conflict disposition baseline entry absent"))?
                .clone();
            let component = action
                .original_component
                .as_ref()
                .ok_or(invalid("conflict disposition original component absent"))?
                .clone();
            let path = owner_path(admission).join(&component);
            let intended = format!("dispose/{component}/intended");
            let mut pending = {
                let tx =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                let state = self.conflict_forward_state(&execution)?;
                tx.commit()?;
                state
            };
            pending.insert(intended.clone());
            if execution
                .held
                .admission
                .selected
                .originals
                .contains_key(&baseline.path)
            {
                self.fulfill_conflict_creator(admission, &intended, &execution.held.keys, || {
                    let original =
                        admission
                            .selected
                            .originals
                            .get(&baseline.path)
                            .ok_or(invalid(
                                "conflict disposition original retained handle absent",
                            ))?;
                    if !original.held.matches_path(&path)? {
                        return Err(invalid(
                            "conflict disposition original fullkey slot differs",
                        ));
                    }
                    super::super::verify_content(original.held.reader(), &baseline)?;
                    execution.verify(&pending)
                })?;
                let tx =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                let parent = &admission.selected.header;
                let before = self.read_view().audit_local_commit_capacity(
                    &parent.target.space_id,
                    storage_policy::capacity_limits(self.max_storage_entries)?,
                )?;
                if !before.report.within_accounted_limits() {
                    return Err(invalid("conflict disposition lowered policy"));
                }
                self.conflict_forward_state(&execution)?;
                self.verify_conflict_creator_cas(admission)?;
                let original = admission
                    .selected
                    .originals
                    .get(&baseline.path)
                    .ok_or(invalid("conflict disposition retained original missing"))?;
                if !original.held.matches_path(&path)? {
                    return Err(invalid("conflict disposition source changed before delete"));
                }
                original.held.delete_on_close()?;
                tx.commit()?;
                // Actual absence is checked only after the last admitted file guard drops.
                let original = execution
                    .held
                    .admission
                    .selected
                    .originals
                    .remove(&baseline.path)
                    .ok_or(invalid(
                        "conflict disposition original guard removal missing",
                    ))?;
                drop(original);
            } else {
                absent(&path)?;
                let tx =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                if !self.conflict_forward_state(&execution)?.contains(&intended) {
                    return Err(invalid("conflict missing original before intended receipt"));
                }
                tx.commit()?;
            }
            absent(&path)?;
            let admission = &execution.held.admission;
            for stage in ["absent", "terminal"] {
                self.fulfill_conflict_creator(
                    admission,
                    &format!("dispose/{component}/{stage}"),
                    &execution.held.keys,
                    || {
                        absent(&path)?;
                        execution.verify(&pending)
                    },
                )?;
                pending.insert(format!("dispose/{component}/{stage}"));
            }
        }
        let admission = &execution.held.admission;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let state = self.conflict_forward_state(&execution)?;
        tx.commit()?;
        self.fulfill_conflict_creator(
            admission,
            "phase/files_cleaned",
            &execution.held.keys,
            || execution.verify(&state),
        )?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        execution.recovery_state = self.conflict_forward_state(&execution)?;
        tx.commit()?;
        Ok(execution)
    }
}
