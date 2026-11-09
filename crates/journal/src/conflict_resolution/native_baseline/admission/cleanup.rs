//! Intended receipts precede exact empty-directory descriptor disposition.
use super::creators::{base_key, base_path, owner_path};
use super::forward::exists;
use super::*;
use sync_extend_platform_fs::LockedDirectoryMutation;

impl Journal {
    /// Delete only this creator's empty owner and, if created here, empty base.
    pub fn cleanup_conflict_native_directories(
        &mut self,
        mut execution: ConflictNativeExecution,
    ) -> Result<ConflictNativeExecution> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict directory cleanup caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if !self
            .conflict_forward_state(&execution)?
            .contains("phase/files_cleaned")
        {
            return Err(invalid(
                "conflict directory cleanup requires all file terminals",
            ));
        }
        tx.commit()?;
        let mut directories = vec![(1, owner_path(&execution.held.admission))];
        if execution.binding.existing_base.is_none() {
            directories.push((0, base_path(&execution.held.admission)));
        }
        for (step, path) in directories {
            let component = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(invalid("conflict directory cleanup component UTF8"))?;
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            let mut state = self.conflict_forward_state(&execution)?;
            tx.commit()?;
            let intended = format!("dispose/{component}/intended");
            let mut pending = state.clone();
            pending.insert(intended.clone());
            self.fulfill_conflict_creator(
                &execution.held.admission,
                &intended,
                &execution.held.keys,
                || execution.verify(&pending),
            )?;
            state.insert(intended);
            if exists(&path)? {
                // Windows read guards deny DELETE sharing: close the original
                // guard before opening mutation, then recheck its complete key.
                let guard = if step == 1 {
                    execution.held.owner.take()
                } else {
                    execution.held.base.take()
                };
                drop(guard);
                let tx =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                self.conflict_forward_state(&execution)?;
                let mutation = LockedDirectoryMutation::open(&path)?;
                let expected = if step == 1 {
                    execution.held.keys[&1].clone()
                } else {
                    base_key(&execution.held.admission, &execution.held.keys)?
                };
                if descriptive(mutation.key()?) != expected || fs::read_dir(&path)?.next().is_some()
                {
                    return Err(invalid("conflict cleanup directory changed or not empty"));
                }
                self.verify_conflict_creator_cas(&execution.held.admission)?;
                mutation.delete_empty_on_close()?;
                drop(mutation);
                execution.verify(&state)?;
                tx.commit()?;
            }
            for stage in ["absent", "terminal"] {
                self.fulfill_conflict_creator(
                    &execution.held.admission,
                    &format!("dispose/{component}/{stage}"),
                    &execution.held.keys,
                    || execution.verify(&state),
                )?;
                state.insert(format!("dispose/{component}/{stage}"));
            }
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let state = self.conflict_forward_state(&execution)?;
        tx.commit()?;
        self.fulfill_conflict_creator(
            &execution.held.admission,
            "phase/cleanup",
            &execution.held.keys,
            || execution.verify(&state),
        )?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        execution.recovery_state = self.conflict_forward_state(&execution)?;
        tx.commit()?;
        Ok(execution)
    }
}
