//! Atomic complete branch history transfer before scoped native cleanup.
use super::*;

impl Journal {
    pub fn handoff_conflict_native_history(
        &mut self,
        observed: ConflictNativeObservation,
    ) -> Result<ConflictNativeObservation> {
        if !self.connection.is_autocommit() {
            return Err(invalid("conflict history handoff caller transaction"));
        }
        let _cas = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let ready = &observed.held.held;
        let admission = &ready.admission;
        let parent = &admission.selected.header;
        let mut fulfilled = self.conflict_forward_state(&observed.held)?;
        if !fulfilled.contains("phase/final") {
            return Err(invalid("conflict complete handoff requires atomic Final"));
        }
        super::super::super::native_final_state::exact_history(&self.connection, parent)?;
        if fulfilled.contains("phase/history_handoff") {
            tx.commit()?;
            return Ok(observed);
        }
        let bounds = storage_policy::capacity_limits(self.max_storage_entries)?;
        let before = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        let mut expected = row_map(&before.rows);
        let ledger = admission
            .header
            .validate(parent, &admission.selected.binding()?)?;
        for template in ledger
            .templates
            .iter()
            .filter(|t| t.name == "phase/history_handoff" || t.name.starts_with("release/"))
        {
            if template
                .dependencies
                .iter()
                .any(|name| !fulfilled.contains(name))
            {
                return Err(invalid(
                    "conflict complete handoff release dependency missing",
                ));
            }
            if template.name == "phase/history_handoff" {
                let values = super::super::super::native_effects::resolve(
                    template
                        .future
                        .as_ref()
                        .ok_or(invalid("conflict history handoff phase values"))?,
                    &ready.keys,
                )?;
                let (key, columns) = value_columns("native_phases", &values)?;
                if expected.insert(key, columns).is_some() {
                    return Err(invalid("conflict complete handoff duplicate phase"));
                }
                let mut issued = vec![Value::Text("native_phases".into())];
                issued.extend(values.clone());
                let _permit = self.conflict_resolution_issuance.permit(Some(issued))?;
                tx.execute(
                    "INSERT INTO main.conflict_resolution_native_phases VALUES(?1,?2,?3,?4,?5)",
                    rusqlite::params_from_iter(values),
                )?;
            } else {
                let values = super::super::super::native_effects::resolve(
                    template
                        .prior
                        .as_ref()
                        .ok_or(invalid("conflict history exact release prior"))?,
                    &ready.keys,
                )?;
                let key = if template.table == "conflict_resolution_objects" {
                    value_columns("objects", &values)?.0
                } else {
                    if template.table != "reference_reservation_objects" || values.len() != 2 {
                        return Err(invalid("conflict complete history release foreign table"));
                    }
                    (
                        template.table.clone(),
                        values
                            .iter()
                            .map(|v| match v {
                                Value::Text(s) => Ok(s.clone()),
                                _ => Err(invalid("conflict complete history key type")),
                            })
                            .collect::<Result<_>>()?,
                    )
                };
                if expected.remove(&key).is_none() {
                    return Err(invalid(
                        "conflict complete history original release pin missing",
                    ));
                }
                let mut issued = vec![
                    Value::Text(template.table.clone()),
                    Value::Text("delete".into()),
                ];
                issued.extend(values.clone());
                let _permit = self
                    .conflict_resolution_issuance
                    .final_permit(vec![issued])?;
                let sql = if template.table == "conflict_resolution_objects" {
                    "DELETE FROM main.conflict_resolution_objects WHERE transaction_id=?1 AND role=?2 AND content_id=?3 AND length=?4"
                } else {
                    "DELETE FROM main.reference_reservation_objects WHERE owner_id=?1 AND content_id=?2"
                };
                if tx.execute(sql, rusqlite::params_from_iter(values))? != 1 {
                    return Err(invalid("conflict complete history release exact row count"));
                }
            }
            fulfilled.insert(template.name.clone());
        }
        let after = self
            .read_view()
            .audit_local_commit_capacity(&parent.target.space_id, bounds)?;
        if row_map(&after.rows) != expected
            || !after.report.within_accounted_limits()
            || after.report.accounted_total().rows > before.report.accounted_total().rows
            || after.report.accounted_total().logical_bytes
                > before.report.accounted_total().logical_bytes
        {
            return Err(invalid(
                "conflict complete history handoff allmain capacity differs",
            ));
        }
        observed.verify_content()?;
        self.verify_conflict_creator_cas(admission)?;
        tx.commit()?;
        Ok(observed)
    }
}
