use crate::{
    storage_capacity::CapacitySnapshot, JournalError, JournalStorageColumn,
    JournalStorageColumnValue, JournalStoredRow, ReceiveOutcome, Result,
};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    tree_storage_capacity::TreeStorageCharge, DeviceId, Operation, OperationId, SpaceId,
};

fn text<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(JournalStorageColumnValue::Text(value)) => Ok(value),
        _ => Err(JournalError::Invariant("receive expected text column")),
    }
}

fn integer(row: &JournalStoredRow, name: &str) -> Result<u64> {
    match row
        .columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
    {
        Some(JournalStorageColumnValue::Integer(value)) => Ok(*value),
        _ => Err(JournalError::Invariant("receive expected integer column")),
    }
}

fn text_column(name: &str, value: &str) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: JournalStorageColumnValue::Text(value.into()),
    }
}

fn integer_column(name: &str, value: u64) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: JournalStorageColumnValue::Integer(value),
    }
}

fn replace(
    columns: &mut [JournalStorageColumn],
    name: &str,
    value: JournalStorageColumnValue,
) -> Result<()> {
    columns
        .iter_mut()
        .find(|column| column.name == name)
        .ok_or(JournalError::Invariant("receive transition column missing"))?
        .value = value;
    Ok(())
}

pub(crate) fn tree_gate(before: &CapacitySnapshot) -> Result<()> {
    let cancelled: BTreeSet<_> = before
        .rows
        .iter()
        .filter(|row| row.table() == "tree_restore_cancellations")
        .map(JournalStoredRow::primary_key)
        .collect();
    if before.rows.iter().any(|row| {
        row.table() == "tree_restore_preparations" && !cancelled.contains(row.primary_key())
    }) {
        return Err(JournalError::Invariant(
            "prepared tree restore owns writer gate",
        ));
    }
    Ok(())
}

pub(crate) fn completion_gate(before: &CapacitySnapshot) -> Result<()> {
    for row in &before.rows {
        let active = match row.table() {
            // CapacitySnapshot has already reconstructed every immutable native
            // dependency; this is not an unaudited bare cleanup-phase escape.
            "conflict_resolution_admissions" => !before.rows.iter().any(|phase| {
                phase.table() == "conflict_resolution_native_phases"
                    && phase.primary_key().first() == row.primary_key().first()
                    && text(phase, "phase").ok() == Some("cleanup")
            }),
            "publications" => text(row, "state")? != "committed",
            "mutations" => !matches!(text(row, "state")?, "cancelled" | "committed"),
            _ => false,
        };
        if active {
            return Err(JournalError::Invariant(
                "active native completion defers new receive",
            ));
        }
    }
    Ok(())
}

pub(crate) struct Projection {
    promoted: BTreeSet<String>,
    promotions: Vec<Promotion>,
    cursors: BTreeMap<String, u64>,
    new_cursors: BTreeSet<String>,
    new_state: &'static str,
    charge: TreeStorageCharge,
}

pub(crate) struct Promotion {
    pub(crate) operation: OperationId,
    pub(crate) space: SpaceId,
    pub(crate) device: DeviceId,
    pub(crate) sequence: u64,
}

pub(crate) fn project(
    before: &CapacitySnapshot,
    incoming: &Operation,
    json: &str,
) -> Result<Projection> {
    let mut cursors = BTreeMap::new();
    for row in before
        .rows
        .iter()
        .filter(|row| row.table() == "receive_cursors")
    {
        cursors.insert(
            text(row, "device_id")?.to_string(),
            integer(row, "contiguous_seq")?,
        );
    }
    let prior_cursors = cursors.clone();
    let mut candidate_json = Vec::new();
    let mut pending_origin = false;
    for row in before.rows.iter().filter(|row| row.table() == "operations") {
        let same_origin =
            text(row, "origin_device_id")? == incoming.payload.origin_device_id.as_str();
        if same_origin && integer(row, "origin_seq")? == incoming.payload.origin_seq {
            return Err(JournalError::Invariant(
                "operation origin sequence collision",
            ));
        }
        if text(row, "state")? == "pending" {
            pending_origin |= same_origin;
            candidate_json.push(text(row, "payload")?);
        }
    }
    let new_cursor =
        !pending_origin && !prior_cursors.contains_key(incoming.payload.origin_device_id.as_str());
    let prior = before.report.accounted_total();
    let charge = TreeStorageCharge {
        rows: prior
            .rows
            .checked_add(1 + u64::from(new_cursor))
            .ok_or(JournalError::Invariant("receive row charge overflow"))?,
        logical_bytes: prior
            .logical_bytes
            .checked_add(json.len() as u64)
            .and_then(|bytes| bytes.checked_add(180 + 104 * u64::from(new_cursor)))
            .ok_or(JournalError::Invariant("receive byte charge overflow"))?,
    };
    let limits = before.report.limits();
    if charge.rows > limits.max_rows || charge.logical_bytes > limits.max_logical_bytes {
        return Err(JournalError::Invariant(
            "journal configured receive capacity exceeded",
        ));
    }
    let mut candidates = candidate_json
        .into_iter()
        .map(serde_json::from_str::<Operation>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    candidates.push(incoming.clone());
    let mut waiting: BTreeMap<String, BTreeMap<u64, Vec<usize>>> = BTreeMap::new();
    let mut missing = vec![0usize; candidates.len()];
    let mut ready = BTreeSet::new();
    for (index, op) in candidates.iter().enumerate() {
        for (device, sequence) in &op.payload.causal.0 {
            if cursors.get(device.as_str()).copied().unwrap_or(0) < *sequence {
                waiting
                    .entry(device.to_string())
                    .or_default()
                    .entry(*sequence)
                    .or_default()
                    .push(index);
                missing[index] += 1;
            }
        }
        if missing[index] == 0 {
            ready.insert((op.payload.origin_seq, index));
        }
    }
    let mut promoted = BTreeSet::new();
    let mut promotions = Vec::new();
    // Each missing causal edge is consumed at most once, without repeated queue scans.
    while let Some((_, index)) = ready.pop_first() {
        let op = &candidates[index];
        let payload = &op.payload;
        let next = cursors
            .get(payload.origin_device_id.as_str())
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(JournalError::Invariant(
                "receive cursor projection overflow",
            ))?;
        if payload.origin_seq != next || !promoted.insert(op.op_id.to_string()) {
            return Err(JournalError::Invariant(
                "receive causal projection discontinuity",
            ));
        }
        cursors.insert(payload.origin_device_id.to_string(), payload.origin_seq);
        promotions.push(Promotion {
            operation: op.op_id.clone(),
            space: payload.space_id.clone(),
            device: payload.origin_device_id.clone(),
            sequence: payload.origin_seq,
        });
        if let Some(thresholds) = waiting.get_mut(payload.origin_device_id.as_str()) {
            while thresholds
                .first_key_value()
                .is_some_and(|(&sequence, _)| sequence <= payload.origin_seq)
            {
                let (_, subscribers) = thresholds
                    .pop_first()
                    .ok_or(JournalError::Invariant("receive causal threshold missing"))?;
                for waiting_index in subscribers {
                    missing[waiting_index] = missing[waiting_index]
                        .checked_sub(1)
                        .ok_or(JournalError::Invariant("receive causal edge underflow"))?;
                    if missing[waiting_index] == 0 {
                        ready.insert((candidates[waiting_index].payload.origin_seq, waiting_index));
                    }
                }
            }
        }
    }
    let new_state = if promoted.contains(incoming.op_id.as_str()) {
        "received"
    } else {
        "pending"
    };
    cursors.retain(|device, sequence| prior_cursors.get(device) != Some(sequence));
    let new_cursors = cursors
        .keys()
        .filter(|device| !prior_cursors.contains_key(*device))
        .cloned()
        .collect();
    Ok(Projection {
        promoted,
        promotions,
        cursors,
        new_cursors,
        new_state,
        charge,
    })
}

impl Projection {
    pub(crate) fn promotions(&self) -> &[Promotion] {
        &self.promotions
    }

    pub(crate) fn receipt(
        &self,
        before: &CapacitySnapshot,
        after: &CapacitySnapshot,
        incoming: &Operation,
        json: &str,
        state: &str,
    ) -> Result<ReceiveOutcome> {
        let operation_key = [incoming.op_id.to_string()];
        let cursor_keys: Vec<_> = self
            .new_cursors
            .iter()
            .map(|device| [incoming.payload.space_id.to_string(), device.clone()])
            .collect();
        let mut remaining: BTreeMap<_, _> = after
            .rows
            .iter()
            .map(|row| ((row.table(), row.primary_key()), row.columns()))
            .collect();
        for row in &before.rows {
            let mut expected = row.columns().to_vec();
            if row.table() == "operations" && self.promoted.contains(text(row, "op_id")?) {
                replace(
                    &mut expected,
                    "state",
                    JournalStorageColumnValue::Text("received".into()),
                )?;
            } else if row.table() == "receive_cursors" {
                if let Some(sequence) = self.cursors.get(text(row, "device_id")?) {
                    replace(
                        &mut expected,
                        "contiguous_seq",
                        JournalStorageColumnValue::Integer(*sequence),
                    )?;
                }
            }
            if remaining.remove(&(row.table(), row.primary_key())) != Some(expected.as_slice()) {
                return Err(JournalError::Invariant(
                    "receive changed unrelated or unprojected values",
                ));
            }
        }
        let expected = [
            text_column("op_id", incoming.op_id.as_str()),
            text_column("space_id", incoming.payload.space_id.as_str()),
            text_column(
                "origin_device_id",
                incoming.payload.origin_device_id.as_str(),
            ),
            integer_column("origin_seq", incoming.payload.origin_seq),
            text_column("payload", json),
            text_column("state", self.new_state),
        ];
        if remaining.remove(&("operations", operation_key.as_slice())) != Some(expected.as_slice())
        {
            return Err(JournalError::Invariant(
                "receive exact operation receipt mismatch",
            ));
        }
        for (device, primary_key) in self.new_cursors.iter().zip(&cursor_keys) {
            let sequence = *self
                .cursors
                .get(device)
                .ok_or(JournalError::Invariant("receive projected cursor missing"))?;
            let expected = [
                text_column("space_id", incoming.payload.space_id.as_str()),
                text_column("device_id", device),
                integer_column("contiguous_seq", sequence),
            ];
            if remaining.remove(&("receive_cursors", primary_key.as_slice()))
                != Some(expected.as_slice())
            {
                return Err(JournalError::Invariant("receive exact new cursor mismatch"));
            }
        }
        if !remaining.is_empty()
            || after.report.accounted_total() != self.charge
            || !after.report.within_accounted_limits()
            || state != self.new_state
        {
            return Err(JournalError::Invariant(
                "receive exact capacity transition mismatch",
            ));
        }
        Ok(if state == "received" {
            ReceiveOutcome::Received
        } else {
            ReceiveOutcome::Pending
        })
    }
}
