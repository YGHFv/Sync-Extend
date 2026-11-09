use super::{audit::Owners, JournalCapacityGap, JournalCapacityObligation};
use crate::{
    storage_inventory::reader::invalid, CleanupState, GcDisposalState, GcExecutionState,
    GcQuarantineState, GcState, JournalStorageColumnValue, JournalStoredRow, MutationAction,
    MutationExecution, MutationState, PublicationState, ReadLeaseState, Result,
};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    reference_owner::ReferenceOwnerKind, tree_storage_capacity::TreeStorageCharge, ContentId,
};

pub(super) struct Liabilities {
    pub obligations: Vec<JournalCapacityObligation>,
    pub gaps: Vec<JournalCapacityGap>,
}

impl Liabilities {
    fn push(&mut self, family: &'static str, key: Vec<String>, rows: u64, bytes: u64) {
        if rows != 0 || bytes != 0 {
            self.obligations.push(JournalCapacityObligation {
                family,
                owner_key: key,
                charge: TreeStorageCharge {
                    rows,
                    logical_bytes: bytes,
                },
            });
        }
    }
    fn gap(&mut self, family: &'static str, key: String, contract: &'static str) {
        self.gaps.push(JournalCapacityGap {
            family,
            owner_key: vec![key],
            missing_contract: contract,
        });
    }
}

pub(super) fn text<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|c| c.name == name)
        .map(|c| &c.value)
    {
        Some(JournalStorageColumnValue::Text(value)) => Ok(value),
        _ => Err(invalid("journal capacity expected text column")),
    }
}

pub(super) fn integer(row: &JournalStoredRow, name: &str) -> Result<u64> {
    match row
        .columns()
        .iter()
        .find(|c| c.name == name)
        .map(|c| &c.value)
    {
        Some(JournalStorageColumnValue::Integer(value)) => Ok(*value),
        _ => Err(invalid("journal capacity expected integer column")),
    }
}

fn execution_bytes(action: &MutationAction) -> Result<u64> {
    // Only serialization width is returned. This candidate is never evidence.
    let width = MutationExecution {
        execution_id: "0".repeat(32).parse()?,
        directory_identity: ContentId::hash(b"private mutation width"),
        owner_identity: ContentId::hash(b"private owner width"),
        payload_identity: matches!(action, MutationAction::Replace { .. })
            .then(|| ContentId::hash(b"private payload width")),
    };
    Ok(serde_json::to_vec(&width)?.len() as u64)
}

pub(super) fn liabilities(owners: &Owners, rows: &[JournalStoredRow]) -> Result<Liabilities> {
    for row in rows.iter().filter(|r| r.table() == "publications") {
        if integer(row, "cleaned")? > 1 {
            return Err(invalid("journal capacity publication cleanup flag"));
        }
    }
    for table in ["read_lease_clock", "gc_clock"] {
        let clocks: Vec<_> = rows.iter().filter(|r| r.table() == table).collect();
        if clocks.len() > 1
            || (table == "read_lease_clock" && clocks.len() != 1)
            || clocks
                .iter()
                .any(|r| !matches!(integer(r, "singleton"), Ok(1)))
        {
            return Err(invalid("journal capacity singleton clock inventory"));
        }
    }
    let mut out = Liabilities {
        obligations: Vec::new(),
        gaps: Vec::new(),
    };
    for snapshot in &owners.snapshots {
        if snapshot.state == "metadata_only" {
            out.push(
                "snapshot_state_peak",
                vec![snapshot.snapshot_id.to_string()],
                0,
                1,
            );
        }
        if snapshot.state != "materialized" {
            out.gap(
                "snapshot",
                snapshot.snapshot_id.to_string(),
                "content-closure-materialization-protocol-not-implemented",
            );
        }
    }
    for lease in &owners.leases {
        if lease.state == ReadLeaseState::Active {
            out.push(
                "read_lease_terminal_peak",
                vec![lease.intent.lease_id.to_string()],
                0,
                10,
            );
        }
    }
    for plan in &owners.cleanup {
        let growth = match plan.state {
            CleanupState::Prepared => 15,
            CleanupState::Executing => 6,
            CleanupState::Cancelled | CleanupState::Cleaned => 0,
        };
        out.push(
            "cleanup_terminal_peak",
            vec![plan.intent.transaction_id.to_string()],
            0,
            growth,
        );
    }
    for publication in &owners.publications {
        let growth = match publication.state {
            PublicationState::Preparing | PublicationState::Published => 64,
            PublicationState::Ready => 68,
            PublicationState::Committed => 0,
        };
        let id = publication.intent.transaction_id.to_string();
        out.push("publication_terminal_columns", vec![id.clone()], 0, growth);
        if publication.state != PublicationState::Committed {
            if let Some(completion) = &publication.intent.completion {
                let charge = completion.charge()?;
                out.push(
                    "publication_exact_history_peak",
                    vec![id.clone()],
                    charge.rows,
                    charge.logical_bytes,
                );
                out.gap(
                    "publication",
                    id.clone(),
                    if rows.iter().any(|row| {
                        row.table() == "native_publication_headers"
                            && row.primary_key() == [id.clone()]
                    }) {
                        "native-ready-publishing-recovery-history-cleanup-not-implemented"
                    } else {
                        "native-creator-activation-provenance-not-implemented"
                    },
                );
            } else {
                out.gap(
                    "publication",
                    id,
                    "pre-effect-history-and-extra-scan-admission-not-converted",
                );
            }
        }
    }
    for mutation in &owners.mutations {
        let growth = match mutation.state {
            MutationState::Prepared => 129 + execution_bytes(&mutation.intent.action)?,
            MutationState::Executing => 64,
            MutationState::Quarantined => 62,
            MutationState::Moved => 68,
            MutationState::Replaced => 65,
            MutationState::Cancelled | MutationState::Committed => 0,
        };
        let id = mutation.intent.transaction_id.to_string();
        out.push("mutation_terminal_columns", vec![id.clone()], 0, growth);
        if mutation.state.active() {
            out.gap(
                "mutation",
                id,
                "pre-effect-exact-history-continuation-not-converted",
            );
        }
    }
    for owner in &owners.references {
        if owner.snapshot_handoff.is_none() && owner.state != "transferred_to_conflict_history" {
            let id = owner.intent.owner_id.to_string();
            match owner.intent.scope.kind {
                ReferenceOwnerKind::Download | ReferenceOwnerKind::Restore => {
                    out.push("local_snapshot_handoff", vec![id], 1, 160);
                }
                ReferenceOwnerKind::Upload
                | ReferenceOwnerKind::OfflineDelivery
                | ReferenceOwnerKind::Conflict => {
                    out.gap(
                        "reference_reservation",
                        id,
                        "unsupported-remote-terminal-pins-retained",
                    );
                }
            }
        }
    }
    for original in &owners.originals {
        if original.completed_at_ms.is_none() {
            out.push(
                "original_disposal_completion",
                vec![original.intent.scope.transaction_id.to_string()],
                1,
                136,
            );
        }
    }
    for mark in &owners.marks {
        if mark.state == GcState::Marked {
            out.push(
                "gc_invalidation",
                vec![mark.intent.mark_id.to_string()],
                1,
                32,
            );
        }
    }
    let live_disposal: BTreeSet<_> = owners
        .disposals
        .iter()
        .filter(|d| {
            matches!(
                d.state,
                GcDisposalState::DeletePending | GcDisposalState::RestorePending
            )
        })
        .map(|d| &d.intent.execution_id)
        .collect();
    for execution in &owners.executions {
        if execution.state == GcExecutionState::Fenced
            && !live_disposal.contains(&execution.intent.execution_id)
        {
            out.push(
                "gc_standalone_abort",
                vec![execution.intent.execution_id.to_string()],
                1,
                40,
            );
        }
    }
    for quarantine in &owners.quarantines {
        let growth = match quarantine.state {
            GcQuarantineState::Prepared => 7,
            GcQuarantineState::Quarantined => 4,
            GcQuarantineState::RestorePending
            | GcQuarantineState::Restored
            | GcQuarantineState::Deleted => 0,
        };
        out.push(
            "gc_quarantine_terminal_peak",
            vec![quarantine.intent.execution_id.to_string()],
            0,
            growth,
        );
    }
    for id in live_disposal {
        out.push(
            "gc_disposal_delete_or_abort_restore",
            vec![id.to_string()],
            2,
            80,
        );
    }
    operations(rows, &mut out)?;
    out.obligations
        .sort_by(|a, b| (&a.family, &a.owner_key).cmp(&(&b.family, &b.owner_key)));
    out.gaps
        .sort_by(|a, b| (&a.family, &a.owner_key).cmp(&(&b.family, &b.owner_key)));
    Ok(out)
}

fn operations(rows: &[JournalStoredRow], out: &mut Liabilities) -> Result<()> {
    let mut cursors = BTreeMap::new();
    let mut accepted: BTreeMap<(&str, &str), BTreeSet<u64>> = BTreeMap::new();
    let mut pending = BTreeMap::new();
    for row in rows.iter().filter(|r| r.table() == "receive_cursors") {
        let key = (text(row, "space_id")?, text(row, "device_id")?);
        if cursors
            .insert(key, integer(row, "contiguous_seq")?)
            .is_some()
        {
            return Err(invalid("journal capacity duplicate cursor"));
        }
    }
    for row in rows.iter().filter(|r| r.table() == "operations") {
        let state = text(row, "state")?;
        let key = (text(row, "space_id")?, text(row, "origin_device_id")?);
        let sequence = integer(row, "origin_seq")?;
        let growth = match state {
            "pending" => {
                if sequence <= cursors.get(&key).copied().unwrap_or(0) {
                    return Err(invalid("journal capacity pending cursor mismatch"));
                }
                pending.insert(key, ());
                5
            }
            "received" | "materialized" => {
                if !accepted.entry(key).or_default().insert(sequence) {
                    return Err(invalid("journal capacity duplicate received sequence"));
                }
                if state == "received" {
                    4
                } else {
                    0
                }
            }
            _ => return Err(invalid("journal capacity operation state")),
        };
        if state != "materialized" {
            out.gap(
                "received_operation",
                row.primary_key()[0].clone(),
                "remote-materialization-history-not-implemented",
            );
        }
        out.push(
            "operation_state_peak",
            row.primary_key().to_vec(),
            0,
            growth,
        );
    }
    for (&key, &cursor) in &cursors {
        let sequences = accepted.remove(&key).unwrap_or_default();
        if sequences.len() as u64 != cursor || sequences.last().copied().unwrap_or(0) != cursor {
            return Err(invalid("journal capacity contiguous cursor mismatch"));
        }
    }
    if !accepted.is_empty() {
        return Err(invalid("journal capacity received cursor missing"));
    }
    for (space, device) in pending.into_keys() {
        if !cursors.contains_key(&(space, device)) {
            out.push(
                "pending_origin_cursor",
                vec![space.into(), device.into()],
                1,
                104,
            );
        }
    }
    Ok(())
}
