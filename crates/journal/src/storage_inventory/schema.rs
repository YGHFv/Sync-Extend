// Pinned legacy general-table schema, independently recounted from SQLite.
use super::reader::{ColumnKind, ColumnSpec, TableSpec};
use crate::MAX_OPERATION_BYTES;

const fn column(
    name: &'static str,
    kind: ColumnKind,
    primary_key: usize,
    not_null: bool,
    default: Option<&'static str>,
) -> ColumnSpec {
    ColumnSpec {
        name,
        kind,
        primary_key,
        not_null,
        default,
    }
}

pub(super) const TABLES: &[TableSpec] = &[
    TableSpec {
        name: "cleanup_plans",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
            column("authorized_at_ms", ColumnKind::Integer, 0, false, None),
            column("cleaned_at_ms", ColumnKind::Integer, 0, false, None),
        ],
    },
    TableSpec {
        name: "current_manifests",
        columns: &[
            column("space_id", ColumnKind::Text(32), 1, true, None),
            column("snapshot_id", ColumnKind::Text(64), 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_authorizations",
        columns: &[
            column("authorization_id", ColumnKind::Text(32), 1, true, None),
            column("mark_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("authorized_at_ms", ColumnKind::Integer, 0, true, None),
            column("expires_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_cancellations",
        columns: &[
            column("mark_id", ColumnKind::Text(32), 1, true, None),
            column("cancelled_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_clock",
        columns: &[
            column("singleton", ColumnKind::Integer, 1, false, None),
            column("observed_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_disposal_restorations",
        columns: &[
            column("execution_id", ColumnKind::Text(32), 1, true, None),
            column(
                "restored_at_watermark_ms",
                ColumnKind::Integer,
                0,
                true,
                None,
            ),
        ],
    },
    TableSpec {
        name: "gc_disposals",
        columns: &[
            column("execution_id", ColumnKind::Text(32), 1, true, None),
            column("disposal_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("admitted_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_execution_aborts",
        columns: &[
            column("execution_id", ColumnKind::Text(32), 1, true, None),
            column(
                "aborted_at_watermark_ms",
                ColumnKind::Integer,
                0,
                true,
                None,
            ),
        ],
    },
    TableSpec {
        name: "gc_execution_deletions",
        columns: &[
            column("execution_id", ColumnKind::Text(32), 1, true, None),
            column(
                "deleted_at_watermark_ms",
                ColumnKind::Integer,
                0,
                true,
                None,
            ),
        ],
    },
    TableSpec {
        name: "gc_executions",
        columns: &[
            column("execution_id", ColumnKind::Text(32), 1, true, None),
            column("authorization_id", ColumnKind::Text(32), 0, true, None),
            column("content_id", ColumnKind::Text(64), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("admitted_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_invalidations",
        columns: &[column("mark_id", ColumnKind::Text(32), 1, true, None)],
    },
    TableSpec {
        name: "gc_marks",
        columns: &[
            column("mark_id", ColumnKind::Text(32), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column("content_id", ColumnKind::Text(64), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("marked_at_ms", ColumnKind::Integer, 0, true, None),
            column("grace_until_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_quarantines",
        columns: &[
            column("execution_id", ColumnKind::Text(32), 1, true, None),
            column("plan_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
        ],
    },
    TableSpec {
        name: "gc_revocations",
        columns: &[
            column("authorization_id", ColumnKind::Text(32), 1, true, None),
            column("revoked_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "local_state",
        columns: &[
            column(
                "key",
                ColumnKind::Utf8 {
                    min: 0,
                    max: MAX_OPERATION_BYTES,
                },
                1,
                true,
                None,
            ),
            column(
                "value",
                ColumnKind::Utf8 {
                    min: 0,
                    max: MAX_OPERATION_BYTES,
                },
                0,
                true,
                None,
            ),
        ],
    },
    TableSpec {
        name: "mutation_objects",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("content_id", ColumnKind::Text(64), 2, true, None),
        ],
    },
    TableSpec {
        name: "mutations",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column("baseline_root", ColumnKind::Text(64), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
            column(
                "execution",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                false,
                None,
            ),
            column("execution_hash", ColumnKind::Text(64), 0, false, None),
            column("committed_snapshot", ColumnKind::Text(64), 0, false, None),
        ],
    },
    TableSpec {
        name: "operations",
        columns: &[
            column("op_id", ColumnKind::Text(64), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column("origin_device_id", ColumnKind::Text(64), 0, true, None),
            column("origin_seq", ColumnKind::Integer, 0, true, None),
            column(
                "payload",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
        ],
    },
    TableSpec {
        name: "original_disposal_completions",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("plan_id", ColumnKind::Text(32), 0, true, None),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("completed_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "original_disposals",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("execution_id", ColumnKind::Text(32), 0, true, None),
            column("plan_id", ColumnKind::Text(32), 0, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("prepared_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "publication_objects",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("content_id", ColumnKind::Text(64), 2, true, None),
        ],
    },
    TableSpec {
        name: "publications",
        columns: &[
            column("transaction_id", ColumnKind::Text(32), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
            column("committed_snapshot", ColumnKind::Text(64), 0, false, None),
            column("cleaned", ColumnKind::Integer, 0, true, Some("0")),
        ],
    },
    TableSpec {
        name: "read_lease_clock",
        columns: &[
            column("singleton", ColumnKind::Integer, 1, false, None),
            column("observed_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "read_lease_objects",
        columns: &[
            column("lease_id", ColumnKind::Text(32), 1, true, None),
            column("content_id", ColumnKind::Text(64), 2, true, None),
        ],
    },
    TableSpec {
        name: "read_leases",
        columns: &[
            column("lease_id", ColumnKind::Text(32), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column("snapshot_id", ColumnKind::Text(64), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
            column("observed_at_ms", ColumnKind::Integer, 0, true, None),
            column("expires_at_ms", ColumnKind::Integer, 0, true, None),
            column("finished_at_ms", ColumnKind::Integer, 0, false, None),
        ],
    },
    TableSpec {
        name: "receive_cursors",
        columns: &[
            column("space_id", ColumnKind::Text(32), 1, true, None),
            column("device_id", ColumnKind::Text(64), 2, true, None),
            column("contiguous_seq", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "reference_reservation_objects",
        columns: &[
            column("owner_id", ColumnKind::Text(32), 1, true, None),
            column("content_id", ColumnKind::Text(64), 2, true, None),
        ],
    },
    TableSpec {
        name: "reference_reservations",
        columns: &[
            column("owner_id", ColumnKind::Text(32), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("created_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "reference_snapshot_handoffs",
        columns: &[
            column("owner_id", ColumnKind::Text(32), 1, true, None),
            column("snapshot_id", ColumnKind::Text(64), 0, true, None),
            column("owner_intent_hash", ColumnKind::Text(64), 0, true, None),
        ],
    },
    TableSpec {
        name: "rename_observations",
        columns: &[
            column("space_id", ColumnKind::Text(32), 1, true, None),
            column("snapshot_id", ColumnKind::Text(64), 0, true, None),
            column(
                "observation",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("observation_hash", ColumnKind::Text(64), 0, true, None),
        ],
    },
    TableSpec {
        name: "snapshot_objects",
        columns: &[
            column("snapshot_id", ColumnKind::Text(64), 1, true, None),
            column("content_id", ColumnKind::Text(64), 2, true, None),
        ],
    },
    TableSpec {
        name: "snapshot_prunings",
        columns: &[
            column("snapshot_id", ColumnKind::Text(64), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column("baseline_root", ColumnKind::Text(64), 0, true, None),
            column(
                "intent",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("intent_hash", ColumnKind::Text(64), 0, true, None),
            column("pruned_at_ms", ColumnKind::Integer, 0, true, None),
        ],
    },
    TableSpec {
        name: "snapshots",
        columns: &[
            column("snapshot_id", ColumnKind::Text(64), 1, true, None),
            column("space_id", ColumnKind::Text(32), 0, true, None),
            column(
                "manifest",
                ColumnKind::Text(MAX_OPERATION_BYTES),
                0,
                true,
                None,
            ),
            column("created_at_ms", ColumnKind::Integer, 0, true, None),
            column("state", ColumnKind::Utf8 { min: 1, max: 32 }, 0, true, None),
            column("locked", ColumnKind::Integer, 0, true, Some("0")),
        ],
    },
];
