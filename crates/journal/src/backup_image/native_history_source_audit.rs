//! Bounded SELECT-only inspection of one complete original schema-69 image.
//! Owner relations and embedded reference columns come from the fixed registry.
use super::{
    native_history_family_registry::{
        NativeHistoryDirectReference, NativeHistoryFamilyRegistry, NativeHistoryOwnerRelation,
    },
    native_history_source_proof::{
        NativeHistoryCasReference, NativeHistoryHoldSpec, NativeHistoryProjectionPlan,
        NativeHistoryProofParts, NativeHistoryReferenceKind, NativeHistoryRootColumnMapping,
        NativeHistoryRootMapping, NativeHistoryRowKey, NativeHistorySourceTable,
    },
    readonly::{NodeInspectionBounds, configure_inspection},
};
use crate::{
    JournalError, JournalReadView, JournalStorageColumnValue, JournalStoredRow, Result,
    storage_inventory::reader::{ColumnKind, TableSpec, add, hash, preflight, read_table},
};
use rusqlite::{Connection, MAIN_DB, Transaction, TransactionBehavior};
use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Component, Path};
use sync_extend_core_model::{
    ChunkRef, ContentId, DeviceId, EntryId, FileManifest, SnapshotId, SpaceId,
};

/// Its fields are private to this audit module. Arbitrary summaries cannot be
/// supplied to the immutable proof's constructor as an audited source.
pub(super) struct AuditedNativeHistorySource {
    parts: NativeHistoryProofParts,
}

impl AuditedNativeHistorySource {
    pub(super) fn into_parts(self) -> NativeHistoryProofParts {
        self.parts
    }
}

fn invalid(message: &'static str) -> JournalError {
    JournalError::Invariant(message)
}

fn key(row: &JournalStoredRow) -> Result<NativeHistoryRowKey> {
    Ok(NativeHistoryRowKey {
        table: NativeHistoryFamilyRegistry::schema69()
            .table(row.table())?
            .table,
        primary_key: row.primary_key().to_vec(),
    })
}

fn column<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a JournalStorageColumnValue> {
    row.columns()
        .iter()
        .find(|column| column.name == name)
        .map(|column| &column.value)
        .ok_or(invalid("native history original column absent"))
}

fn text<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match column(row, name)? {
        JournalStorageColumnValue::Text(value) => Ok(value),
        _ => Err(invalid("native history original text required")),
    }
}

fn integer(row: &JournalStoredRow, name: &str) -> Result<u64> {
    match column(row, name)? {
        JournalStorageColumnValue::Integer(value) => Ok(*value),
        _ => Err(invalid("native history original integer required")),
    }
}

fn key_value(row: &JournalStoredRow, name: &str) -> Result<String> {
    match column(row, name)? {
        JournalStorageColumnValue::Text(value) => Ok(value.clone()),
        JournalStorageColumnValue::Integer(value) => Ok(value.to_string()),
        JournalStorageColumnValue::Null => Err(invalid("native history owner key is null")),
        JournalStorageColumnValue::Bytes(_) => Err(invalid("native history owner key is blob")),
    }
}

fn state<'a>(rows: &'a [JournalStoredRow], name: &str) -> Result<Option<&'a str>> {
    rows.iter()
        .find(|row| row.table() == "local_state" && row.primary_key() == [name])
        .map(|row| text(row, "value"))
        .transpose()
}

fn required_state<'a>(rows: &'a [JournalStoredRow], name: &str) -> Result<&'a str> {
    state(rows, name)?.ok_or(invalid("native history original identity absent"))
}

fn catalog(connection: &Connection, registry: NativeHistoryFamilyRegistry) -> Result<ContentId> {
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != NativeHistoryFamilyRegistry::SOURCE_SCHEMA {
        return Err(invalid("native history requires exact original schema69"));
    }
    let mut query = connection.prepare(
        "SELECT type,name,tbl_name,sql FROM main.sqlite_schema ORDER BY type,name LIMIT ?1",
    )?;
    let mut rows = query.query([registry.catalog().len() as i64 + 1])?;
    for expected in registry.catalog() {
        let row = rows
            .next()?
            .ok_or(invalid("native history original catalog object absent"))?;
        // Borrow original SQLite text. An oversized malicious catalog value is
        // rejected against the compiled length before copying into Rust.
        for (index, expected) in [(0, expected.kind), (1, expected.name), (2, expected.table)] {
            match row.get_ref(index)? {
                rusqlite::types::ValueRef::Text(value) if value == expected.as_bytes() => (),
                _ => return Err(invalid("native history original catalog identity differs")),
            }
        }
        match (row.get_ref(3)?, expected.sql) {
            (rusqlite::types::ValueRef::Null, None) => (),
            (rusqlite::types::ValueRef::Text(value), Some(expected))
                if value == expected.as_bytes() => {}
            _ => {
                return Err(invalid(
                    "native history complete original catalog SQL differs",
                ));
            }
        }
    }
    if rows.next()?.is_some() {
        return Err(invalid("native history extra original catalog family"));
    }
    hash(&(
        "sync-extend.native-history-source-catalog.v1",
        NativeHistoryFamilyRegistry::SOURCE_SCHEMA,
        registry.catalog(),
    ))
}

fn column_layout(connection: &Connection, specs: &[TableSpec]) -> Result<()> {
    let mut list = connection.prepare(
        "SELECT name,type,ncol,wr,strict FROM pragma_table_list
         WHERE schema='main' AND lower(substr(name,1,7))!='sqlite_' ORDER BY name",
    )?;
    let mut actual = list.query([])?;
    let mut seen = BTreeSet::new();
    while let Some(row) = actual.next()? {
        let name: String = row.get(0)?;
        let spec = specs
            .iter()
            .find(|spec| spec.name == name)
            .ok_or(invalid("native history unknown physical table"))?;
        if !seen.insert(name)
            || row.get::<_, String>(1)? != "table"
            || row.get::<_, i64>(2)? != spec.columns.len() as i64
            || row.get::<_, i64>(3)? != 0
            || row.get::<_, i64>(4)? != 1
        {
            return Err(invalid(
                "native history original strict table layout differs",
            ));
        }
        let mut query = connection.prepare(
            "SELECT cid,name,type,\"notnull\",dflt_value,pk,hidden
             FROM pragma_table_xinfo(?1,'main') ORDER BY cid",
        )?;
        let mut columns = query.query([spec.name])?;
        for (index, expected) in spec.columns.iter().enumerate() {
            let row = columns
                .next()?
                .ok_or(invalid("native history original physical column absent"))?;
            let declared = match expected.kind {
                ColumnKind::Integer => "INTEGER",
                ColumnKind::Text(_) | ColumnKind::Utf8 { .. } => "TEXT",
                ColumnKind::Blob { .. } => "BLOB",
            };
            if row.get::<_, i64>(0)? != index as i64
                || row.get::<_, String>(1)? != expected.name
                || row.get::<_, String>(2)? != declared
                || row.get::<_, bool>(3)? != expected.not_null
                || row.get::<_, Option<String>>(4)?.as_deref() != expected.default
                || row.get::<_, i64>(5)? != expected.primary_key as i64
                || row.get::<_, i64>(6)? != 0
            {
                return Err(invalid(
                    "native history original column or primary key differs",
                ));
            }
        }
        if columns.next()?.is_some() {
            return Err(invalid("native history extra original physical column"));
        }
    }
    if seen.len() != specs.len() {
        return Err(invalid("native history original table missing"));
    }
    let shadowed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema
         WHERE type IN ('table','view','trigger','index'))",
        [],
        |row| row.get(0),
    )?;
    if shadowed {
        return Err(invalid(
            "native history original inspection has temp shadow",
        ));
    }
    Ok(())
}

fn integrity(connection: &Connection) -> Result<()> {
    let mut query = connection.prepare("PRAGMA main.integrity_check(1)")?;
    let mut rows = query.query([])?;
    if rows
        .next()?
        .map(|row| row.get::<_, String>(0))
        .transpose()?
        .as_deref()
        != Some("ok")
        || rows.next()?.is_some()
    {
        return Err(invalid("native history original integrity check differs"));
    }
    let mut query = connection.prepare("PRAGMA main.foreign_key_check")?;
    if query.query([])?.next()?.is_some() {
        return Err(invalid("native history original foreign key orphan"));
    }
    Ok(())
}

fn original_identity(rows: &[JournalStoredRow], space: &SpaceId) -> Result<()> {
    if required_state(rows, "space_id")? != space.as_str() {
        return Err(invalid("native history original space differs"));
    }
    let _: DeviceId = required_state(rows, "device_id")?.parse()?;
    for row in rows {
        if row.columns().iter().any(|column| column.name == "space_id")
            && text(row, "space_id")? != space.as_str()
        {
            return Err(invalid("native history original row from foreign space"));
        }
    }
    match (state(rows, "worktree")?, state(rows, "storage_role")?) {
        (Some(worktree), None) => absolute_root(worktree)?,
        (None, Some("storage-v1")) => {
            let actual: Vec<_> = rows
                .iter()
                .filter(|row| row.table() == "local_state")
                .map(|row| text(row, "key"))
                .collect::<Result<_>>()?;
            if actual != ["device_id", "space_id", "storage_role"] {
                return Err(invalid(
                    "native history exact worktree-free storage identity",
                ));
            }
        }
        _ => {
            return Err(invalid(
                "native history original client or storage role differs",
            ));
        }
    }
    Ok(())
}

fn absolute_root(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 32_768
        || value.contains('\0')
        || !Path::new(value).is_absolute()
        || Path::new(value)
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(invalid(
            "native history explicit absolute root mapping required",
        ));
    }
    Ok(())
}

fn singleton_clocks(rows: &[JournalStoredRow]) -> Result<()> {
    for table in [
        "read_lease_clock",
        "gc_clock",
        "storage_retirement_clock",
        "unix_storage_retirement_v1_clock",
        "unix_storage_retirement_native_v1_clock",
        "webdav_native_clock",
    ] {
        let clocks: Vec<_> = rows.iter().filter(|row| row.table() == table).collect();
        if clocks.len() > 1
            || (table == "read_lease_clock" && clocks.len() != 1)
            || clocks
                .iter()
                .any(|row| !matches!(integer(row, "singleton"), Ok(1)))
        {
            return Err(invalid("native history original singleton clock shape"));
        }
    }
    Ok(())
}

fn publication_anchors(
    view: &JournalReadView<'_>,
    space: &SpaceId,
    publications: &[crate::Publication],
) -> Result<()> {
    // Reuse the original capacity owner's exact typed baseline/source/Final
    // contract. A descriptive state or terminal table is never sufficient.
    for publication in publications {
        let intent = &publication.intent;
        let baseline = view
            .retained_snapshot(space, &intent.baseline_root)?
            .manifest;
        let requested = baseline
            .entries
            .values()
            .find(|entry| entry.path == intent.requested_path);
        if requested != intent.requested_baseline.as_ref()
            || baseline.entries.contains_key(&intent.entry_id)
        {
            return Err(invalid(
                "native history publication original baseline differs",
            ));
        }
        if let Some(root) = &intent.source_snapshot {
            let source = view.retained_snapshot(space, root)?;
            if !source
                .manifest
                .entries
                .values()
                .any(|entry| entry.content.as_ref() == Some(&intent.content))
            {
                return Err(invalid(
                    "native history publication original source differs",
                ));
            }
        }
        if let Some(root) = &publication.committed_snapshot {
            let completed = view.retained_snapshot(space, root)?;
            if completed
                .manifest
                .entries
                .get(&intent.entry_id)
                .is_none_or(|entry| {
                    entry.path != intent.target_path
                        || entry.content.as_ref() != Some(&intent.content)
                })
            {
                return Err(invalid(
                    "native history publication original completion differs",
                ));
            }
        }
    }
    Ok(())
}

fn tree_preflight(connection: &Connection, max: usize) -> Result<()> {
    // The complete frozen table layout above replaces only the current-schema
    // gate. The original typed future/issuer/record audits remain mandatory.
    crate::tree_native_future::preflight_all(connection, max)?;
    let invalid_owner: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.tree_native_capacity_admissions c
            LEFT JOIN main.tree_restore_coordinator_admissions a USING(transaction_id)
            WHERE a.transaction_id IS NULL
            OR (SELECT count(*) FROM main.tree_native_action_headers
                WHERE transaction_id=c.transaction_id)!=1
            OR NOT EXISTS(SELECT 1 FROM main.tree_native_action_records
                WHERE transaction_id=c.transaction_id AND record_index=0))
         OR EXISTS(SELECT 1 FROM main.tree_native_action_headers h
            LEFT JOIN main.tree_native_capacity_admissions c USING(transaction_id)
            WHERE c.transaction_id IS NULL)
         OR EXISTS(SELECT 1 FROM main.tree_native_action_records r
            LEFT JOIN main.tree_native_action_headers h USING(transaction_id)
            WHERE h.transaction_id IS NULL)",
        [],
        |row| row.get(0),
    )?;
    if invalid_owner {
        return Err(invalid(
            "native history original TREE prewrite owner is incomplete",
        ));
    }
    Ok(())
}

fn typed_families(
    connection: &Connection,
    rows: &[JournalStoredRow],
    space: &SpaceId,
    bounds: NodeInspectionBounds,
) -> Result<Vec<crate::OriginalLinuxNativeFinalDiagnostic>> {
    let view = JournalReadView {
        connection,
        dav_read_charge_cache: None,
    };
    singleton_clocks(rows)?;
    crate::deletion_retention::audit(connection, space, bounds.max_entries)?;
    crate::webdav_native::audit(connection)?;
    tree_preflight(connection, bounds.max_entries)?;
    view.snapshot_audit(space)?;
    view.current(space)?;
    view.diagnostic_operation_count(space, bounds.max_entries)?;
    crate::rename_observation::audit_observation(connection, space, bounds.max_entries)?;
    view.read_leases(space)?;
    for mutation in view.mutations(space)? {
        view.verify_mutation_references(&mutation.intent.transaction_id)?;
    }
    let publications = view.publications(space)?;
    publication_anchors(&view, space, &publications)?;
    view.cleanup_plans(space)?;
    view.reference_reservations(space, bounds.max_entries)?;
    view.audit_original_disposals(space, bounds.max_entries)?;
    let marks = view.gc_marks(space)?;
    let authorizations = view.gc_authorizations(space, &marks)?;
    let executions = view.gc_executions(&authorizations)?;
    let quarantines = view.audit_gc_quarantines(&executions)?;
    view.audit_gc_disposals(&quarantines, &executions)?;
    view.audit_tree_restore_preparations(space, bounds.max_entries)?;
    crate::original_provenance::audit(connection)?;
    crate::original_page_inbox::audit(connection)?;
    crate::forwarded_page_inbox::audit(connection)?;
    crate::storage_page_handoff::audit(connection)?;
    crate::storage_snapshot_handoff::audit(connection)?;
    crate::storage_retirement::audit(connection)?;
    crate::storage_retirement::owner::audit(connection)?;
    crate::storage_retirement::payload::audit(connection)?;
    crate::storage_retirement::disposal::audit(connection)?;
    crate::storage_retirement::terminal::audit(connection)?;
    crate::storage_retirement_unix::audit(connection)?;
    crate::storage_retirement_unix::native::audit(connection)?;
    crate::remote_rename::obligations(rows, connection)?;
    crate::remote_delete::obligations(rows, connection)?;
    crate::remote_replace::obligations(rows, connection)?;
    crate::conflict_resolution::obligations(rows, connection)?;
    crate::native_publication::validate_schema(connection)?;
    crate::native_publication::scope(rows, connection)?;
    crate::native_publication::obligations(rows, &publications)?;
    crate::read_lease::recovery_hold::validate_rows(rows)?;
    crate::history_reservation::validate_cancellation_rows(rows)?;
    crate::history_reservation::validate_native_liability_rows(rows)?;
    crate::history_reservation::validate_native_phase_rows(rows)?;
    crate::history_reservation::audit_recovered_attempt_rows(rows, space, bounds.max_entries)?;
    crate::history_reservation::original_reserved_content(connection)?;
    crate::recovered_retention::audit(connection)?;
    // This read adapter reuses the original Final/context/THAWED/progress
    // validators. Its public Journal wrapper retains its original behavior.
    crate::history_reservation::audit_source_native_terminals(connection, bounds.max_entries)
}

fn typed_local_state(
    rows: &[JournalStoredRow],
    native_finals: &[crate::OriginalLinuxNativeFinalDiagnostic],
) -> Result<()> {
    let finals: BTreeMap<_, _> = native_finals
        .iter()
        .map(|value| (value.transaction_id.as_str(), value))
        .collect();
    for row in rows.iter().filter(|row| row.table() == "local_state") {
        let name = text(row, "key")?;
        let value = text(row, "value")?;
        match name {
            "space_id" | "device_id" | "worktree" | "storage_role" => (),
            "original_recovery_session" => {
                let _: SpaceId = value.parse()?;
            }
            crate::history_reservation::KEY | crate::read_lease::recovery_hold::KEY => (),
            _ if name.starts_with("original.local-history.cancelled.v1.")
                || name.starts_with("original.native-create.liability.v1.")
                || name.starts_with("original.native-create.cursor.v1.")
                || name.starts_with("original.native-create.phase.v1.")
                || name.starts_with(crate::recovered_retention::RETAIN)
                || name.starts_with(crate::recovered_retention::RELEASE) => {}
            _ if name.starts_with("original.linux-native.") => {
                let expected = [
                    ("original.linux-native.final.v1.", false),
                    ("original.linux-native.thawed.v1.", false),
                    ("original.linux-native.cleanup-prepared.v1.", false),
                    ("original.linux-native.cleaned.v1.", false),
                    ("original.linux-native.successor.v1.", true),
                ]
                .into_iter()
                .find_map(|(prefix, successor)| {
                    name.strip_prefix(prefix)
                        .map(|attempt| (attempt, successor))
                })
                .ok_or(invalid(
                    "native history unknown Linux terminal state version",
                ))?;
                if !finals.contains_key(expected.0) {
                    return Err(invalid(
                        "native history Linux terminal has no typed original Final",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "native history unknown original local state family",
                ));
            }
        }
    }
    successors(rows, &finals)
}

type OriginalSuccessorTuple = (
    u32,
    [u8; 16],
    u64,
    u64,
    EntryId,
    ContentId,
    ContentId,
    ContentId,
    SnapshotId,
    Option<ContentId>,
);

fn successors(
    rows: &[JournalStoredRow],
    finals: &BTreeMap<&str, &crate::OriginalLinuxNativeFinalDiagnostic>,
) -> Result<()> {
    let mut generations: BTreeMap<[u8; 16], BTreeMap<u64, (ContentId, Option<ContentId>)>> =
        BTreeMap::new();
    for row in rows.iter().filter(|row| {
        row.table() == "local_state"
            && row
                .primary_key()
                .first()
                .is_some_and(|key| key.starts_with("original.linux-native.successor.v1."))
    }) {
        let json = text(row, "value")?;
        let value: OriginalSuccessorTuple = serde_json::from_str(json)?;
        let name = format!("original.linux-native.successor.v1.{}", value.4);
        let final_record = finals
            .get(value.4.as_str())
            .ok_or(invalid("native history successor original Final absent"))?;
        if value.0 != 1
            || text(row, "key")? != name
            || value.2.checked_add(1) != Some(value.3)
            || value.3 > i64::MAX as u64
            || serde_json::to_string(&value)? != json
            || value.8 != final_record.snapshot_id
            || !final_record.helper_thawed
            || !final_record.cleanup_completed
        {
            return Err(invalid("native history original successor tuple differs"));
        }
        for (prefix, digest) in [
            ("original.linux-native.final.v1.", &value.5),
            ("original.linux-native.thawed.v1.", &value.6),
            ("original.linux-native.cleaned.v1.", &value.7),
        ] {
            let original = required_state(rows, &format!("{prefix}{}", value.4))?;
            if ContentId::hash(original.as_bytes()) != *digest {
                return Err(invalid(
                    "native history successor immutable parent digest differs",
                ));
            }
        }
        if generations
            .entry(value.1)
            .or_default()
            .insert(value.2, (ContentId::hash(json.as_bytes()), value.9))
            .is_some()
        {
            return Err(invalid(
                "native history original successor sequence duplicated",
            ));
        }
    }
    for sequence in generations.into_values() {
        let mut previous = None;
        for (expected, (ordinal, (digest, parent))) in sequence.into_iter().enumerate() {
            if ordinal != expected as u64 || parent != previous {
                return Err(invalid(
                    "native history original successor sequence skipped",
                ));
            }
            previous = Some(digest);
        }
    }
    Ok(())
}

fn local_anchor(
    row: &JournalStoredRow,
    rows: &BTreeMap<NativeHistoryRowKey, &JournalStoredRow>,
) -> Result<(NativeHistoryRowKey, &'static str)> {
    let name = text(row, "key")?;
    let (anchor_name, family) = match name {
        "space_id" | "device_id" | "worktree" | "storage_role" => {
            ("device_id".to_owned(), "local_history_identity")
        }
        "original_recovery_session" => (name.to_owned(), "local_history_identity"),
        crate::read_lease::recovery_hold::KEY => (name.to_owned(), "read_lease"),
        crate::history_reservation::KEY => (name.to_owned(), "local_history_identity"),
        _ if name.starts_with("original.native-create.cursor.v1.")
            || name.starts_with("original.native-create.phase.v1.") =>
        {
            let tail = name
                .strip_prefix("original.native-create.cursor.v1.")
                .or_else(|| name.strip_prefix("original.native-create.phase.v1."))
                .ok_or(invalid("native history native cursor owner prefix"))?;
            let attempt = tail
                .get(..32)
                .ok_or(invalid("native history native cursor owner key"))?;
            let _: EntryId = attempt.parse()?;
            (
                format!("original.native-create.liability.v1.{attempt}"),
                "local_history_identity",
            )
        }
        _ if name.starts_with("original.native-create.liability.v1.")
            || name.starts_with("original.local-history.cancelled.v1.") =>
        {
            (name.to_owned(), "local_history_identity")
        }
        _ if name.starts_with("original.linux-native.") => {
            let attempt = name
                .rsplit_once('.')
                .map(|(_, attempt)| attempt)
                .ok_or(invalid("native history Linux original owner key"))?;
            let _: EntryId = attempt.parse()?;
            (
                format!("original.linux-native.final.v1.{attempt}"),
                "local_history_identity",
            )
        }
        _ if name.starts_with(crate::recovered_retention::RETAIN) => {
            (name.to_owned(), "reference_reservation")
        }
        _ if name.starts_with(crate::recovered_retention::RELEASE) => {
            let owner = name
                .strip_prefix(crate::recovered_retention::RELEASE)
                .ok_or(invalid("native history recovered release owner prefix"))?;
            (
                format!("{}{owner}", crate::recovered_retention::RETAIN),
                "reference_reservation",
            )
        }
        _ => return Err(invalid("native history local state owner adapter absent")),
    };
    let anchor = NativeHistoryRowKey {
        table: "local_state",
        primary_key: vec![anchor_name],
    };
    if !rows.contains_key(&anchor) {
        return Err(invalid("native history original local owner header absent"));
    }
    Ok((anchor, family))
}

fn owner_anchor(
    row: &JournalStoredRow,
    all: &BTreeMap<NativeHistoryRowKey, &JournalStoredRow>,
    registry: NativeHistoryFamilyRegistry,
) -> Result<(NativeHistoryRowKey, &'static str)> {
    let mut current = row;
    let mut visited = BTreeSet::new();
    for _ in 0..NativeHistoryFamilyRegistry::TABLE_COUNT {
        let current_key = key(current)?;
        if !visited.insert(current_key.clone()) {
            return Err(invalid("native history compiled original owner cycle"));
        }
        let rule = registry.table(current.table())?;
        match rule.owner {
            NativeHistoryOwnerRelation::Anchor => return Ok((current_key, rule.family)),
            NativeHistoryOwnerRelation::LocalIdentityOrTypedHistory => {
                return local_anchor(current, all);
            }
            NativeHistoryOwnerRelation::Child { parent, columns } => {
                let parent_key = NativeHistoryRowKey {
                    table: parent,
                    primary_key: columns
                        .iter()
                        .map(|(from, _)| key_value(current, from))
                        .collect::<Result<_>>()?,
                };
                current = all.get(&parent_key).copied().ok_or(invalid(
                    "native history original owner child has no exact header",
                ))?;
            }
        }
    }
    Err(invalid("native history original owner resolution bound"))
}

struct ReferenceCollector<'a> {
    row: &'a JournalStoredRow,
    source_column: &'a str,
    max: usize,
    remaining: &'a mut usize,
    references: Vec<NativeHistoryCasReference>,
}

impl ReferenceCollector<'_> {
    fn push(
        &mut self,
        path: &str,
        kind: NativeHistoryReferenceKind,
        content_id: ContentId,
        length: u64,
    ) -> Result<()> {
        if path.len() > 4096
            || self.references.len() >= self.max
            || *self.remaining == 0
            || (kind.is_cas_object() && !(1..=4 * 1024 * 1024).contains(&length))
        {
            return Err(invalid(
                "native history original reference count length or path bound",
            ));
        }
        *self.remaining -= 1;
        self.references.push(NativeHistoryCasReference {
            kind,
            content_id,
            length,
            source: key(self.row)?,
            source_column: if path.is_empty() {
                self.source_column.to_owned()
            } else {
                format!("{}{path}", self.source_column)
            },
        });
        Ok(())
    }

    fn file(&mut self, path: &str, file: FileManifest) -> Result<()> {
        file.validate()?;
        self.push(
            path,
            NativeHistoryReferenceKind::FileContentDigest,
            file.content_id,
            file.length,
        )?;
        for (index, chunk) in file.chunks.into_iter().enumerate() {
            self.push(
                &format!("{path}/chunks/{index}"),
                NativeHistoryReferenceKind::CasChunk,
                chunk.content_id,
                u64::from(chunk.length),
            )?;
        }
        Ok(())
    }

    fn json(&mut self, value: &serde_json::Value, path: &str, depth: usize) -> Result<()> {
        if depth > 64 || path.len() > 4096 {
            return Err(invalid(
                "native history original embedded reference depth bound",
            ));
        }
        match value {
            serde_json::Value::Object(object) => {
                if object.contains_key("chunking")
                    || object.contains_key("hash_algorithm")
                    || object.contains_key("compression")
                {
                    // Use the original core decoder, including deny_unknown_fields.
                    // A FileManifest's whole hash is separate from its CAS chunks.
                    return self.file(path, serde_json::from_value(value.clone())?);
                }
                if object.len() == 2
                    && object.contains_key("content_id")
                    && object.contains_key("length")
                {
                    let chunk: ChunkRef = serde_json::from_value(value.clone())?;
                    return self.push(
                        path,
                        NativeHistoryReferenceKind::CasChunk,
                        chunk.content_id,
                        u64::from(chunk.length),
                    );
                }
                for (name, child) in object {
                    let next = format!("{path}/{}", name.replace('~', "~0").replace('/', "~1"));
                    if matches!(name.as_str(), "original_reservation" | "reservation_json")
                        && child.is_string()
                    {
                        let encoded = child.as_str().ok_or(invalid(
                            "native history original embedded reservation string",
                        ))?;
                        crate::history_reservation::persisted_charge(encoded, self.max)?;
                        self.json(&serde_json::from_str(encoded)?, &next, depth + 1)?;
                    } else if name == "protected_objects" || (name == "chunks" && child.is_object())
                    {
                        let chunks: BTreeMap<ContentId, u32> =
                            serde_json::from_value(child.clone())?;
                        for (id, length) in chunks {
                            self.push(
                                &format!("{next}/{id}"),
                                NativeHistoryReferenceKind::CasChunk,
                                id,
                                u64::from(length),
                            )?;
                        }
                    } else {
                        self.json(child, &next, depth + 1)?;
                    }
                }
            }
            serde_json::Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    self.json(child, &format!("{path}/{index}"), depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
}

fn references(
    connection: &Connection,
    rows: &[JournalStoredRow],
    registry: NativeHistoryFamilyRegistry,
    max: usize,
) -> Result<BTreeMap<NativeHistoryRowKey, Vec<NativeHistoryCasReference>>> {
    let mut result: BTreeMap<_, Vec<_>> = BTreeMap::new();
    let mut lengths = BTreeMap::new();
    let mut whole_lengths = BTreeMap::new();
    let mut remaining = max;
    for row in rows {
        let rule = registry.table(row.table())?;
        let mut embedded = rule.audited_embedded_columns.to_vec();
        if row.table() == "local_state" {
            let name = text(row, "key")?;
            if name == crate::history_reservation::KEY
                || name.starts_with("original.native-create.liability.v1.")
                || name.starts_with("original.linux-native.final.v1.")
                || name.starts_with(crate::recovered_retention::RETAIN)
            {
                embedded.push("value");
            }
        }
        for name in embedded {
            let original = match column(row, name)? {
                JournalStorageColumnValue::Null => continue,
                JournalStorageColumnValue::Text(value) => value,
                _ => {
                    return Err(invalid(
                        "native history embedded original JSON type differs",
                    ));
                }
            };
            let mut collector = ReferenceCollector {
                row,
                source_column: name,
                max,
                remaining: &mut remaining,
                references: Vec::new(),
            };
            let value: serde_json::Value = serde_json::from_str(original)?;
            collector.json(&value, "", 0)?;
            for reference in &collector.references {
                let sizes = if reference.kind.is_cas_object() {
                    &mut lengths
                } else {
                    &mut whole_lengths
                };
                if sizes
                    .insert(reference.content_id.clone(), reference.length)
                    .is_some_and(|old| old != reference.length)
                {
                    return Err(invalid(
                        "native history original content has conflicting lengths",
                    ));
                }
            }
            result
                .entry(key(row)?)
                .or_default()
                .extend(collector.references);
        }
    }
    // These exact original typed observations carry chunk lengths even without
    // a FileManifest (for example a terminal GC object or retirement fence).
    let view = JournalReadView {
        connection,
        dav_read_charge_cache: None,
    };
    for mark in view.gc_marks(&required_state(rows, "space_id")?.parse::<SpaceId>()?)? {
        insert_length(
            &mut lengths,
            mark.intent.content_id,
            u64::from(mark.intent.observation.length),
        )?;
    }
    for admission in crate::storage_retirement::audit(connection)? {
        insert_length(
            &mut lengths,
            admission.request.content_id,
            u64::from(admission.request.length),
        )?;
    }
    for admission in crate::storage_retirement_unix::audit(connection)? {
        insert_length(
            &mut lengths,
            admission.request.content_id,
            u64::from(admission.request.binding.length),
        )?;
    }
    for row in rows {
        let rule = registry.table(row.table())?;
        let (kind, name, length_column) = match rule.direct_reference {
            NativeHistoryDirectReference::None => continue,
            NativeHistoryDirectReference::CasChunk {
                column,
                length_column,
            } => (NativeHistoryReferenceKind::CasChunk, column, length_column),
            NativeHistoryDirectReference::WholeFileDigest { column } => {
                (NativeHistoryReferenceKind::FileContentDigest, column, None)
            }
        };
        let id: ContentId = text(row, name)?.parse()?;
        let known = if kind.is_cas_object() {
            &mut lengths
        } else {
            &mut whole_lengths
        };
        let length = if let Some(name) = length_column {
            let length = integer(row, name)?;
            insert_length(known, id.clone(), length)?;
            length
        } else {
            *known.get(&id).ok_or(invalid(
                "native history direct reference typed length absent",
            ))?
        };
        if remaining == 0 {
            return Err(invalid(
                "native history direct original reference count bound",
            ));
        }
        remaining -= 1;
        result
            .entry(key(row)?)
            .or_default()
            .push(NativeHistoryCasReference {
                kind,
                content_id: id,
                length,
                source: key(row)?,
                source_column: name.to_owned(),
            });
    }
    // Existing recovered holds can list pins as IDs. Their original typed
    // decoder has already verified scope, lineage, release and exact bytes.
    for record in crate::recovered_retention::audit(connection)? {
        let source = NativeHistoryRowKey {
            table: "local_state",
            primary_key: vec![format!(
                "{}{}",
                crate::recovered_retention::RETAIN,
                record.mapping.retention_id
            )],
        };
        for id in record.mapping.pins {
            let length = *lengths.get(&id).ok_or(invalid(
                "native history recovered pin original chunk length absent",
            ))?;
            if remaining == 0 {
                return Err(invalid(
                    "native history recovered owner reference count bound",
                ));
            }
            remaining -= 1;
            result
                .entry(source.clone())
                .or_default()
                .push(NativeHistoryCasReference {
                    kind: NativeHistoryReferenceKind::CasChunk,
                    content_id: id.clone(),
                    length,
                    source: source.clone(),
                    source_column: format!("value/pins/{id}"),
                });
        }
    }
    Ok(result)
}

fn insert_length(lengths: &mut BTreeMap<ContentId, u64>, id: ContentId, length: u64) -> Result<()> {
    if !(1..=4 * 1024 * 1024).contains(&length)
        || lengths.insert(id, length).is_some_and(|old| old != length)
    {
        return Err(invalid("native history original CAS chunk length differs"));
    }
    Ok(())
}

struct OwnerRows {
    family: &'static str,
    rows: Vec<NativeHistoryRowKey>,
    references: BTreeSet<NativeHistoryCasReference>,
}

fn holds(
    rows: &[JournalStoredRow],
    mut references: BTreeMap<NativeHistoryRowKey, Vec<NativeHistoryCasReference>>,
    registry: NativeHistoryFamilyRegistry,
    bounds: NodeInspectionBounds,
) -> Result<Vec<NativeHistoryHoldSpec>> {
    let all: BTreeMap<_, _> = rows
        .iter()
        .map(|row| Ok((key(row)?, row)))
        .collect::<Result<_>>()?;
    if all.len() != rows.len() {
        return Err(invalid("native history original table key duplicated"));
    }
    let mut owners: BTreeMap<NativeHistoryRowKey, OwnerRows> = BTreeMap::new();
    for row in rows {
        let (anchor, family) = owner_anchor(row, &all, registry)?;
        if owners.len() >= bounds.max_entries && !owners.contains_key(&anchor) {
            return Err(invalid(
                "native history independent original owner count bound",
            ));
        }
        let owner = owners.entry(anchor).or_insert_with(|| OwnerRows {
            family,
            rows: Vec::new(),
            references: BTreeSet::new(),
        });
        if owner.family != family {
            return Err(invalid("native history owner family differs"));
        }
        let source = key(row)?;
        owner.rows.push(source.clone());
        owner
            .references
            .extend(references.remove(&source).unwrap_or_default());
    }
    if !references.is_empty() {
        return Err(invalid("native history reference has no original owner"));
    }
    let mut result = Vec::new();
    let mut encoded_bytes = 0;
    for (anchor, mut owner) in owners {
        owner.rows.sort();
        if !owner.rows.contains(&anchor) {
            return Err(invalid("native history independent owner header omitted"));
        }
        let objects: Vec<_> = owner.references.into_iter().collect();
        let description = (
            "sync-extend.native-history-original-owner-hold.v1",
            owner.family,
            &anchor,
            &owner.rows,
            &objects,
        );
        let (digest, bytes) =
            bounded_digest(&description, bounds.capacity.inventory.max_logical_bytes)?;
        encoded_bytes = add(encoded_bytes, bytes)?;
        if encoded_bytes > bounds.capacity.inventory.max_logical_bytes {
            return Err(invalid(
                "native history complete original hold metadata byte bound",
            ));
        }
        result.push(NativeHistoryHoldSpec {
            family: owner.family,
            anchor,
            source_rows: owner.rows,
            objects,
            digest,
        });
    }
    Ok(result)
}

fn projection(
    rows: &[JournalStoredRow],
    registry: NativeHistoryFamilyRegistry,
    roots: &[NativeHistoryRootMapping],
    bounds: NodeInspectionBounds,
) -> Result<NativeHistoryProjectionPlan> {
    let mut mappings = Vec::new();
    let worktree = state(rows, "worktree")?;
    match worktree {
        Some(original) if roots.len() == 1 => {
            let mapping = &roots[0];
            absolute_root(mapping.original_worktree())?;
            absolute_root(mapping.projected_worktree())?;
            if mapping.original_worktree() != original
                || mapping.original_worktree() == mapping.projected_worktree()
            {
                return Err(invalid(
                    "native history actual original root mapping differs",
                ));
            }
            mappings.push(NativeHistoryRootColumnMapping {
                source: NativeHistoryRowKey {
                    table: "local_state",
                    primary_key: vec!["worktree".to_owned()],
                },
                column: "value",
                original: original.to_owned(),
                projected: mapping.projected_worktree().to_owned(),
            });
        }
        None if roots.is_empty() => (),
        _ => {
            return Err(invalid(
                "native history explicit complete root mapping required",
            ));
        }
    }
    let materialized: BTreeSet<_> = rows
        .iter()
        .filter(|row| row.table() == "operations")
        .filter_map(|row| match text(row, "state") {
            Ok("materialized") => Some(text(row, "op_id").map(str::to_owned)),
            Ok("received" | "pending") => None,
            _ => Some(Err(invalid(
                "native history original operation state differs",
            ))),
        })
        .collect::<Result<_>>()?;
    let mut portable = Vec::new();
    for row in rows {
        let rule = registry.table(row.table())?;
        let safe = match row.table() {
            "local_state" => matches!(
                row.primary_key(),
                [key] if matches!(key.as_str(), "space_id" | "device_id" | "worktree" | "storage_role")
            ),
            "operations" => materialized.contains(text(row, "op_id")?),
            "original_operation_provenance" => materialized.contains(text(row, "op_id")?),
            "deletion_retention_observations" => materialized.contains(text(row, "operation_id")?),
            // Old inbox acknowledgements and receive cursors are immutable
            // original source data. A fresh session has independent cursors.
            "receive_cursors" | "original_page_inbox" | "forwarded_page_inbox" => false,
            _ => rule.portable_state,
        };
        if safe {
            portable.push(key(row)?);
        }
    }
    portable.sort();
    let (digest, _) = bounded_digest(
        &(
            "sync-extend.native-history-independent-active-projection.v1",
            &portable,
            &mappings,
        ),
        bounds.capacity.inventory.max_logical_bytes,
    )?;
    Ok(NativeHistoryProjectionPlan {
        portable_rows: portable,
        root_columns: mappings,
        digest,
    })
}

struct BoundedHashWriter {
    hasher: blake3::Hasher,
    bytes: u64,
    max: u64,
}

impl Write for BoundedHashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= self.max)
            .ok_or_else(|| std::io::Error::other("native history encoded byte bound"))?;
        self.hasher.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_digest<T: Serialize>(value: &T, max: u64) -> Result<(ContentId, u64)> {
    let mut writer = BoundedHashWriter {
        hasher: blake3::Hasher::new(),
        bytes: 0,
        max,
    };
    serde_json::to_writer(&mut writer, value)?;
    Ok((ContentId::from_hasher(&writer.hasher), writer.bytes))
}

struct InspectionBudget(NodeInspectionBounds);
impl Serialize for InspectionBudget {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        (
            self.0.max_entries,
            self.0.capacity,
            self.0.max_vm_instructions,
            self.0.max_query_time.as_nanos(),
        )
            .serialize(serializer)
    }
}

pub(super) fn audit(
    image: Vec<u8>,
    expected_digest: &str,
    max_image_bytes: usize,
    space: &SpaceId,
    roots: &[NativeHistoryRootMapping],
    bounds: NodeInspectionBounds,
) -> Result<AuditedNativeHistorySource> {
    bounds.validate()?;
    super::limit(max_image_bytes)?;
    if image.len() < super::MIN_IMAGE_BYTES
        || image.len() > max_image_bytes
        || expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || image.get(..16) != Some(b"SQLite format 3\0")
        || image.get(18..20) != Some(&[1, 1])
    {
        return Err(invalid(
            "native history bounded standalone original image required",
        ));
    }
    let image_digest = ContentId::hash(&image);
    if image_digest.as_str() != expected_digest {
        return Err(invalid("native history original image digest differs"));
    }
    let registry = NativeHistoryFamilyRegistry::schema69();
    registry.verify_complete()?;
    let mut database = Connection::open_in_memory()?;
    database.deserialize_read_exact(MAIN_DB, std::io::Cursor::new(&image), image.len(), true)?;
    configure_inspection(&mut database, bounds)?;
    database.busy_timeout(std::time::Duration::ZERO)?;
    let transaction = Transaction::new_unchecked(&database, TransactionBehavior::Deferred)?;
    let before_changes = database.total_changes();
    let catalog_digest = catalog(&database, registry)?;
    let specs = NativeHistoryFamilyRegistry::row_specs();
    column_layout(&database, &specs)?;
    integrity(&database)?;
    let table_counts = preflight(
        &database,
        &specs,
        bounds.capacity.inventory.max_rows,
        bounds.capacity.inventory.max_logical_bytes,
    )?;
    let mut rows = Vec::new();
    let mut tables = Vec::new();
    let mut total_bytes = 0;
    for (spec, count) in specs.iter().zip(&table_counts) {
        let values = read_table(&database, spec, count)?;
        total_bytes = add(total_bytes, count.logical_bytes)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"sync-extend.native-history-original-table.v1");
        hasher.update(&(spec.name.len() as u64).to_le_bytes());
        hasher.update(spec.name.as_bytes());
        hasher.update(&count.rows.to_le_bytes());
        hasher.update(&count.logical_bytes.to_le_bytes());
        for value in &values {
            hasher.update(value.fingerprint().as_str().as_bytes());
        }
        tables.push(NativeHistorySourceTable {
            table: spec.name,
            rows: count.rows,
            logical_bytes: count.logical_bytes,
            digest: ContentId::from_hasher(&hasher),
        });
        rows.extend(values);
    }
    if rows.len() as u64 > bounds.capacity.max_rows
        || total_bytes > bounds.capacity.max_logical_bytes
        || tables.len() != NativeHistoryFamilyRegistry::TABLE_COUNT
    {
        return Err(invalid(
            "native history complete original source capacity exceeded",
        ));
    }
    original_identity(&rows, space)?;
    let native_finals = typed_families(&database, &rows, space, bounds)?;
    typed_local_state(&rows, &native_finals)?;
    // Validation is complete before a reference is attributed or a hold exists.
    let references = references(&database, &rows, registry, bounds.max_entries)?;
    let owners = holds(&rows, references, registry, bounds)?;
    let projection = projection(&rows, registry, roots, bounds)?;
    let rows_digest = hash(&(
        "sync-extend.native-history-all-original-rows.v1",
        NativeHistoryFamilyRegistry::SOURCE_SCHEMA,
        space,
        &tables,
        rows.iter()
            .map(JournalStoredRow::fingerprint)
            .collect::<Vec<_>>(),
    ))?;
    let registry_digest = hash(&(
        "sync-extend.native-history-compiled-schema69-registry.v1",
        registry.families(),
        registry.slices(),
        registry.tables(),
        registry.catalog(),
    ))?;
    let source_digest = hash(&(
        "sync-extend.immutable-native-history-source-proof.v1",
        NativeHistoryFamilyRegistry::SOURCE_SCHEMA,
        space,
        &image_digest,
        &catalog_digest,
        &rows_digest,
        &registry_digest,
        &tables,
        owners
            .iter()
            .map(NativeHistoryHoldSpec::digest)
            .collect::<Vec<_>>(),
        projection.digest(),
        InspectionBudget(bounds),
    ))?;
    if database.total_changes() != before_changes
        || catalog(&database, registry)? != catalog_digest
        || database.pragma_query_value(None, "query_only", |row| row.get::<_, i64>(0))? != 1
        || ContentId::hash(&image) != image_digest
    {
        return Err(invalid(
            "native history original source changed during pure inspection",
        ));
    }
    transaction.rollback()?;
    database
        .close()
        .map_err(|(_, error)| JournalError::from(error))?;
    Ok(AuditedNativeHistorySource {
        parts: NativeHistoryProofParts {
            image,
            space: space.clone(),
            image_digest,
            catalog_digest,
            rows_digest,
            source_digest,
            registry_digest,
            tables,
            rows,
            owners,
            projection,
            bounds,
        },
    })
}
