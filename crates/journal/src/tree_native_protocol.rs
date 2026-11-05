//! Immutable actual-admission-bound descriptions, never native effect evidence.
use crate::{
    check_storage_metadata_limit, sql_integer, CasAccessGuard, Journal, JournalError, Result,
    TreeRestorePreparation, MAX_OPERATION_BYTES,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    tree_native_protocol::{
        audit_tree_native_protocol_records, plan_tree_native_protocol, TreeNativeProtocolAudit,
        TreeNativeProtocolInput, TreeNativeProtocolLimits, TreeNativeProtocolRecord,
    },
    tree_restore_history::encode_history_record,
    ContentId,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TreeNativeProtocolDescriptionRequest {
    pub input: TreeNativeProtocolInput,
    pub limits: TreeNativeProtocolLimits,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TreeNativeProtocolDescriptionAudit {
    pub request: TreeNativeProtocolDescriptionRequest,
    pub protocol_hash: ContentId,
    pub request_hash: ContentId,
    pub records: Vec<TreeNativeProtocolRecord>,
    pub fingerprint: ContentId,
    pub metadata_bytes: u64,
    pub native_effects_verified: bool,
    pub history_commit_available: bool,
    pub input_reference_release_available: bool,
    pub original_reference_release_available: bool,
    pub final_handoff_capacity_verified: bool,
    pub tree_atomic: bool,
}

fn project(
    connection: &Connection,
    p: &TreeRestorePreparation,
    request: &TreeNativeProtocolDescriptionRequest,
    records: &[TreeNativeProtocolRecord],
    max: usize,
) -> Result<(ContentId, TreeNativeProtocolAudit)> {
    let admission = p
        .coordinator_admission
        .as_ref()
        .ok_or(JournalError::Invariant(
            "tree protocol actual admission missing",
        ))?;
    let binding = &request.input.admission;
    if binding.input != admission.request.input
        || binding.limits != admission.request.limits
        || binding.intent_hash != admission.intent_hash
        || binding.request_hash != admission.request_hash
        || request.limits.max_records > max
        || request.limits.max_input_bytes > MAX_OPERATION_BYTES as u64
        || request.limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
    {
        return Err(JournalError::Invariant(
            "tree protocol actual admission binding",
        ));
    }
    let projection =
        crate::tree_coordinator_admission::project(connection, p, &admission.request, max)?;
    let context = projection.context();
    let plan = plan_tree_native_protocol(&context, &request.input, request.limits)?;
    let audit = audit_tree_native_protocol_records(&context, &plan, records, request.limits)?;
    Ok((plan.intent_hash().clone(), audit))
}

fn report(
    request: &TreeNativeProtocolDescriptionRequest,
    protocol_hash: ContentId,
    audit: &TreeNativeProtocolAudit,
) -> Result<TreeNativeProtocolDescriptionAudit> {
    let json = encode_history_record(request, MAX_OPERATION_BYTES as u64)?;
    let mut bytes = json.len() as u64 + 232;
    for record in audit.records() {
        bytes = bytes
            .checked_add(
                encode_history_record(record, MAX_OPERATION_BYTES as u64)?.len() as u64 + 368,
            )
            .ok_or(JournalError::Invariant("tree protocol metadata overflow"))?;
    }
    Ok(TreeNativeProtocolDescriptionAudit {
        request: request.clone(),
        protocol_hash,
        request_hash: ContentId::hash(&json),
        records: audit.records().to_vec(),
        fingerprint: audit.fingerprint().clone(),
        metadata_bytes: bytes,
        native_effects_verified: false,
        history_commit_available: false,
        input_reference_release_available: false,
        original_reference_release_available: false,
        final_handoff_capacity_verified: false,
        tree_atomic: false,
    })
}

pub(crate) fn audit(
    connection: &Connection,
    p: &TreeRestorePreparation,
    max: usize,
) -> Result<Option<TreeNativeProtocolDescriptionAudit>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(request AS BLOB)) BETWEEN 1 AND 16777216
        THEN request ELSE '' END FROM tree_restore_protocol_descriptions WHERE transaction_id=?1",
            [p.intent.transaction_id.as_str()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(json) = json else {
        return Ok(None);
    };
    let request: TreeNativeProtocolDescriptionRequest = serde_json::from_str(&json)?;
    let mut statement = connection.prepare(
        "SELECT record_index,coordinator_execution_id,admission_id,admission_hash,
        protocol_hash,previous_hash,record_hash,recorded_at_ms,
        CASE WHEN length(CAST(record AS BLOB)) BETWEEN 1 AND 16777216 THEN record ELSE '' END
        FROM tree_restore_protocol_records WHERE transaction_id=?1 ORDER BY record_index",
    )?;
    let mut records = Vec::new();
    let mut bytes = json.len() as u64 + 232;
    let mut encoded = encode_history_record(
        &(&request.input, &[] as &[TreeNativeProtocolRecord]),
        request.limits.max_encoded_bytes,
    )?
    .len() as u64;
    let mut rows = statement.query([p.intent.transaction_id.as_str()])?;
    while let Some(row) = rows.next()? {
        let text: String = row.get(8)?;
        encoded = encoded
            .checked_add(text.len() as u64 + u64::from(!records.is_empty()))
            .filter(|n| *n <= request.limits.max_encoded_bytes)
            .ok_or(JournalError::Invariant(
                "tree protocol stored encoded inventory",
            ))?;
        bytes = bytes
            .checked_add(text.len() as u64 + 368)
            .filter(|n| *n <= max as u64 * 1024)
            .ok_or(JournalError::Invariant(
                "tree protocol stored byte inventory",
            ))?;
        if records.len() >= max || records.len() >= request.limits.max_records {
            return Err(JournalError::Invariant(
                "tree protocol stored record inventory",
            ));
        }
        let record: TreeNativeProtocolRecord = serde_json::from_str(&text)?;
        if serde_json::to_string(&record)? != text
            || record.transaction_id != p.intent.transaction_id
            || sql_integer(record.record_index as u64)? != row.get::<_, i64>(0)?
            || record.coordinator_execution_id.as_str() != row.get::<_, String>(1)?
            || record.admission_id.as_str() != row.get::<_, String>(2)?
            || record.admission_hash.as_str() != row.get::<_, String>(3)?
            || record.protocol_hash.as_str() != row.get::<_, String>(4)?
            || record.previous_hash.as_str() != row.get::<_, String>(5)?
            || ContentId::hash(text.as_bytes()).as_str() != row.get::<_, String>(6)?
            || sql_integer(record.recorded_at_ms)? != row.get::<_, i64>(7)?
        {
            return Err(JournalError::Invariant("tree protocol exact stored record"));
        }
        records.push(record);
    }
    let (protocol_hash, core) = project(connection, p, &request, &records, max)?;
    let expected = report(&request, protocol_hash, &core)?;
    let i = &request.input.admission.input;
    let exact: bool = connection.query_row(
        "SELECT coordinator_execution_id=?2 AND admission_id=?3 AND protocol_hash=?4
        AND request_hash=?5 AND created_at_ms=?6 AND request=?7
        FROM tree_restore_protocol_descriptions WHERE transaction_id=?1",
        params![
            i.transaction_id.as_str(),
            i.coordinator_execution_id.as_str(),
            i.admission_id.as_str(),
            expected.protocol_hash.as_str(),
            expected.request_hash.as_str(),
            sql_integer(i.admitted_at_ms)?,
            serde_json::to_string(&request)?
        ],
        |r| r.get(0),
    )?;
    if !exact || json != serde_json::to_string(&request)? || bytes != expected.metadata_bytes {
        return Err(JournalError::Invariant("tree protocol exact stored header"));
    }
    Ok(Some(expected))
}

impl Journal {
    /// Persist a description bound to actual irreversible admission, not execute.
    pub fn with_tree_native_protocol_description<T, E>(
        &self,
        request: &TreeNativeProtocolDescriptionRequest,
        max: usize,
        inspect: impl FnOnce(&TreeNativeProtocolAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<
        (
            Option<(CasAccessGuard, T)>,
            TreeNativeProtocolDescriptionAudit,
        ),
        E,
    >
    where
        E: From<JournalError>,
    {
        self.write_tree_protocol_description(request, None, max, inspect)
    }

    /// Append one exact descriptive record; native effect evidence is unavailable.
    pub fn with_tree_native_protocol_record_description<T, E>(
        &self,
        request: &TreeNativeProtocolDescriptionRequest,
        record: &TreeNativeProtocolRecord,
        max: usize,
        inspect: impl FnOnce(&TreeNativeProtocolAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<
        (
            Option<(CasAccessGuard, T)>,
            TreeNativeProtocolDescriptionAudit,
        ),
        E,
    >
    where
        E: From<JournalError>,
    {
        self.write_tree_protocol_description(request, Some(record), max, inspect)
    }

    fn write_tree_protocol_description<T, E>(
        &self,
        request: &TreeNativeProtocolDescriptionRequest,
        record: Option<&TreeNativeProtocolRecord>,
        max: usize,
        inspect: impl FnOnce(&TreeNativeProtocolAudit) -> std::result::Result<T, E>,
    ) -> std::result::Result<
        (
            Option<(CasAccessGuard, T)>,
            TreeNativeProtocolDescriptionAudit,
        ),
        E,
    >
    where
        E: From<JournalError>,
    {
        if max == 0
            || max > sync_extend_core_model::limits::MAX_ENTRIES
            || request.limits.max_records > max
            || request.limits.max_input_bytes > MAX_OPERATION_BYTES as u64
            || request.limits.max_encoded_bytes > MAX_OPERATION_BYTES as u64
        {
            return Err(JournalError::Invariant("tree protocol inventory limit").into());
        }
        encode_history_record(request, MAX_OPERATION_BYTES as u64).map_err(JournalError::from)?;
        if let Some(record) = record {
            encode_history_record(record, request.limits.max_encoded_bytes)
                .map_err(JournalError::from)?;
        }
        let space = self
            .state("space_id")?
            .ok_or(JournalError::Invariant("tree protocol space missing"))?
            .parse()
            .map_err(JournalError::from)?;
        let find = || {
            self.tree_restore_preparations(&space, max)?
                .into_iter()
                .find(|p| p.intent.transaction_id == request.input.admission.input.transaction_id)
                .ok_or(JournalError::Invariant("unknown tree protocol owner"))
        };
        let replay =
            |p: &TreeRestorePreparation| -> Result<Option<TreeNativeProtocolDescriptionAudit>> {
                let Some(old) = &p.native_protocol_description else {
                    if record.is_some() {
                        return Err(JournalError::Invariant("tree protocol header missing"));
                    }
                    return Ok(None);
                };
                if old.request != *request {
                    return Err(JournalError::Invariant("tree protocol request collision"));
                }
                match record {
                    None => Ok(Some(old.clone())),
                    Some(r) => match old.records.get(r.record_index) {
                        Some(existing) if existing == r => Ok(Some(old.clone())),
                        Some(_) => Err(JournalError::Invariant("tree protocol record collision")),
                        None => Ok(None),
                    },
                }
            };
        let p = find()?;
        if let Some(old) = replay(&p)? {
            return Ok((None, old));
        }
        let coordination = self.acquire_cas_coordination()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(JournalError::from)?;
        self.audit_gc_owners(&space, max)?;
        let p = find()?;
        if let Some(old) = replay(&p)? {
            tx.commit().map_err(JournalError::from)?;
            return Ok((None, old));
        }
        let old_bytes = p
            .native_protocol_description
            .as_ref()
            .map_or(0, |a| a.metadata_bytes);
        let stored = p
            .native_protocol_description
            .as_ref()
            .map_or(&[][..], |a| a.records.as_slice());
        if let Some(r) = record {
            if stored.len() >= request.limits.max_records || r.record_index != stored.len() {
                return Err(JournalError::Invariant("tree protocol append index or limit").into());
            }
        }
        // Bound the complete prefix before copying nested action payloads.
        let borrowed: Vec<_> = stored.iter().chain(record).collect();
        encode_history_record(
            &(&request.input, &borrowed),
            request.limits.max_encoded_bytes,
        )
        .map_err(JournalError::from)?;
        let records: Vec<_> = borrowed.into_iter().cloned().collect();
        let (hash, core) = project(&tx, &p, request, &records, max)?;
        let expected = report(request, hash, &core)?;
        let additional = expected
            .metadata_bytes
            .checked_sub(old_bytes)
            .ok_or(JournalError::Invariant("tree protocol metadata shrank"))?;
        check_storage_metadata_limit(&tx, max, 1, additional)?;
        let i = &request.input.admission.input;
        if let Some(r) = record {
            let json = serde_json::to_string(r).map_err(JournalError::from)?;
            tx.execute(
                "INSERT INTO tree_restore_protocol_records VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    r.transaction_id.as_str(),
                    r.coordinator_execution_id.as_str(),
                    r.admission_id.as_str(),
                    r.admission_hash.as_str(),
                    r.protocol_hash.as_str(),
                    sql_integer(r.record_index as u64)?,
                    r.previous_hash.as_str(),
                    ContentId::hash(json.as_bytes()).as_str(),
                    sql_integer(r.recorded_at_ms)?,
                    json
                ],
            )
            .map_err(JournalError::from)?;
        } else {
            tx.execute(
                "INSERT INTO tree_restore_protocol_descriptions VALUES (?1,?2,?3,?4,?5,?6,?7)",
                params![
                    i.transaction_id.as_str(),
                    i.coordinator_execution_id.as_str(),
                    i.admission_id.as_str(),
                    expected.protocol_hash.as_str(),
                    expected.request_hash.as_str(),
                    sql_integer(i.admitted_at_ms)?,
                    serde_json::to_string(request).map_err(JournalError::from)?
                ],
            )
            .map_err(JournalError::from)?;
        }
        if find()?.native_protocol_description.as_ref() != Some(&expected) {
            return Err(JournalError::Invariant("tree protocol changed before inspection").into());
        }
        let held = inspect(&core)?;
        self.audit_gc_owners(&space, max)?;
        let actual = find()?
            .native_protocol_description
            .ok_or(JournalError::Invariant("tree protocol disappeared"))?;
        if actual != expected {
            return Err(JournalError::Invariant("tree protocol changed during inspection").into());
        }
        tx.commit().map_err(JournalError::from)?;
        Ok((Some((coordination, held)), actual))
    }
}
