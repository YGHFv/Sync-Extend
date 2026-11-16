//! Private D01 draft: complete proposed Journal row peak, without native authority.
//! Actual admission must rebuild this from full exact schema/inventory and live originals.
use super::{
    future_history::FutureHistory,
    initial_binding::InitialHeldBinding,
    receipt_protocol::{ReceiptScope, ReceiptTemplate},
};
use crate::{storage_inventory::reader::add, JournalError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{
    tree_restore_history::encode_history_record, tree_storage_capacity::TreeStorageCharge,
    ContentId,
};

const TEMPLATE_FIXED: u64 = 128;
const BINDING_FIXED: u64 = 112;
const RECEIPT_FIXED: u64 = 120;
const EXECUTION_ADMISSION_FIXED: u64 = 320;
const EXECUTION_RECORD_FIXED: u64 = 112;
// transaction32/hash64 + six INTEGER fields of eight bytes.
const MANIFEST_FIXED: u64 = 144;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OriginalMainRow {
    pub table: String,
    pub primary_key: Vec<String>,
    pub column_names: Vec<String>,
    pub values: Vec<crate::JournalStorageColumnValue>,
}

impl OriginalMainRow {
    pub(super) fn table(&self) -> &str {
        &self.table
    }
    pub(super) fn primary_key(&self) -> &[String] {
        &self.primary_key
    }
}

pub(super) fn original_values(rows: &[crate::JournalStoredRow]) -> Result<Vec<OriginalMainRow>> {
    let mut result: Vec<_> = rows
        .iter()
        .map(|row| OriginalMainRow {
            table: row.table().to_owned(),
            primary_key: row.primary_key().to_vec(),
            column_names: row
                .columns()
                .iter()
                .map(|column| column.name.clone())
                .collect(),
            values: row
                .columns()
                .iter()
                .map(|column| column.value.clone())
                .collect(),
        })
        .collect();
    result.sort_by(|left, right| {
        (&left.table, &left.primary_key).cmp(&(&right.table, &right.primary_key))
    });
    if result
        .windows(2)
        .any(|pair| pair[0].table == pair[1].table && pair[0].primary_key == pair[1].primary_key)
    {
        return Err(invalid());
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub max_templates: usize,
    pub max_bindings: usize,
    pub max_binding_json: u64,
    pub max_manifest_json: u64,
    pub execution_records: usize,
    pub max_execution_record_json: u64,
    pub max_total_execution_json: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetFamily {
    pub table: String,
    pub rows: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetManifest {
    pub scope: ReceiptScope,
    pub original_schema_hash: ContentId,
    pub original_inventory_hash: ContentId,
    pub original_main: Vec<OriginalMainRow>,
    pub template_hashes: Vec<ContentId>,
    pub binding_hashes: Vec<ContentId>,
    pub history_hash: ContentId,
    pub history: FutureHistory,
    pub native_peak: super::native_capacity::NativePeak,
    pub native_handles: super::native_capacity::NativeHandles,
    pub limits: BudgetLimits,
    pub immediate: Vec<BudgetFamily>,
    pub future: Vec<BudgetFamily>,
    pub admitted_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PreparedBudget {
    pub manifest: BudgetManifest,
    pub manifest_json: Vec<u8>,
    pub manifest_hash: ContentId,
    pub immediate: TreeStorageCharge,
    pub future: TreeStorageCharge,
    pub total_new_peak: TreeStorageCharge,
}

fn invalid() -> JournalError {
    JournalError::Invariant("exact complete DAV Journal budget manifest")
}

fn charge(families: &[BudgetFamily]) -> Result<TreeStorageCharge> {
    families
        .iter()
        .try_fold(TreeStorageCharge::default(), |sum, item| {
            Ok(TreeStorageCharge {
                rows: add(sum.rows, item.rows)?,
                logical_bytes: add(sum.logical_bytes, item.bytes)?,
            })
        })
}

fn family(table: &str, rows: usize, bytes: u64) -> BudgetFamily {
    BudgetFamily {
        table: table.to_owned(),
        rows: rows as u64,
        bytes,
    }
}

/// This is a projection only. Serialized binding JSON cannot issue native effects.
/// D02 must derive every binding from the first held capture and retain those guards.
/// Only the proposed receipt tables hold additional native lineage; adding another
/// durable table requires another exact family before any effect is permitted.
// Keep each independently checked scope and budget input explicit.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare(
    scope: &ReceiptScope,
    original_schema_hash: &ContentId,
    original_main: &[OriginalMainRow],
    templates: &[ReceiptTemplate],
    bindings: &[InitialHeldBinding],
    history: &FutureHistory,
    native_peak: &super::native_capacity::NativePeak,
    native_handles: &super::native_capacity::NativeHandles,
    limits: BudgetLimits,
    admitted_at_ms: u64,
) -> Result<PreparedBudget> {
    crate::sql_integer(admitted_at_ms)?;
    let ceiling = sync_extend_core_model::tree_restore_history::MAX_TREE_HISTORY_BYTES;
    if templates.is_empty()
        || templates.len() > limits.max_templates
        || bindings.is_empty()
        || bindings.len() > limits.max_bindings
        || limits.max_templates > crate::limits::MAX_ENTRIES
        || limits.max_bindings > crate::limits::MAX_ENTRIES
        || limits.execution_records == 0
        || limits.execution_records > crate::limits::MAX_ENTRIES
        || limits.max_binding_json == 0
        || limits.max_binding_json > ceiling
        || limits.max_manifest_json == 0
        || limits.max_manifest_json > ceiling
        || limits.max_execution_record_json == 0
        || limits.max_execution_record_json > ceiling
        || limits.max_total_execution_json
            < (limits.execution_records as u64)
                .checked_mul(limits.max_execution_record_json)
                .ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    let expected_handles = super::native_capacity::NativeHandles::derive(
        bindings,
        native_peak,
        usize::try_from(native_handles.admission_limit).map_err(|_| invalid())?,
    )?;
    if &expected_handles != native_handles
        || native_handles.admission_limit > limits.max_bindings as u64
    {
        return Err(invalid());
    }
    let mut template_hashes = Vec::new();
    let mut template_bytes = 0_u64;
    let mut receipt_bytes = 0_u64;
    for (index, template) in templates.iter().enumerate() {
        if template.scope != *scope
            || template.index != index
            || template.predecessor != index.checked_sub(1)
            || template.max_receipt_json_bytes == 0
            || template.max_receipt_json_bytes > ceiling
        {
            return Err(invalid());
        }
        let json = encode_history_record(template, ceiling)?;
        template_hashes.push(ContentId::hash(&json));
        template_bytes = add(template_bytes, add(TEMPLATE_FIXED, json.len() as u64)?)?;
        receipt_bytes = add(
            receipt_bytes,
            add(RECEIPT_FIXED, template.max_receipt_json_bytes)?,
        )?;
    }
    let mut binding_hashes = Vec::new();
    let mut binding_bytes = 0_u64;
    for (index, binding) in bindings.iter().enumerate() {
        if binding.index != index || binding.plan_hash != scope.plan_hash {
            return Err(invalid());
        }
        binding.identity.validate()?;
        if let Some(identity) = &binding.parent_identity {
            identity.validate()?;
        }
        let json = encode_history_record(binding, limits.max_binding_json)?;
        binding_hashes.push(ContentId::hash(&json));
        binding_bytes = add(binding_bytes, add(BINDING_FIXED, json.len() as u64)?)?;
    }
    let record_bytes = add(
        (limits.execution_records as u64)
            .checked_mul(EXECUTION_RECORD_FIXED)
            .ok_or_else(invalid)?,
        limits.max_total_execution_json,
    )?;
    if ContentId::hash(&encode_history_record(
        &history.rows,
        limits.max_manifest_json,
    )?) != history.fingerprint
    {
        return Err(invalid());
    }
    let manifest = BudgetManifest {
        scope: scope.clone(),
        original_schema_hash: original_schema_hash.clone(),
        original_inventory_hash: ContentId::hash(&encode_history_record(
            &original_main,
            limits.max_manifest_json,
        )?),
        original_main: original_main.to_vec(),
        template_hashes,
        binding_hashes,
        history_hash: history.fingerprint.clone(),
        history: history.clone(),
        native_peak: native_peak.clone(),
        native_handles: native_handles.clone(),
        limits,
        immediate: vec![
            family(
                "webdav_native_execution_admissions",
                1,
                EXECUTION_ADMISSION_FIXED,
            ),
            family(
                "webdav_native_execution_templates",
                templates.len(),
                template_bytes,
            ),
            family(
                "webdav_native_execution_bindings",
                bindings.len(),
                binding_bytes,
            ),
        ],
        future: vec![
            family(
                "webdav_native_execution_records",
                limits.execution_records,
                record_bytes,
            ),
            family(
                "webdav_native_execution_receipts",
                templates.len(),
                receipt_bytes,
            ),
            family(
                "original_planner_final_main_rows",
                history.charge.rows as usize,
                history.charge.logical_bytes,
            ),
        ],
        admitted_at_ms,
    };
    // The manifest row stores only the above non-self-referential families.
    // Its actual encoded width is separately added exactly once.
    let manifest_json = encode_history_record(&manifest, limits.max_manifest_json)?;
    let manifest_hash = ContentId::hash(&manifest_json);
    let base = charge(&manifest.immediate)?;
    let immediate = TreeStorageCharge {
        rows: add(base.rows, 1)?,
        logical_bytes: add(
            base.logical_bytes,
            add(MANIFEST_FIXED, manifest_json.len() as u64)?,
        )?,
    };
    let future = charge(&manifest.future)?;
    let total_new_peak = TreeStorageCharge {
        rows: add(immediate.rows, future.rows)?,
        logical_bytes: add(immediate.logical_bytes, future.logical_bytes)?,
    };
    Ok(PreparedBudget {
        manifest,
        manifest_json,
        manifest_hash,
        immediate,
        future,
        total_new_peak,
    })
}

/// Release only the unused bound of a stage proved by an exact private receipt.
/// The actual inserted row is already charged by the ordinary inventory.
pub(super) fn remaining_receipt_peak(
    templates: &[ReceiptTemplate],
    actual_canonical_json: &[Vec<u8>],
    proved_prefix: usize,
) -> Result<TreeStorageCharge> {
    if proved_prefix != actual_canonical_json.len() || proved_prefix > templates.len() {
        return Err(invalid());
    }
    for (template, json) in templates.iter().zip(actual_canonical_json) {
        if json.is_empty() || json.len() as u64 > template.max_receipt_json_bytes {
            return Err(invalid());
        }
    }
    let remaining = &templates[proved_prefix..];
    Ok(TreeStorageCharge {
        rows: remaining.len() as u64,
        logical_bytes: remaining.iter().try_fold(0, |sum, template| {
            add(sum, add(RECEIPT_FIXED, template.max_receipt_json_bytes)?)
        })?,
    })
}
