//! Action observations require the exact durable private native result receipt.
//! This audits bytes only and never reconstructs a holder or grants an effect.
use super::{
    budget_manifest::BudgetManifest,
    execution::WebDavDurableExecutionLimits,
    receipt_protocol::{self, ReceiptDescription, ReceiptEvidence, ReceiptStage, ReceiptTemplate},
};
use crate::{JournalError, Result};
use rusqlite::Connection;
use sync_extend_core_model::{
    tree_restore_history::encode_history_record,
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
    webdav_native_execution::{
        WebDavExecutionObservation, WebDavExecutionPhase, WebDavExecutionRecord,
    },
    ContentId,
};
fn invalid() -> JournalError {
    JournalError::Invariant("original native DAV result receipt and ordered action observation")
}

pub(super) fn audit(
    connection: &Connection,
    plan: &WebDavNativePlan,
    records: &[WebDavExecutionRecord],
    limits: WebDavDurableExecutionLimits,
) -> Result<bool> {
    let Some(first) = records.first() else {
        return Ok(false);
    };
    let id = first.scope.transaction_id.as_str();
    let mut query=connection.prepare(
        "SELECT manifest_hash,manifest FROM main.webdav_native_execution_manifests WHERE transaction_id=?1")?;
    let manifests: Vec<(String, String)> = query
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    // The first activation still supports the legacy metadata-only admission;
    // no later observation is allowed without a complete original manifest.
    if manifests.is_empty() {
        if records.len() != 1 || !matches!(first.phase, WebDavExecutionPhase::Activated) {
            return Err(invalid());
        }
        return Ok(false);
    }
    if manifests.len() != 1 {
        return Err(invalid());
    }
    let (fingerprint, json) = &manifests[0];
    let manifest: BudgetManifest = serde_json::from_str(json)?;
    let bytes = encode_history_record(&manifest, manifest.limits.max_manifest_json)?;
    if bytes != json.as_bytes()
        || ContentId::hash(&bytes).as_str() != fingerprint
        || manifest.scope.transaction_id != first.scope.transaction_id
        || manifest.scope.description_hash != first.scope.description_hash
        || manifest.scope.request_hash != *plan.request_hash()
        || manifest.scope.plan_hash != *plan.fingerprint()
    {
        return Err(invalid());
    }
    let templates:Vec<ReceiptTemplate>=connection.prepare(
        "SELECT template FROM main.webdav_native_execution_templates WHERE transaction_id=?1 ORDER BY template_index")?
        .query_map([id],|row|row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter().map(|json|serde_json::from_str(&json)).collect::<serde_json::Result<_>>()?;
    let receipts:Vec<ReceiptDescription>=connection.prepare(
        "SELECT receipt FROM main.webdav_native_execution_receipts WHERE transaction_id=?1 ORDER BY receipt_index")?
        .query_map([id],|row|row.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter().map(|json|serde_json::from_str(&json)).collect::<serde_json::Result<_>>()?;
    let max = templates.iter().try_fold(0u64, |sum, template| {
        sum.checked_add(template.max_receipt_json_bytes)
            .ok_or_else(invalid)
    })?;
    let verified = receipt_protocol::verified_prefix(
        plan,
        &templates,
        &receipts,
        &fingerprint.parse::<ContentId>()?,
        manifest.admitted_at_ms,
        max,
    )?;
    let mut previous_time = manifest.admitted_at_ms;
    for record in records {
        if record.recorded_at_ms < previous_time {
            return Err(invalid());
        }
        previous_time = record.recorded_at_ms;
        let WebDavExecutionPhase::Observed { observation, .. } = &record.phase else {
            continue;
        };
        let stage = match plan
            .steps()
            .get(record.action_index)
            .ok_or_else(invalid)?
            .action
        {
            WebDavNativeAction::QuarantineOriginal { .. } => {
                ReceiptStage::QuarantineMoved(record.action_index)
            }
            WebDavNativeAction::CreateDirectory { .. } => {
                ReceiptStage::DirectoryCreated(record.action_index)
            }
            WebDavNativeAction::PublishFile { .. } => {
                ReceiptStage::FilePublished(record.action_index)
            }
            WebDavNativeAction::CommitHistory { .. } => {
                ReceiptStage::HistoryCommitted(record.action_index)
            }
            WebDavNativeAction::CleanupOriginal { .. } => {
                ReceiptStage::OriginalAbsent(record.action_index)
            }
        };
        let receipt = verified.first(stage).ok_or_else(invalid)?;
        if receipt.recorded_at_ms > record.recorded_at_ms {
            return Err(invalid());
        }
        if let ReceiptEvidence::History {
            action,
            final_snapshot,
            operation_count,
            history_hash,
        } = &receipt.evidence
        {
            if *action != record.action_index
                || history_hash != &manifest.history.fingerprint
                || !matches!(observation,WebDavExecutionObservation::HistoryCommitted {
                    final_snapshot:snapshot,operation_count:count
                } if snapshot==final_snapshot && count==operation_count)
            {
                return Err(invalid());
            }
            continue;
        }
        if let ReceiptEvidence::Disposal {
            action,
            quarantine_action,
            original,
            ..
        } = &receipt.evidence
        {
            if *action != record.action_index
                || !matches!(observation,WebDavExecutionObservation::OriginalAbsent {
                    quarantine_action:expected,original:identity
                } if expected==quarantine_action && identity==original)
            {
                return Err(invalid());
            }
            continue;
        }
        let ReceiptEvidence::CollectionObject { object } = &receipt.evidence else {
            return Err(invalid());
        };
        let original = object.original.as_ref().ok_or_else(invalid)?;
        let matches = match observation {
            WebDavExecutionObservation::QuarantinedOriginal { identity }
            | WebDavExecutionObservation::CreatedDirectory { identity } => identity == original,
            WebDavExecutionObservation::PublishedFile {
                identity,
                content_id,
                length,
            } => {
                identity == original
                    && object.content_hash.as_ref() == Some(content_id)
                    && object.length == *length
            }
            _ => false,
        };
        if !matches
            || object.action != record.action_index
            || encode_history_record(record, limits.max_record_bytes)?.is_empty()
        {
            return Err(invalid());
        }
    }
    // A durable result may be present just before its action observation commit;
    // receipts cannot advance into a future action that has no activation.
    if let Some(last) = records.last() {
        for receipt in receipts.iter().skip(10) {
            let action = match &receipt.evidence {
                ReceiptEvidence::CollectionObject { object } => object.action,
                ReceiptEvidence::History { action, .. } => *action,
                ReceiptEvidence::Disposal { action, .. } => *action,
                ReceiptEvidence::InternalRemoval { .. } | ReceiptEvidence::References { .. } => {
                    continue
                }
                _ => return Err(invalid()),
            };
            if action > last.action_index {
                return Err(invalid());
            }
            let activation = records
                .get(action.checked_mul(2).ok_or_else(invalid)?)
                .ok_or_else(invalid)?;
            if !matches!(activation.phase, WebDavExecutionPhase::Activated)
                || receipt.recorded_at_ms < activation.recorded_at_ms
            {
                return Err(invalid());
            }
        }
    }
    Ok(!receipts.is_empty())
}
