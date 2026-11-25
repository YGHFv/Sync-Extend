//! Descriptive namespace projection; only original live effect holders authorize IO.
use super::receipt_protocol::{ReceiptDescription, ReceiptEvidence, ReceiptStage, VerifiedPrefix};
use std::collections::{BTreeMap, BTreeSet};
use sync_extend_core_model::{
    ContentId, Entry, Manifest, ModelError, PortablePath, Result,
    tree_restore_identity::TreeNativeIdentity,
    webdav_native::{WebDavNativeAction, WebDavNativePlan},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProjectedObject {
    pub entry: Entry,
    pub original: TreeNativeIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Projection {
    pub user: BTreeMap<PortablePath, ProjectedObject>,
    pub quarantined: BTreeMap<String, ProjectedObject>,
    pub payloads: BTreeMap<String, ProjectedObject>,
    pub completed: BTreeSet<usize>,
}

/// An immutable descriptive result from this audit's exact plan and receipts.
/// Consumers must still compare their live handles/namespace and exact inputs.
pub(super) struct VerifiedProjection {
    baseline: Manifest,
    plan: WebDavNativePlan,
    receipts: Vec<ReceiptDescription>,
    projection: Projection,
}

impl VerifiedProjection {
    pub(super) fn derive(baseline: &Manifest, receipts: &VerifiedPrefix<'_>) -> Result<Self> {
        Ok(Self {
            baseline: baseline.clone(),
            plan: receipts.plan().clone(),
            receipts: receipts.records().to_vec(),
            projection: Projection::derive(baseline, receipts)?,
        })
    }

    pub(super) fn get(
        &self,
        baseline: &Manifest,
        plan: &WebDavNativePlan,
        receipts: &[ReceiptDescription],
    ) -> Result<&Projection> {
        if self.baseline != *baseline || self.plan != *plan || self.receipts.as_slice() != receipts
        {
            return Err(invalid());
        }
        Ok(&self.projection)
    }

    /// Borrow only the baseline of this audit's exact plan and receipt snapshot.
    /// The returned description carries no native or cleanup authority.
    pub(super) fn baseline_for(
        &self,
        plan: &WebDavNativePlan,
        receipts: &[ReceiptDescription],
    ) -> Result<&Manifest> {
        if self.plan != *plan || self.receipts.as_slice() != receipts {
            return Err(invalid());
        }
        Ok(&self.baseline)
    }
}

fn invalid() -> ModelError {
    ModelError::InvalidData("exact original DAV collection namespace projection")
}

impl Projection {
    /// Derive descriptive expectations from audited receipts. This never opens a path.
    fn derive(baseline: &Manifest, verified: &VerifiedPrefix<'_>) -> Result<Self> {
        let plan = verified.plan();
        let receipts = verified.records();
        let mut result = Self {
            user: BTreeMap::new(),
            quarantined: BTreeMap::new(),
            payloads: BTreeMap::new(),
            completed: BTreeSet::new(),
        };
        let mut identities = BTreeSet::from([
            plan.inventory().root.clone(),
            plan.inventory().marker_directory.clone(),
            plan.inventory().marker_file.clone(),
        ]);
        for entry in baseline.entries.values() {
            let native = plan
                .inventory()
                .entries
                .get(&entry.path)
                .ok_or_else(invalid)?;
            if native.entry_id != entry.entry_id
                || native.kind != entry.kind
                || !identities.insert(native.identity.clone())
                || result
                    .user
                    .insert(
                        entry.path.clone(),
                        ProjectedObject {
                            entry: entry.clone(),
                            original: native.identity.clone(),
                        },
                    )
                    .is_some()
            {
                return Err(invalid());
            }
        }
        if receipts.len() < 10 {
            return Ok(result);
        }
        for record in &receipts[10..] {
            if let ReceiptEvidence::Disposal {
                action,
                quarantine_action,
                original,
                component,
                ..
            } = &record.evidence
            {
                if matches!(record.stage, ReceiptStage::OriginalAbsent(_)) {
                    let removed = result.quarantined.remove(component).ok_or_else(invalid)?;
                    if &removed.original != original || *quarantine_action >= *action {
                        return Err(invalid());
                    }
                }
                if matches!(record.stage, ReceiptStage::OwnerSlotCleared(_))
                    && !result.completed.insert(*action)
                {
                    return Err(invalid());
                }
                continue;
            }
            if matches!(
                record.evidence,
                ReceiptEvidence::History { .. }
                    | ReceiptEvidence::InternalRemoval { .. }
                    | ReceiptEvidence::References { .. }
            ) {
                continue;
            }
            let ReceiptEvidence::CollectionObject { object } = &record.evidence else {
                return Err(invalid());
            };
            let step = plan.steps().get(object.action).ok_or_else(invalid)?;
            use ReceiptStage as S;
            match (&step.action, record.stage) {
                (
                    WebDavNativeAction::QuarantineOriginal {
                        entry,
                        identity,
                        owner_component,
                    },
                    S::QuarantineMoved(action),
                ) => {
                    let source = result.user.remove(&entry.path).ok_or_else(invalid)?;
                    if source.entry != *entry
                        || source.original != *identity
                        || object.original.as_ref() != Some(identity)
                        || result
                            .quarantined
                            .insert(owner_component.clone(), source)
                            .is_some()
                        || !result.completed.insert(action)
                    {
                        return Err(invalid());
                    }
                }
                (WebDavNativeAction::CreateDirectory { entry }, S::DirectoryCreated(action)) => {
                    let original = object.original.clone().ok_or_else(invalid)?;
                    if !identities.insert(original.clone())
                        || result
                            .user
                            .insert(
                                entry.path.clone(),
                                ProjectedObject {
                                    entry: entry.clone(),
                                    original,
                                },
                            )
                            .is_some()
                        || !result.completed.insert(action)
                    {
                        return Err(invalid());
                    }
                }
                (WebDavNativeAction::PublishFile { entry }, S::FileCreated(_)) => {
                    let original = object.original.clone().ok_or_else(invalid)?;
                    if !identities.insert(original.clone())
                        || object.content_hash != Some(ContentId::hash(b""))
                        || object.length != 0
                        || result
                            .payloads
                            .insert(
                                object.component.clone(),
                                ProjectedObject {
                                    entry: entry.clone(),
                                    original,
                                },
                            )
                            .is_some()
                    {
                        return Err(invalid());
                    }
                }
                (WebDavNativeAction::PublishFile { entry }, S::FilePublished(action)) => {
                    let component = format!("dav-{}-{action}.payload", record.scope.transaction_id);
                    let source = result.payloads.remove(&component).ok_or_else(invalid)?;
                    if source.entry != *entry
                        || object.original.as_ref() != Some(&source.original)
                        || result.user.insert(entry.path.clone(), source).is_some()
                        || !result.completed.insert(action)
                    {
                        return Err(invalid());
                    }
                }
                _ => {}
            }
        }
        Ok(result)
    }
}
