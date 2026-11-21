use super::{budget_error, FrameClass, ProducerKind, MAX_ENTRIES, MAX_POLICY_BYTES};
use crate::{PeerIdentity, Result, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use sync_extend_core_model::{ContentId, EntryId, SpaceId};

pub const FILE_NAME: &str = "transport-attempt-budget.sqlite";
const SIGNING_DOMAIN: &str = "SyncExtend explicit application frame attempt policy v1";
const FINGERPRINT_DOMAIN: &str = "sync-extend-transport-attempt-policy-v1";

/// Every producer, period, byte and entry limit is explicit. No billing default.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerLimit {
    pub producer: ProducerKind,
    pub max_frame_bytes: u64,
    pub max_reserved_bytes: u64,
    pub max_attempt_entries: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportAttemptPolicy {
    pub format_version: u32,
    pub budget_id: EntryId,
    pub space_id: SpaceId,
    pub owner: PeerIdentity,
    pub approved_peer: PeerIdentity,
    pub data_root: PathBuf,
    pub control_root: PathBuf,
    pub ledger_path: PathBuf,
    pub period_start_ms: u64,
    pub period_end_ms: u64,
    pub max_reserved_frame_bytes: u64,
    pub max_attempt_entries: u64,
    pub meter_unit: String,
    pub route_scope: String,
    pub producer_limits: Vec<ProducerLimit>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransportAttemptPolicy {
    pub policy: TransportAttemptPolicy,
    pub signature: Vec<u8>,
}

fn normalized(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .to_str()
            .is_some_and(|value| value.len() <= 4096 && !value.contains('\0'))
        && !path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

impl TransportAttemptPolicy {
    pub fn fixed_ledger_path(control_root: &Path) -> PathBuf {
        control_root.join(FILE_NAME)
    }

    pub fn validate(&self, data_root: &Path, control_root: &Path) -> Result<()> {
        self.owner.validate()?;
        self.approved_peer.validate()?;
        if self.format_version != 1
            || self.owner.space_id != self.space_id
            || self.approved_peer.space_id != self.space_id
            || self.owner.device_id == self.approved_peer.device_id
            || self.data_root != data_root
            || self.control_root != control_root
            || !normalized(data_root)
            || !normalized(control_root)
            || self.ledger_path != Self::fixed_ledger_path(control_root)
            || self.period_start_ms >= self.period_end_ms
            || self.period_end_ms > i64::MAX as u64
            || self.max_reserved_frame_bytes == 0
            || self.max_reserved_frame_bytes > i64::MAX as u64
            || self.max_attempt_entries == 0
            || self.max_attempt_entries > MAX_ENTRIES
            || self.meter_unit != "reserved_sync_quic_application_frame_bytes"
            || self.route_scope != "all_sync_quic_application_paths"
            || self.producer_limits.len() != ProducerKind::ALL.len()
        {
            return Err(budget_error(
                "finite explicit application-frame policy differs",
            ));
        }
        // A vector, exact closed order and one occurrence reject duplicate JSON
        // map keys, omitted producers and ambiguous canonical policy encodings.
        for (expected, limit) in ProducerKind::ALL.iter().zip(&self.producer_limits) {
            let minimum = if expected.frame_class() == FrameClass::Probe {
                1
            } else {
                6
            };
            if expected != &limit.producer
                || limit.max_frame_bytes < minimum
                || limit.max_frame_bytes > expected.maximum_frame_bytes()
                || limit.max_reserved_bytes < limit.max_frame_bytes
                || limit.max_reserved_bytes > self.max_reserved_frame_bytes
                || limit.max_attempt_entries == 0
                || limit.max_attempt_entries > self.max_attempt_entries
            {
                return Err(budget_error(
                    "every registered producer needs finite explicit caps",
                ));
            }
        }
        if serde_json::to_vec(self)?.len() > MAX_POLICY_BYTES {
            return Err(budget_error("application-frame policy encoding bound"));
        }
        self.max_file_bytes()?;
        Ok(())
    }

    pub fn producer_limit(&self, kind: ProducerKind) -> Result<&ProducerLimit> {
        self.producer_limits
            .iter()
            .find(|limit| limit.producer == kind)
            .ok_or_else(|| budget_error("selected policy has no producer cap"))
    }

    pub(crate) fn max_file_bytes(&self) -> Result<u64> {
        self.max_attempt_entries
            .checked_mul(4096)
            .and_then(|bytes| bytes.checked_add(1024 * 1024))
            .ok_or_else(|| budget_error("transport ledger future capacity overflow"))
    }
}

impl SignedTransportAttemptPolicy {
    pub fn sign(
        identity: &TransportIdentity,
        data_root: &Path,
        control_root: &Path,
        policy: TransportAttemptPolicy,
    ) -> Result<Self> {
        policy.validate(data_root, control_root)?;
        if &policy.owner != identity.peer_identity() {
            return Err(budget_error(
                "application budget signer is not the exact owner",
            ));
        }
        let hash = blake3::derive_key(SIGNING_DOMAIN, &serde_json::to_vec(&policy)?);
        Ok(Self {
            signature: identity.signing_key.sign(&hash).to_bytes().to_vec(),
            policy,
        })
    }

    pub fn verify(&self, data_root: &Path, control_root: &Path) -> Result<()> {
        self.policy.validate(data_root, control_root)?;
        let key = VerifyingKey::from_bytes(&self.policy.owner.public_key)
            .map_err(|_| budget_error("invalid application budget owner key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| budget_error("application budget requires one exact signature"))?;
        let hash = blake3::derive_key(SIGNING_DOMAIN, &serde_json::to_vec(&self.policy)?);
        key.verify_strict(&hash, &signature)
            .map_err(|_| budget_error("application budget signature differs"))
    }

    pub fn fingerprint(&self) -> Result<ContentId> {
        Ok(ContentId::hash(&serde_json::to_vec(&(
            FINGERPRINT_DOMAIN,
            self,
        ))?))
    }
}
