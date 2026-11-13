//! Independently signed last-reported manifests; storage completion requires actual CAS audit.
use crate::{PeerIdentity, Result, TransportError, TransportIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, DeviceId, Manifest, SnapshotId, PROTOCOL_VERSION};

const REPORT_DOMAIN: &str = "SyncExtend original last-reported storage snapshot v1";
const FORWARD_DOMAIN: &str = "SyncExtend channel forwarded storage snapshot v1";
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSnapshotReport {
    pub protocol_version: u32,
    pub source_device: DeviceId,
    pub manifest: Manifest,
    pub snapshot_id: SnapshotId,
    pub reported_at_ms: u64,
}

impl StorageSnapshotReport {
    pub fn validate(&self) -> Result<()> {
        self.manifest.validate()?;
        if self.protocol_version != PROTOCOL_VERSION
            || self.manifest.root()? != self.snapshot_id
            || self.reported_at_ms > i64::MAX as u64
            || serde_json::to_vec(self)?.len() > MAX_BYTES
        {
            return Err(TransportError::Authorization(
                "storage signed snapshot bounds/root",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStorageSnapshotReport {
    pub report: StorageSnapshotReport,
    pub signature: Vec<u8>,
}

impl SignedStorageSnapshotReport {
    pub fn sign(identity: &TransportIdentity, report: StorageSnapshotReport) -> Result<Self> {
        report.validate()?;
        if report.manifest.space_id != identity.peer.space_id
            || report.source_device != identity.peer.device_id
        {
            return Err(TransportError::Authorization(
                "storage snapshot original signer",
            ));
        }
        let digest = blake3::derive_key(REPORT_DOMAIN, &serde_json::to_vec(&report)?);
        Ok(Self {
            report,
            signature: identity.signing_key.sign(&digest).to_bytes().to_vec(),
        })
    }
    pub fn verify(&self, source: &PeerIdentity) -> Result<()> {
        self.report.validate()?;
        source.validate()?;
        if self.report.manifest.space_id != source.space_id
            || self.report.source_device != source.device_id
        {
            return Err(TransportError::Authorization(
                "storage snapshot original approval",
            ));
        }
        let key = VerifyingKey::from_bytes(&source.public_key)
            .map_err(|_| TransportError::Authorization("snapshot source key"))?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| TransportError::Authorization("snapshot source signature"))?;
        key.verify_strict(
            &blake3::derive_key(REPORT_DOMAIN, &serde_json::to_vec(&self.report)?),
            &signature,
        )
        .map_err(|_| TransportError::Authorization("snapshot source signature changed"))
    }
    pub fn storage_id(&self, receiver: &PeerIdentity) -> Result<ContentId> {
        self.report.validate()?;
        receiver.validate()?;
        if receiver.space_id != self.report.manifest.space_id
            || receiver.device_id == self.report.source_device
        {
            return Err(TransportError::Authorization("snapshot receiver scope"));
        }
        Ok(ContentId::hash(&serde_json::to_vec(&(
            REPORT_DOMAIN,
            &self.report.source_device,
            &receiver.device_id,
            &self.report.manifest.space_id,
            &self.report.snapshot_id,
        ))?))
    }
    /// Distinct original reports retain their signed observation time. Content
    /// ownership and logical delivery remain keyed by the stable snapshot ID.
    pub fn report_id(&self, receiver: &PeerIdentity) -> Result<ContentId> {
        let owner = self.storage_id(receiver)?;
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "SyncExtend exact retained signed snapshot report v1",
            owner,
            self,
        ))?))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedSnapshotEnvelope {
    pub origin: PeerIdentity,
    pub forwarder: PeerIdentity,
    pub receiver: PeerIdentity,
    pub channel_binding: ContentId,
    pub signed_report: SignedStorageSnapshotReport,
    pub forwarding_signature: Vec<u8>,
}

impl ForwardedSnapshotEnvelope {
    fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&(
            FORWARD_DOMAIN,
            &self.origin,
            &self.forwarder,
            &self.receiver,
            &self.channel_binding,
            &self.signed_report,
        ))?;
        if bytes.len() > MAX_BYTES + 128 * 1024 {
            return Err(TransportError::Limit("snapshot envelope bytes"));
        }
        Ok(bytes)
    }
    pub fn sign(
        forwarder: &TransportIdentity,
        origin: &PeerIdentity,
        receiver: &PeerIdentity,
        channel_binding: ContentId,
        signed_report: SignedStorageSnapshotReport,
    ) -> Result<Self> {
        signed_report.verify(origin)?;
        let mut envelope = Self {
            origin: origin.clone(),
            forwarder: forwarder.peer_identity().clone(),
            receiver: receiver.clone(),
            channel_binding,
            signed_report,
            forwarding_signature: Vec::new(),
        };
        envelope.forwarding_signature = forwarder
            .signing_key
            .sign(&blake3::derive_key(FORWARD_DOMAIN, &envelope.bytes()?))
            .to_bytes()
            .to_vec();
        envelope.verify(
            origin,
            forwarder.peer_identity(),
            receiver,
            &envelope.channel_binding,
        )?;
        Ok(envelope)
    }
    pub fn verify(
        &self,
        origin: &PeerIdentity,
        forwarder: &PeerIdentity,
        receiver: &PeerIdentity,
        binding: &ContentId,
    ) -> Result<()> {
        for peer in [origin, forwarder, receiver] {
            peer.validate()?;
        }
        self.signed_report.verify(origin)?;
        if origin.device_id == forwarder.device_id
            || origin.device_id == receiver.device_id
            || forwarder.device_id == receiver.device_id
            || origin.space_id != forwarder.space_id
            || origin.space_id != receiver.space_id
            || &self.origin != origin
            || &self.forwarder != forwarder
            || &self.receiver != receiver
            || &self.channel_binding != binding
        {
            return Err(TransportError::Authorization(
                "snapshot forwarding channel/peer",
            ));
        }
        let signature = Signature::from_slice(&self.forwarding_signature)
            .map_err(|_| TransportError::Authorization("snapshot forwarding signature"))?;
        VerifyingKey::from_bytes(&forwarder.public_key)
            .map_err(|_| TransportError::Authorization("snapshot forwarding key"))?
            .verify_strict(
                &blake3::derive_key(FORWARD_DOMAIN, &self.bytes()?),
                &signature,
            )
            .map_err(|_| TransportError::Authorization("snapshot forwarding signature changed"))
    }
    pub fn storage_id(&self) -> Result<ContentId> {
        self.signed_report.storage_id(&self.receiver)
    }
    pub fn report_id(&self) -> Result<ContentId> {
        self.signed_report.report_id(&self.receiver)
    }
}
