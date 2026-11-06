use crate::{Result, TransportError};
use ed25519_dalek::SigningKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, DeviceId, SpaceId};

const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentity {
    pub space_id: SpaceId,
    pub device_id: DeviceId,
    pub public_key: [u8; 32],
    pub certificate_der: Vec<u8>,
}

impl PeerIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.certificate_der.is_empty() || self.certificate_der.len() > MAX_CERTIFICATE_BYTES {
            return Err(TransportError::Limit("certificate length"));
        }
        ed25519_dalek::VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| TransportError::Authorization("invalid device public key"))?;
        if DeviceId::from_public_key(&self.public_key) != self.device_id {
            return Err(TransportError::Authorization("device public key mismatch"));
        }
        Ok(())
    }

    pub fn certificate_fingerprint(&self) -> ContentId {
        ContentId::hash(&self.certificate_der)
    }
}

pub struct TransportIdentity {
    pub(crate) peer: PeerIdentity,
    pub(crate) signing_key: SigningKey,
    pub(crate) private_key: Vec<u8>,
}

impl TransportIdentity {
    /// Derive TLS credentials from the existing, privately stored device seed.
    pub fn from_signing_key(space_id: SpaceId, signing_key: SigningKey) -> Result<Self> {
        // RFC 8410 PKCS#8 wrapping, without a second independent device key.
        let mut private_key = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        private_key.extend_from_slice(signing_key.as_bytes());
        let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(private_key.clone()),
            &rcgen::PKCS_ED25519,
        )?;
        let mut params = rcgen::CertificateParams::new(vec!["sync-extend.local".to_owned()])?;
        // A deterministic serial makes a stable seed produce a stable pairing certificate.
        params.serial_number = Some(rcgen::SerialNumber::from_slice(
            &signing_key.verifying_key().as_bytes()[..20],
        ));
        let certificate = params.self_signed(&key)?;
        let public_key = *signing_key.verifying_key().as_bytes();
        let peer = PeerIdentity {
            space_id,
            device_id: DeviceId::from_public_key(&public_key),
            public_key,
            certificate_der: certificate.der().to_vec(),
        };
        peer.validate()?;
        Ok(Self {
            peer,
            signing_key,
            private_key,
        })
    }

    pub fn peer_identity(&self) -> &PeerIdentity {
        &self.peer
    }

    pub(crate) fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.peer.certificate_der.clone())
    }

    pub(crate) fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key.clone()).into()
    }
}
