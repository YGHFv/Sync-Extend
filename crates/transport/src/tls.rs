use crate::{PeerIdentity, Result, TransportError, TransportIdentity};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};
use std::sync::Arc;

const ALPN: &[u8] = b"sync-extend/1";

#[derive(Debug)]
struct ExactPeer {
    certificate: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ExactPeer {
    fn check(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> std::result::Result<(), Error> {
        if certificate.as_ref() != self.certificate || !intermediates.is_empty() {
            return Err(Error::General("unpaired device certificate".to_owned()));
        }
        Ok(())
    }

    fn verify_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
}

impl ServerCertVerifier for ExactPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        // Out-of-band exact certificate approval replaces public DNS/CA trust.
        self.check(end_entity, intermediates)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is forbidden".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for ExactPeer {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, Error> {
        self.check(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is forbidden".to_owned()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.verify_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn paired_verifier(identity: &TransportIdentity, peer: &PeerIdentity) -> Result<Arc<ExactPeer>> {
    peer.validate()?;
    if identity.peer.space_id != peer.space_id || identity.peer.device_id == peer.device_id {
        return Err(TransportError::Authorization(
            "peer is not a different member of this space",
        ));
    }
    Ok(Arc::new(ExactPeer {
        certificate: peer.certificate_der.clone(),
        provider: Arc::new(rustls::crypto::ring::default_provider()),
    }))
}

pub(crate) fn client(
    identity: &TransportIdentity,
    peer: &PeerIdentity,
) -> Result<Arc<ClientConfig>> {
    let verifier = paired_verifier(identity, peer)?;
    let mut config = ClientConfig::builder_with_provider(verifier.provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.certificate()], identity.private_key())?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_early_data = false;
    // Every connection rechecks pairing instead of resuming revoked trust.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

pub(crate) fn server(
    identity: &TransportIdentity,
    peer: &PeerIdentity,
) -> Result<Arc<ServerConfig>> {
    let verifier = paired_verifier(identity, peer)?;
    let mut config = ServerConfig::builder_with_provider(verifier.provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.certificate()], identity.private_key())?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}
