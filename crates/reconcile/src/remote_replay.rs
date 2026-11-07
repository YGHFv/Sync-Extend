//! Explicit approved-peer diagnostics, without receive, scan or mutation.
use crate::{LocalSpace, ReconcileError, Result};
use sync_extend_journal::{RemotePublicationProof, RemoteReplayReport};
use sync_extend_transport::{PeerIdentity, SignedOperation};

impl LocalSpace {
    pub fn replay_signed_remote_operation(
        &self,
        peer: &PeerIdentity,
        signed: &SignedOperation,
    ) -> Result<RemoteReplayReport> {
        signed
            .verify(peer)
            .map_err(|_| ReconcileError::Invariant("remote replay original signature invalid"))?;
        if self.read_transport_peer(&peer.device_id)? != *peer {
            return Err(ReconcileError::Invariant(
                "remote replay requires exact stored approval",
            ));
        }
        let report = self
            .journal
            .replay_remote_operation(&RemotePublicationProof {
                public_key: peer.public_key,
                operation: signed.operation.clone(),
                signature: signed.signature.clone(),
            })?;
        self.verify_root()?;
        Ok(report)
    }
}
