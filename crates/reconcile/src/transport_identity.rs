use crate::{identity, LocalSpace, ReconcileError, Result};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
};
use sync_extend_core_model::{ContentId, DeviceId, EntryId};
use sync_extend_transport::{PeerIdentity, TransportIdentity};

impl LocalSpace {
    pub fn transport_identity(&self) -> Result<TransportIdentity> {
        self.verify_root()?;
        let key = identity::load_signing_key(&self.data_dir.join("device.secret"), false)?;
        if DeviceId::from_public_key(key.verifying_key().as_bytes()) != self.device_id {
            return Err(ReconcileError::Invariant(
                "transport device key differs from journal",
            ));
        }
        TransportIdentity::from_signing_key(self.space_id.clone(), key)
            .map_err(|_| ReconcileError::Invariant("transport credential generation failed"))
    }

    /// Out-of-band peer approval is explicit and compare-and-create only.
    /// No secret keys are exported, replaced or trusted automatically.
    pub fn approve_transport_peer(
        &self,
        peer: &PeerIdentity,
        expected_public_key: &ContentId,
    ) -> Result<()> {
        self.verify_root()?;
        peer.validate()
            .map_err(|_| ReconcileError::Invariant("invalid peer identity"))?;
        let public_key_hex: String = peer
            .public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if peer.space_id != self.space_id
            || peer.device_id == self.device_id
            || public_key_hex != expected_public_key.as_str()
        {
            return Err(ReconcileError::Invariant(
                "explicit pairing key or space mismatch",
            ));
        }
        let directory = self.data_dir.join("peers");
        crate::check_ancestors(&directory)?;
        crate::create_private_directory(&directory)?;
        let target = directory.join(format!("{}.json", peer.device_id));
        if target.try_exists()? {
            let old = self.read_transport_peer(&peer.device_id)?;
            if old != *peer {
                return Err(ReconcileError::Invariant(
                    "existing pairing differs; explicit revoke required",
                ));
            }
            return Ok(());
        }
        let bytes = serde_json::to_vec(peer)?;
        if bytes.len() > 64 * 1024 {
            return Err(ReconcileError::ResourceLimit("pairing bytes"));
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let temporary = directory.join(format!(".pairing-{}.tmp", EntryId::random()?));
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        // Same-directory hard-link publication is atomic and refuses replacement.
        // A crash can leave a private temporary file, never a partial trust record.
        fs::hard_link(&temporary, &target)?;
        sync_extend_cas::sync_directory(&directory)?;
        fs::remove_file(&temporary)?;
        sync_extend_cas::sync_directory(&directory)?;
        self.verify_root()?;
        Ok(())
    }

    pub fn read_transport_peer(&self, device: &DeviceId) -> Result<PeerIdentity> {
        self.verify_root()?;
        let path = self.data_dir.join("peers").join(format!("{device}.json"));
        crate::check_ancestors(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || sync_extend_cas::is_reparse(&metadata)
            || metadata.len() > 64 * 1024
        {
            return Err(ReconcileError::Invariant("unsafe pairing file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ReconcileError::Invariant("pairing file must be private"));
            }
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 64 * 1024 {
            return Err(ReconcileError::ResourceLimit("pairing bytes"));
        }
        let peer: PeerIdentity = serde_json::from_slice(&bytes)?;
        peer.validate()
            .map_err(|_| ReconcileError::Invariant("invalid stored pairing"))?;
        if peer.space_id != self.space_id || peer.device_id != *device || *device == self.device_id
        {
            return Err(ReconcileError::Invariant("stored pairing scope mismatch"));
        }
        Ok(peer)
    }
}
