//! Explicit config bytes use the same actual CREATE ACL/readback boundary.
impl super::ExplicitOriginalConfigMapping {
    pub fn install_current_user_config(
        self,
        parent: &sync_extend_platform_fs::LockedDirectory,
        component: &str,
    ) -> crate::Result<crate::InstalledExplicitWebDavCredential> {
        crate::explicit_credential_mapping::install_private_bytes(
            self.mapped_bytes(),
            self.mapped_digest(),
            parent,
            component,
        )
    }
}
