//! Durable intent before exact handle no-replace rename; no final history yet.
use super::NativePublicationReadiness;
use crate::{
    native_publication::{physical, Header},
    storage_inventory::reader::{hash, invalid},
    Journal, Result,
};
use std::{fs, path::PathBuf};
use sync_extend_core_model::EntryId;

/// Exact guarded original payload observed at its admitted target. This is not
/// history completion, remote apply, reference release or cleanup permission.
pub struct NativePublicationObservation {
    held: NativePublicationReadiness,
}
impl NativePublicationObservation {
    pub fn transaction_id(&self) -> &EntryId {
        self.held.transaction_id()
    }
    pub fn verify_content(&self) -> Result<()> {
        self.held.verify_content()?;
        verify_target(&self.held)
    }
}

pub(super) fn slot_present(path: &std::path::Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn target_path(header: &Header) -> Result<PathBuf> {
    let component = header
        .intent
        .target_path
        .as_str()
        .rsplit('/')
        .next()
        .ok_or(invalid("native target component missing"))?;
    Ok(PathBuf::from(&header.ancestors[0].path).join(component))
}
fn source_path(held: &NativePublicationReadiness) -> PathBuf {
    PathBuf::from(&held.header.ancestors[0].path)
        .join(".sync-tmp")
        .join(format!("native-{}", held.header.generation))
        .join("payload-0")
}
fn verify_source(held: &NativePublicationReadiness) -> Result<()> {
    if !held.payload.matches_path(&source_path(held))? || slot_present(&target_path(&held.header)?)?
    {
        return Err(invalid("native source or occupied target differs"));
    }
    held.verify_content()
}
fn verify_target(held: &NativePublicationReadiness) -> Result<()> {
    if slot_present(&source_path(held))?
        || !held.payload.matches_path(&target_path(&held.header)?)?
    {
        return Err(invalid("native observed target or source absence differs"));
    }
    Ok(())
}
pub(super) fn verify_forward_slot(held: &NativePublicationReadiness) -> Result<()> {
    if slot_present(&source_path(held))? {
        verify_source(held)
    } else {
        verify_target(held)
    }
}
impl Journal {
    fn native_forward_phase(
        &mut self,
        held: &NativePublicationReadiness,
        phase: &'static str,
    ) -> Result<()> {
        let header = &held.header;
        let text = |value: &str| rusqlite::types::Value::Text(value.into());
        self.native_insert(
            header,
            "native_publication_phases",
            vec![
                text(header.intent.transaction_id.as_str()),
                text(header.generation.as_str()),
                rusqlite::types::Value::Integer(0),
                text(hash(header)?.as_str()),
                text(phase),
                text(physical(&held.payload_key)?.as_str()),
                text(header.intent.content.content_id.as_str()),
                text(hash(&header.intent.target_path)?.as_str()),
                rusqlite::types::Value::Integer(header.intent.created_at_ms as i64),
                text(&held.owner_key.volume),
                text(&held.owner_key.id),
                text(&header.parent.volume),
                text(&header.parent.id),
                text(header.intent.target_path.as_str()),
            ],
            false,
            || {
                held.verify_content()?;
                if phase == "publishing" {
                    verify_source(held)
                } else {
                    verify_target(held)
                }
            },
        )
    }

    /// Commit exact Publishing before the actual no-replace descriptor rename.
    /// Errors preserve durable receipts, any native outcome and all history pins.
    pub fn publish_native_publication_ready(
        &mut self,
        held: NativePublicationReadiness,
    ) -> Result<NativePublicationObservation> {
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "native publishing refuses caller-owned transaction",
            ));
        }
        verify_source(&held)?;
        self.native_forward_phase(&held, "publishing")?;
        held.payload
            .rename_no_replace(&target_path(&held.header)?)?;
        held.verify_content()?;
        verify_target(&held)?;
        self.native_forward_phase(&held, "observed")?;
        Ok(NativePublicationObservation { held })
    }

    /// Reopen original receipts after durable Publishing; resume only its rename
    /// or observe the exact target. Never create, overwrite, adopt or delete.
    pub fn recover_native_publication_forward(
        &mut self,
        id: &EntryId,
    ) -> Result<NativePublicationObservation> {
        if !self.connection.is_autocommit() {
            return Err(invalid(
                "native forward recovery refuses caller-owned transaction",
            ));
        }
        let held = self.reopen_native_publication_guarded(id, true)?;
        let observed: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_publication_phases
             WHERE transaction_id=?1 AND attempt=0 AND phase='observed')",
            [id.as_str()],
            |row| row.get(0),
        )?;
        if observed {
            verify_target(&held)?;
        } else {
            if slot_present(&source_path(&held))? {
                verify_source(&held)?;
                held.payload
                    .rename_no_replace(&target_path(&held.header)?)?;
            }
            held.verify_content()?;
            verify_target(&held)?;
            self.native_forward_phase(&held, "observed")?;
        }
        let observation = NativePublicationObservation { held };
        observation.verify_content()?;
        Ok(observation)
    }
}
