use super::{physical, Header};
use crate::{
    storage_inventory::reader::invalid, NativePublicationCreation, NativePublicationObservation,
    NativePublicationReadiness, Result,
};
use std::{
    fs::{File, Metadata},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{ContentId, FileManifest};
use sync_extend_platform_fs::{regular_file_matches_path, FileKey};

enum Held<'a> {
    Creation(&'a NativePublicationCreation),
    Ready(&'a NativePublicationReadiness),
    Observed(&'a NativePublicationObservation),
}

/// Bounded borrowed view of two exact original files. No caller-selected skip,
/// reader/writer/Clone/constructor or persisted mutation authority is exposed.
pub struct NativePublicationFileView<'a> {
    held: Held<'a>,
}

pub struct NativePublicationFileObservation {
    pub metadata: Metadata,
    pub physical_identity: ContentId,
    pub content: Option<FileManifest>,
}

impl NativePublicationCreation {
    pub fn file_view(&self) -> NativePublicationFileView<'_> {
        NativePublicationFileView {
            held: Held::Creation(self),
        }
    }
}
impl NativePublicationReadiness {
    pub fn file_view(&self) -> NativePublicationFileView<'_> {
        NativePublicationFileView {
            held: Held::Ready(self),
        }
    }
}
impl NativePublicationObservation {
    pub fn file_view(&self) -> NativePublicationFileView<'_> {
        NativePublicationFileView {
            held: Held::Observed(self),
        }
    }
}
impl NativePublicationFileView<'_> {
    fn files(&self) -> (&Header, &File, &File, bool) {
        match self.held {
            Held::Creation(held) => (
                &held.header,
                held.marker.reader(),
                held.payload.reader(),
                false,
            ),
            Held::Ready(held) => (
                &held.header,
                held.marker.reader(),
                held.payload.reader(),
                false,
            ),
            Held::Observed(held) => {
                let held = &held.held;
                (
                    &held.header,
                    held.marker.reader(),
                    held.payload.reader(),
                    true,
                )
            }
        }
    }
    fn paths(&self) -> Result<(PathBuf, PathBuf)> {
        let (header, _, _, observed) = self.files();
        let owner = PathBuf::from(&header.ancestors[0].path)
            .join(".sync-tmp")
            .join(format!("native-{}", header.generation));
        let forward_target = matches!(self.held, Held::Ready(_))
            && !super::sealing::publishing::slot_present(&owner.join("payload-0"))?;
        let payload = if observed || forward_target {
            let component = header
                .intent
                .target_path
                .as_str()
                .rsplit('/')
                .next()
                .ok_or(invalid("native view target missing"))?;
            PathBuf::from(&header.ancestors[0].path).join(component)
        } else {
            owner.join("payload-0")
        };
        Ok((owner.join("owner"), payload))
    }
    pub fn verify(&self) -> Result<()> {
        match self.held {
            Held::Creation(held) => held.verify_originals()?,
            Held::Ready(held) => held.verify_content()?,
            Held::Observed(held) => held.verify_content()?,
        }
        let (_, marker, payload, _) = self.files();
        let (marker_path, payload_path) = self.paths()?;
        if !regular_file_matches_path(marker, &marker_path)?
            || !regular_file_matches_path(payload, &payload_path)?
        {
            return Err(invalid("native file view original slot differs"));
        }
        Ok(())
    }
    pub fn observe_file(&self, path: &Path) -> Result<Option<NativePublicationFileObservation>> {
        let (marker_path, payload_path) = self.paths()?;
        if path != marker_path && path != payload_path {
            return Ok(None);
        }
        self.verify()?;
        let (header, marker, payload, observed) = self.files();
        let file = if path == marker_path { marker } else { payload };
        Ok(Some(NativePublicationFileObservation {
            metadata: file.metadata()?,
            physical_identity: physical(&super::creation::key(FileKey::from_file(file)?))?,
            content: (observed && path == payload_path).then(|| header.intent.content.clone()),
        }))
    }
    /// Remaining internal liability, not a second charge for existing bytes.
    pub fn remaining_internal_bytes(&self) -> Result<u64> {
        self.verify()?;
        let (header, marker, payload, observed) = self.files();
        let marker = marker.metadata()?.len();
        let payload = payload.metadata()?.len();
        if marker > 32 || payload > header.intent.content.length {
            return Err(invalid("native materialization exceeds original lengths"));
        }
        let (_, payload_path) = self.paths()?;
        let internal_payload = PathBuf::from(&header.ancestors[0].path)
            .join(".sync-tmp")
            .join(format!("native-{}", header.generation))
            .join("payload-0");
        let external = observed || payload_path != internal_payload;
        header
            .intent
            .content
            .length
            .checked_mul(16)
            .and_then(|n| {
                n.checked_add(if external {
                    0
                } else {
                    header.intent.content.length - payload
                })
            })
            .and_then(|n| n.checked_add(32 - marker))
            .ok_or(invalid("native remaining internal liability overflow"))
    }
}
