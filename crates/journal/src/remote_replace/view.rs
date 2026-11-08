//! Borrowed identity-aware observation, not a creator or publication grant.
use super::payload::{RemoteReplaceCreation, RemoteReplaceReadiness};
use super::windows::*;
use super::*;
use crate::NativePublicationFileObservation;
use std::{fs::File, path::Path};
use sync_extend_platform_fs::{regular_file_matches_path, FileKey};

fn matches(file: &File, path: &Path) -> Result<bool> {
    Ok(present(path)? && regular_file_matches_path(file, path)?)
}
enum Held<'a> {
    Source(&'a RemoteReplaceSource),
    Creation(&'a RemoteReplaceCreation),
    Ready(&'a RemoteReplaceReadiness),
    Observed(&'a RemoteReplaceObservation),
}
pub struct RemoteReplaceFileView<'a> {
    held: Held<'a>,
}
impl RemoteReplaceSource {
    pub fn file_view(&self) -> RemoteReplaceFileView<'_> {
        RemoteReplaceFileView {
            held: Held::Source(self),
        }
    }
}
impl RemoteReplaceCreation {
    pub fn file_view(&self) -> RemoteReplaceFileView<'_> {
        RemoteReplaceFileView {
            held: Held::Creation(self),
        }
    }
}
impl RemoteReplaceReadiness {
    pub fn file_view(&self) -> RemoteReplaceFileView<'_> {
        RemoteReplaceFileView {
            held: Held::Ready(self),
        }
    }
}
impl RemoteReplaceObservation {
    pub fn file_view(&self) -> RemoteReplaceFileView<'_> {
        RemoteReplaceFileView {
            held: Held::Observed(self),
        }
    }
}
impl RemoteReplaceFileView<'_> {
    fn files(&self) -> (&RemoteReplaceSource, Option<&File>) {
        match self.held {
            Held::Source(h) => (h, h.payload.as_ref().map(|p| p.reader())),
            Held::Creation(c) => (&c.held, Some(c.payload.reader())),
            Held::Ready(r) => (&r.held, r.held.payload.as_ref().map(|p| p.reader())),
            Held::Observed(o) => (&o.held, o.held.payload.as_ref().map(|p| p.reader())),
        }
    }
    pub fn verify(&self) -> Result<()> {
        match self.held {
            Held::Source(h) => h.verify_content()?,
            Held::Creation(c) => c.verify()?,
            Held::Ready(r) => r.verify_content()?,
            Held::Observed(o) => o.verify_content()?,
        }
        let (held, payload) = self.files();
        let target = at(&held.header, &held.header.source.path);
        let quarantine = destination(&held.header);
        if !matches(held.file.reader(), &target)? && !matches(held.file.reader(), &quarantine)? {
            return Err(invalid("remote Replace view original source slot differs"));
        }
        if let Some(payload) = payload {
            if !matches(payload, &owner_path(&held.header).join("payload-0"))?
                && !matches(payload, &target)?
            {
                return Err(invalid("remote Replace view original payload slot differs"));
            }
            let expected = held.incoming()?.content.unwrap().length;
            if payload.metadata()?.len() > expected {
                return Err(invalid(
                    "remote Replace original writer exceeds bounded length",
                ));
            }
        }
        Ok(())
    }
    pub fn observe_file(&self, path: &Path) -> Result<Option<NativePublicationFileObservation>> {
        let (held, payload) = self.files();
        if path != at(&held.header, &held.header.source.path)
            && path != destination(&held.header)
            && path != owner_path(&held.header).join("payload-0")
        {
            return Ok(None);
        }
        self.verify()?;
        let file = if matches(held.file.reader(), path)? {
            held.file.reader()
        } else {
            let payload = payload.ok_or(invalid("remote Replace view refuses foreign slot"))?;
            if !matches(payload, path)? {
                return Err(invalid("remote Replace view refuses foreign slot"));
            }
            payload
        };
        let observed = matches!(self.held, Held::Observed(_))
            && path == at(&held.header, &held.header.source.path);
        Ok(Some(NativePublicationFileObservation {
            metadata: file.metadata()?,
            physical_identity: ContentId::hash(FileKey::from_file(file)?.to_string().as_bytes()),
            content: if observed {
                held.incoming()?.content
            } else {
                None
            },
        }))
    }
    pub fn remaining_internal_bytes(&self) -> Result<u64> {
        self.verify()?;
        let (held, payload) = self.files();
        let original_remaining = if matches(held.file.reader(), &destination(&held.header))? {
            0
        } else {
            held.header.source.content.as_ref().unwrap().length
        };
        let incoming = held.incoming()?.content.unwrap().length;
        let payload_remaining = match payload {
            Some(p) if matches(p, &at(&held.header, &held.header.source.path))? => 0,
            Some(p) => incoming
                .checked_sub(p.metadata()?.len())
                .ok_or(invalid("remote Replace payload length grew"))?,
            None => incoming,
        };
        original_remaining
            .checked_add(payload_remaining)
            .ok_or(invalid("remote Replace complete native peak overflow"))
    }
}
