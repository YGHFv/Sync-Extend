//! Storage-only effects through one acquired image and one original CAS loan.
//! This module is a private child of storage_cas; no pathname executor is exposed.
use super::{
    absent, close_original, key, name, private, refuse, same_image, same_slot, Graph,
    LinuxStorageCasDirectoryGuard, LinuxStorageCasExclusiveCoordination,
    LinuxStorageCasFileObservation, LinuxStorageCasRetirementInspection, OriginalWriteLease,
    CHUNK_BYTES, F_GETLEASE,
};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileExt, MetadataExt},
    },
    sync::Arc,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxStorageRetirementPayloadSlot {
    Original,
    Quarantine,
    Restored,
    UnlinkedLive,
    Unlinked,
    RestoredClosed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageRetirementMarkerObservation {
    pub identity: crate::UnixFileKey,
    pub parent: crate::UnixFileKey,
    pub component: String,
    pub bytes: [u8; 65],
    pub private_single_link: bool,
    pub mandatory_original_write_lease: bool,
    pub original_creator: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageRetirementMoveObservation {
    pub original: LinuxStorageCasFileObservation,
    pub original_parent: crate::UnixFileKey,
    pub quarantine_parent: crate::UnixFileKey,
    pub quarantine_component: String,
    pub current_slot: LinuxStorageRetirementPayloadSlot,
    pub source_slot_absent: bool,
    pub both_original_parents_synced: bool,
    pub original_payload_descriptor_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageRetirementUnlinkObservation {
    pub original_identity: crate::UnixFileKey,
    pub parent_identity: crate::UnixFileKey,
    pub component: String,
    pub parent_synced: bool,
    pub original_nlink_zero_verified: bool,
    pub original_payload_descriptor_closed: bool,
    pub original_slot_absent: bool,
    pub quarantine_slot_absent: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageRetirementMarkerUnlinkObservation {
    pub original_identity: crate::UnixFileKey,
    pub parent_identity: crate::UnixFileKey,
    pub component: String,
    pub parent_synced: bool,
    pub original_nlink_zero_verified: bool,
    pub original_marker_descriptor_closed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageRetirementClosedObservation {
    pub original_parent: crate::UnixFileKey,
    pub marker_identity: crate::UnixFileKey,
    pub marker_parent: crate::UnixFileKey,
    pub marker_component: String,
    pub marker_parent_synced: bool,
    pub original_marker_nlink_zero_verified: bool,
    pub original_owner_descriptors_closed: bool,
    pub independent_marker_slot_absent: bool,
    pub independent_original_slot_absent: bool,
    pub independent_quarantine_slot_absent: bool,
    pub restored_payload_identity: Option<crate::UnixFileKey>,
}

struct OriginalMarker {
    // The watcher and every lease FD end before the one original creator FD.
    lease: Option<OriginalWriteLease>,
    file: Option<File>,
    key: crate::UnixFileKey,
    parent: crate::UnixFileKey,
    component: CString,
    bytes: [u8; 65],
    before: Metadata,
    creator_receipt_consumed: bool,
    unlinked: bool,
}

/// Not Clone/Deserialize and never reconstructed from a stored marker receipt.
pub struct LinuxStorageRetirementBoundary {
    marker: Option<OriginalMarker>,
    payload_lease: Option<OriginalWriteLease>,
    payload: Option<File>,
    parent: Option<File>,
    graph: Option<Graph>,
    possession: Arc<()>,
    layout: super::LinuxStorageCasObservation,
    payload_before: Metadata,
    payload_key: crate::UnixFileKey,
    original_parent_key: crate::UnixFileKey,
    original_component: CString,
    shard: String,
    quarantine_component: CString,
    length: u64,
    slot: LinuxStorageRetirementPayloadSlot,
    request_id: String,
    activation_id: String,
}

/// A single receipt borrow of the still-live original CREATE description.
pub struct LinuxStorageRetirementCreatorReceipt<'a> {
    boundary: &'a LinuxStorageRetirementBoundary,
}

impl LinuxStorageRetirementCreatorReceipt<'_> {
    pub fn activation_ids(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<(&str, &str)> {
        self.verify(exclusive)?;
        self.boundary.activation_ids(exclusive)
    }

    pub fn verify(&self, exclusive: &LinuxStorageCasExclusiveCoordination<'_>) -> io::Result<()> {
        self.boundary.verify(exclusive)?;
        let marker = self
            .boundary
            .marker
            .as_ref()
            .ok_or_else(|| refuse("original storage marker creator is no longer live"))?;
        if !marker.creator_receipt_consumed {
            return Err(refuse("original storage marker receipt was not consumed"));
        }
        self.boundary.verify_marker(marker)
    }

    pub fn observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMarkerObservation> {
        self.verify(exclusive)?;
        self.boundary.marker_observation()
    }

    pub fn layout_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<super::LinuxStorageCasObservation> {
        self.verify(exclusive)?;
        self.boundary.layout_observation(exclusive)
    }

    pub fn payload_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageCasFileObservation> {
        self.verify(exclusive)?;
        self.boundary.payload_observation(exclusive)
    }

    pub fn read_payload(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<Vec<u8>> {
        self.verify(exclusive)?;
        self.boundary.read_payload(exclusive)
    }
}

fn same_payload(before: &Metadata, now: &Metadata, named: bool) -> bool {
    before.dev() == now.dev()
        && before.ino() == now.ino()
        && before.uid() == now.uid()
        && before.mode() == now.mode()
        && now.nlink() == u64::from(named)
        && before.len() == now.len()
        && before.mtime() == now.mtime()
        && before.mtime_nsec() == now.mtime_nsec()
}

fn same_named_payload(before: &Metadata, now: &libc::stat) -> bool {
    before.dev() == now.st_dev
        && before.ino() == now.st_ino
        && before.uid() == now.st_uid
        && before.mode() == now.st_mode
        && now.st_nlink == 1
        && u64::try_from(now.st_size).ok() == Some(before.len())
        && before.mtime() == now.st_mtime
        && before.mtime_nsec() == now.st_mtime_nsec
}

fn close_leased(lease: Option<OriginalWriteLease>, file: File) -> io::Result<()> {
    let mut failure = lease.map_or(Ok(()), OriginalWriteLease::close).err();
    // SAFETY: query the still-live original description; the lease watcher has
    // joined and released every descriptor that it owned before this close.
    let actual = unsafe { libc::fcntl(file.as_raw_fd(), F_GETLEASE) };
    if actual != libc::F_UNLCK {
        failure.get_or_insert_with(|| {
            if actual < 0 {
                io::Error::last_os_error()
            } else {
                refuse("original retirement mandatory kernel lease did not release")
            }
        });
    }
    if let Err(error) = close_original(file) {
        failure.get_or_insert(error);
    }
    failure.map_or(Ok(()), Err)
}

fn combine_close<T>(operation: io::Result<T>, closed: io::Result<()>) -> io::Result<T> {
    match (operation, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(closed)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; original descriptor closure also refused: {closed}"),
        )),
    }
}

impl LinuxStorageCasRetirementInspection {
    /// Consume precisely the inspection issued by this same exclusive loan.
    pub fn into_storage_retirement_boundary(
        mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
        request_id: &str,
        activation_id: &str,
    ) -> io::Result<LinuxStorageRetirementBoundary> {
        let inputs = (|| {
            super::validate_hex(request_id, 32)?;
            super::validate_hex(activation_id, 32)?;
            if request_id == activation_id {
                return Err(refuse("storage retirement activation must be independent"));
            }
            self.verify(exclusive)?;
            let graph = self
                .original
                .graph
                .as_ref()
                .expect("verified original graph");
            // Validate every fallible input before taking any original field.
            if Arc::strong_count(&graph.realm_lease) != 2 {
                return Err(refuse("other original inside CAS loans remain active"));
            }
            let payload = self
                .original
                .file
                .as_ref()
                .expect("verified original payload");
            let parent = self
                .original
                .parent
                .as_ref()
                .expect("verified original parent");
            Ok((
                payload.metadata()?,
                key(payload)?,
                key(parent)?,
                name(&format!("retirement-{activation_id}.payload"))?,
            ))
        })();
        let (payload_before, payload_key, original_parent_key, quarantine_component) = match inputs
        {
            Ok(inputs) => inputs,
            Err(error) => {
                return combine_close(
                    Err(error),
                    self.close_file().and_then(|guard| guard.close()),
                )
            }
        };
        let graph = self.original.graph.take().expect("verified original graph");
        let parent = self
            .original
            .parent
            .take()
            .expect("verified original parent");
        let payload = self
            .original
            .file
            .take()
            .expect("verified original payload");
        let result = LinuxStorageRetirementBoundary {
            marker: None,
            payload_lease: self.original.lease.take(),
            payload_before,
            payload_key,
            original_parent_key,
            payload: Some(payload),
            parent: Some(parent),
            graph: Some(graph),
            possession: self.possession,
            layout: self.layout,
            original_component: self.original.component,
            shard: self.original.shard,
            quarantine_component,
            length: self.original.length,
            slot: LinuxStorageRetirementPayloadSlot::Original,
            request_id: request_id.to_owned(),
            activation_id: activation_id.to_owned(),
        };
        if let Err(error) = result.verify(exclusive) {
            return combine_close(Err(error), result.close().and_then(|guard| guard.close()));
        }
        Ok(result)
    }
}

impl LinuxStorageRetirementBoundary {
    pub fn activation_ids(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<(&str, &str)> {
        self.verify(exclusive)?;
        Ok((&self.request_id, &self.activation_id))
    }

    fn graph(&self) -> io::Result<&Graph> {
        self.graph
            .as_ref()
            .ok_or_else(|| refuse("original retirement graph closed"))
    }

    fn parent(&self) -> io::Result<&File> {
        self.parent
            .as_ref()
            .ok_or_else(|| refuse("original retirement parent closed"))
    }

    fn verify_namespace(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<()> {
        exclusive.verify()?;
        let graph = self.graph()?;
        graph.verify()?;
        if !Arc::ptr_eq(&self.possession, &exclusive.guard.possession)
            || !Arc::ptr_eq(&graph.owner, &exclusive.guard.owner)
            || Arc::strong_count(&graph.realm_lease) != 2
        {
            return Err(refuse(
                "same live storage namespace, exclusive possession and sole native loan required",
            ));
        }
        let parent = self.parent()?;
        same_image(parent, &graph.owner, true)?;
        same_slot(&graph.objects, &name(&self.shard)?, parent)?;
        if key(parent)? != self.original_parent_key {
            return Err(refuse("original retirement shard parent changed"));
        }
        exclusive.verify()
    }

    fn verify_marker(&self, marker: &OriginalMarker) -> io::Result<()> {
        let graph = self.graph()?;
        let file = marker
            .file
            .as_ref()
            .ok_or_else(|| refuse("original creator FD closed"))?;
        marker
            .lease
            .as_ref()
            .ok_or_else(|| refuse("original creator lease closed"))?
            .verify()?;
        let current = if marker.unlinked {
            absent(&graph.temporary, &marker.component)?;
            file.metadata()?
        } else {
            same_image(file, &graph.owner, false)?;
            same_slot(&graph.temporary, &marker.component, file)?;
            private(file, false)?
        };
        let mut bytes = [0; 65];
        file.read_exact_at(&mut bytes, 0)?;
        if key(file)? != marker.key
            || key(&graph.temporary)? != marker.parent
            || !same_payload(&marker.before, &current, !marker.unlinked)
            || current.len() != 65
            || bytes != marker.bytes
        {
            return Err(refuse("original storage CREATE receipt changed"));
        }
        marker
            .lease
            .as_ref()
            .expect("verified marker lease")
            .verify()
    }

    pub fn verify(&self, exclusive: &LinuxStorageCasExclusiveCoordination<'_>) -> io::Result<()> {
        self.verify_namespace(exclusive)?;
        let graph = self.graph()?;
        if let Some(marker) = &self.marker {
            self.verify_marker(marker)?;
        }
        match self.slot {
            LinuxStorageRetirementPayloadSlot::Original
            | LinuxStorageRetirementPayloadSlot::Restored
            | LinuxStorageRetirementPayloadSlot::Quarantine => {
                let file = self
                    .payload
                    .as_ref()
                    .ok_or_else(|| refuse("original payload FD closed"))?;
                self.payload_lease
                    .as_ref()
                    .ok_or_else(|| refuse("original payload lease closed"))?
                    .verify()?;
                same_image(file, &graph.owner, false)?;
                let (parent, component) = match self.slot {
                    LinuxStorageRetirementPayloadSlot::Original
                    | LinuxStorageRetirementPayloadSlot::Restored => {
                        (self.parent()?, &self.original_component)
                    }
                    _ => (&graph.temporary, &self.quarantine_component),
                };
                same_slot(parent, component, file)?;
                if key(file)? != self.payload_key
                    || !same_payload(&self.payload_before, &private(file, false)?, true)
                {
                    return Err(refuse("original retirement payload changed"));
                }
                self.payload_lease
                    .as_ref()
                    .expect("verified payload lease")
                    .verify()?;
                if self.slot == LinuxStorageRetirementPayloadSlot::Quarantine {
                    absent(self.parent()?, &self.original_component)?;
                } else {
                    absent(&graph.temporary, &self.quarantine_component)?;
                }
            }
            LinuxStorageRetirementPayloadSlot::UnlinkedLive => {
                let file = self
                    .payload
                    .as_ref()
                    .ok_or_else(|| refuse("unlinked original FD closed"))?;
                self.payload_lease
                    .as_ref()
                    .ok_or_else(|| refuse("unlinked original lease closed"))?
                    .verify()?;
                if key(file)? != self.payload_key
                    || !same_payload(&self.payload_before, &file.metadata()?, false)
                {
                    return Err(refuse(
                        "unlinked original held payload did not remain nlink zero",
                    ));
                }
                absent(self.parent()?, &self.original_component)?;
                absent(&graph.temporary, &self.quarantine_component)?;
                self.payload_lease
                    .as_ref()
                    .expect("verified unlinked original lease")
                    .verify()?;
            }
            LinuxStorageRetirementPayloadSlot::Unlinked
            | LinuxStorageRetirementPayloadSlot::RestoredClosed => {
                if self.payload.is_some() || self.payload_lease.is_some() {
                    return Err(refuse("closed retirement payload retained an owner FD"));
                }
                absent(&graph.temporary, &self.quarantine_component)?;
                if self.slot == LinuxStorageRetirementPayloadSlot::RestoredClosed {
                    let named = super::slot(self.parent()?, &self.original_component)?;
                    if !same_named_payload(&self.payload_before, &named) {
                        return Err(refuse("closed restored original slot changed"));
                    }
                } else {
                    absent(self.parent()?, &self.original_component)?;
                }
            }
        }
        self.verify_namespace(exclusive)
    }

    pub fn payload_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageCasFileObservation> {
        self.verify(exclusive)?;
        Ok(LinuxStorageCasFileObservation {
            identity: self.payload_key,
            parent: self.original_parent_key,
            length: self.length,
            modified_seconds: self.payload_before.mtime(),
            modified_nanoseconds: self.payload_before.mtime_nsec(),
            single_link: !matches!(
                self.slot,
                LinuxStorageRetirementPayloadSlot::UnlinkedLive
                    | LinuxStorageRetirementPayloadSlot::Unlinked
            ),
            mandatory_original_write_lease: self.payload_lease.is_some(),
        })
    }

    pub fn layout_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<super::LinuxStorageCasObservation> {
        self.verify(exclusive)?;
        let graph = self.graph()?;
        let root = key(&graph.root)?;
        let cas = key(&graph.cas)?;
        let objects = key(&graph.objects)?;
        let temporary = key(&graph.temporary)?;
        let realm = key(&graph.realm)?;
        let observed = super::LinuxStorageCasObservation {
            expected_layout: super::LinuxStorageCasExpectedLayout {
                format_version: 1,
                backing_image: graph.owner.backing_image_key(),
                image_filesystem_id: graph.filesystem_id,
                mounted_root_inode: root.inode,
                cas_inode: cas.inode,
                objects_inode: objects.inode,
                temporary_inode: temporary.inode,
                realm_inode: realm.inode,
                realm_fingerprint: graph.realm_fingerprint,
                owner_uid: private(&graph.root, true)?.uid(),
            },
            owner_generation: graph.generation,
            namespace: graph.owner.namespace_key(),
            runtime_mount_id: graph.mount_id,
            mounted_root: root,
            cas,
            objects,
            temporary,
            realm,
            limits: self.layout.limits,
            physical_liability_bytes: self.layout.physical_liability_bytes,
        };
        if observed != self.layout {
            return Err(refuse(
                "original storage retirement layout or complete budget changed",
            ));
        }
        Ok(observed)
    }

    pub fn inventory_with_retirement_prefixes(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
        inventory: &super::LinuxStorageRetirementInventoryContext,
    ) -> io::Result<super::LinuxStorageCasInventory> {
        self.verify(exclusive)?;
        super::retirement_inventory::bounded_inventory(
            self.graph()?,
            self.layout.limits,
            Some(inventory),
        )
    }

    pub fn read_payload(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<Vec<u8>> {
        self.verify(exclusive)?;
        if self.length == 0 || self.length > CHUNK_BYTES {
            return Err(refuse("bounded original retirement payload required"));
        }
        let file = self
            .payload
            .as_ref()
            .ok_or_else(|| refuse("payload already closed"))?;
        let mut bytes = vec![0; self.length as usize];
        file.read_exact_at(&mut bytes, 0)?;
        let mut excess = [0];
        if file.read_at(&mut excess, self.length)? != 0 {
            return Err(refuse("original retirement payload grew"));
        }
        self.verify(exclusive)?;
        Ok(bytes)
    }

    /// The Journal calls this only after committing its one-shot activation.
    /// Failure preserves the actual created prefix; Drop never removes it.
    pub fn create_marker(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
        inventory: &super::LinuxStorageRetirementInventoryContext,
    ) -> io::Result<()> {
        self.verify(exclusive)?;
        if self.marker.is_some() || self.slot != LinuxStorageRetirementPayloadSlot::Original {
            return Err(refuse(
                "storage marker CREATE is a one-shot original effect",
            ));
        }
        let component = name(&format!("retirement-{}.owner", self.activation_id))?;
        let mut bytes = [0; 65];
        bytes.copy_from_slice(format!("{}:{}", self.request_id, self.activation_id).as_bytes());
        let graph = self.graph()?;
        absent(&graph.temporary, &component)?;
        absent(&graph.temporary, &self.quarantine_component)?;
        inventory.require_unreceipted_activation(&self.request_id, &self.activation_id)?;
        let mut reserved = super::retirement_inventory::bounded_inventory(
            graph,
            self.layout.limits,
            Some(inventory),
        )?;
        reserved.temporary_entries = reserved
            .temporary_entries
            .checked_add(1)
            .ok_or_else(|| refuse("storage marker entry reservation overflow"))?;
        reserved.temporary_bytes = reserved
            .temporary_bytes
            .checked_add(65)
            .ok_or_else(|| refuse("storage marker complete byte reservation overflow"))?;
        super::inventory_limit(reserved, self.layout.limits)?;
        // SAFETY: one fixed component, original held parent, no-follow exclusive
        // CREATE. The acquired private image namespace and mandatory leases,
        // rather than flock or lstat, exclude outside writers throughout.
        let descriptor = unsafe {
            libc::openat(
                graph.temporary.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
        };
        let file = super::super::owned_descriptor(descriptor)?;
        let mut lease = None;
        let inspected = (|| {
            same_image(&file, &graph.owner, false)?;
            lease = Some(OriginalWriteLease::acquire(&file)?);
            file.write_all_at(&bytes, 0)?;
            file.sync_all()?;
            graph.temporary.sync_all()?;
            same_slot(&graph.temporary, &component, &file)?;
            lease.as_ref().expect("original marker lease").verify()?;
            Ok((key(&file)?, key(&graph.temporary)?, private(&file, false)?))
        })();
        let (marker_key, marker_parent, before) = match inspected {
            Ok(observed) => observed,
            Err(error) => return combine_close(Err(error), close_leased(lease, file)),
        };
        let marker = OriginalMarker {
            key: marker_key,
            parent: marker_parent,
            component,
            before,
            bytes,
            file: Some(file),
            lease,
            creator_receipt_consumed: false,
            unlinked: false,
        };
        self.marker = Some(marker);
        self.verify(exclusive)
    }

    fn marker_observation(&self) -> io::Result<LinuxStorageRetirementMarkerObservation> {
        let marker = self
            .marker
            .as_ref()
            .ok_or_else(|| refuse("no original marker CREATE"))?;
        self.verify_marker(marker)?;
        Ok(LinuxStorageRetirementMarkerObservation {
            identity: marker.key,
            parent: marker.parent,
            component: marker.component.to_string_lossy().into_owned(),
            bytes: marker.bytes,
            private_single_link: !marker.unlinked,
            mandatory_original_write_lease: true,
            original_creator: true,
        })
    }

    pub fn original_marker_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMarkerObservation> {
        self.verify(exclusive)?;
        self.require_receipted()?;
        self.marker_observation()
    }

    pub fn consume_creator_receipt<'a>(
        &'a mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementCreatorReceipt<'a>> {
        self.verify(exclusive)?;
        let marker = self
            .marker
            .as_mut()
            .ok_or_else(|| refuse("CREATE has no live original receipt"))?;
        if marker.creator_receipt_consumed {
            return Err(refuse("original CREATE receipt already consumed"));
        }
        marker.creator_receipt_consumed = true;
        let receipt = LinuxStorageRetirementCreatorReceipt { boundary: self };
        receipt.verify(exclusive)?;
        Ok(receipt)
    }

    fn require_receipted(&self) -> io::Result<()> {
        if self
            .marker
            .as_ref()
            .is_none_or(|marker| !marker.creator_receipt_consumed)
        {
            return Err(refuse("unreceipted activation cannot move or unlink"));
        }
        Ok(())
    }

    fn require_named_creator(&self) -> io::Result<()> {
        self.require_receipted()?;
        if self.marker.as_ref().is_none_or(|marker| marker.unlinked) {
            return Err(refuse(
                "native payload effect requires its still-named original creator",
            ));
        }
        Ok(())
    }

    pub fn current_payload_slot(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementPayloadSlot> {
        self.verify(exclusive)?;
        Ok(self.slot)
    }

    pub fn move_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMoveObservation> {
        self.verify(exclusive)?;
        self.require_receipted()?;
        if !matches!(
            self.slot,
            LinuxStorageRetirementPayloadSlot::Quarantine
                | LinuxStorageRetirementPayloadSlot::Restored
                | LinuxStorageRetirementPayloadSlot::RestoredClosed
        ) {
            return Err(refuse("original native move has no immutable observation"));
        }
        // After the actual marker unlink, only the already-closed restored
        // payload remains observable. verify() still checks that same held
        // marker FD at nlink zero and its name absent; this grants no effect.
        if self.marker.as_ref().is_some_and(|marker| marker.unlinked)
            && self.slot != LinuxStorageRetirementPayloadSlot::RestoredClosed
        {
            return Err(refuse("unlinked marker requires closed restored payload observation"));
        }
        Ok(LinuxStorageRetirementMoveObservation {
            original: self.payload_observation(exclusive)?,
            original_parent: self.original_parent_key,
            quarantine_parent: key(&self.graph()?.temporary)?,
            quarantine_component: self.quarantine_component.to_string_lossy().into_owned(),
            current_slot: self.slot,
            source_slot_absent: true,
            both_original_parents_synced: true,
            original_payload_descriptor_closed: self.slot
                == LinuxStorageRetirementPayloadSlot::RestoredClosed,
        })
    }

    pub fn quarantine(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMoveObservation> {
        self.move_original(exclusive, false)
    }

    pub fn restore(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMoveObservation> {
        self.move_original(exclusive, true)
    }

    fn move_original(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
        restore: bool,
    ) -> io::Result<LinuxStorageRetirementMoveObservation> {
        self.verify(exclusive)?;
        self.require_named_creator()?;
        let expected = if restore {
            LinuxStorageRetirementPayloadSlot::Quarantine
        } else {
            LinuxStorageRetirementPayloadSlot::Original
        };
        if self.slot != expected {
            return Err(refuse("original retirement pre-move slot differs"));
        }
        let graph = self.graph()?;
        let (source_parent, source, target_parent, target) = if restore {
            (
                &graph.temporary,
                &self.quarantine_component,
                self.parent()?,
                &self.original_component,
            )
        } else {
            (
                self.parent()?,
                &self.original_component,
                &graph.temporary,
                &self.quarantine_component,
            )
        };
        absent(target_parent, target)?;
        let file = self.payload.as_ref().expect("verified original payload");
        same_slot(source_parent, source, file)?;
        self.payload_lease
            .as_ref()
            .expect("verified payload lease")
            .verify()?;
        self.verify_namespace(exclusive)?;
        // SAFETY: same acquired namespace/mount, original held parents and FD.
        // Linux RENAME_NOREPLACE is atomic against a destination occupant.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                source_parent.as_raw_fd(),
                source.as_ptr(),
                target_parent.as_raw_fd(),
                target.as_ptr(),
                1u32,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        source_parent.sync_all()?;
        target_parent.sync_all()?;
        absent(source_parent, source)?;
        same_slot(target_parent, target, file)?;
        let now = private(file, false)?;
        if !same_payload(&self.payload_before, &now, true) {
            return Err(refuse(
                "native move changed original payload identity/content metadata",
            ));
        }
        self.payload_lease
            .as_ref()
            .expect("verified payload lease")
            .verify()?;
        self.slot = if restore {
            LinuxStorageRetirementPayloadSlot::Restored
        } else {
            LinuxStorageRetirementPayloadSlot::Quarantine
        };
        self.verify(exclusive)?;
        Ok(LinuxStorageRetirementMoveObservation {
            original: self.payload_observation(exclusive)?,
            original_parent: self.original_parent_key,
            quarantine_parent: key(&self.graph()?.temporary)?,
            quarantine_component: self.quarantine_component.to_string_lossy().into_owned(),
            current_slot: self.slot,
            source_slot_absent: true,
            both_original_parents_synced: true,
            original_payload_descriptor_closed: false,
        })
    }

    pub fn close_restored_payload(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMoveObservation> {
        self.verify(exclusive)?;
        self.require_named_creator()?;
        if self.slot != LinuxStorageRetirementPayloadSlot::Restored {
            return Err(refuse("restored-close requires the original named payload"));
        }
        let original = self.payload_observation(exclusive)?;
        absent(&self.graph()?.temporary, &self.quarantine_component)?;
        let file = self.payload.take().expect("verified original payload");
        close_leased(self.payload_lease.take(), file)?;
        self.slot = LinuxStorageRetirementPayloadSlot::RestoredClosed;
        self.verify(exclusive)?;
        Ok(LinuxStorageRetirementMoveObservation {
            original,
            original_parent: self.original_parent_key,
            quarantine_parent: key(&self.graph()?.temporary)?,
            quarantine_component: self.quarantine_component.to_string_lossy().into_owned(),
            current_slot: self.slot,
            source_slot_absent: true,
            both_original_parents_synced: true,
            original_payload_descriptor_closed: true,
        })
    }

    pub fn unlink_payload(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementUnlinkObservation> {
        self.verify(exclusive)?;
        self.require_named_creator()?;
        if self.slot != LinuxStorageRetirementPayloadSlot::Quarantine {
            return Err(refuse(
                "durable delete request must identify original quarantine",
            ));
        }
        let graph = self.graph()?;
        let file = self.payload.as_ref().expect("verified original payload");
        let parent_key = key(&graph.temporary)?;
        same_slot(&graph.temporary, &self.quarantine_component, file)?;
        absent(self.parent()?, &self.original_component)?;
        self.payload_lease
            .as_ref()
            .expect("verified payload lease")
            .verify()?;
        self.verify_namespace(exclusive)?;
        // SAFETY: consumes only the same original named payload under its
        // mandatory lease and acquired namespace. No pathname fallback exists.
        if unsafe {
            libc::unlinkat(
                graph.temporary.as_raw_fd(),
                self.quarantine_component.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        graph.temporary.sync_all()?;
        let after = file.metadata()?;
        if key(file)? != self.payload_key || !same_payload(&self.payload_before, &after, false) {
            return Err(refuse(
                "original unlinked payload FD did not reach nlink zero",
            ));
        }
        self.payload_lease
            .as_ref()
            .expect("verified payload lease")
            .verify()?;
        self.slot = LinuxStorageRetirementPayloadSlot::UnlinkedLive;
        self.verify(exclusive)?;
        Ok(LinuxStorageRetirementUnlinkObservation {
            original_identity: self.payload_key,
            parent_identity: parent_key,
            component: self.quarantine_component.to_string_lossy().into_owned(),
            parent_synced: true,
            original_nlink_zero_verified: true,
            original_payload_descriptor_closed: false,
            original_slot_absent: true,
            quarantine_slot_absent: true,
        })
    }

    pub fn unlink_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementUnlinkObservation> {
        self.verify(exclusive)?;
        self.require_receipted()?;
        if !matches!(
            self.slot,
            LinuxStorageRetirementPayloadSlot::UnlinkedLive
                | LinuxStorageRetirementPayloadSlot::Unlinked
        ) {
            return Err(refuse("original payload has no native unlink proof"));
        }
        // A removed marker may describe only the closed nlink-zero payload.
        // Mutating entry points continue to require the still-named creator.
        if self.marker.as_ref().is_some_and(|marker| marker.unlinked)
            && self.slot != LinuxStorageRetirementPayloadSlot::Unlinked
        {
            return Err(refuse("unlinked marker requires closed deleted payload observation"));
        }
        if self.slot == LinuxStorageRetirementPayloadSlot::Unlinked {
            self.independent_payload_absence()?;
        }
        Ok(LinuxStorageRetirementUnlinkObservation {
            original_identity: self.payload_key,
            parent_identity: key(&self.graph()?.temporary)?,
            component: self.quarantine_component.to_string_lossy().into_owned(),
            parent_synced: true,
            original_nlink_zero_verified: true,
            original_payload_descriptor_closed: self.slot
                == LinuxStorageRetirementPayloadSlot::Unlinked,
            original_slot_absent: true,
            quarantine_slot_absent: true,
        })
    }

    fn independent_payload_absence(&self) -> io::Result<()> {
        let parent = self.parent()?.try_clone()?;
        let temporary = match self.graph()?.temporary.try_clone() {
            Ok(temporary) => temporary,
            Err(error) => return combine_close(Err(error), close_original(parent)),
        };
        let observed = (|| {
            absent(&parent, &self.original_component)?;
            absent(&temporary, &self.quarantine_component)
        })();
        combine_close(
            combine_close(observed, close_original(parent)),
            close_original(temporary),
        )
    }

    pub fn close_unlinked_payload(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementUnlinkObservation> {
        self.verify(exclusive)?;
        self.require_named_creator()?;
        if self.slot != LinuxStorageRetirementPayloadSlot::UnlinkedLive {
            return Err(refuse(
                "original payload close requires its recorded held-FD unlink prefix",
            ));
        }
        let file = self.payload.take().expect("verified unlinked original FD");
        close_leased(self.payload_lease.take(), file)?;
        self.slot = LinuxStorageRetirementPayloadSlot::Unlinked;
        // A separate held parent description performs each absence observation
        // after the original payload and every lease/watcher FD have closed.
        self.independent_payload_absence()?;
        self.verify(exclusive)?;
        Ok(LinuxStorageRetirementUnlinkObservation {
            original_identity: self.payload_key,
            parent_identity: key(&self.graph()?.temporary)?,
            component: self.quarantine_component.to_string_lossy().into_owned(),
            parent_synced: true,
            original_nlink_zero_verified: true,
            original_payload_descriptor_closed: true,
            original_slot_absent: true,
            quarantine_slot_absent: true,
        })
    }

    pub fn unlink_marker(
        &mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMarkerUnlinkObservation> {
        self.verify(exclusive)?;
        self.require_receipted()?;
        if !matches!(
            self.slot,
            LinuxStorageRetirementPayloadSlot::Unlinked
                | LinuxStorageRetirementPayloadSlot::RestoredClosed
        ) {
            return Err(refuse(
                "original payload owner must close before marker unlink",
            ));
        }
        let marker = self.marker.as_ref().expect("verified original creator");
        if marker.unlinked {
            return Err(refuse("original marker unlink is a one-shot effect"));
        }
        self.verify_marker(marker)?;
        let graph = self.graph()?;
        let file = marker.file.as_ref().expect("verified original marker");
        self.verify_namespace(exclusive)?;
        // SAFETY: exact original CREATE FD/slot and parent, no foreign reopen.
        if unsafe { libc::unlinkat(graph.temporary.as_raw_fd(), marker.component.as_ptr(), 0) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        graph.temporary.sync_all()?;
        if key(file)? != marker.key || !same_payload(&marker.before, &file.metadata()?, false) {
            return Err(refuse("original marker unlink did not reach nlink zero"));
        }
        marker
            .lease
            .as_ref()
            .expect("verified marker lease")
            .verify()?;
        let observed = LinuxStorageRetirementMarkerUnlinkObservation {
            original_identity: marker.key,
            parent_identity: marker.parent,
            component: marker.component.to_string_lossy().into_owned(),
            parent_synced: true,
            original_nlink_zero_verified: true,
            original_marker_descriptor_closed: false,
        };
        self.marker
            .as_mut()
            .expect("verified original marker")
            .unlinked = true;
        self.verify(exclusive)?;
        Ok(observed)
    }

    pub fn marker_unlink_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementMarkerUnlinkObservation> {
        self.verify(exclusive)?;
        self.require_receipted()?;
        let marker = self.marker.as_ref().expect("verified original creator");
        if !marker.unlinked {
            return Err(refuse(
                "original creator marker has no held-FD unlink proof",
            ));
        }
        Ok(LinuxStorageRetirementMarkerUnlinkObservation {
            original_identity: marker.key,
            parent_identity: marker.parent,
            component: marker.component.to_string_lossy().into_owned(),
            parent_synced: true,
            original_nlink_zero_verified: true,
            original_marker_descriptor_closed: false,
        })
    }

    /// A separate durable close request consumes the original unlinked creator.
    /// Only independent parent witnesses remain after all original owner FDs end.
    pub fn close_unlinked_marker_owner(
        mut self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementClosedBoundary> {
        let inputs = (|| {
            self.verify(exclusive)?;
            self.require_receipted()?;
            if !matches!(
                self.slot,
                LinuxStorageRetirementPayloadSlot::Unlinked
                    | LinuxStorageRetirementPayloadSlot::RestoredClosed
            ) {
                return Err(refuse(
                    "original payload must be durably closed before owner close",
                ));
            }
            let marker = self.marker.as_ref().expect("verified original creator");
            if !marker.unlinked {
                return Err(refuse(
                    "owner close requires the original marker nlink-zero prefix",
                ));
            }
            self.verify_marker(marker)?;
            Ok((marker.key, marker.parent, marker.component.clone()))
        })();
        let (marker_key, marker_parent, marker_component) = match inputs {
            Ok(inputs) => inputs,
            Err(error) => {
                return combine_close(Err(error), self.close().and_then(|guard| guard.close()))
            }
        };
        // Independent retained parents contain no payload or marker descriptor.
        let witness_graph = match self
            .graph
            .as_ref()
            .expect("verified original graph")
            .duplicate()
        {
            Ok(graph) => graph,
            Err(error) => {
                return combine_close(Err(error), self.close().and_then(|guard| guard.close()))
            }
        };
        let witness_parent = match self
            .parent
            .as_ref()
            .expect("verified original parent")
            .try_clone()
        {
            Ok(parent) => parent,
            Err(error) => {
                let originals = self.close().and_then(|guard| guard.close());
                return combine_close(
                    combine_close(Err(error), originals),
                    witness_graph.close(false),
                );
            }
        };
        let mut first = None;
        let mut marker = self.marker.take().expect("verified marker");
        if let Err(error) = close_leased(
            marker.lease.take(),
            marker.file.take().expect("original marker FD"),
        ) {
            first = Some(error);
        }
        if let Err(error) = close_original(self.parent.take().expect("original owner parent")) {
            first.get_or_insert(error);
        }
        if let Err(error) = self
            .graph
            .take()
            .expect("original owner graph")
            .close(false)
        {
            first.get_or_insert(error);
        }
        if let Some(error) = first {
            return combine_close(
                combine_close(Err(error), close_original(witness_parent)),
                witness_graph.close(false),
            );
        }
        let result = LinuxStorageRetirementClosedBoundary {
            graph: Some(witness_graph),
            parent: Some(witness_parent),
            possession: self.possession,
            original_parent_key: self.original_parent_key,
            layout: self.layout,
            request_id: self.request_id,
            activation_id: self.activation_id,
            shard: self.shard,
            payload_before: self.payload_before,
            original_component: self.original_component,
            quarantine_component: self.quarantine_component,
            marker_component,
            marker_key,
            marker_parent,
            payload_key: self.payload_key,
            restored: self.slot == LinuxStorageRetirementPayloadSlot::RestoredClosed,
        };
        if let Err(error) = result.verify(exclusive) {
            return combine_close(Err(error), result.close().and_then(|guard| guard.close()));
        }
        Ok(result)
    }

    /// Error closure preserves every named prefix and grants no terminal.
    pub fn close(mut self) -> io::Result<LinuxStorageCasDirectoryGuard> {
        let mut first = None;
        if let Some(mut marker) = self.marker.take() {
            if let Some(file) = marker.file.take() {
                if let Err(error) = close_leased(marker.lease.take(), file) {
                    first = Some(error);
                }
            }
        }
        if let Some(file) = self.payload.take() {
            if let Err(error) = close_leased(self.payload_lease.take(), file) {
                first.get_or_insert(error);
            }
        }
        if let Some(parent) = self.parent.take() {
            if let Err(error) = close_original(parent) {
                first.get_or_insert(error);
            }
        }
        let graph = self
            .graph
            .take()
            .ok_or_else(|| refuse("original retirement graph already closed"))?;
        if let Some(error) = first {
            return combine_close(Err(error), graph.close(false));
        }
        Ok(LinuxStorageCasDirectoryGuard { graph })
    }
}

/// Independent held-parent evidence after every original owner descriptor ends.
/// It cannot CREATE, move, unlink or become a reopened original owner.
pub struct LinuxStorageRetirementClosedBoundary {
    graph: Option<Graph>,
    parent: Option<File>,
    possession: Arc<()>,
    layout: super::LinuxStorageCasObservation,
    request_id: String,
    activation_id: String,
    original_parent_key: crate::UnixFileKey,
    shard: String,
    payload_before: Metadata,
    original_component: CString,
    quarantine_component: CString,
    marker_component: CString,
    marker_key: crate::UnixFileKey,
    marker_parent: crate::UnixFileKey,
    payload_key: crate::UnixFileKey,
    restored: bool,
}

impl LinuxStorageRetirementClosedBoundary {
    pub fn inventory_with_retirement_prefixes(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
        inventory: &super::LinuxStorageRetirementInventoryContext,
    ) -> io::Result<super::LinuxStorageCasInventory> {
        self.verify(exclusive)?;
        super::retirement_inventory::bounded_inventory(
            self.graph.as_ref().expect("verified independent graph"),
            self.layout.limits,
            Some(inventory),
        )
    }

    pub fn activation_ids(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<(&str, &str)> {
        self.verify(exclusive)?;
        Ok((&self.request_id, &self.activation_id))
    }

    pub fn layout_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<super::LinuxStorageCasObservation> {
        self.verify(exclusive)?;
        let graph = self.graph.as_ref().expect("verified independent graph");
        let root = key(&graph.root)?;
        let cas = key(&graph.cas)?;
        let objects = key(&graph.objects)?;
        let temporary = key(&graph.temporary)?;
        let realm = key(&graph.realm)?;
        let observed = super::LinuxStorageCasObservation {
            expected_layout: super::LinuxStorageCasExpectedLayout {
                format_version: 1,
                backing_image: graph.owner.backing_image_key(),
                image_filesystem_id: graph.filesystem_id,
                mounted_root_inode: root.inode,
                cas_inode: cas.inode,
                objects_inode: objects.inode,
                temporary_inode: temporary.inode,
                realm_inode: realm.inode,
                realm_fingerprint: graph.realm_fingerprint,
                owner_uid: private(&graph.root, true)?.uid(),
            },
            owner_generation: graph.generation,
            namespace: graph.owner.namespace_key(),
            runtime_mount_id: graph.mount_id,
            mounted_root: root,
            cas,
            objects,
            temporary,
            realm,
            limits: self.layout.limits,
            physical_liability_bytes: self.layout.physical_liability_bytes,
        };
        if observed != self.layout {
            return Err(refuse("independent retirement layout binding changed"));
        }
        Ok(observed)
    }

    pub fn verify(&self, exclusive: &LinuxStorageCasExclusiveCoordination<'_>) -> io::Result<()> {
        exclusive.verify()?;
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refuse("independent witness closed"))?;
        graph.verify()?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| refuse("independent parent closed"))?;
        if !Arc::ptr_eq(&self.possession, &exclusive.guard.possession)
            || !Arc::ptr_eq(&graph.owner, &exclusive.guard.owner)
            || Arc::strong_count(&graph.realm_lease) != 2
            || key(parent)? != self.original_parent_key
            || key(&graph.temporary)? != self.marker_parent
        {
            return Err(refuse("independent retirement absence owner changed"));
        }
        same_image(parent, &graph.owner, true)?;
        same_slot(&graph.objects, &name(&self.shard)?, parent)?;
        absent(&graph.temporary, &self.marker_component)?;
        absent(&graph.temporary, &self.quarantine_component)?;
        if self.restored {
            let named = super::slot(parent, &self.original_component)?;
            if !same_named_payload(&self.payload_before, &named) {
                return Err(refuse("independent restored original slot differs"));
            }
        } else {
            absent(parent, &self.original_component)?;
        }
        graph.verify()?;
        exclusive.verify()
    }

    pub fn observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageRetirementClosedObservation> {
        self.verify(exclusive)?;
        Ok(LinuxStorageRetirementClosedObservation {
            original_parent: self.original_parent_key,
            marker_identity: self.marker_key,
            marker_parent: self.marker_parent,
            marker_component: self.marker_component.to_string_lossy().into_owned(),
            marker_parent_synced: true,
            original_marker_nlink_zero_verified: true,
            original_owner_descriptors_closed: true,
            independent_marker_slot_absent: true,
            independent_original_slot_absent: !self.restored,
            independent_quarantine_slot_absent: true,
            restored_payload_identity: self.restored.then_some(self.payload_key),
        })
    }

    pub fn close(mut self) -> io::Result<LinuxStorageCasDirectoryGuard> {
        let closed = match self.parent.take() {
            Some(parent) => close_original(parent),
            None => Err(refuse("independent parent already closed")),
        };
        let graph = self
            .graph
            .take()
            .ok_or_else(|| refuse("independent graph already closed"))?;
        if let Err(error) = closed {
            return combine_close(Err(error), graph.close(false));
        }
        Ok(LinuxStorageCasDirectoryGuard { graph })
    }
}
