//! A typed metadata allowance for bounded retirement prefixes, never a creator.
use super::{
    directory_names, inventory_file_length, inventory_limit, key, name, open_directory_at, refuse,
    same_image, same_slot, slot, validate_hex, Graph, LinuxStorageCasExpectedLayout,
    LinuxStorageCasInventory, LinuxStorageCasLimits, CHUNK_BYTES, MAX_ENTRIES,
};
use std::{collections::BTreeSet, fs::File, io, os::unix::fs::MetadataExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxStorageRetirementInventoryPhase {
    ActivationUnreceipted,
    CreatorReceipted,
    QuarantineRequested,
    Quarantined,
    RestoreRequested,
    Restored,
    RestoredCloseRequested,
    RestoredClosed,
    DeleteRequested,
    PayloadUnlinked,
    PayloadCloseRequested,
    PayloadUnlinkedClosed,
    MarkerUnlinkRequestedDeleted,
    MarkerUnlinkRequestedRestored,
    MarkerUnlinkedDeleted,
    MarkerUnlinkedRestored,
    OwnerCloseRequestedDeleted,
    OwnerCloseRequestedRestored,
    OwnerClosedDeleted,
    OwnerClosedRestored,
    TerminalDeleted,
    TerminalRestored,
    ReleasedDeleted,
    ReleasedRestored,
}

impl LinuxStorageRetirementInventoryPhase {
    fn released(self) -> bool {
        matches!(self, Self::ReleasedDeleted | Self::ReleasedRestored)
    }

    fn slots(self, original: bool, quarantine: bool, marker: bool) -> bool {
        use LinuxStorageRetirementInventoryPhase as P;
        match self {
            P::ActivationUnreceipted => original && !quarantine,
            P::CreatorReceipted => original && !quarantine && marker,
            P::QuarantineRequested | P::RestoreRequested => original != quarantine && marker,
            P::Quarantined => !original && quarantine && marker,
            P::Restored | P::RestoredCloseRequested | P::RestoredClosed => {
                original && !quarantine && marker
            }
            P::DeleteRequested => !original && marker,
            P::PayloadUnlinked | P::PayloadCloseRequested | P::PayloadUnlinkedClosed => {
                !original && !quarantine && marker
            }
            P::MarkerUnlinkRequestedDeleted => !original && !quarantine,
            P::MarkerUnlinkRequestedRestored => original && !quarantine,
            P::MarkerUnlinkedDeleted
            | P::OwnerCloseRequestedDeleted
            | P::OwnerClosedDeleted
            | P::TerminalDeleted => !original && !quarantine && !marker,
            P::MarkerUnlinkedRestored
            | P::OwnerCloseRequestedRestored
            | P::OwnerClosedRestored
            | P::TerminalRestored => original && !quarantine && !marker,
            P::ReleasedDeleted | P::ReleasedRestored => !quarantine && !marker,
        }
    }
}

/// Built by the complete durable native-family audit. These freely copyable
/// expectations allow inventory accounting only; no payload/marker FD is owned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageRetirementInventoryPrefix {
    pub request_id: String,
    pub activation_id: String,
    pub content: String,
    pub original_parent_inode: u64,
    pub original_payload_inode: u64,
    pub length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub marker_inode: Option<u64>,
    pub phase: LinuxStorageRetirementInventoryPhase,
}

/// A versioned fixed image/realm projection and a finite audited prefix list.
/// Describing an unreceipted prefix never upgrades it to an original creator.
#[derive(Clone)]
pub struct LinuxStorageRetirementInventoryContext {
    expected: LinuxStorageCasExpectedLayout,
    prefixes: Vec<LinuxStorageRetirementInventoryPrefix>,
}

pub(super) fn require_only_durable_temporaries(
    graph: &Graph,
    context: &LinuxStorageRetirementInventoryContext,
    limits: LinuxStorageCasLimits,
) -> io::Result<()> {
    bounded_inventory(graph, limits, Some(context))?;
    for component in directory_names(&graph.temporary, limits.max_entries)? {
        if !context.prefixes.iter().any(|prefix| {
            !prefix.phase.released()
                && (component == format!("retirement-{}.owner", prefix.activation_id)
                    || component == format!("retirement-{}.payload", prefix.activation_id))
        }) {
            return Err(refuse(
                "unresolved receive prefix cannot become an audited retirement prefix",
            ));
        }
    }
    Ok(())
}

impl LinuxStorageRetirementInventoryContext {
    pub fn from_audited_prefixes(
        expected: LinuxStorageCasExpectedLayout,
        prefixes: Vec<LinuxStorageRetirementInventoryPrefix>,
    ) -> io::Result<Self> {
        if expected.format_version != 1
            || prefixes.len() > MAX_ENTRIES
            || expected.image_filesystem_id == [0; 8]
        {
            return Err(refuse(
                "bounded typed storage retirement inventory required",
            ));
        }
        super::validate_binding(&expected.realm_fingerprint)?;
        let mut requests = BTreeSet::new();
        let mut activations = BTreeSet::new();
        let mut active_content = BTreeSet::new();
        for prefix in &prefixes {
            validate_hex(&prefix.request_id, 32)?;
            validate_hex(&prefix.activation_id, 32)?;
            validate_hex(&prefix.content, 64)?;
            if prefix.request_id == prefix.activation_id
                || !requests.insert(&prefix.request_id)
                || !activations.insert(&prefix.activation_id)
                || (!prefix.phase.released() && !active_content.insert(&prefix.content))
                || prefix.original_parent_inode == 0
                || prefix.original_payload_inode == 0
                || prefix.original_parent_inode == prefix.original_payload_inode
                || prefix.original_parent_inode > i64::MAX as u64
                || prefix.original_payload_inode > i64::MAX as u64
                || !(1..=CHUNK_BYTES).contains(&prefix.length)
                || prefix.modified_seconds < 0
                || !(0..1_000_000_000).contains(&prefix.modified_nanoseconds)
                || prefix.marker_inode.is_some_and(|inode| {
                    inode == 0
                        || inode > i64::MAX as u64
                        || inode == prefix.original_parent_inode
                        || inode == prefix.original_payload_inode
                })
                || (prefix.phase != LinuxStorageRetirementInventoryPhase::ActivationUnreceipted
                    && prefix.marker_inode.is_none())
            {
                return Err(refuse(
                    "complete unique durable storage prefix expectation required",
                ));
            }
        }
        Ok(Self { expected, prefixes })
    }

    pub(super) fn require_unreceipted_activation(
        &self,
        request_id: &str,
        activation_id: &str,
    ) -> io::Result<()> {
        if !self.prefixes.iter().any(|prefix| {
            prefix.request_id == request_id
                && prefix.activation_id == activation_id
                && prefix.phase == LinuxStorageRetirementInventoryPhase::ActivationUnreceipted
                && prefix.marker_inode.is_none()
        }) {
            return Err(refuse(
                "marker CREATE requires its exact audited activation allowance",
            ));
        }
        Ok(())
    }

    fn verify_graph(&self, graph: &Graph) -> io::Result<()> {
        graph.verify()?;
        let observed = LinuxStorageCasExpectedLayout {
            format_version: 1,
            backing_image: graph.owner.backing_image_key(),
            image_filesystem_id: graph.filesystem_id,
            mounted_root_inode: key(&graph.root)?.inode,
            cas_inode: key(&graph.cas)?.inode,
            objects_inode: key(&graph.objects)?.inode,
            temporary_inode: key(&graph.temporary)?.inode,
            realm_inode: key(&graph.realm)?.inode,
            realm_fingerprint: graph.realm_fingerprint,
            owner_uid: super::private(&graph.root, true)?.uid(),
        };
        if observed != self.expected {
            return Err(refuse(
                "typed retirement inventory belongs to another image/realm",
            ));
        }
        Ok(())
    }
}

fn maybe_slot(parent: &File, component: &str) -> io::Result<Option<libc::stat>> {
    match slot(parent, &name(component)?) {
        Ok(observed) => Ok(Some(observed)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

fn verify_prefix(
    graph: &Graph,
    shard: &File,
    prefix: &LinuxStorageRetirementInventoryPrefix,
) -> io::Result<()> {
    if key(shard)?.inode != prefix.original_parent_inode {
        return Err(refuse("audited original retirement shard was replaced"));
    }
    let original = maybe_slot(shard, &prefix.content)?;
    let quarantine = maybe_slot(
        &graph.temporary,
        &format!("retirement-{}.payload", prefix.activation_id),
    )?;
    let marker = maybe_slot(
        &graph.temporary,
        &format!("retirement-{}.owner", prefix.activation_id),
    )?;
    if !prefix
        .phase
        .slots(original.is_some(), quarantine.is_some(), marker.is_some())
    {
        return Err(refuse(
            "native retirement slots do not match their immutable phase",
        ));
    }
    if !prefix.phase.released() {
        for observed in original.iter().chain(quarantine.iter()) {
            if observed.st_ino != prefix.original_payload_inode
                || observed.st_dev != key(&graph.root)?.device
                || u64::try_from(observed.st_size).ok() != Some(prefix.length)
                || observed.st_mtime != prefix.modified_seconds
                || observed.st_mtime_nsec != prefix.modified_nanoseconds
            {
                return Err(refuse(
                    "audited retirement payload identity or metadata differs",
                ));
            }
        }
    }
    if let Some(observed) = marker {
        let length = u64::try_from(observed.st_size)
            .map_err(|_| refuse("native marker inventory length is negative"))?;
        if prefix.phase == LinuxStorageRetirementInventoryPhase::ActivationUnreceipted {
            if length > 65 {
                return Err(refuse(
                    "unreceipted CREATE prefix exceeds its complete marker budget",
                ));
            }
        } else if length != 65 || Some(observed.st_ino) != prefix.marker_inode {
            return Err(refuse("receipted native marker inventory was substituted"));
        }
    }
    Ok(())
}

pub(super) fn bounded_inventory(
    graph: &Graph,
    limits: LinuxStorageCasLimits,
    context: Option<&LinuxStorageRetirementInventoryContext>,
) -> io::Result<LinuxStorageCasInventory> {
    limits.validate()?;
    graph.verify()?;
    if let Some(context) = context {
        context.verify_graph(graph)?;
    }
    let prefixes = context.map_or(&[][..], |context| context.prefixes.as_slice());
    let mut result = LinuxStorageCasInventory {
        object_entries: 0,
        shard_entries: 0,
        temporary_entries: 0,
        payload_bytes: 0,
        temporary_bytes: 0,
    };
    let mut observed_shards = BTreeSet::new();
    for shard in directory_names(&graph.objects, limits.max_entries)? {
        validate_hex(&shard, 2)?;
        let original = open_directory_at(&graph.objects, &name(&shard)?)?;
        same_image(&original, &graph.owner, true)?;
        result.shard_entries += 1;
        let known = prefixes
            .iter()
            .filter(|prefix| prefix.content.starts_with(&shard))
            .collect::<Vec<_>>();
        let components = directory_names(&original, limits.max_entries)?;
        if components.is_empty() && known.is_empty() {
            return Err(refuse(
                "unfinished unknown empty storage shard is preserved and refused",
            ));
        }
        for prefix in &known {
            verify_prefix(graph, &original, prefix)?;
            // Unlink changes the named inventory before the original held
            // descriptor closes. Keep that physical liability until the
            // independent durable close observation replaces the request.
            if matches!(
                prefix.phase,
                LinuxStorageRetirementInventoryPhase::DeleteRequested
                    | LinuxStorageRetirementInventoryPhase::PayloadUnlinked
                    | LinuxStorageRetirementInventoryPhase::PayloadCloseRequested
            ) && maybe_slot(&original, &prefix.content)?.is_none()
                && maybe_slot(
                    &graph.temporary,
                    &format!("retirement-{}.payload", prefix.activation_id),
                )?
                .is_none()
            {
                result.payload_bytes = result
                    .payload_bytes
                    .checked_add(prefix.length)
                    .ok_or_else(|| refuse("unlinked original payload liability overflow"))?;
            }
            if matches!(
                prefix.phase,
                LinuxStorageRetirementInventoryPhase::MarkerUnlinkRequestedDeleted
                    | LinuxStorageRetirementInventoryPhase::MarkerUnlinkRequestedRestored
                    | LinuxStorageRetirementInventoryPhase::MarkerUnlinkedDeleted
                    | LinuxStorageRetirementInventoryPhase::MarkerUnlinkedRestored
                    | LinuxStorageRetirementInventoryPhase::OwnerCloseRequestedDeleted
                    | LinuxStorageRetirementInventoryPhase::OwnerCloseRequestedRestored
            ) && maybe_slot(
                &graph.temporary,
                &format!("retirement-{}.owner", prefix.activation_id),
            )?
            .is_none()
            {
                result.temporary_bytes = result
                    .temporary_bytes
                    .checked_add(65)
                    .ok_or_else(|| refuse("unlinked original marker liability overflow"))?;
            }
        }
        for component in components {
            validate_hex(&component, 64)?;
            if !component.starts_with(&shard) {
                return Err(refuse("inside CAS payload differs from its exact shard"));
            }
            let length = inventory_file_length(&original, &name(&component)?, graph)?;
            if !(1..=CHUNK_BYTES).contains(&length) {
                return Err(refuse("inside CAS bounded original payload required"));
            }
            result.object_entries += 1;
            result.payload_bytes = result
                .payload_bytes
                .checked_add(length)
                .ok_or_else(|| refuse("inside CAS payload inventory overflow"))?;
            inventory_limit(result, limits)?;
        }
        same_slot(&graph.objects, &name(&shard)?, &original)?;
        observed_shards.insert(shard);
    }
    if prefixes
        .iter()
        .any(|prefix| !observed_shards.contains(&prefix.content[..2]))
    {
        return Err(refuse("audited original retirement shard is absent"));
    }
    for component in directory_names(&graph.temporary, limits.max_entries)? {
        let length = inventory_file_length(&graph.temporary, &name(&component)?, graph)?;
        let payload = prefixes
            .iter()
            .find(|prefix| component == format!("retirement-{}.payload", prefix.activation_id));
        let marker = prefixes
            .iter()
            .find(|prefix| component == format!("retirement-{}.owner", prefix.activation_id));
        result.temporary_entries += 1;
        if let Some(prefix) = payload {
            if length != prefix.length {
                return Err(refuse("native quarantine payload length differs"));
            }
            // Moving the one original payload never lowers total payload cost.
            result.payload_bytes = result
                .payload_bytes
                .checked_add(length)
                .ok_or_else(|| refuse("native quarantine payload inventory overflow"))?;
        } else {
            let charged = if marker.is_some() {
                if length > 65 {
                    return Err(refuse("native marker exceeds its complete 65-byte budget"));
                }
                // An interrupted partial CREATE still reserves its full marker.
                65
            } else {
                validate_hex(&component, 32)?;
                if length > CHUNK_BYTES {
                    return Err(refuse("bounded original receive prefix required"));
                }
                length
            };
            result.temporary_bytes = result
                .temporary_bytes
                .checked_add(charged)
                .ok_or_else(|| refuse("inside CAS complete temporary inventory overflow"))?;
        }
        inventory_limit(result, limits)?;
    }
    inventory_limit(result, limits)?;
    graph.verify()?;
    if let Some(context) = context {
        context.verify_graph(graph)?;
    }
    Ok(result)
}
