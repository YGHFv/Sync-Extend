//! One complete typed future close envelope is sized before runtime effects.
//! A budget contains no native creator, connection or restart authority.
use super::{completion_codec, completion_frames};
use crate::{ReconcileError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, PortableEntryMetadata, SnapshotId, SpaceId};

pub(super) const MAX_GENERATIONS: u32 = 64;
pub(super) const MAX_TURNS: u32 = 128;
pub(super) const MAX_OBJECTS: usize = 4096;
pub(super) const MAX_HELD_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const HEADER: &[u8] = b"SYNC-UNIX-GENERATION1\n";

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Key {
    device: u64,
    inode: u64,
    uid: u32,
}
impl Key {
    pub(super) fn described(&self) -> sync_extend_platform_fs::UnixProtectedArtifactKey {
        sync_extend_platform_fs::UnixProtectedArtifactKey {
            device: self.device,
            inode: self.inode,
            uid: self.uid,
        }
    }
    pub(super) fn observed(key: sync_extend_platform_fs::UnixProtectedArtifactKey) -> Self {
        Self {
            device: key.device,
            inode: key.inode,
            uid: key.uid,
        }
    }
    fn future() -> Self {
        Self {
            device: u64::MAX,
            inode: u64::MAX,
            uid: u32::MAX,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Object {
    #[serde(deserialize_with = "completion_codec::text")]
    pub(super) role: String,
    #[serde(deserialize_with = "completion_codec::path_text")]
    pub(super) path: String,
    pub(super) original: Key,
    pub(super) parent: Key,
    pub(super) bytes: u64,
    pub(super) digest: Option<ContentId>,
    pub(super) projected_metadata: Option<PortableEntryMetadata>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) version: u32,
    pub(super) sequence: u32,
    #[serde(deserialize_with = "completion_codec::text")]
    pub(super) phase: String,
    pub(super) generation: u32,
    pub(super) turns: u32,
    pub(super) archive: ContentId,
    pub(super) source: Option<ContentId>,
    pub(super) predecessor: Option<ContentId>,
    pub(super) space: SpaceId,
    pub(super) root: SnapshotId,
    pub(super) rows: ContentId,
    pub(super) namespace: Key,
    pub(super) data: Key,
    pub(super) worktree: Key,
    pub(super) database: [Key; 5],
    #[serde(deserialize_with = "objects")]
    pub(super) objects: Vec<Object>,
    pub(super) runtime_closed_descriptors: Option<u64>,
}

fn objects<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Object>, D::Error> {
    struct Objects;
    impl<'de> serde::de::Visitor<'de> for Objects {
        type Value = Vec<Object>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("bounded actual Unix generation object descriptions")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            if sequence
                .size_hint()
                .is_some_and(|count| count > MAX_OBJECTS)
            {
                return Err(serde::de::Error::custom(
                    "Unix generation object count before decode",
                ));
            }
            let mut values = Vec::new();
            loop {
                if values.len() == MAX_OBJECTS {
                    if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                        return Err(serde::de::Error::custom("Unix generation object count"));
                    }
                    break;
                }
                let Some(value) = sequence.next_element()? else {
                    break;
                };
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(Objects)
}

pub(super) fn encode(record: &Record) -> Result<Vec<u8>> {
    if record.version != 1
        || record.generation >= MAX_GENERATIONS
        || (record.generation == 0) != record.predecessor.is_none()
        || record.turns > MAX_TURNS
        || record.objects.len() > MAX_OBJECTS
    {
        return Err(ReconcileError::ResourceLimit(
            "complete Unix generation membership bounds",
        ));
    }
    let bytes = record.objects.iter().try_fold(0u64, |sum, object| {
        if object.role.is_empty()
            || object.role.len() > 255
            || object.path.is_empty()
            || object.path.len() > 4096
            || object.path.starts_with('/')
            || object.path.contains(['\\', '\0'])
            || object
                .path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | "..") || part.len() > 255)
        {
            return Err(ReconcileError::ResourceLimit(
                "Unix generation descriptor encoding",
            ));
        }
        if let Some(metadata) = &object.projected_metadata {
            metadata.validate()?;
        }
        sum.checked_add(object.bytes)
            .filter(|sum| *sum <= MAX_HELD_BYTES)
            .ok_or(ReconcileError::ResourceLimit(
                "complete Unix held generation byte budget",
            ))
    })?;
    let _ = bytes;
    let mut slots = std::collections::BTreeSet::new();
    if record
        .objects
        .iter()
        .any(|object| !slots.insert((object.role.starts_with("work_"), &object.path)))
    {
        return Err(ReconcileError::Invariant(
            "Unix generation duplicate descriptor slot",
        ));
    }
    completion_codec::bytes(record, completion_frames::MAX_RECORD_BYTES)
}

pub(super) fn future_metadata() -> PortableEntryMetadata {
    use sync_extend_core_model::{
        PortableMetadataUnsupportedReason, PortableReadonly, PortableTimestamp,
        PortableUnixExecutable,
    };
    PortableEntryMetadata {
        format_version: 1,
        modified: PortableTimestamp::Captured {
            seconds: i64::MIN,
            nanos: 999_999_999,
        },
        readonly: PortableReadonly::Unknown,
        creation: Some(PortableTimestamp::Captured {
            seconds: i64::MIN,
            nanos: 999_999_999,
        }),
        unix_executable: Some(PortableUnixExecutable::Unsupported {
            reason: PortableMetadataUnsupportedReason::Filesystem,
        }),
    }
}

/// The envelope includes worst-case physical keys and descriptor counts for
/// every newly planned original, plus complete prior retained membership.
pub(super) fn require_future_close(
    record: &Record,
    additional: &[Object],
    future_turns: u32,
) -> Result<()> {
    encode(record)?;
    if record
        .objects
        .len()
        .checked_add(additional.len())
        .is_none_or(|count| count > MAX_OBJECTS)
    {
        return Err(ReconcileError::ResourceLimit(
            "Unix generation future object count",
        ));
    }
    let mut future = record.clone();
    future.turns = future
        .turns
        .checked_add(future_turns)
        .filter(|turns| *turns <= MAX_TURNS)
        .ok_or(ReconcileError::ResourceLimit("Unix generation turn budget"))?;
    for object in additional {
        let mut object = object.clone();
        object.original = Key::future();
        object.parent = Key::future();
        future.objects.push(object);
    }
    future.sequence = 1;
    future.phase = "runtime_closed".into();
    future.runtime_closed_descriptors = Some(u64::MAX);
    let terminal = encode(&future)?;
    future.sequence = 0;
    future.phase = "close_intended".into();
    future.runtime_closed_descriptors = None;
    let intended = encode(&future)?;
    let first = completion_frames::intended(HEADER, &intended)?;
    let second = completion_frames::terminal(&intended, &terminal)?;
    if first
        .len()
        .checked_add(second.len())
        .is_none_or(|length| length > completion_frames::MAX_FRAME_BYTES)
    {
        return Err(ReconcileError::ResourceLimit(
            "complete Unix future close frame budget",
        ));
    }
    Ok(())
}

pub(super) fn decode(bytes: &[u8]) -> Result<Record> {
    let [intended, terminal] = completion_frames::closed_payloads(HEADER, bytes)?;
    completion_codec::preflight_decode(intended)?;
    completion_codec::preflight_decode(terminal)?;
    let first: Record = serde_json::from_slice(intended)?;
    let final_record: Record = serde_json::from_slice(terminal)?;
    if first.sequence != 0
        || first.phase != "close_intended"
        || first.runtime_closed_descriptors.is_some()
        || final_record.sequence != 1
        || final_record.phase != "runtime_closed"
        || final_record
            .runtime_closed_descriptors
            .is_none_or(|count| count == 0)
        || encode(&first)? != intended
        || encode(&final_record)? != terminal
    {
        return Err(ReconcileError::Invariant(
            "canonical Unix closed generation records",
        ));
    }
    let mut normalized = final_record.clone();
    normalized.sequence = 0;
    normalized.phase = "close_intended".into();
    normalized.runtime_closed_descriptors = None;
    if encode(&normalized)? != intended {
        return Err(ReconcileError::Invariant(
            "Unix generation final binding changed",
        ));
    }
    // This is only a historical description. A new runtime must reacquire all
    // actual originals; neither decoded keys nor a closed record mint a loan.
    Ok(final_record)
}
