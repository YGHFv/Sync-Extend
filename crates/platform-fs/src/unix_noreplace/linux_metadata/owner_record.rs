//! Fixed-size durable identity record for the five originally allocated objects.
//! A new owner reacquires kernel leases before using these exact inode identities.
use super::{refuse, State, UnixFileKey};
use std::{fs::File, io, os::unix::fs::FileExt, sync::atomic::Ordering};

pub(super) const RECORD_BYTES: usize = 4096;
const MAGIC: &[u8] = b"sync-extend.linux-metadata-owner.v2\0";

#[derive(Clone)]
pub(super) struct Record {
    pub generation: [u8; 16],
    pub backing_image: UnixFileKey,
    pub directory: UnixFileKey,
    pub capacities: [u64; 5],
    pub files: [UnixFileKey; 5],
    pub allocated: u64,
    pub total_limit: u64,
    pub logical: [u64; 5],
}

// This is a torn-write detector. Authority comes from the original embedded
// inode identities, owner-only boundaries and newly acquired kernel leases.
fn checksum(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |value, byte| {
        (value ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

impl Record {
    pub fn encode(&self) -> io::Result<[u8; RECORD_BYTES]> {
        self.validate()?;
        let mut output = [0u8; RECORD_BYTES];
        output[..MAGIC.len()].copy_from_slice(MAGIC);
        let mut offset = MAGIC.len();
        output[offset..offset + 16].copy_from_slice(&self.generation);
        offset += 16;
        let values = [
            self.backing_image.device,
            self.backing_image.inode,
            self.directory.device,
            self.directory.inode,
            self.allocated,
            self.total_limit,
        ]
        .into_iter()
        .chain(self.capacities)
        .chain(self.files.iter().flat_map(|key| [key.device, key.inode]))
        .chain(self.logical);
        for value in values {
            output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            offset += 8;
        }
        let digest = checksum(&output[..RECORD_BYTES - 8]);
        output[RECORD_BYTES - 8..].copy_from_slice(&digest.to_le_bytes());
        Ok(output)
    }

    pub fn read(file: &File) -> io::Result<Self> {
        if file.metadata()?.len() != RECORD_BYTES as u64 {
            return Err(refuse("original metadata owner record v2 is required"));
        }
        let mut input = [0u8; RECORD_BYTES];
        file.read_exact_at(&mut input, 0)?;
        if !input.starts_with(MAGIC)
            || checksum(&input[..RECORD_BYTES - 8]).to_le_bytes() != input[RECORD_BYTES - 8..]
        {
            return Err(refuse("metadata owner record identity or checksum differs"));
        }
        let mut offset = MAGIC.len();
        let generation = input[offset..offset + 16]
            .try_into()
            .map_err(|_| refuse("metadata owner generation encoding"))?;
        offset += 16;
        let mut next = || {
            let value = u64::from_le_bytes(
                input[offset..offset + 8]
                    .try_into()
                    .expect("fixed owner record field"),
            );
            offset += 8;
            value
        };
        let backing_image = UnixFileKey {
            device: next(),
            inode: next(),
        };
        let directory = UnixFileKey {
            device: next(),
            inode: next(),
        };
        let allocated = next();
        let total_limit = next();
        let capacities = std::array::from_fn(|_| next());
        let files = std::array::from_fn(|_| UnixFileKey {
            device: next(),
            inode: next(),
        });
        let logical = std::array::from_fn(|_| next());
        if input[offset..RECORD_BYTES - 8]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(refuse("metadata owner record reserved bytes are occupied"));
        }
        let record = Self {
            generation,
            backing_image,
            directory,
            capacities,
            files,
            allocated,
            total_limit,
            logical,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> io::Result<()> {
        if self.generation == [0; 16]
            || self.backing_image.device == 0
            || self.backing_image.inode == 0
            || self.directory.device == 0
            || self.directory.inode == 0
            || self
                .files
                .iter()
                .any(|key| key.device != self.directory.device || key.inode == 0)
            || self
                .files
                .iter()
                .enumerate()
                .any(|(index, key)| self.files[..index].contains(key))
            || self.capacities.iter().enumerate().any(|(index, capacity)| {
                *capacity == 0
                    || *capacity > super::MAX_FILE_CAPACITY
                    || self.logical[index] > *capacity
            })
            || self.logical[2] != self.capacities[2]
            || self.logical[4] != RECORD_BYTES as u64
            || self.allocated > self.total_limit
            || self
                .capacities
                .iter()
                .try_fold(0u64, |total, value| total.checked_add(*value))
                .is_none_or(|total| total > self.allocated)
        {
            return Err(refuse(
                "metadata owner record fixed physical contract differs",
            ));
        }
        Ok(())
    }
}

impl State {
    pub(super) fn verify_owner_record(&self) -> io::Result<()> {
        let _guard = self
            .owner_record_lock
            .lock()
            .map_err(|_| refuse("metadata owner record lock poisoned"))?;
        let record = Record::read(&self.files[4].file)?;
        if record.generation != self.persistent_generation
            || record.backing_image != self.backing_image
            || record.directory != self.directory_key
            || record.capacities != std::array::from_fn(|index| self.files[index].capacity)
            || record.files != std::array::from_fn(|index| self.files[index].identity)
            || record.allocated != self.initial_allocated
            || record.total_limit != self.total_limit
        {
            return Err(refuse("original metadata owner record was substituted"));
        }
        Ok(())
    }

    pub(super) fn persist_owner_record(&self) -> io::Result<()> {
        let _guard = self
            .owner_record_lock
            .lock()
            .map_err(|_| refuse("metadata owner record lock poisoned"))?;
        let record = Record {
            generation: self.persistent_generation,
            backing_image: self.backing_image,
            directory: self.directory_key,
            capacities: std::array::from_fn(|index| self.files[index].capacity),
            files: std::array::from_fn(|index| self.files[index].identity),
            allocated: self.initial_allocated,
            total_limit: self.total_limit,
            logical: std::array::from_fn(|index| {
                self.files[index].logical_bytes.load(Ordering::Acquire)
            }),
        };
        self.files[4].file.write_all_at(&record.encode()?, 0)?;
        self.files[4].file.sync_all()
    }
}
