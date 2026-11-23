//! Fixed-size durable identity record for the five originally allocated objects.
//! A new owner reacquires kernel leases before using these exact inode identities.
use super::{refuse, State, UnixFileKey};
use std::{fs::File, io, os::unix::fs::FileExt, sync::atomic::Ordering};

pub(super) const RECORD_BYTES: usize = 4096;
const MAGIC: &[u8] = b"sync-extend.linux-metadata-owner.v2\0";
const STORAGE_MAGIC: &[u8] = b"sync-extend.linux-metadata-owner.storage-only.v3\0";
const STORAGE_RECEIVE_MAGIC: &[u8] = b"sync-extend.linux-metadata-owner.storage-only.v4\0";
pub(super) const CAS_RECEIVE_CLEAN: u8 = 0;
pub(super) const CAS_RECEIVE_ARMED: u8 = 1;
pub(super) const CAS_RECEIVE_FAILED: u8 = 2;

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
    pub storage_sealed: Option<[u64; 5]>,
    pub cas_receive_state: u8,
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
        let magic = if self.storage_sealed.is_some() && self.cas_receive_state != CAS_RECEIVE_CLEAN
        {
            STORAGE_RECEIVE_MAGIC
        } else if self.storage_sealed.is_some() {
            STORAGE_MAGIC
        } else {
            MAGIC
        };
        output[..magic.len()].copy_from_slice(magic);
        let mut offset = magic.len();
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
        if let Some(sealed) = self.storage_sealed {
            for value in sealed {
                output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                offset += 8;
            }
        }
        if self.cas_receive_state != CAS_RECEIVE_CLEAN {
            output[offset] = self.cas_receive_state;
        }
        let digest = checksum(&output[..RECORD_BYTES - 8]);
        output[RECORD_BYTES - 8..].copy_from_slice(&digest.to_le_bytes());
        Ok(output)
    }

    pub fn read(file: &File) -> io::Result<Self> {
        Self::read_impl(file, false)
    }

    pub fn read_storage_only(file: &File) -> io::Result<Self> {
        let record = Self::read_impl(file, true)?;
        // The logical record is fixed at 4096; the rest of its fully
        // initialized original capacity is permanently reserved zero data.
        // Check it during read-only preflight/reacquisition, before any
        // recovery write. Live verification uses the fixed record prefix
        // under the already held mandatory lease.
        let mut zero_tail = [0u8; 64 * 1024];
        let mut offset = RECORD_BYTES as u64;
        while offset < record.capacities[4] {
            let amount = (record.capacities[4] - offset).min(zero_tail.len() as u64) as usize;
            file.read_exact_at(&mut zero_tail[..amount], offset)?;
            if zero_tail[..amount].iter().any(|byte| *byte != 0) {
                return Err(refuse("storage v3 owner reserved capacity was tampered"));
            }
            offset += amount as u64;
        }
        if record.cas_receive_state != CAS_RECEIVE_CLEAN {
            return Err(refuse(
                "storage-only durable inside CAS receive remains incomplete or failed; no reopen or repair",
            ));
        }
        Ok(record)
    }

    fn read_impl(file: &File, storage_only: bool) -> io::Result<Self> {
        if !storage_only && file.metadata()?.len() != RECORD_BYTES as u64 {
            return Err(refuse("original metadata owner record v2 is required"));
        }
        let mut input = [0u8; RECORD_BYTES];
        file.read_exact_at(&mut input, 0)?;
        let receive_record = storage_only && input.starts_with(STORAGE_RECEIVE_MAGIC);
        let magic = if receive_record {
            STORAGE_RECEIVE_MAGIC
        } else if storage_only {
            STORAGE_MAGIC
        } else {
            MAGIC
        };
        if !input.starts_with(magic)
            || checksum(&input[..RECORD_BYTES - 8]).to_le_bytes() != input[RECORD_BYTES - 8..]
        {
            return Err(refuse("metadata owner record identity or checksum differs"));
        }
        let mut offset = magic.len();
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
        let storage_sealed = storage_only.then(|| std::array::from_fn(|_| next()));
        let cas_receive_state = if receive_record {
            let value = input[offset];
            offset += 1;
            if !matches!(value, CAS_RECEIVE_ARMED | CAS_RECEIVE_FAILED) {
                return Err(refuse(
                    "storage-only durable receive state encoding differs",
                ));
            }
            value
        } else {
            CAS_RECEIVE_CLEAN
        };
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
            storage_sealed,
            cas_receive_state,
        };
        record.validate()?;
        if storage_only && file.metadata()?.len() != record.capacities[4] {
            return Err(refuse("storage v3 owner actual capacity extent differs"));
        }
        Ok(record)
    }

    fn validate(&self) -> io::Result<()> {
        if self.cas_receive_state > CAS_RECEIVE_FAILED
            || (self.storage_sealed.is_none() && self.cas_receive_state != CAS_RECEIVE_CLEAN)
            || self.generation == [0; 16]
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
        if let Some(sealed) = self.storage_sealed {
            let liabilities = super::LinuxMetadataLimits {
                main: self.capacities[0],
                wal: self.capacities[1],
                shm: self.capacities[2],
                rollback_journal: self.capacities[3],
                owner_record: self.capacities[4],
                total_physical: self.total_limit,
            }
            .storage_only_physical_liabilities()?;
            if self.capacities.iter().any(|capacity| capacity % 4096 != 0)
                || sealed.iter().enumerate().any(|(index, allocation)| {
                    *allocation < self.capacities[index]
                        || *allocation > liabilities[index]
                        || allocation % 4096 != 0
                })
                || sealed
                    .iter()
                    .try_fold(0u64, |sum, value| sum.checked_add(*value))
                    != Some(self.allocated)
            {
                return Err(refuse(
                    "storage v3 sealed class allocation contract differs",
                ));
            }
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
        self.verify_owner_record_locked()
    }

    fn verify_owner_record_locked(&self) -> io::Result<()> {
        let record = if self.storage_sealed.is_some() {
            Record::read_impl(&self.files[4].file, true)?
        } else {
            Record::read(&self.files[4].file)?
        };
        if record.generation != self.persistent_generation
            || record.backing_image != self.backing_image
            || record.directory != self.directory_key
            || record.capacities != std::array::from_fn(|index| self.files[index].capacity)
            || record.files != std::array::from_fn(|index| self.files[index].identity)
            || record.allocated != self.initial_allocated
            || record.total_limit != self.total_limit
            || record.storage_sealed != self.storage_sealed
            || record.cas_receive_state != self.storage_cas_receive.load(Ordering::Acquire)
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
        self.persist_owner_record_locked()
    }

    fn persist_owner_record_locked(&self) -> io::Result<()> {
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
            storage_sealed: self.storage_sealed,
            cas_receive_state: self.storage_cas_receive.load(Ordering::Acquire),
        };
        self.files[4].file.write_all_at(&record.encode()?, 0)?;
        self.files[4].file.sync_all()
    }

    pub(super) fn transition_storage_cas_receive(
        &self,
        expected: Option<u8>,
        next: u8,
    ) -> io::Result<()> {
        // Recheck every original lease, namespace and named slot before the
        // record mutex. It serializes this state with all ordinary VFS syncs.
        self.verify()?;
        let _guard = self
            .owner_record_lock
            .lock()
            .map_err(|_| refuse("metadata owner record lock poisoned"))?;
        self.verify_owner_record_locked()?;
        let current = self.storage_cas_receive.load(Ordering::Acquire);
        if expected.is_some_and(|expected| current != expected)
            || (current == CAS_RECEIVE_FAILED && next != CAS_RECEIVE_FAILED)
        {
            return Err(refuse("original durable receive transition refused"));
        }
        if current == next {
            return Ok(());
        }
        self.storage_cas_receive.store(next, Ordering::Release);
        if let Err(error) = self.persist_owner_record_locked() {
            // Never permit another live clean transition after a failed
            // checkpoint. The pre-CREATE arm protects actual failed prefixes
            // even if writing a more specific failed state also fails.
            self.storage_cas_receive
                .store(CAS_RECEIVE_FAILED, Ordering::Release);
            return match self.persist_owner_record_locked() {
                Ok(()) => Err(error),
                Err(retained) => Err(io::Error::other(format!(
                    "{error}; durable receive refusal checkpoint also failed: {retained}"
                ))),
            };
        }
        Ok(())
    }
}
