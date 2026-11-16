//! Allocate the four exact retained SQLite payload files before byte effects.
//! Allocation observations do not cover later truncation, directory/inode/CAS
//! metadata, unknown streams, namespace exclusion or a complete writer budget.
use super::FreshExclusiveSqliteFile;
use crate::FileKey;
use std::{io, mem::size_of, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        FileAllocationInfo, FileBasicInfo, FileStandardInfo, GetFileInformationByHandleEx,
        SetFileInformationByHandle, FILE_ALLOCATION_INFO, FILE_ATTRIBUTE_COMPRESSED,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_BASIC_INFO,
        FILE_STANDARD_INFO,
    },
};

/// Explicit caller limits for main, WAL, rollback journal and SHM, in that order.
pub struct OriginalSqlitePayloadAllocationBounds {
    pub per_file_bytes: [u64; 4],
    pub max_total_allocated_bytes: u64,
}

/// Every failed allocation leaves the caller's original exclusive files held.
/// No path reopening or retry permission follows from observing this error.
pub struct OriginalSqlitePayloadAllocationFailure {
    error: io::Error,
    completed_file_count: usize,
}

impl OriginalSqlitePayloadAllocationFailure {
    pub fn error(&self) -> &io::Error {
        &self.error
    }
    pub fn completed_file_count(&self) -> usize {
        self.completed_file_count
    }
}

pub struct OriginalSqlitePayloadAllocation<'a> {
    files: [&'a FreshExclusiveSqliteFile; 4],
    keys: [FileKey; 4],
    logical_lengths: [u64; 4],
    allocated_lengths: [u64; 4],
    total_allocated_bytes: u64,
    bounds: OriginalSqlitePayloadAllocationBounds,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn observe(file: &FreshExclusiveSqliteFile) -> io::Result<(u64, u64)> {
    file.verify()?;
    let handle = file.native_file().as_raw_handle() as HANDLE;
    let mut standard = FILE_STANDARD_INFO::default();
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: original retained native handle and correctly sized writable outputs.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            std::ptr::from_mut(&mut standard).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same retained original and sized basic-information structure.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            std::ptr::from_mut(&mut basic).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if standard.AllocationSize < 0
        || standard.EndOfFile < 0
        || standard.NumberOfLinks != 1
        || standard.Directory
        || standard.DeletePending
        || basic.FileAttributes
            & (FILE_ATTRIBUTE_SPARSE_FILE
                | FILE_ATTRIBUTE_COMPRESSED
                | FILE_ATTRIBUTE_REPARSE_POINT)
            != 0
    {
        return Err(invalid(
            "original SQLite regular nonsparse allocation scope",
        ));
    }
    file.verify()?;
    Ok((standard.EndOfFile as u64, standard.AllocationSize as u64))
}

impl FreshExclusiveSqliteFile {
    /// Borrow all four held originals. First preflight checks every identity,
    /// current length and explicit limit before any FileAllocationInfo call.
    /// The caller must retain these files on failure; no descriptor is closed.
    pub fn allocate_original_sqlite_payloads<'a>(
        files: [&'a FreshExclusiveSqliteFile; 4],
        bounds: OriginalSqlitePayloadAllocationBounds,
    ) -> Result<OriginalSqlitePayloadAllocation<'a>, OriginalSqlitePayloadAllocationFailure> {
        let mut completed_file_count = 0;
        let attempt = (|| -> io::Result<OriginalSqlitePayloadAllocation<'a>> {
            if bounds
                .per_file_bytes
                .iter()
                .any(|bytes| !(512..=256 * 1024 * 1024).contains(bytes))
                || bounds.max_total_allocated_bytes == 0
                || bounds.max_total_allocated_bytes > 512 * 1024 * 1024
            {
                return Err(invalid("original SQLite explicit allocation bounds"));
            }
            let total = bounds.per_file_bytes.iter().try_fold(0u64, |sum, bytes| {
                sum.checked_add(*bytes)
                    .ok_or_else(|| invalid("original SQLite total allocation overflow"))
            })?;
            if total > bounds.max_total_allocated_bytes {
                return Err(invalid("original SQLite total before allocation bound"));
            }
            let mut keys = Vec::new();
            let mut logical_lengths = [0u64; 4];
            let parent = files[0].parent_key()?;
            for (index, file) in files.iter().enumerate() {
                let key = file.key()?;
                if key.volume != parent.volume
                    || file.parent_key()? != parent
                    || keys.contains(&key)
                {
                    return Err(invalid(
                        "original SQLite four distinct same-parent exclusive files",
                    ));
                }
                let (logical, allocated) = observe(file)?;
                if logical > bounds.per_file_bytes[index]
                    || allocated > bounds.per_file_bytes[index]
                {
                    return Err(invalid(
                        "original SQLite existing length/allocation exceeds bounds",
                    ));
                }
                logical_lengths[index] = logical;
                keys.push(key);
            }
            let keys: [FileKey; 4] = keys
                .try_into()
                .map_err(|_| invalid("four original SQLite keys required"))?;
            let mut allocated_lengths = [0u64; 4];
            let mut total_allocated_bytes = 0u64;
            for (index, file) in files.iter().enumerate() {
                file.verify()?;
                let information = FILE_ALLOCATION_INFO {
                    AllocationSize: i64::try_from(bounds.per_file_bytes[index])
                        .map_err(|_| invalid("original SQLite native allocation integer"))?,
                };
                // SAFETY: same original exclusive handle, sized readonly request,
                // bounded allocation size at least the existing logical length.
                if unsafe {
                    SetFileInformationByHandle(
                        file.native_file().as_raw_handle() as HANDLE,
                        FileAllocationInfo,
                        std::ptr::from_ref(&information).cast(),
                        size_of::<FILE_ALLOCATION_INFO>() as u32,
                    )
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                file.native_file().sync_all()?;
                let (logical, allocated) = observe(file)?;
                if logical != logical_lengths[index]
                    || file.key()? != keys[index]
                    || allocated < bounds.per_file_bytes[index]
                {
                    return Err(invalid(
                        "original SQLite allocation changed logical bytes or identity",
                    ));
                }
                allocated_lengths[index] = allocated;
                total_allocated_bytes = total_allocated_bytes
                    .checked_add(allocated)
                    .filter(|total| *total <= bounds.max_total_allocated_bytes)
                    .ok_or_else(|| {
                        invalid("original SQLite observed aggregate allocation bound")
                    })?;
                completed_file_count += 1;
            }
            Ok(OriginalSqlitePayloadAllocation {
                files,
                keys,
                logical_lengths,
                allocated_lengths,
                total_allocated_bytes,
                bounds,
            })
        })();
        attempt.map_err(|error| OriginalSqlitePayloadAllocationFailure {
            error,
            completed_file_count,
        })
    }
}

impl OriginalSqlitePayloadAllocation<'_> {
    /// A static pre-effect observation. Callers must verify again before using
    /// it; a later SQLite truncate can release reserved payload blocks.
    pub fn verify_before_sqlite_effects(&self) -> io::Result<()> {
        let mut total = 0u64;
        for (index, file) in self.files.iter().enumerate() {
            let (logical, allocated) = observe(file)?;
            if file.key()? != self.keys[index]
                || logical != self.logical_lengths[index]
                || allocated != self.allocated_lengths[index]
                || allocated < self.bounds.per_file_bytes[index]
            {
                return Err(invalid(
                    "original SQLite allocation observation no longer current",
                ));
            }
            total = total
                .checked_add(allocated)
                .ok_or_else(|| invalid("original SQLite current aggregate allocation overflow"))?;
        }
        if total != self.total_allocated_bytes || total > self.bounds.max_total_allocated_bytes {
            return Err(invalid("original SQLite current total allocation differs"));
        }
        Ok(())
    }
    pub fn observed_allocated_lengths(&self) -> &[u64; 4] {
        &self.allocated_lengths
    }
    pub fn observed_logical_lengths(&self) -> &[u64; 4] {
        &self.logical_lengths
    }
    pub fn total_allocated_bytes(&self) -> u64 {
        self.total_allocated_bytes
    }
}
