//! Shared bounded two-record framing. Platform records retain their own types;
//! neither the hash chain nor decoding creates any live resource authority.
use crate::{ReconcileError, Result};
use sync_extend_core_model::ContentId;

pub(super) const MAX_RECORD_BYTES: usize = 384 * 1024;
pub(super) const MAX_FRAME_BYTES: usize = 1024 * 1024;

fn payload(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(ReconcileError::ResourceLimit("bounded close chain record"));
    }
    // This shared layer preserves existing platform record semantics. Each
    // record decoder applies its own string/depth/schema limits separately.
    Ok(())
}

fn frame(parts: &[&[u8]]) -> Result<Vec<u8>> {
    let length = parts.iter().try_fold(0usize, |sum, part| {
        sum.checked_add(part.len())
            .filter(|sum| *sum <= MAX_FRAME_BYTES)
            .ok_or(ReconcileError::ResourceLimit("bounded close chain frame"))
    })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ReconcileError::ResourceLimit("close chain frame allocation"))?;
    for part in parts {
        bytes.extend_from_slice(part);
    }
    Ok(bytes)
}

pub(super) fn intended(header: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    payload(record)?;
    if header.is_empty() || header.len() > 64 {
        return Err(ReconcileError::Invariant("bounded close chain header"));
    }
    frame(&[header, &(record.len() as u32).to_le_bytes(), record])
}

pub(super) fn terminal(previous: &[u8], record: &[u8]) -> Result<Vec<u8>> {
    payload(previous)?;
    payload(record)?;
    frame(&[
        &(record.len() as u32).to_le_bytes(),
        ContentId::hash(previous).as_str().as_bytes(),
        record,
    ])
}

pub(super) fn closed_payloads<'a>(header: &[u8], bytes: &'a [u8]) -> Result<[&'a [u8]; 2]> {
    if header.is_empty()
        || header.len() > 64
        || !bytes.starts_with(header)
        || bytes.len() > MAX_FRAME_BYTES
    {
        return Err(ReconcileError::Invariant(
            "exact bounded close chain header",
        ));
    }
    let mut offset = header.len();
    let mut records: [&[u8]; 2] = [&[], &[]];
    for index in 0..2 {
        let length = u32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or(ReconcileError::Invariant("close chain length"))?
                .try_into()
                .map_err(|_| ReconcileError::Invariant("close chain length encoding"))?,
        ) as usize;
        offset += 4;
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(ReconcileError::ResourceLimit("close chain record bytes"));
        }
        if index == 1 {
            let digest = bytes
                .get(offset..offset + 64)
                .ok_or(ReconcileError::Invariant("close chain previous digest"))?;
            if digest != ContentId::hash(records[0]).as_str().as_bytes() {
                return Err(ReconcileError::Invariant(
                    "close chain intended record changed",
                ));
            }
            offset += 64;
        }
        records[index] = bytes
            .get(offset..offset + length)
            .ok_or(ReconcileError::Invariant("close chain truncated record"))?;
        payload(records[index])?;
        offset += length;
    }
    if offset != bytes.len() {
        return Err(ReconcileError::Invariant("close chain trailing bytes"));
    }
    Ok(records)
}
