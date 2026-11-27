//! Shared positional IO over borrowed original descriptors, with no path opens.
use std::{fs::File, io, os::unix::fs::FileExt};

pub(crate) fn read_until_eof(file: &File, output: &mut [u8], offset: u64) -> io::Result<usize> {
    offset
        .checked_add(output.len() as u64)
        .ok_or_else(|| io::Error::other("original read offset overflow"))?;
    let mut done = 0;
    while done < output.len() {
        match file.read_at(&mut output[done..], offset + done as u64) {
            Ok(0) => break,
            Ok(count) => done += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(done)
}

pub(crate) fn write_all(file: &File, input: &[u8], offset: u64) -> io::Result<()> {
    offset
        .checked_add(input.len() as u64)
        .ok_or_else(|| io::Error::other("original write offset overflow"))?;
    let mut done = 0;
    while done < input.len() {
        match file.write_at(&input[done..], offset + done as u64) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "original descriptor write stopped",
                ))
            }
            Ok(count) => done += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
