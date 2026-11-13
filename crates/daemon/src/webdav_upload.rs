//! Upload bytes exist only behind the request's original file handle.
//! Windows delete-on-close and Linux anonymous files reclaim them on process termination.
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};
#[cfg(windows)]
use sync_extend_core_model::EntryId;

pub struct Upload {
    #[cfg(windows)]
    original: sync_extend_platform_fs::OwnedFileCreation,
    #[cfg(not(windows))]
    original: File,
    length: u64,
}

impl Upload {
    pub fn receive(stream: &mut impl Read, parent: &Path, length: u64) -> io::Result<Self> {
        if !parent.is_absolute() {
            return Err(io::Error::other("absolute private upload parent required"));
        }
        if fs2::available_space(parent)? < length {
            return Err(io::Error::other("insufficient upload storage"));
        }
        #[cfg(windows)]
        let name = format!(
            "{}.upload",
            EntryId::random().map_err(|_| io::Error::other("upload RNG"))?
        );
        #[cfg(windows)]
        let mut original = {
            let directory = sync_extend_platform_fs::LockedDirectory::open(parent)?;
            // Kernel delete-on-close is part of exclusive CREATE itself.
            directory.create_request_file(&name)?
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let mut original = sync_extend_platform_fs::create_anonymous_upload(parent)?;
        #[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
        let mut original: File = {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "anonymous upload platform unavailable",
            ));
        };
        #[cfg(windows)]
        let writer = original.writer();
        #[cfg(not(windows))]
        let writer = &mut original;
        let mut remaining = length;
        let mut buffer = [0u8; 65536];
        while remaining > 0 {
            let size = remaining.min(buffer.len() as u64) as usize;
            stream.read_exact(&mut buffer[..size])?;
            writer.write_all(&buffer[..size])?;
            remaining -= size as u64;
        }
        writer.sync_all()?;
        writer.seek(SeekFrom::Start(0))?;
        let upload = Self { original, length };
        upload.verify()?;
        Ok(upload)
    }

    pub fn reader(&self) -> &File {
        #[cfg(windows)]
        {
            self.original.reader()
        }
        #[cfg(not(windows))]
        {
            &self.original
        }
    }

    pub fn verify(&self) -> io::Result<()> {
        #[cfg(windows)]
        self.original.original_creation()?.verify()?;
        if self.reader().metadata()?.len() != self.length {
            return Err(io::Error::other("exact complete upload length changed"));
        }
        Ok(())
    }
}
