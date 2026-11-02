use fastcdc::v2020::{Normalization, StreamCDC};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{ChunkRef, ContentId, EntryId, FileManifest, FORMAT_VERSION};

pub const MIN_CHUNK: usize = 256 * 1024;
pub const AVG_CHUNK: usize = 1024 * 1024;
pub const MAX_CHUNK: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CasError {
    #[error("CAS I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid content metadata: {0}")]
    Model(#[from] sync_extend_core_model::ModelError),
    #[error("content chunking failed: {0}")]
    Chunking(String),
    #[error("content integrity failure")]
    Integrity,
    #[error("unsafe CAS directory")]
    UnsafeDirectory,
}

pub type Result<T> = std::result::Result<T, CasError>;

pub struct Cas {
    root: PathBuf,
}

impl Cas {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("tmp"))?;
        for path in [root, &root.join("objects"), &root.join("tmp")] {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() || is_reparse(&metadata) {
                return Err(CasError::UnsafeDirectory);
            }
        }
        Ok(Self {
            root: root.to_owned(),
        })
    }

    pub fn object_path(&self, id: &ContentId) -> PathBuf {
        self.root
            .join("objects")
            .join(&id.as_str()[..2])
            .join(id.as_str())
    }

    pub fn put(&self, data: &[u8]) -> Result<ChunkRef> {
        if data.is_empty() || data.len() > MAX_CHUNK {
            return Err(CasError::Integrity);
        }
        let id = ContentId::hash(data);
        let reference = ChunkRef {
            content_id: id.clone(),
            length: data.len() as u32,
        };
        let target = self.object_path(&id);
        if target.try_exists()? {
            self.read(&reference)?;
            return Ok(reference);
        }
        let parent = target.parent().ok_or(CasError::UnsafeDirectory)?;
        fs::create_dir_all(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.file_type().is_symlink() || is_reparse(&metadata) {
            return Err(CasError::UnsafeDirectory);
        }
        let temporary = self.root.join("tmp").join(EntryId::random()?.as_str());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        // Hard-link publication is atomic and cannot replace an existing object.
        match fs::hard_link(&temporary, &target) {
            Ok(()) => {
                sync_directory(parent)?;
                fs::remove_file(&temporary)?;
                self.read(&reference)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)?;
                self.read(&reference)?;
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        Ok(reference)
    }

    pub fn read(&self, reference: &ChunkRef) -> Result<Vec<u8>> {
        if reference.length == 0 || reference.length as usize > MAX_CHUNK {
            return Err(CasError::Integrity);
        }
        let path = self.object_path(&reference.content_id);
        let metadata = fs::symlink_metadata(&path)?;
        let parent = fs::symlink_metadata(path.parent().ok_or(CasError::UnsafeDirectory)?)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || is_reparse(&metadata)
            || is_reparse(&parent)
            || parent.file_type().is_symlink()
            || metadata.len() != u64::from(reference.length)
        {
            return Err(CasError::Integrity);
        }
        let mut data = Vec::with_capacity(reference.length as usize);
        File::open(path)?
            .take(u64::from(reference.length) + 1)
            .read_to_end(&mut data)?;
        if data.len() != reference.length as usize || ContentId::hash(&data) != reference.content_id
        {
            return Err(CasError::Integrity);
        }
        Ok(data)
    }

    pub fn import(&self, reader: impl Read) -> Result<FileManifest> {
        let mut hasher = blake3::Hasher::new();
        let mut chunks = Vec::new();
        let mut length = 0u64;
        for chunk in StreamCDC::with_level_and_seed(
            reader,
            MIN_CHUNK,
            AVG_CHUNK,
            MAX_CHUNK,
            Normalization::Level1,
            0,
        ) {
            let chunk = chunk.map_err(|e| CasError::Chunking(e.to_string()))?;
            hasher.update(&chunk.data);
            chunks.push(self.put(&chunk.data)?);
            length = length
                .checked_add(chunk.length as u64)
                .ok_or(CasError::Integrity)?;
            if chunks.len() > 1_000_000 {
                return Err(CasError::Integrity);
            }
        }
        let manifest = FileManifest {
            format_version: FORMAT_VERSION,
            chunking: "fastcdc-2020-v1".to_owned(),
            hash_algorithm: "blake3".to_owned(),
            compression: "none".to_owned(),
            content_id: ContentId::from_hasher(&hasher),
            length,
            chunks,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn write_file(&self, manifest: &FileManifest, mut writer: impl Write) -> Result<()> {
        manifest.validate()?;
        let mut hasher = blake3::Hasher::new();
        for reference in &manifest.chunks {
            let data = self.read(reference)?;
            hasher.update(&data);
            writer.write_all(&data)?;
        }
        if ContentId::from_hasher(&hasher) != manifest.content_id {
            return Err(CasError::Integrity);
        }
        Ok(())
    }

    pub fn verify(&self, manifest: &FileManifest) -> Result<()> {
        self.write_file(manifest, std::io::sink())
    }
}

#[cfg(unix)]
pub fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
pub fn sync_directory(_path: &Path) -> std::io::Result<()> {
    // std has no portable Windows directory flush; power-loss certification is open.
    Ok(())
}

pub fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}
