use fastcdc::v2020::{Normalization, StreamCDC};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use sync_extend_core_model::{
    limits::MAX_CHUNKS, ChunkRef, ContentId, EntryId, FileManifest, FORMAT_VERSION,
};

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
    #[error("content resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("CAS access deferred: {0}")]
    AccessDeferred(String),
}

pub type Result<T> = std::result::Result<T, CasError>;

pub struct Cas {
    root: PathBuf,
    access: Option<Box<CasAccess>>,
    coordinated_access: Option<Box<CoordinatedAccess>>,
    session_access: Option<Box<SessionAccess>>,
    original_read_handoff: Option<Box<OriginalReadHandoff>>,
}

type CasAccess = dyn Fn(&ContentId) -> std::result::Result<(), String> + Send;
type CoordinatedAccess = dyn Fn(&ContentId) -> std::result::Result<Box<dyn Send>, String> + Send;
type SessionAccess = dyn Fn() -> std::result::Result<Box<dyn Send>, String> + Send;
type OriginalReadHandoff = dyn Fn() -> std::result::Result<(), String> + Send;

/// Cooperative process-lifetime exclusion, not a durable reference or authorization.
pub struct CasSessionGuard {
    _guard: Box<dyn Send>,
}

impl Cas {
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_layout(root, true)
    }

    /// Open only an existing original layout. Caller supplies and retains
    /// independent original root/ancestor/file ownership during node assembly.
    /// This does not adopt filesystem objects or mint recovery authority.
    pub fn open_existing_layout(root: &Path) -> Result<Self> {
        Self::open_layout(root, false)
    }

    fn open_layout(root: &Path, create: bool) -> Result<Self> {
        for ancestor in root.ancestors() {
            match fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.file_type().is_symlink() || is_reparse(&metadata) => {
                    return Err(CasError::UnsafeDirectory);
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        if create {
            fs::create_dir_all(root.join("objects"))?;
            fs::create_dir_all(root.join("tmp"))?;
        }
        for path in [root, &root.join("objects"), &root.join("tmp")] {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() || is_reparse(&metadata) {
                return Err(CasError::UnsafeDirectory);
            }
        }
        Ok(Self {
            root: root.to_owned(),
            access: None,
            coordinated_access: None,
            session_access: None,
            original_read_handoff: None,
        })
    }

    /// Assemble the original session callbacks without creating any scaffold.
    /// Exact original directory identity retention is the node caller's contract.
    pub fn open_existing_session_coordinated(
        root: &Path,
        access: impl Fn(&ContentId) -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
        session: impl Fn() -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
    ) -> Result<Self> {
        let mut cas = Self::open_existing_layout(root)?;
        cas.coordinated_access = Some(Box::new(access));
        cas.session_access = Some(Box::new(session));
        Ok(cas)
    }

    /// Original assembly retains a callback that can close its own readonly
    /// Journal observers. This never replaces or removes CAS access fences.
    pub fn open_existing_session_coordinated_with_read_handoff(
        root: &Path,
        access: impl Fn(&ContentId) -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
        session: impl Fn() -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
        handoff: impl Fn() -> std::result::Result<(), String> + Send + 'static,
    ) -> Result<Self> {
        let mut cas = Self::open_existing_session_coordinated(root, access, session)?;
        cas.original_read_handoff = Some(Box::new(handoff));
        Ok(cas)
    }

    /// Only the caller's owned original readers are closed. The retained
    /// callbacks refuse all CAS access after handoff, including failed closes.
    /// This does not return an uncoordinated layout or a native capability.
    pub fn suspend_original_read_coordination(&mut self) -> Result<()> {
        let close = self.original_read_handoff.as_ref().ok_or_else(|| {
            CasError::AccessDeferred("original read handoff is absent or already consumed".into())
        })?;
        close().map_err(CasError::AccessDeferred)?;
        drop(self.original_read_handoff.take());
        Ok(())
    }
    /// Install the managed journal fence check; not a concurrent access lease.
    pub fn open_managed(
        root: &Path,
        access: impl Fn(&ContentId) -> std::result::Result<(), String> + Send + 'static,
    ) -> Result<Self> {
        let mut cas = Self::open(root)?;
        cas.access = Some(Box::new(access));
        Ok(cas)
    }

    /// The callback must acquire coordination BEFORE checking the durable fence.
    /// Its returned guard survives the complete chunk operation, including errors.
    pub fn open_coordinated(
        root: &Path,
        access: impl Fn(&ContentId) -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
    ) -> Result<Self> {
        let mut cas = Self::open(root)?;
        cas.coordinated_access = Some(Box::new(access));
        Ok(cas)
    }

    /// Retain a shared session for complete import/write/verify operations.
    /// Both callbacks acquire coordination before any journal/fence access.
    pub fn open_session_coordinated(
        root: &Path,
        access: impl Fn(&ContentId) -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
        session: impl Fn() -> std::result::Result<Box<dyn Send>, String> + Send + 'static,
    ) -> Result<Self> {
        let mut cas = Self::open_coordinated(root, access)?;
        cas.session_access = Some(Box::new(session));
        Ok(cas)
    }

    /// Keep this guard through a caller's reference commit when operation return
    /// alone is too short. Existing fences still refuse individual chunk access.
    pub fn acquire_session(&self) -> Result<CasSessionGuard> {
        let access = self.session_access.as_ref().ok_or_else(|| {
            CasError::AccessDeferred("CAS session coordination is not configured".to_owned())
        })?;
        Ok(CasSessionGuard {
            _guard: access().map_err(CasError::AccessDeferred)?,
        })
    }

    fn operation_session(&self) -> Result<Option<CasSessionGuard>> {
        self.session_access
            .as_ref()
            .map(|_| self.acquire_session())
            .transpose()
    }

    fn require_access(&self, id: &ContentId) -> Result<Option<Box<dyn Send>>> {
        let guard = self
            .coordinated_access
            .as_ref()
            .map(|access| access(id).map_err(CasError::AccessDeferred))
            .transpose()?;
        if let Some(access) = &self.access {
            access(id).map_err(CasError::AccessDeferred)?;
        }
        Ok(guard)
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
        let _access = self.require_access(&id)?;
        let reference = ChunkRef {
            content_id: id.clone(),
            length: data.len() as u32,
        };
        let target = self.object_path(&id);
        if target.try_exists()? {
            self.read_under_access(&reference)?;
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
                self.read_under_access(&reference)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary)?;
                self.read_under_access(&reference)?;
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        Ok(reference)
    }

    pub fn read(&self, reference: &ChunkRef) -> Result<Vec<u8>> {
        let _access = self.require_access(&reference.content_id)?;
        self.read_under_access(reference)
    }

    fn read_under_access(&self, reference: &ChunkRef) -> Result<Vec<u8>> {
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
        self.import_bounded(reader, MAX_CHUNKS as u64 * MAX_CHUNK as u64, MAX_CHUNKS)
    }

    pub fn import_bounded(
        &self,
        reader: impl Read,
        max_bytes: u64,
        max_chunks: usize,
    ) -> Result<FileManifest> {
        let _session = self.operation_session()?;
        bounded_content(reader, max_bytes, max_chunks, |data| self.put(data))
    }

    pub fn write_file(&self, manifest: &FileManifest, mut writer: impl Write) -> Result<()> {
        let _session = self.operation_session()?;
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

/// Observe bounded streaming content without a CAS session or chunk publication.
pub fn observe_bounded_content(
    reader: impl Read,
    max_bytes: u64,
    max_chunks: usize,
) -> Result<FileManifest> {
    bounded_content(reader, max_bytes, max_chunks, |data| {
        Ok(ChunkRef {
            content_id: ContentId::hash(data),
            length: data.len() as u32,
        })
    })
}

fn bounded_content(
    reader: impl Read,
    max_bytes: u64,
    max_chunks: usize,
    mut chunk_reference: impl FnMut(&[u8]) -> Result<ChunkRef>,
) -> Result<FileManifest> {
    let max_chunks = max_chunks.min(MAX_CHUNKS);
    let mut hasher = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut length = 0u64;
    // Probe one excess byte without consuming an unbounded, growing source.
    for chunk in StreamCDC::with_level_and_seed(
        reader.take(max_bytes.saturating_add(1)),
        MIN_CHUNK,
        AVG_CHUNK,
        MAX_CHUNK,
        Normalization::Level1,
        0,
    ) {
        let chunk = chunk.map_err(|e| CasError::Chunking(e.to_string()))?;
        length = length
            .checked_add(chunk.length as u64)
            .ok_or(CasError::Integrity)?;
        if length > max_bytes {
            return Err(CasError::ResourceLimit("file bytes"));
        }
        if chunks.len() >= max_chunks {
            return Err(CasError::ResourceLimit("file chunks"));
        }
        hasher.update(&chunk.data);
        chunks.push(chunk_reference(&chunk.data)?);
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

/// Bounded owned content plan. Chunking has no filesystem or Journal effects.
/// The caller must publish every chunk under its own actual native protocol.
pub struct BoundedContentPlan {
    pub manifest: FileManifest,
    pub chunks: Vec<(ChunkRef, Vec<u8>)>,
}

pub fn plan_bounded_content(
    bytes: &[u8],
    max_bytes: u64,
    max_chunks: usize,
) -> Result<BoundedContentPlan> {
    if max_bytes == 0 || max_chunks == 0 || bytes.len() as u64 > max_bytes {
        return Err(CasError::ResourceLimit(
            "bounded original content bytes/chunks",
        ));
    }
    let max_chunks = max_chunks.min(MAX_CHUNKS);
    let mut chunks = Vec::new();
    for chunk in StreamCDC::with_level_and_seed(
        std::io::Cursor::new(bytes),
        MIN_CHUNK,
        AVG_CHUNK,
        MAX_CHUNK,
        Normalization::Level1,
        0,
    ) {
        let chunk = chunk.map_err(|error| CasError::Chunking(error.to_string()))?;
        if chunks.len() >= max_chunks {
            return Err(CasError::ResourceLimit("bounded original content chunks"));
        }
        let reference = ChunkRef {
            content_id: ContentId::hash(&chunk.data),
            length: chunk.length as u32,
        };
        chunks.push((reference, chunk.data));
    }
    let manifest = FileManifest {
        format_version: FORMAT_VERSION,
        chunking: "fastcdc-2020-v1".into(),
        hash_algorithm: "blake3".into(),
        compression: "none".into(),
        content_id: ContentId::hash(bytes),
        length: bytes.len() as u64,
        chunks: chunks
            .iter()
            .map(|(reference, _)| reference.clone())
            .collect(),
    };
    manifest.validate()?;
    Ok(BoundedContentPlan { manifest, chunks })
}
