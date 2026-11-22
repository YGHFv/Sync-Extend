//! Fixed inside-image storage CAS, acquired from the actual namespace owner.
//! No arbitrary path, caller volume, observation constructor or Drop deletion.
use super::{key, name, open_directory_at, owned_descriptor, UnixFileKey};
use crate::{
    linux_write_lease::OriginalWriteLease, LinuxNamespaceCapability,
    LinuxStorageCasExclusiveCoordination, LinuxStorageCasRetirementInspection,
};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, IntoRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    sync::Arc,
};

#[path = "held_volume/storage_retirement.rs"]
mod retirement;
pub use retirement::{
    LinuxStorageRetirementBoundary, LinuxStorageRetirementClosedBoundary,
    LinuxStorageRetirementClosedObservation, LinuxStorageRetirementCreatorReceipt,
    LinuxStorageRetirementMarkerObservation, LinuxStorageRetirementMarkerUnlinkObservation,
    LinuxStorageRetirementMoveObservation, LinuxStorageRetirementPayloadSlot,
    LinuxStorageRetirementUnlinkObservation,
};
#[path = "held_volume/storage_retirement_inventory.rs"]
mod retirement_inventory;
pub use retirement_inventory::{
    LinuxStorageRetirementInventoryContext, LinuxStorageRetirementInventoryPhase,
    LinuxStorageRetirementInventoryPrefix,
};

const CHUNK_BYTES: u64 = 4 * 1024 * 1024;
const BLOCK_BYTES: u64 = 4096;
const MAX_ENTRIES: usize = 10_000;
const COORDINATION: &str = "cas-access.lock";
const REALM: &str = "realm-v1";
const REALM_BYTES: usize = 64;
const F_GETLEASE: libc::c_int = 1025;

fn refuse(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStorageCasLimits {
    pub max_payload_bytes: u64,
    pub max_entries: usize,
}

impl LinuxStorageCasLimits {
    pub fn validate(self) -> io::Result<()> {
        if self.max_payload_bytes == 0
            || self.max_payload_bytes > 16 * 1024 * 1024 * 1024
            || !(3..=MAX_ENTRIES).contains(&self.max_entries)
        {
            return Err(refuse(
                "bounded inside-image CAS byte and entry limits required",
            ));
        }
        Ok(())
    }

    /// Conservative complete-realm ext4 liability, separate from the five
    /// sealed outside Journal classes. Per-file rounding, extent tree depth <=5,
    /// one external xattr block, all bounded directory entries and one maximum
    /// chunk receive prefix are included. It grants no allocation/native right.
    pub fn physical_liability_bytes(self) -> io::Result<u64> {
        self.validate()?;
        let entries = self.max_entries as u64;
        let payload_blocks = self
            .max_payload_bytes
            .checked_add(BLOCK_BYTES - 1)
            .map(|value| value / BLOCK_BYTES)
            .and_then(|value| value.checked_add(entries + 1))
            .ok_or_else(|| refuse("inside CAS payload rounding overflow"))?;
        let directory_blocks = entries
            .checked_mul(128)
            .and_then(|value| value.checked_add(BLOCK_BYTES - 1))
            .map(|value| value / BLOCK_BYTES)
            .and_then(|value| value.checked_add(entries.min(256) + 4))
            .ok_or_else(|| refuse("inside CAS directory liability overflow"))?;
        let temporary_blocks = self
            .max_payload_bytes
            .min(CHUNK_BYTES)
            .checked_add(BLOCK_BYTES - 1)
            .map(|value| value / BLOCK_BYTES)
            .ok_or_else(|| refuse("inside CAS receive-prefix rounding overflow"))?;
        payload_blocks
            .checked_add(directory_blocks)
            .and_then(|value| value.checked_add(temporary_blocks))
            .and_then(|value| value.checked_mul(6))
            .and_then(|value| value.checked_add(entries + entries.min(256) + 5))
            .and_then(|value| value.checked_mul(BLOCK_BYTES))
            .ok_or_else(|| refuse("inside CAS complete physical liability overflow"))
    }
}

/// Only a rejection/audit expectation. This freely copyable projection owns no
/// namespace, image, descriptor, lease, payload or native action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStorageCasExpectedLayout {
    pub format_version: u32,
    pub backing_image: UnixFileKey,
    pub image_filesystem_id: [u8; 8],
    pub mounted_root_inode: u64,
    pub cas_inode: u64,
    pub objects_inode: u64,
    pub temporary_inode: u64,
    pub realm_inode: u64,
    pub realm_fingerprint: [u8; REALM_BYTES],
    pub owner_uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxStorageCasObservation {
    pub expected_layout: LinuxStorageCasExpectedLayout,
    pub owner_generation: [u8; 16],
    pub namespace: UnixFileKey,
    pub runtime_mount_id: u64,
    pub mounted_root: UnixFileKey,
    pub cas: UnixFileKey,
    pub objects: UnixFileKey,
    pub temporary: UnixFileKey,
    pub realm: UnixFileKey,
    pub limits: LinuxStorageCasLimits,
    pub physical_liability_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStorageCasInventory {
    pub object_entries: usize,
    pub shard_entries: usize,
    pub temporary_entries: usize,
    pub payload_bytes: u64,
    pub temporary_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxStorageCasFileObservation {
    pub identity: UnixFileKey,
    pub parent: UnixFileKey,
    pub length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
    pub single_link: bool,
    pub mandatory_original_write_lease: bool,
}

fn private(file: &File, directory: bool) -> io::Result<Metadata> {
    let metadata = file.metadata()?;
    // SAFETY: pointer-free current effective UID query.
    let uid = unsafe { libc::geteuid() };
    if metadata.uid() != uid
        || metadata.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file() || metadata.nlink() != 1
        }
    {
        return Err(refuse(
            "original private same-UID storage CAS object required",
        ));
    }
    Ok(metadata)
}

fn mount_id(file: &File) -> io::Result<u64> {
    let mut text = String::new();
    File::open(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?
        .take(4097)
        .read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(refuse("inside CAS original descriptor info bound"));
    }
    let mut values = text.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let result = values
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| refuse("inside CAS original runtime mount unavailable"))?;
    if values.next().is_some() {
        return Err(refuse("inside CAS original runtime mount ambiguous"));
    }
    Ok(result)
}

struct Geometry {
    filesystem_id: [u8; 8],
    available_bytes: u64,
    total_bytes: u64,
}

fn geometry(file: &File) -> io::Result<Geometry> {
    let mut result = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: retained real directory descriptor and fully sized writable output.
    if unsafe { libc::fstatfs(file.as_raw_fd(), result.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the full result.
    let result = unsafe { result.assume_init() };
    if result.f_type != 0xef53 || result.f_bsize != 4096 || result.f_frsize != 4096 {
        return Err(refuse(
            "inside CAS requires original 4-KiB ext4 image geometry",
        ));
    }
    if std::mem::size_of_val(&result.f_fsid) != 8 {
        return Err(refuse(
            "inside CAS kernel filesystem identity layout unsupported",
        ));
    }
    let mut filesystem_id = [0u8; 8];
    // SAFETY: f_fsid is initialized and checked to be exactly eight bytes; the
    // projection copies its opaque native representation without aliasing.
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&result.f_fsid as *const libc::fsid_t).cast::<u8>(),
            filesystem_id.as_mut_ptr(),
            filesystem_id.len(),
        );
    }
    if filesystem_id == [0; 8] {
        return Err(refuse(
            "inside CAS original ext4 filesystem identity is zero",
        ));
    }
    Ok(Geometry {
        filesystem_id,
        available_bytes: result
            .f_bavail
            .checked_mul(BLOCK_BYTES)
            .ok_or_else(|| refuse("inside CAS available image geometry overflow"))?,
        total_bytes: result
            .f_blocks
            .checked_mul(BLOCK_BYTES)
            .ok_or_else(|| refuse("inside CAS total image geometry overflow"))?,
    })
}

fn slot(parent: &File, component: &CString) -> io::Result<libc::stat> {
    let mut value = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: actual retained parent, terminated component, correctly sized
    // writable output; AT_SYMLINK_NOFOLLOW observes the original slot only.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            component.as_ptr(),
            value.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized the full output.
    Ok(unsafe { value.assume_init() })
}

fn absent(parent: &File, component: &CString) -> io::Result<()> {
    match slot(parent, component) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(refuse("inside CAS original destination slot is occupied")),
    }
}

fn same_slot(parent: &File, component: &CString, file: &File) -> io::Result<()> {
    let named = slot(parent, component)?;
    let metadata = file.metadata()?;
    if named.st_dev != metadata.dev()
        || named.st_ino != metadata.ino()
        || named.st_mode != metadata.mode()
        || named.st_uid != metadata.uid()
        || named.st_nlink != metadata.nlink()
        || u64::try_from(named.st_size).ok() != Some(metadata.len())
        || named.st_mode & libc::S_IFMT == libc::S_IFLNK
    {
        return Err(refuse("inside CAS original parent slot or inode changed"));
    }
    Ok(())
}

fn same_image(file: &File, owner: &LinuxNamespaceCapability, directory: bool) -> io::Result<()> {
    private(file, directory)?;
    let root = owner.volume().observation();
    if key(file)?.device != root.root_key.device
        || mount_id(file)? != root.runtime_mount_id
        || geometry(file)?.filesystem_id != geometry(owner.mount_descriptor())?.filesystem_id
    {
        return Err(refuse(
            "inside CAS crossed original image filesystem or runtime mount",
        ));
    }
    Ok(())
}

fn directory_names(directory: &File, maximum: usize) -> io::Result<BTreeSet<String>> {
    let dot = CString::new(".").expect("fixed descriptor-relative component");
    let opened = open_directory_at(directory, &dot)?;
    if key(&opened)? != key(directory)? || mount_id(&opened)? != mount_id(directory)? {
        return Err(refuse(
            "inside CAS descriptor-relative directory view differs",
        ));
    }
    let descriptor = opened.into_raw_fd();
    // SAFETY: fdopendir consumes this newly owned real directory descriptor on
    // success; errors leave ownership with the caller, which closes it below.
    let native = unsafe { libc::fdopendir(descriptor) };
    if native.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: unsuccessful fdopendir did not consume this owned descriptor.
        unsafe { libc::close(descriptor) };
        return Err(error);
    }
    let mut values = BTreeSet::new();
    let result = (|| {
        loop {
            // SAFETY: thread-local errno and a live DIR owned exclusively here.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: native is a live DIR; the result is consumed before the
            // next readdir and closedir calls.
            let entry = unsafe { libc::readdir(native) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(values)
                } else {
                    Err(error)
                };
            }
            // SAFETY: successful readdir returns a terminated d_name in the
            // live dirent, read before another call can replace its storage.
            let bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let component = std::str::from_utf8(bytes)
                .map_err(|_| refuse("inside CAS directory component encoding"))?;
            if !values.insert(component.to_owned()) || values.len() > maximum {
                return Err(refuse("inside CAS directory entry work bound"));
            }
        }
    })();
    // SAFETY: native is this invocation's single owned DIR; this closes its FD.
    let closed = unsafe { libc::closedir(native) };
    if closed != 0 {
        return Err(io::Error::last_os_error());
    }
    result
}

fn close_original(file: File) -> io::Result<()> {
    let descriptor = file.into_raw_fd();
    // SAFETY: consume exactly this owned descriptor once. Do not retry EINTR:
    // Linux may have already closed it, and a reused FD must never be closed.
    if unsafe { libc::close(descriptor) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn create_directory(parent: &File, component: &str) -> io::Result<File> {
    let component = name(component)?;
    absent(parent, &component)?;
    // SAFETY: original retained parent and fixed terminated native component;
    // mkdirat creates one fresh owner-only slot and does not follow a symlink.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all()?;
    let file = open_directory_at(parent, &component)?;
    private(&file, true)?;
    same_slot(parent, &component, &file)?;
    Ok(file)
}

struct Graph {
    root: File,
    cas: File,
    objects: File,
    temporary: File,
    realm: File,
    realm_lease: Arc<OriginalWriteLease>,
    realm_fingerprint: [u8; REALM_BYTES],
    realm_before: Metadata,
    lost_found: Option<File>,
    filesystem_id: [u8; 8],
    mount_id: u64,
    generation: [u8; 16],
    owner: Arc<LinuxNamespaceCapability>,
}

impl Graph {
    fn verify(&self) -> io::Result<()> {
        self.owner.verify()?;
        if self.owner.owner_generation() != self.generation
            || key(&self.root)? != key(self.owner.mount_descriptor())?
            || mount_id(&self.root)? != self.mount_id
            || geometry(&self.root)?.filesystem_id != self.filesystem_id
        {
            return Err(refuse(
                "inside CAS actual namespace owner or original image root changed",
            ));
        }
        for file in [&self.root, &self.cas, &self.objects, &self.temporary] {
            same_image(file, &self.owner, true)?;
        }
        for (parent, component, original) in [
            (&self.root, "cas", &self.cas),
            (&self.cas, "objects", &self.objects),
            (&self.cas, "tmp", &self.temporary),
        ] {
            let component = name(component)?;
            same_slot(parent, &component, original)?;
            let current = open_directory_at(parent, &component)?;
            let observed = (|| {
                same_image(&current, &self.owner, true)?;
                if key(&current)? != key(original)? {
                    return Err(refuse("inside CAS original directory slot substituted"));
                }
                Ok(())
            })();
            let closed = close_original(current);
            if let Err(error) = observed {
                let _ = closed;
                return Err(error);
            }
            closed?;
        }
        self.realm_lease.verify()?;
        same_image(&self.realm, &self.owner, false)?;
        same_slot(&self.cas, &name(REALM)?, &self.realm)?;
        let current = private(&self.realm, false)?;
        let mut actual = [0u8; REALM_BYTES];
        if current.len() != REALM_BYTES as u64 || !stable(&self.realm_before, &current) {
            return Err(refuse("inside CAS original durable realm seal changed"));
        }
        self.realm.read_exact_at(&mut actual, 0)?;
        if actual != self.realm_fingerprint {
            return Err(refuse("inside CAS actual durable realm binding differs"));
        }
        self.realm_lease.verify()?;
        let mut expected_root = BTreeSet::from(["cas".to_owned()]);
        if let Some(lost_found) = &self.lost_found {
            expected_root.insert("lost+found".to_owned());
            same_slot(&self.root, &name("lost+found")?, lost_found)?;
            same_image(lost_found, &self.owner, true)?;
            if !directory_names(lost_found, 1)?.is_empty() {
                return Err(refuse("inside CAS original image lost+found is occupied"));
            }
        }
        if directory_names(&self.root, 3)? != expected_root
            || directory_names(&self.cas, 4)?
                != BTreeSet::from(["objects".to_owned(), "tmp".to_owned(), REALM.to_owned()])
        {
            return Err(refuse(
                "inside CAS original fixed scaffold contains foreign slots",
            ));
        }
        self.owner.verify()
    }

    fn duplicate(&self) -> io::Result<Self> {
        self.verify()?;
        let mut originals = Vec::with_capacity(6);
        let retained = (|| {
            for original in [
                &self.root,
                &self.cas,
                &self.objects,
                &self.temporary,
                &self.realm,
            ] {
                originals.push(original.try_clone()?);
            }
            if let Some(lost_found) = &self.lost_found {
                originals.push(lost_found.try_clone()?);
            }
            Ok(())
        })();
        if let Err(error) = retained {
            for file in originals {
                let _ = close_original(file);
            }
            return Err(error);
        }
        let mut originals = originals.into_iter();
        let result = Self {
            root: originals.next().expect("retained original root"),
            cas: originals.next().expect("retained original CAS"),
            objects: originals.next().expect("retained original objects"),
            temporary: originals.next().expect("retained original temporary"),
            // A lease belongs to the original open description. Never open the
            // leased named seal again merely to construct a guard.
            realm: originals.next().expect("retained original realm"),
            realm_lease: Arc::clone(&self.realm_lease),
            realm_fingerprint: self.realm_fingerprint,
            realm_before: self.realm_before.clone(),
            lost_found: originals.next(),
            filesystem_id: self.filesystem_id,
            mount_id: self.mount_id,
            generation: self.generation,
            owner: Arc::clone(&self.owner),
        };
        if let Err(error) = result.verify() {
            let _ = result.close(false);
            return Err(error);
        }
        Ok(result)
    }

    fn close(self, terminal: bool) -> io::Result<()> {
        // Verification failure is not a close receipt, but it must not skip
        // explicit attempts to end any descriptor owned by this invocation.
        let mut failure = self.verify().err();
        if terminal && Arc::strong_count(&self.realm_lease) != 1 {
            failure.get_or_insert_with(|| {
                refuse("inside CAS original realm seal still has live guard loans")
            });
        }
        for file in [&self.temporary, &self.objects, &self.cas, &self.root] {
            if let Err(error) = file.sync_all() {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = self.realm.sync_all() {
            failure.get_or_insert(error);
        }
        let Self {
            owner,
            root,
            cas,
            objects,
            temporary,
            realm,
            realm_lease,
            lost_found,
            ..
        } = self;
        // Guard close drops only its original seal loan; the layout retains the
        // real lease. Terminal close must release the final actual kernel lease.
        if terminal {
            match Arc::try_unwrap(realm_lease) {
                Ok(lease) => {
                    if let Err(error) = lease.close() {
                        failure.get_or_insert(error);
                    }
                }
                Err(_lease) => {
                    failure.get_or_insert_with(|| {
                        refuse("original realm lease cannot close while other loans remain")
                    });
                }
            }
            // SAFETY: query through this still-live original description after
            // the last lease owner has released F_SETLEASE and joined its watcher.
            let state = unsafe { libc::fcntl(realm.as_raw_fd(), F_GETLEASE) };
            if state != libc::F_UNLCK {
                failure.get_or_insert_with(|| {
                    if state < 0 {
                        io::Error::last_os_error()
                    } else {
                        refuse("inside CAS original realm kernel lease did not release")
                    }
                });
            }
        } else {
            drop(realm_lease);
        }
        for file in [
            Some(realm),
            Some(temporary),
            Some(objects),
            Some(cas),
            lost_found,
            Some(root),
        ]
        .into_iter()
        .flatten()
        {
            if let Err(error) = close_original(file) {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = owner.verify() {
            failure.get_or_insert(error);
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }
}

/// Acquired original FD layout. Neither this value nor its file guards are
/// Clone/Deserialize. The actual owner retains its original image FD and lease.
pub struct LinuxStorageCas {
    graph: Graph,
    limits: LinuxStorageCasLimits,
}

impl LinuxStorageCas {
    pub fn preflight_new(
        owner: &LinuxNamespaceCapability,
        limits: LinuxStorageCasLimits,
    ) -> io::Result<()> {
        limits.validate()?;
        owner.verify()?;
        let root = owner.mount_descriptor();
        same_image(root, owner, true)?;
        let geometry = geometry(root)?;
        if limits.physical_liability_bytes()? > geometry.available_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "complete inside CAS image geometry/budget refused before first CREATE",
            ));
        }
        let names = directory_names(root, 3)?;
        if !names.is_empty() && names != BTreeSet::from(["lost+found".to_owned()]) {
            return Err(refuse(
                "fresh inside CAS image scaffold is occupied; no CREATE",
            ));
        }
        if names.contains("lost+found") {
            let original = open_directory_at(root, &name("lost+found")?)?;
            same_image(&original, owner, true)?;
            if !directory_names(&original, 1)?.is_empty() {
                return Err(refuse("original image lost+found is occupied; no CREATE"));
            }
        }
        absent(root, &name("cas")?)?;
        owner.verify()
    }

    pub fn create_new(
        owner: Arc<LinuxNamespaceCapability>,
        limits: LinuxStorageCasLimits,
        make_binding: impl FnOnce(LinuxStorageCasExpectedLayout) -> io::Result<[u8; REALM_BYTES]>,
    ) -> io::Result<Self> {
        Self::preflight_new(&owner, limits)?;
        let root = owner.mount_descriptor().try_clone()?;
        let cas = create_directory(&root, "cas").map_err(|error| {
            io::Error::other(format!("{error}; inside CAS CREATE prefix preserved: cas"))
        })?;
        same_image(&cas, &owner, true)?;
        let objects = create_directory(&cas, "objects").map_err(|error| {
            io::Error::other(format!(
                "{error}; inside CAS CREATE prefix preserved: cas/objects"
            ))
        })?;
        same_image(&objects, &owner, true)?;
        let temporary = create_directory(&cas, "tmp").map_err(|error| {
            io::Error::other(format!(
                "{error}; inside CAS CREATE prefix preserved: cas/tmp"
            ))
        })?;
        same_image(&temporary, &owner, true)?;
        let mut realm = open_file_at(&cas, &name(REALM)?, true, true).map_err(|error| {
            io::Error::other(format!(
                "{error}; inside CAS CREATE prefix preserved: cas/{REALM}"
            ))
        })?;
        same_image(&realm, &owner, false)?;
        same_slot(&cas, &name(REALM)?, &realm)?;
        let lease = Arc::new(OriginalWriteLease::acquire(&realm)?);
        // Inner st_dev is deliberately omitted from durable identity: a later
        // acquisition can use a different actual loop device and runtime mount.
        let expectation = LinuxStorageCasExpectedLayout {
            format_version: 1,
            backing_image: owner.backing_image_key(),
            image_filesystem_id: geometry(&root)?.filesystem_id,
            mounted_root_inode: key(&root)?.inode,
            cas_inode: key(&cas)?.inode,
            objects_inode: key(&objects)?.inode,
            temporary_inode: key(&temporary)?.inode,
            realm_inode: key(&realm)?.inode,
            realm_fingerprint: [0; REALM_BYTES],
            owner_uid: private(&root, true)?.uid(),
        };
        let binding = make_binding(expectation)?;
        validate_binding(&binding)?;
        realm.write_all(&binding)?;
        realm.sync_all()?;
        cas.sync_all()?;
        Self::from_originals(
            owner, limits, root, cas, objects, temporary, realm, lease, binding,
        )
    }

    pub fn reopen_existing(
        owner: Arc<LinuxNamespaceCapability>,
        limits: LinuxStorageCasLimits,
        expected: LinuxStorageCasExpectedLayout,
    ) -> io::Result<Self> {
        Self::reopen_with_inventory(owner, limits, expected, None)
    }

    /// A complete original Journal catalog may account immutable retirement
    /// residue. It cannot recover any old creator or native execution loan.
    pub fn reopen_existing_with_retirement_prefixes(
        owner: Arc<LinuxNamespaceCapability>,
        limits: LinuxStorageCasLimits,
        expected: LinuxStorageCasExpectedLayout,
        inventory: &LinuxStorageRetirementInventoryContext,
    ) -> io::Result<Self> {
        Self::reopen_with_inventory(owner, limits, expected, Some(inventory))
    }

    fn reopen_with_inventory(
        owner: Arc<LinuxNamespaceCapability>,
        limits: LinuxStorageCasLimits,
        expected: LinuxStorageCasExpectedLayout,
        inventory: Option<&LinuxStorageRetirementInventoryContext>,
    ) -> io::Result<Self> {
        limits.validate()?;
        owner.verify()?;
        let root = owner.mount_descriptor().try_clone()?;
        let image = geometry(&root)?;
        if expected.format_version != 1
            || expected.backing_image != owner.backing_image_key()
            || expected.owner_uid != 0
            || expected.image_filesystem_id != image.filesystem_id
            || expected.mounted_root_inode != key(&root)?.inode
            || limits.physical_liability_bytes()? > image.total_bytes
        {
            return Err(refuse(
                "inside CAS stale image/layout/geometry expectation; no CREATE",
            ));
        }
        let cas = open_directory_at(&root, &name("cas")?)?;
        let objects = open_directory_at(&cas, &name("objects")?)?;
        let temporary = open_directory_at(&cas, &name("tmp")?)?;
        // An absent/partial/foreign seal is a refusal, never a repair or adopt.
        let realm = open_file_at(&cas, &name(REALM)?, true, false)?;
        same_image(&realm, &owner, false)?;
        same_slot(&cas, &name(REALM)?, &realm)?;
        if key(&realm)?.inode != expected.realm_inode
            || private(&realm, false)?.len() != REALM_BYTES as u64
        {
            return Err(refuse(
                "inside CAS original fixed realm seal expectation differs",
            ));
        }
        validate_binding(&expected.realm_fingerprint)?;
        let lease = Arc::new(OriginalWriteLease::acquire(&realm)?);
        let mut binding = [0; REALM_BYTES];
        realm.read_exact_at(&mut binding, 0)?;
        lease.verify()?;
        if binding != expected.realm_fingerprint {
            return Err(refuse(
                "inside CAS actual durable seal differs from reopen expectation",
            ));
        }
        let result = Self::from_originals(
            owner, limits, root, cas, objects, temporary, realm, lease, binding,
        )?;
        if result.observation()?.expected_layout != expected {
            return Err(refuse(
                "inside CAS original directory inode expectation differs",
            ));
        }
        if let Some(inventory) = inventory {
            retirement_inventory::require_only_durable_temporaries(
                &result.graph,
                inventory,
                result.limits,
            )?;
        } else if result.inventory()?.temporary_entries != 0 {
            return Err(refuse(
                "inside CAS unresolved original receive prefix; never adopted or deleted",
            ));
        }
        result.verify()?;
        Ok(result)
    }

    fn from_originals(
        owner: Arc<LinuxNamespaceCapability>,
        limits: LinuxStorageCasLimits,
        root: File,
        cas: File,
        objects: File,
        temporary: File,
        realm: File,
        realm_lease: Arc<OriginalWriteLease>,
        realm_fingerprint: [u8; REALM_BYTES],
    ) -> io::Result<Self> {
        let lost_found = if directory_names(&root, 3)?.contains("lost+found") {
            Some(open_directory_at(&root, &name("lost+found")?)?)
        } else {
            None
        };
        let graph = Graph {
            filesystem_id: geometry(&root)?.filesystem_id,
            mount_id: owner.volume().observation().runtime_mount_id,
            generation: owner.owner_generation(),
            realm_before: realm.metadata()?,
            owner,
            root,
            cas,
            objects,
            temporary,
            realm,
            realm_lease,
            realm_fingerprint,
            lost_found,
        };
        let result = Self { graph, limits };
        result.verify()?;
        Ok(result)
    }

    pub fn verify(&self) -> io::Result<()> {
        self.limits.validate()?;
        self.graph.verify()
    }

    /// Recomputed by the backend from its actual persistent Journal generation,
    /// original outside root/sentinel and explicit v2 config after VFS reopen.
    /// The caller bytes are rejection inputs and never reacquire this layout.
    pub fn verify_realm_binding(&self, binding: [u8; REALM_BYTES]) -> io::Result<()> {
        validate_binding(&binding)?;
        self.verify()?;
        if binding != self.graph.realm_fingerprint {
            return Err(refuse(
                "inside CAS actual metadata/config/original-key realm binding differs",
            ));
        }
        self.verify()
    }

    pub fn observation(&self) -> io::Result<LinuxStorageCasObservation> {
        self.verify()?;
        let root = key(&self.graph.root)?;
        let cas = key(&self.graph.cas)?;
        let objects = key(&self.graph.objects)?;
        let temporary = key(&self.graph.temporary)?;
        let realm = key(&self.graph.realm)?;
        Ok(LinuxStorageCasObservation {
            expected_layout: LinuxStorageCasExpectedLayout {
                format_version: 1,
                backing_image: self.graph.owner.backing_image_key(),
                image_filesystem_id: self.graph.filesystem_id,
                mounted_root_inode: root.inode,
                cas_inode: cas.inode,
                objects_inode: objects.inode,
                temporary_inode: temporary.inode,
                realm_inode: realm.inode,
                realm_fingerprint: self.graph.realm_fingerprint,
                owner_uid: private(&self.graph.root, true)?.uid(),
            },
            owner_generation: self.graph.generation,
            namespace: self.graph.owner.namespace_key(),
            runtime_mount_id: self.graph.mount_id,
            mounted_root: root,
            cas,
            objects,
            temporary,
            realm,
            limits: self.limits,
            physical_liability_bytes: self.limits.physical_liability_bytes()?,
        })
    }

    pub fn directory_guard(&self) -> io::Result<LinuxStorageCasDirectoryGuard> {
        Ok(LinuxStorageCasDirectoryGuard {
            graph: self.graph.duplicate()?,
        })
    }

    pub fn inventory(&self) -> io::Result<LinuxStorageCasInventory> {
        self.verify()?;
        let result = retirement_inventory::bounded_inventory(&self.graph, self.limits, None)?;
        self.verify()?;
        Ok(result)
    }

    /// Only a complete typed durable catalog can account a retirement prefix.
    /// This reads metadata through held parents and never opens a leased file.
    pub fn inventory_with_retirement_prefixes(
        &self,
        context: &LinuxStorageRetirementInventoryContext,
    ) -> io::Result<LinuxStorageCasInventory> {
        self.verify()?;
        let result =
            retirement_inventory::bounded_inventory(&self.graph, self.limits, Some(context))?;
        self.verify()?;
        Ok(result)
    }

    pub fn contains(&self, content: &str) -> io::Result<bool> {
        validate_hex(content, 64)?;
        self.verify()?;
        let shard = match open_directory_at(&self.graph.objects, &name(&content[..2])?) {
            Ok(shard) => shard,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.verify()?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        same_image(&shard, &self.graph.owner, true)?;
        let result = match slot(&shard, &name(content)?) {
            Ok(named) => {
                if named.st_mode & libc::S_IFMT != libc::S_IFREG {
                    return Err(refuse("inside CAS occupied original leaf is not regular"));
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        same_slot(&self.graph.objects, &name(&content[..2])?, &shard)?;
        self.verify()?;
        Ok(result)
    }

    pub fn original(&self, content: &str, length: u64) -> io::Result<LinuxStorageCasFileGuard> {
        validate_hex(content, 64)?;
        if length == 0 || length > CHUNK_BYTES || length > self.limits.max_payload_bytes {
            return Err(refuse("inside CAS checked original payload length refused"));
        }
        self.verify()?;
        let parent = open_directory_at(&self.graph.objects, &name(&content[..2])?)?;
        same_image(&parent, &self.graph.owner, true)?;
        let file = open_file_at(&parent, &name(content)?, true, false)?;
        same_image(&file, &self.graph.owner, false)?;
        if private(&file, false)?.len() != length {
            return Err(refuse("inside CAS original checked length differs"));
        }
        same_slot(&parent, &name(content)?, &file)?;
        let lease = OriginalWriteLease::acquire(&file)?;
        let result = LinuxStorageCasFileGuard {
            graph: Some(self.graph.duplicate()?),
            parent: Some(parent),
            file: Some(file),
            lease: Some(lease),
            component: name(content)?,
            shard: content[..2].to_owned(),
            length,
            before: None,
        };
        let mut result = result;
        result.before = Some(result.file.as_ref().expect("live original").metadata()?);
        result.verify()?;
        Ok(result)
    }

    /// No second shared acquisition or second payload lease is hidden here.
    /// The caller keeps the actual exclusive guard until the original payload
    /// lease and FD have closed.
    pub fn inspect_retirement_original(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
        content: &str,
        length: u64,
    ) -> io::Result<LinuxStorageCasRetirementInspection> {
        exclusive.verify()?;
        self.verify()?;
        if !Arc::ptr_eq(&self.graph.owner, &exclusive.guard.owner) {
            return Err(refuse(
                "retirement inspection requires the same actual namespace owner",
            ));
        }
        let inspection = LinuxStorageCasRetirementInspection {
            original: self.original(content, length)?,
            possession: Arc::clone(&exclusive.guard.possession),
            layout: self.observation()?,
        };
        inspection.verify(exclusive)?;
        Ok(inspection)
    }

    pub fn stage_new(&self, content: &str, bytes: &[u8]) -> io::Result<LinuxStorageCasStaged> {
        validate_hex(content, 64)?;
        if bytes.is_empty() || bytes.len() as u64 > CHUNK_BYTES {
            return Err(refuse("inside CAS receive chunk length refused"));
        }
        self.verify()?;
        let inventory = self.inventory()?;
        if inventory.temporary_entries != 0 {
            return Err(refuse(
                "inside CAS unresolved receive prefix refuses another CREATE",
            ));
        }
        if inventory
            .payload_bytes
            .checked_add(bytes.len() as u64)
            .is_none_or(|value| value > self.limits.max_payload_bytes)
            || inventory.object_entries + inventory.shard_entries + 2 > self.limits.max_entries
        {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "inside CAS whole byte/entry budget refused before receive CREATE",
            ));
        }
        self.stage_admitted(content, bytes).map_err(|error| {
            // Only the admission above may retain StorageFull. Once shard/tmp
            // CREATE can have run, every failure preserves the prefix and must
            // keep the outer owner from reporting a successful clean closure.
            io::Error::other(format!(
                "{error}; original inside receive CREATE prefix preserved; target={content}"
            ))
        })
    }

    fn stage_admitted(&self, content: &str, bytes: &[u8]) -> io::Result<LinuxStorageCasStaged> {
        let shard_name = name(&content[..2])?;
        let shard = match open_directory_at(&self.graph.objects, &shard_name) {
            Ok(original) => original,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_directory(&self.graph.objects, &content[..2])?
            }
            Err(error) => return Err(error),
        };
        same_image(&shard, &self.graph.owner, true)?;
        same_slot(&self.graph.objects, &shard_name, &shard)?;
        absent(&shard, &name(content)?)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| io::Error::other("inside CAS receive-prefix randomness unavailable"))?;
        let temporary = random
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<String>();
        let component = name(&temporary)?;
        let mut file = open_file_at(&self.graph.temporary, &component, true, true)?;
        private(&file, false)?;
        same_image(&file, &self.graph.owner, false)?;
        same_slot(&self.graph.temporary, &component, &file)?;
        let lease = OriginalWriteLease::acquire(&file)?;
        let written = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            self.graph.temporary.sync_all()?;
            lease.verify()?;
            same_slot(&self.graph.temporary, &component, &file)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(error) = written {
            return Err(io::Error::other(format!(
                "{error}; original inside receive prefix preserved: {temporary}; target={content}"
            )));
        }
        let result = LinuxStorageCasStaged {
            graph: self.graph.duplicate()?,
            parent: shard,
            file,
            lease,
            temporary: component,
            target: name(content)?,
            shard: content[..2].to_owned(),
            before: None,
            length: bytes.len() as u64,
        };
        let mut result = result;
        result.before = Some(result.file.metadata()?);
        result.verify()?;
        Ok(result)
    }

    /// Rejection only, before closing any original FD. Observations cannot
    /// satisfy the actual shared lease ownership or unresolved-prefix checks.
    pub fn verify_closed_constraints(&self) -> io::Result<()> {
        self.verify_close_inventory(None)
    }

    pub fn verify_closed_constraints_with_retirement_prefixes(
        &self,
        inventory: &LinuxStorageRetirementInventoryContext,
    ) -> io::Result<()> {
        self.verify_close_inventory(Some(inventory))
    }

    fn verify_close_inventory(
        &self,
        inventory: Option<&LinuxStorageRetirementInventoryContext>,
    ) -> io::Result<()> {
        self.verify()?;
        if Arc::strong_count(&self.graph.realm_lease) != 1 {
            return Err(refuse(
                "inside CAS original directory/file guards are still active",
            ));
        }
        if let Some(inventory) = inventory {
            retirement_inventory::require_only_durable_temporaries(
                &self.graph,
                inventory,
                self.limits,
            )?;
        } else if self.inventory()?.temporary_entries != 0 {
            return Err(refuse(
                "inside CAS unresolved receive prefix prevents clean closure",
            ));
        }
        self.verify()
    }

    /// Actual original directory FD closes precede the metadata checkpoint and
    /// the namespace owner's normal unmount. No persistent slot is removed.
    pub fn close(self) -> io::Result<LinuxStorageCasObservation> {
        let verified = self.verify_closed_constraints();
        let observation = self.observation();
        let closed = self.graph.close(true);
        match (verified, observation, closed) {
            (Ok(()), Ok(observation), Ok(())) => Ok(observation),
            (Err(error), _, _) | (Ok(()), Err(error), _) | (Ok(()), Ok(_), Err(error)) => {
                Err(error)
            }
        }
    }

    pub fn close_with_retirement_prefixes(
        self,
        inventory: &LinuxStorageRetirementInventoryContext,
    ) -> io::Result<LinuxStorageCasObservation> {
        let verified = self.verify_closed_constraints_with_retirement_prefixes(inventory);
        let observation = self.observation();
        let closed = self.graph.close(true);
        match (verified, observation, closed) {
            (Ok(()), Ok(observation), Ok(())) => Ok(observation),
            (Err(error), _, _) | (Ok(()), Err(error), _) | (Ok(()), Ok(_), Err(error)) => {
                Err(error)
            }
        }
    }
}

fn inventory_file_length(parent: &File, component: &CString, graph: &Graph) -> io::Result<u64> {
    let observed = slot(parent, component)?;
    // SAFETY: pointer-free current effective UID query.
    let uid = unsafe { libc::geteuid() };
    if observed.st_mode & libc::S_IFMT != libc::S_IFREG
        || observed.st_mode & 0o7777 != 0o600
        || observed.st_uid != uid
        || observed.st_nlink != 1
        || observed.st_ino == 0
        || observed.st_dev != key(&graph.root)?.device
    {
        return Err(refuse(
            "inside CAS original descriptor-relative inventory slot differs",
        ));
    }
    // Actual namespace topology verification before/after the whole inventory
    // rejects foreign/bind mounts. This stat is an observation, never payload
    // possession; payload reads separately acquire exact File FD/lease/hash.
    u64::try_from(observed.st_size)
        .map_err(|_| refuse("inside CAS original inventory has a negative file length"))
}

fn inventory_limit(
    value: LinuxStorageCasInventory,
    limits: LinuxStorageCasLimits,
) -> io::Result<()> {
    if value.object_entries + value.shard_entries + value.temporary_entries > limits.max_entries
        || value
            .payload_bytes
            .checked_add(value.temporary_bytes)
            .is_none_or(|bytes| bytes > limits.max_payload_bytes)
        || value.temporary_bytes > limits.max_payload_bytes.min(CHUNK_BYTES)
    {
        return Err(refuse(
            "inside CAS original bounded inventory exceeds realm limits",
        ));
    }
    Ok(())
}

fn validate_hex(value: &str, length: usize) -> io::Result<()> {
    if value.len() != length
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(refuse(
            "one canonical lowercase inside CAS component required",
        ));
    }
    Ok(())
}

fn validate_binding(value: &[u8; REALM_BYTES]) -> io::Result<()> {
    let text = std::str::from_utf8(value)
        .map_err(|_| refuse("inside CAS fixed durable realm binding encoding"))?;
    validate_hex(text, REALM_BYTES)
}

fn open_file_at(parent: &File, component: &CString, write: bool, create: bool) -> io::Result<File> {
    let flags = (if write { libc::O_RDWR } else { libc::O_RDONLY })
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if create {
            libc::O_CREAT | libc::O_EXCL
        } else {
            0
        };
    // SAFETY: original live parent and terminated single component. The optional
    // variadic owner-only mode is supplied only for an exclusive fresh CREATE.
    let descriptor = unsafe {
        if create {
            libc::openat(parent.as_raw_fd(), component.as_ptr(), flags, 0o600)
        } else {
            libc::openat(parent.as_raw_fd(), component.as_ptr(), flags)
        }
    };
    owned_descriptor(descriptor)
}

pub struct LinuxStorageCasDirectoryGuard {
    graph: Graph,
}

impl LinuxStorageCasDirectoryGuard {
    pub fn verify(&self) -> io::Result<()> {
        self.graph.verify()
    }

    pub fn close(self) -> io::Result<()> {
        self.graph.close(false)
    }
}

pub struct LinuxStorageCasFileGuard {
    // Default error/Drop cleanup also keeps the namespace loan until the
    // payload lease, original file and original parent FDs have been released.
    lease: Option<OriginalWriteLease>,
    file: Option<File>,
    parent: Option<File>,
    graph: Option<Graph>,
    component: CString,
    shard: String,
    length: u64,
    before: Option<Metadata>,
}

fn stable(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

impl LinuxStorageCasFileGuard {
    pub fn verify(&self) -> io::Result<()> {
        let graph = self
            .graph
            .as_ref()
            .ok_or_else(|| refuse("original inside CAS file is closed"))?;
        let parent = self
            .parent
            .as_ref()
            .ok_or_else(|| refuse("original inside CAS parent is closed"))?;
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| refuse("original inside CAS file FD is closed"))?;
        graph.verify()?;
        self.lease
            .as_ref()
            .ok_or_else(|| refuse("original inside CAS lease is closed"))?
            .verify()?;
        same_image(parent, &graph.owner, true)?;
        same_image(file, &graph.owner, false)?;
        same_slot(&graph.objects, &name(&self.shard)?, parent)?;
        same_slot(parent, &self.component, file)?;
        let current = private(file, false)?;
        if current.len() != self.length
            || self
                .before
                .as_ref()
                .is_none_or(|before| !stable(before, &current))
        {
            return Err(refuse(
                "inside CAS original payload identity/length/timestamp changed",
            ));
        }
        self.lease.as_ref().expect("live original lease").verify()?;
        graph.verify()
    }

    pub fn read_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        let file = self.file.as_ref().expect("verified original FD");
        let mut bytes = vec![0u8; self.length as usize];
        file.read_exact_at(&mut bytes, 0)?;
        let mut excess = [0u8; 1];
        if file.read_at(&mut excess, self.length)? != 0 {
            return Err(refuse(
                "inside CAS original payload grew during bounded read",
            ));
        }
        self.verify()?;
        Ok(bytes)
    }

    pub fn observation(&self) -> io::Result<LinuxStorageCasFileObservation> {
        self.verify()?;
        let file = self.file.as_ref().expect("verified original FD");
        let metadata = file.metadata()?;
        Ok(LinuxStorageCasFileObservation {
            identity: key(file)?,
            parent: key(self.parent.as_ref().expect("verified original parent"))?,
            length: self.length,
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            single_link: metadata.nlink() == 1,
            mandatory_original_write_lease: true,
        })
    }

    /// Close the actual payload lease/file/parent first. The caller closes its
    /// original Journal guard before closing the returned inside directory loan.
    pub fn close_file(mut self) -> io::Result<LinuxStorageCasDirectoryGuard> {
        let mut failure = self.verify().err();
        if let Some(lease) = self.lease.take() {
            if let Err(error) = lease.close() {
                failure.get_or_insert(error);
            }
        }
        if let Some(file) = self.file.take() {
            // SAFETY: pointer-free query through the still-live original FD.
            let state = unsafe { libc::fcntl(file.as_raw_fd(), F_GETLEASE) };
            if state != libc::F_UNLCK {
                failure.get_or_insert_with(|| {
                    if state < 0 {
                        io::Error::last_os_error()
                    } else {
                        refuse("inside CAS original kernel lease did not release")
                    }
                });
            }
            if let Err(error) = close_original(file) {
                failure.get_or_insert(error);
            }
        }
        if let Some(parent) = self.parent.take() {
            if let Err(error) = close_original(parent) {
                failure.get_or_insert(error);
            }
        }
        let graph = self
            .graph
            .take()
            .ok_or_else(|| refuse("original graph already closed"))?;
        if let Some(error) = failure {
            let _ = graph.close(false);
            return Err(error);
        }
        Ok(LinuxStorageCasDirectoryGuard { graph })
    }

    pub fn close(self) -> io::Result<()> {
        self.close_file()?.close()
    }
}

/// Original fresh receive prefix. Drop closes FDs/leases and preserves any
/// named prefix; it never erases a failed or unfamiliar pathname.
pub struct LinuxStorageCasStaged {
    lease: OriginalWriteLease,
    file: File,
    parent: File,
    graph: Graph,
    temporary: CString,
    target: CString,
    shard: String,
    before: Option<Metadata>,
    length: u64,
}

impl LinuxStorageCasStaged {
    fn verify(&self) -> io::Result<()> {
        self.graph.verify()?;
        self.lease.verify()?;
        same_image(&self.parent, &self.graph.owner, true)?;
        same_image(&self.file, &self.graph.owner, false)?;
        same_slot(&self.graph.objects, &name(&self.shard)?, &self.parent)?;
        same_slot(&self.graph.temporary, &self.temporary, &self.file)?;
        let current = private(&self.file, false)?;
        if self
            .before
            .as_ref()
            .is_none_or(|before| !stable(before, &current))
            || current.len() != self.length
        {
            return Err(refuse("inside CAS original receive prefix changed"));
        }
        self.lease.verify()
    }

    pub fn read_bytes(&self) -> io::Result<Vec<u8>> {
        self.verify()?;
        let mut bytes = vec![0; self.length as usize];
        self.file.read_exact_at(&mut bytes, 0)?;
        self.verify()?;
        Ok(bytes)
    }

    pub fn publish(self) -> io::Result<LinuxStorageCasFileGuard> {
        self.verify()?;
        absent(&self.parent, &self.target)?;
        // SAFETY: original retained same-mount source/destination parents and
        // terminated names. RENAME_NOREPLACE never overwrites an occupant.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                self.graph.temporary.as_raw_fd(),
                self.temporary.as_ptr(),
                self.parent.as_raw_fd(),
                self.target.as_ptr(),
                1u32,
            )
        } != 0
        {
            return Err(io::Error::other(format!(
                "{}; original inside receive prefix preserved: {}; target={}",
                io::Error::last_os_error(),
                self.temporary.to_string_lossy(),
                self.target.to_string_lossy(),
            )));
        }
        self.parent.sync_all()?;
        self.graph.temporary.sync_all()?;
        absent(&self.graph.temporary, &self.temporary)?;
        same_slot(&self.parent, &self.target, &self.file)?;
        self.lease.verify()?;
        let before = self.file.metadata()?;
        let result = LinuxStorageCasFileGuard {
            graph: Some(self.graph),
            parent: Some(self.parent),
            file: Some(self.file),
            lease: Some(self.lease),
            component: self.target,
            shard: self.shard,
            length: self.length,
            before: Some(before),
        };
        result.verify()?;
        Ok(result)
    }
}

/// Fixed zero-length cooperative Journal sentinel at the original outside data
/// root. It is not a sealed SQLite physical class or native writer authority.
pub struct LinuxStorageCasCoordination {
    parent: File,
    original: File,
    parent_key: UnixFileKey,
    original_key: UnixFileKey,
    owner: Arc<LinuxNamespaceCapability>,
}

/// A consuming original regular-file close, never a serialized ownership proof.
pub struct LinuxStorageOutsideFileClosed {
    identity: UnixFileKey,
}

impl LinuxStorageOutsideFileClosed {
    pub fn identity(&self) -> UnixFileKey {
        self.identity
    }
}

impl LinuxStorageCasCoordination {
    pub fn preflight_new(parent: &File) -> io::Result<()> {
        private(parent, true)?;
        absent(parent, &name(COORDINATION)?)
    }

    pub fn preflight_existing(parent: &File, expected: UnixFileKey) -> io::Result<()> {
        private(parent, true)?;
        let original = open_file_at(parent, &name(COORDINATION)?, true, false)?;
        let metadata = private(&original, false)?;
        if metadata.len() != 0
            || key(&original)? != expected
            || key(&original)?.device != key(parent)?.device
        {
            return Err(refuse(
                "original outside CAS cooperative sentinel expectation differs",
            ));
        }
        same_slot(parent, &name(COORDINATION)?, &original)
    }

    pub fn create_new(owner: Arc<LinuxNamespaceCapability>, parent: &File) -> io::Result<Self> {
        owner.verify()?;
        Self::preflight_new(parent)?;
        let original = open_file_at(parent, &name(COORDINATION)?, true, true)?;
        original.sync_all()?;
        parent.sync_all()?;
        Self::from_original(owner, parent.try_clone()?, original)
    }

    pub fn reopen_existing(
        owner: Arc<LinuxNamespaceCapability>,
        parent: &File,
        expected: UnixFileKey,
    ) -> io::Result<Self> {
        owner.verify()?;
        Self::preflight_existing(parent, expected)?;
        let original = open_file_at(parent, &name(COORDINATION)?, true, false)?;
        if key(&original)? != expected {
            return Err(refuse(
                "original outside CAS cooperative sentinel substituted",
            ));
        }
        Self::from_original(owner, parent.try_clone()?, original)
    }

    fn from_original(
        owner: Arc<LinuxNamespaceCapability>,
        parent: File,
        original: File,
    ) -> io::Result<Self> {
        let result = Self {
            owner,
            parent_key: key(&parent)?,
            original_key: key(&original)?,
            parent,
            original,
        };
        result.verify()?;
        Ok(result)
    }

    pub fn key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.original_key)
    }

    pub fn verify(&self) -> io::Result<()> {
        self.owner.verify()?;
        private(&self.parent, true)?;
        let metadata = private(&self.original, false)?;
        if key(&self.parent)? != self.parent_key
            || key(&self.original)? != self.original_key
            || self.original_key.device != self.parent_key.device
            || metadata.len() != 0
        {
            return Err(refuse(
                "original outside zero-length CAS cooperative sentinel changed",
            ));
        }
        same_slot(&self.parent, &name(COORDINATION)?, &self.original)?;
        self.owner.verify()
    }

    /// Retain actual original FDs for the Journal v2 opt-in. This is not a
    /// caller identity constructor and never opens or creates a pathname.
    pub fn loan(&self) -> io::Result<LinuxStorageCasCoordinationLoan> {
        self.verify()?;
        let result = LinuxStorageCasCoordinationLoan {
            parent: self.parent.try_clone()?,
            original: self.original.try_clone()?,
            parent_key: self.parent_key,
            original_key: self.original_key,
            owner: Arc::clone(&self.owner),
        };
        result.verify()?;
        self.verify()?;
        Ok(result)
    }

    pub fn close(self) -> io::Result<()> {
        let mut failure = self.verify().err();
        for file in [&self.original, &self.parent] {
            if let Err(error) = file.sync_all() {
                failure.get_or_insert(error);
            }
        }
        for file in [self.original, self.parent] {
            if let Err(error) = close_original(file) {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = self.owner.verify() {
            failure.get_or_insert(error);
        }
        failure.map_or(Ok(()), Err)
    }

    /// Explicitly close the final original outside root after the actual
    /// metadata checkpoint. Closing a descriptor grants no native permission.
    pub fn close_outside_root(original: File) -> io::Result<()> {
        let mut failure = private(&original, true).err();
        if let Err(error) = original.sync_all() {
            failure.get_or_insert(error);
        }
        // SAFETY: release only this retained cooperative root description.
        if unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_UN) } != 0 {
            failure.get_or_insert_with(io::Error::last_os_error);
        }
        if let Err(error) = close_original(original) {
            failure.get_or_insert(error);
        }
        failure.map_or(Ok(()), Err)
    }

    /// Pure conservative 4-KiB ext4 data/extent/xattr arithmetic. This grants
    /// neither allocation nor authority over a pathname or a filesystem.
    pub fn outside_control_physical_liability(capacity: u64) -> io::Result<u64> {
        let data_blocks = capacity
            .checked_add(BLOCK_BYTES - 1)
            .map(|value| value / BLOCK_BYTES)
            .ok_or_else(|| refuse("outside control capacity rounding overflow"))?;
        data_blocks
            .checked_mul(6)
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_mul(BLOCK_BYTES))
            .ok_or_else(|| refuse("outside control physical liability overflow"))
    }

    /// Read-only gate on the acquired original outside root. The caller must
    /// also retain the exact metadata ext4/kernel/profile preflight.
    pub fn preflight_outside_physical_capacity(
        original_root: &File,
        complete_liability: u64,
    ) -> io::Result<()> {
        private(original_root, true)?;
        let before = key(original_root)?;
        let observed = geometry(original_root)?;
        if key(original_root)? != before || complete_liability > observed.available_bytes {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "whole original outside metadata/control future liability exceeds actual free space",
            ));
        }
        Ok(())
    }

    /// Open only the fixed original 32-byte signing-secret slot through its
    /// retained owner root. No CREATE, write, pathname fallback or authority.
    pub fn retain_outside_identity(original_root: &File) -> io::Result<File> {
        private(original_root, true)?;
        let component = name("device.secret")?;
        let original = open_file_at(original_root, &component, false, false)?;
        if private(&original, false)?.len() != 32 {
            return Err(refuse("exact original 32-byte storage identity required"));
        }
        Self::verify_outside_identity(original_root, &original)?;
        Ok(original)
    }

    pub fn verify_outside_identity(original_root: &File, original: &File) -> io::Result<()> {
        private(original_root, true)?;
        if private(original, false)?.len() != 32
            || key(original)?.device != key(original_root)?.device
        {
            return Err(refuse(
                "original private storage identity FD or parent changed",
            ));
        }
        same_slot(original_root, &name("device.secret")?, original)
    }

    pub fn close_outside_regular_file(
        original: File,
        expected: UnixFileKey,
        maximum_bytes: u64,
    ) -> io::Result<LinuxStorageOutsideFileClosed> {
        let verified = (|| {
            let metadata = private(&original, false)?;
            if key(&original)? != expected || metadata.len() > maximum_bytes {
                return Err(refuse(
                    "original outside control identity or bound changed at close",
                ));
            }
            Ok(())
        })();
        let mut failure = verified.err();
        if let Err(error) = original.sync_all() {
            failure.get_or_insert(error);
        }
        // Actual unlock also releases a lock shared by retained duplicates.
        if unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_UN) } != 0 {
            failure.get_or_insert_with(io::Error::last_os_error);
        }
        if let Err(error) = close_original(original) {
            failure.get_or_insert(error);
        }
        failure.map_or(
            Ok(LinuxStorageOutsideFileClosed { identity: expected }),
            Err,
        )
    }
}

/// Original sentinel/root/namespace FD possession for one Journal connection.
/// The projected key, path, or bytes cannot construct or renew this loan.
pub struct LinuxStorageCasCoordinationLoan {
    parent: File,
    original: File,
    parent_key: UnixFileKey,
    original_key: UnixFileKey,
    owner: Arc<LinuxNamespaceCapability>,
}

impl LinuxStorageCasCoordinationLoan {
    pub fn verify(&self) -> io::Result<()> {
        self.owner.verify()?;
        private(&self.parent, true)?;
        if key(&self.parent)? != self.parent_key
            || key(&self.original)? != self.original_key
            || self.original_key.device != self.parent_key.device
            || private(&self.original, false)?.len() != 0
        {
            return Err(refuse(
                "original Linux storage CAS coordination loan changed",
            ));
        }
        same_slot(&self.parent, &name(COORDINATION)?, &self.original)?;
        self.owner.verify()
    }

    pub fn parent_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.parent_key)
    }

    pub fn original_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.original_key)
    }

    pub fn owner_generation(&self) -> io::Result<[u8; 16]> {
        self.verify()?;
        Ok(self.owner.owner_generation())
    }

    /// Only openat through the retained original root, with no CREATE or
    /// fallback. A fresh description makes actual guard close release flock.
    pub fn acquire_shared(&self) -> io::Result<LinuxStorageCasCoordinationGuard> {
        self.verify()?;
        let original = open_file_at(&self.parent, &name(COORDINATION)?, true, false)?;
        if key(&original)? != self.original_key {
            return Err(refuse(
                "original outside CAS coordination guard opened a substitute",
            ));
        }
        // SAFETY: nonblocking shared flock on this newly owned original
        // description. No pathname CREATE or descriptor replacement occurs.
        if unsafe { libc::flock(original.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let result = LinuxStorageCasCoordinationGuard {
            parent: self.parent.try_clone()?,
            original,
            parent_key: self.parent_key,
            original_key: self.original_key,
            owner: Arc::clone(&self.owner),
            state: CoordinationLockState::Shared,
            possession: Arc::new(()),
        };
        result.verify()?;
        self.verify()?;
        Ok(result)
    }

    pub fn close(self) -> io::Result<()> {
        let mut failure = self.verify().err();
        for file in [self.original, self.parent] {
            if let Err(error) = close_original(file) {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = self.owner.verify() {
            failure.get_or_insert(error);
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Real original cooperative lock possession, never a native writer capability.
#[derive(Clone, Copy, Eq, PartialEq)]
enum CoordinationLockState {
    Shared,
    Unlocked,
    Exclusive,
}

pub struct LinuxStorageCasCoordinationGuard {
    parent: File,
    original: File,
    parent_key: UnixFileKey,
    original_key: UnixFileKey,
    owner: Arc<LinuxNamespaceCapability>,
    state: CoordinationLockState,
    possession: Arc<()>,
}

impl LinuxStorageCasCoordinationGuard {
    fn verify_identity(&self) -> io::Result<()> {
        self.owner.verify()?;
        private(&self.parent, true)?;
        if key(&self.parent)? != self.parent_key
            || key(&self.original)? != self.original_key
            || self.original_key.device != self.parent_key.device
            || private(&self.original, false)?.len() != 0
        {
            return Err(refuse(
                "original outside cooperative CAS guard identity changed",
            ));
        }
        same_slot(&self.parent, &name(COORDINATION)?, &self.original)?;
        self.owner.verify()
    }

    pub fn verify(&self) -> io::Result<()> {
        self.verify_identity()?;
        if self.state == CoordinationLockState::Unlocked {
            return Err(refuse("original CAS upgrade failed; guard has no lock"));
        }
        Ok(())
    }

    /// Preserve the Journal's existing fail-fast upgrade semantics. A failed
    /// real upgrade grants nothing and its caller must abandon the transaction.
    pub fn try_exclusive(&mut self) -> io::Result<()> {
        self.verify()?;
        if self.state == CoordinationLockState::Exclusive {
            return Ok(());
        }
        // SAFETY: unlock only this retained original description.
        if unsafe { libc::flock(self.original.as_raw_fd(), libc::LOCK_UN) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.state = CoordinationLockState::Unlocked;
        // SAFETY: nonblocking upgrade only this retained original description.
        if unsafe { libc::flock(self.original.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.state = CoordinationLockState::Exclusive;
        self.verify()
    }

    pub fn exclusive_borrow(&self) -> io::Result<LinuxStorageCasExclusiveCoordination<'_>> {
        let borrowed = LinuxStorageCasExclusiveCoordination { guard: self };
        borrowed.verify()?;
        Ok(borrowed)
    }

    pub fn close(self) -> io::Result<()> {
        // A failed upgrade still owns its original FDs and must release them.
        // Identity verification grants closure, never exclusive inspection.
        let mut failure = self.verify_identity().err();
        // SAFETY: explicit release of this guard's retained original description.
        if unsafe { libc::flock(self.original.as_raw_fd(), libc::LOCK_UN) } != 0 {
            failure.get_or_insert_with(io::Error::last_os_error);
        }
        for file in [self.original, self.parent] {
            if let Err(error) = close_original(file) {
                failure.get_or_insert(error);
            }
        }
        if let Err(error) = self.owner.verify() {
            failure.get_or_insert(error);
        }
        failure.map_or(Ok(()), Err)
    }
}

impl LinuxStorageCasExclusiveCoordination<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.guard.verify()?;
        if self.guard.state != CoordinationLockState::Exclusive {
            return Err(refuse("actual original exclusive CAS description required"));
        }
        Ok(())
    }

    pub fn outside_data_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.guard.parent_key)
    }

    pub fn coordination_key(&self) -> io::Result<UnixFileKey> {
        self.verify()?;
        Ok(self.guard.original_key)
    }
}

impl LinuxStorageCasRetirementInspection {
    pub fn verify(&self, exclusive: &LinuxStorageCasExclusiveCoordination<'_>) -> io::Result<()> {
        exclusive.verify()?;
        let graph = self
            .original
            .graph
            .as_ref()
            .ok_or_else(|| refuse("original retirement inspection payload has closed"))?;
        if !Arc::ptr_eq(&self.possession, &exclusive.guard.possession)
            || !Arc::ptr_eq(&graph.owner, &exclusive.guard.owner)
        {
            return Err(refuse(
                "retirement inspection cannot adopt a reopened coordination guard",
            ));
        }
        self.original.verify()?;
        exclusive.verify()
    }

    pub fn read_bytes(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<Vec<u8>> {
        self.verify(exclusive)?;
        let bytes = self.original.read_bytes()?;
        self.verify(exclusive)?;
        Ok(bytes)
    }

    pub fn payload_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageCasFileObservation> {
        self.verify(exclusive)?;
        let observed = self.original.observation()?;
        self.verify(exclusive)?;
        Ok(observed)
    }

    pub fn layout_observation(
        &self,
        exclusive: &LinuxStorageCasExclusiveCoordination<'_>,
    ) -> io::Result<LinuxStorageCasObservation> {
        self.verify(exclusive)?;
        let graph = self
            .original
            .graph
            .as_ref()
            .expect("verified original graph");
        let root = key(&graph.root)?;
        let cas = key(&graph.cas)?;
        let objects = key(&graph.objects)?;
        let temporary = key(&graph.temporary)?;
        let realm = key(&graph.realm)?;
        let limits = self.layout.limits;
        let observed = LinuxStorageCasObservation {
            expected_layout: LinuxStorageCasExpectedLayout {
                format_version: 1,
                backing_image: graph.owner.backing_image_key(),
                image_filesystem_id: graph.filesystem_id,
                mounted_root_inode: root.inode,
                cas_inode: cas.inode,
                objects_inode: objects.inode,
                temporary_inode: temporary.inode,
                realm_inode: realm.inode,
                realm_fingerprint: graph.realm_fingerprint,
                owner_uid: private(&graph.root, true)?.uid(),
            },
            owner_generation: graph.generation,
            namespace: graph.owner.namespace_key(),
            runtime_mount_id: graph.mount_id,
            mounted_root: root,
            cas,
            objects,
            temporary,
            realm,
            limits,
            physical_liability_bytes: limits.physical_liability_bytes()?,
        };
        if observed != self.layout {
            return Err(refuse("original retirement inspection layout changed"));
        }
        self.verify(exclusive)?;
        Ok(observed)
    }

    /// Release the original payload lease/file/parent before the caller closes
    /// its exclusive guard and then the returned original directory loan.
    pub fn close_file(self) -> io::Result<LinuxStorageCasDirectoryGuard> {
        self.original.close_file()
    }
}
