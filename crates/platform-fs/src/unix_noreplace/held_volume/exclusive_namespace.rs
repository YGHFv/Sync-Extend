//! Acquire a private ext4 mount from a mandatorily held backing image.
//! Authority comes from acquisition, never from mountinfo or a boolean.
//! Privileged administrators remain trusted. Other UID peers cannot enter the
//! nondumpable owner process or open the private image during an admitted attempt.
use super::{mount_id, private, HeldPrivateDirectory, HeldPrivateVolume};
use crate::{linux_write_lease::OriginalWriteLease, OutsidePreparationPair, UnixFileKey};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

const LOOP_CTL_GET_FREE: libc::Ioctl = 0x4c82;
const LOOP_CONFIGURE: libc::Ioctl = 0x4c0a;
const LOOP_GET_STATUS64: libc::Ioctl = 0x4c05;
const LOOP_CLR_FD: libc::Ioctl = 0x4c01;
const LO_FLAGS_AUTOCLEAR: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    size_limit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    encrypt_key: [u8; 32],
    init: [u64; 2],
}
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo,
    reserved: [u64; 8],
}

fn refusal(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn terminated(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| refusal("NUL in owner path"))
}

/// Owns acquired mount, image lease, namespace and fresh owner generation.
/// It has no Clone/Deserialize/public fields or observation-based constructor.
pub struct LinuxNamespaceCapability {
    volume: HeldPrivateVolume,
    image: File,
    image_lease: OriginalWriteLease,
    image_path: PathBuf,
    image_key: UnixFileKey,
    image_parent: File,
    image_parent_key: UnixFileKey,
    initial_namespace: File,
    namespace: File,
    namespace_key: UnixFileKey,
    loop_device: File,
    loop_number: u32,
    loop_rdev: u64,
    generation: [u8; 16],
    owner_pid: u32,
    pub(crate) publication: std::sync::Mutex<crate::publication_epoch::PublicationCursor>,
    released: AtomicBool,
}

impl LinuxNamespaceCapability {
    /// Runs before this owner starts threads. The explicit image is already
    /// formatted ext4 and unmounted; this function never launches a formatter.
    /// A foreign outstanding open fails F_WRLCK before any loop/mount effect.
    pub fn acquire_private_ext4_image(image_path: &Path, mount_path: &Path) -> io::Result<Self> {
        Self::acquire_private_ext4_image_impl(image_path, mount_path, None)
    }

    /// Storage-only admission validates the final unique original image FD,
    /// while its early mandatory lease is held and before unshare/loop/mount.
    /// That same descriptor is passed to LOOP_CONFIGURE; a preflight pathname
    /// or observation cannot substitute a different image after admission.
    pub fn acquire_storage_only_private_ext4_image(
        image_path: &Path,
        mount_path: &Path,
        expected_image: UnixFileKey,
    ) -> io::Result<Self> {
        Self::acquire_private_ext4_image_impl(image_path, mount_path, Some(expected_image))
    }

    fn acquire_private_ext4_image_impl(
        image_path: &Path,
        mount_path: &Path,
        storage_original: Option<UnixFileKey>,
    ) -> io::Result<Self> {
        if !image_path.is_absolute() || !mount_path.is_absolute() {
            return Err(refusal("absolute image and mount roots required"));
        }
        // SAFETY: uid query has no pointers.
        if unsafe { libc::geteuid() } != 0 || std::fs::read_dir("/proc/self/task")?.count() != 1 {
            return Err(refusal(
                "dedicated single-thread privileged Linux owner required",
            ));
        }
        let image_parent_path = image_path
            .parent()
            .ok_or_else(|| refusal("image parent absent"))?;
        let image_parent = super::super::UnixDirectory::open(image_parent_path)?.file;
        private(&image_parent, true)?;
        let image_parent_key = super::super::key(&image_parent)?;
        let mount_parent = super::super::UnixDirectory::open(
            mount_path
                .parent()
                .ok_or_else(|| refusal("mount parent absent"))?,
        )?;
        private(&mount_parent.file, true)?;
        let mount_slot = super::super::UnixDirectory::open(mount_path)?;
        private(&mount_slot.file, true)?;
        if std::fs::read_dir(mount_path)?.next().is_some() {
            return Err(refusal("empty original owner mount slot required"));
        }
        let image = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(image_path)?;
        private(&image, false)?;
        let image_key = super::super::key(&image)?;
        let image_length = image.metadata()?.len();
        if !(16 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&image_length) {
            return Err(refusal("bounded preformatted private ext4 image required"));
        }
        let storage_image_lease = if let Some(expected) = storage_original {
            if image_key != expected {
                return Err(refusal(
                    "storage original image was substituted before mount",
                ));
            }
            let lease = OriginalWriteLease::acquire(&image)?;
            super::super::linux_metadata::LinuxMetadataBudget::preflight_storage_only_image(
                &image,
            )?;
            lease.verify()?;
            Some(lease)
        } else {
            None
        };
        let initial_namespace = File::open("/proc/self/ns/mnt")?;
        // SAFETY: nondumpable setting blocks unprivileged proc/root/fd access.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: explicit dedicated owner acquires its new mount namespace.
        if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let slash = CString::new("/").expect("fixed root");
        // SAFETY: fixed existing root, private recursive flags, no data pointer.
        if unsafe {
            libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let namespace = File::open("/proc/self/ns/mnt")?;
        let namespace_key = super::super::key(&namespace)?;
        if namespace_key == super::super::key(&initial_namespace)? {
            return Err(refusal("new owner namespace was not acquired"));
        }
        let image_lease = match storage_image_lease {
            Some(lease) => lease,
            None => OriginalWriteLease::acquire(&image)?,
        };
        let control = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/loop-control")?;
        // SAFETY: loop control ioctl has no pointer argument.
        let loop_number = unsafe { libc::ioctl(control.as_raw_fd(), LOOP_CTL_GET_FREE) };
        let loop_number = u32::try_from(loop_number).map_err(|_| io::Error::last_os_error())?;
        let loop_path = PathBuf::from(format!("/dev/loop{loop_number}"));
        let loop_device = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&loop_path)?;
        if !loop_device.metadata()?.file_type().is_block_device() {
            return Err(refusal("original Linux loop block descriptor required"));
        }
        let mut generation = [0u8; 16];
        getrandom::fill(&mut generation)
            .map_err(|_| io::Error::other("owner generation randomness unavailable"))?;
        let mut info = LoopInfo {
            device: 0,
            inode: 0,
            rdevice: 0,
            offset: 0,
            size_limit: image_length,
            number: loop_number,
            encrypt_type: 0,
            encrypt_key_size: 0,
            flags: LO_FLAGS_AUTOCLEAR,
            file_name: [0; 64],
            crypt_name: [0; 64],
            encrypt_key: [0; 32],
            init: [0; 2],
        };
        info.file_name[..17].copy_from_slice(b"sync-extend.r02.1");
        info.file_name[17..33].copy_from_slice(&generation);
        let config = LoopConfig {
            fd: u32::try_from(image.as_raw_fd()).map_err(|_| refusal("image fd invalid"))?,
            block_size: 4096,
            info,
            reserved: [0; 8],
        };
        image_lease.verify()?;
        // SAFETY: atomic unused-loop claim through the exact original image fd.
        if unsafe { libc::ioctl(loop_device.as_raw_fd(), LOOP_CONFIGURE, &config) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let source = terminated(&loop_path)?;
        let target = terminated(mount_path)?;
        let filesystem = CString::new("ext4").expect("fixed filesystem");
        let options = CString::new("errors=remount-ro").expect("fixed options");
        // SAFETY: newly owned loop, original empty slot, fixed filesystem/mount policy.
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                filesystem.as_ptr(),
                libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
                options.as_ptr().cast(),
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            // SAFETY: clear only this just-configured still-unmounted loop.
            unsafe { libc::ioctl(loop_device.as_raw_fd(), LOOP_CLR_FD, 0) };
            return Err(error);
        }
        std::fs::set_permissions(mount_path, std::fs::Permissions::from_mode(0o700))?;
        let volume = HeldPrivateVolume::open(mount_path)?;
        let capability = Self {
            volume,
            image,
            image_lease,
            image_path: image_path.to_owned(),
            image_key,
            image_parent,
            image_parent_key,
            initial_namespace,
            namespace,
            namespace_key,
            loop_rdev: loop_device.metadata()?.rdev(),
            loop_device,
            loop_number,
            generation,
            owner_pid: std::process::id(),
            publication: std::sync::Mutex::new(
                crate::publication_epoch::PublicationCursor::initial(generation),
            ),
            released: AtomicBool::new(false),
        };
        capability.verify()?;
        Ok(capability)
    }

    pub fn verify(&self) -> io::Result<()> {
        if self.released.load(Ordering::Acquire) || std::process::id() != self.owner_pid {
            return Err(refusal("original namespace owner is terminal or foreign"));
        }
        // SAFETY: pointer-free process security query.
        if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(refusal("original namespace owner became dumpable"));
        }
        self.image_lease.verify()?;
        private(&self.image, false)?;
        private(&self.image_parent, true)?;
        let image_name = self
            .image_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(|| refusal("image component encoding"))?;
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        let component = super::super::name(image_name)?;
        // SAFETY: retained parent and bounded filename; no symlink is followed.
        if unsafe {
            libc::fstatat(
                self.image_parent.as_raw_fd(),
                component.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatat initialized the full output.
        let status = unsafe { status.assume_init() };
        let current_namespace = File::open("/proc/self/ns/mnt")?;
        if super::super::key(&self.image)? != self.image_key
            || status.st_dev != self.image_key.device
            || status.st_ino != self.image_key.inode
            || super::super::key(&self.image_parent)? != self.image_parent_key
            || super::super::key(&self.namespace)? != self.namespace_key
            || super::super::key(&current_namespace)? != self.namespace_key
            || super::super::key(&self.initial_namespace)? == self.namespace_key
        {
            return Err(refusal(
                "original image slot, owner parent or namespace changed",
            ));
        }
        let mut info = std::mem::MaybeUninit::<LoopInfo>::uninit();
        // SAFETY: retained block descriptor and sized loop_info64 output.
        if unsafe {
            libc::ioctl(
                self.loop_device.as_raw_fd(),
                LOOP_GET_STATUS64,
                info.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful ioctl initialized the full output.
        let info = unsafe { info.assume_init() };
        if info.device != self.image_key.device
            || info.inode != self.image_key.inode
            || info.number != self.loop_number
            || info.offset != 0
            || info.flags & LO_FLAGS_AUTOCLEAR == 0
            || info.size_limit != self.image.metadata()?.len()
            || info.file_name[17..33] != self.generation
            || self.loop_device.metadata()?.rdev() != self.loop_rdev
            || self.volume.observation().root_key.device != self.loop_rdev
        {
            return Err(refusal("private loop backing or owner generation changed"));
        }
        self.volume.verify()?;
        self.volume
            .observe_original_private_mount_topology()?
            .verify()?;
        self.image_lease.verify()
    }

    pub fn volume(&self) -> &HeldPrivateVolume {
        &self.volume
    }
    pub fn mount_descriptor(&self) -> &File {
        &self.volume.root.file
    }
    pub fn owner_generation(&self) -> [u8; 16] {
        self.generation
    }
    pub fn backing_image_key(&self) -> UnixFileKey {
        self.image_key
    }
    pub fn namespace_key(&self) -> UnixFileKey {
        self.namespace_key
    }
    pub fn mount_path(&self) -> &Path {
        &self.volume.path
    }

    /// Both live prepared helpers must belong to this acquired owner before ARM.
    /// SQL/CAS/full-plan preparation grants no protected native effect.
    pub fn verify_prepared_helpers(&self, session: &crate::OutsideHelperSession) -> io::Result<()> {
        self.verify_publication_state(&session.epoch)?;
        if session.epoch.attempt_issued.load(Ordering::Acquire) {
            return Err(refusal(
                "original namespace Final attempt was already consumed",
            ));
        }
        session.verify_prepared_owner(self)
    }

    /// Actual both-READY/ARM helpers must retain this same acquired root.
    /// The native capability is single-attempt and expires after 2 seconds.
    pub fn admit_native_attempt<'a>(
        &'a self,
        session: &'a crate::OutsideHelperSession,
    ) -> io::Result<LinuxNativeAttempt<'a>> {
        self.verify_publication_state(&session.epoch)?;
        let pair = session.pair();
        pair.verify_original_mount(&self.volume.root.file)?;
        if session.epoch.attempt_issued.swap(true, Ordering::AcqRel) {
            return Err(refusal("original namespace attempt was already consumed"));
        }
        let scope = pair.original_attempt_scope()?;
        *session
            .epoch
            .attempt_scope
            .lock()
            .map_err(|_| refusal("original attempt scope poisoned"))? = Some(scope.clone());
        let attempt = LinuxNativeAttempt {
            owner: self,
            epoch: std::sync::Arc::clone(&session.epoch),
            pair,
            deadline: pair.original_guardian_arm_deadline()?,
            scope,
        };
        attempt.verify()?;
        Ok(attempt)
    }

    /// Release only an unarmed acquired mount. This deletes no persistent
    /// image, journal, worktree object, directory or unfamiliar residue.
    pub fn release_unarmed_mount(self) -> io::Result<()> {
        self.verify()?;
        let cursor = self
            .publication
            .lock()
            .map_err(|_| refusal("publication cursor poisoned"))?;
        if cursor
            .current
            .helper_preparation_started
            .load(Ordering::Acquire)
            || cursor.current.attempt_issued.load(Ordering::Acquire)
        {
            return Err(refusal(
                "started helpers require their retained original terminal release",
            ));
        }
        drop(cursor);
        self.release_owned_mount()
    }

    /// The token is issued only after the two exact originally armed helpers
    /// successfully exit and the guardian's committed thaw is authenticated.
    pub fn release_mount_after_helpers(
        self,
        terminal: crate::OriginalPairTerminalRelease,
    ) -> io::Result<()> {
        self.verify()?;
        terminal.verify_owner(&self)?;
        self.verify_original_terminal(&terminal)?;
        self.release_owned_mount()
    }

    pub(crate) fn verify_original_terminal(
        &self,
        terminal: &crate::OriginalPairTerminalRelease,
    ) -> io::Result<()> {
        self.verify_publication_state(&terminal.epoch)?;
        let scope = terminal
            .epoch
            .attempt_scope
            .lock()
            .map_err(|_| refusal("original attempt scope poisoned"))?;
        if scope.is_some() != terminal.epoch.attempt_issued.load(Ordering::Acquire) {
            return Err(refusal("original attempt issuance state differs"));
        }
        terminal.verify_attempt_state(scope.as_ref())
    }

    fn release_owned_mount(self) -> io::Result<()> {
        let target = terminated(&self.volume.path)?;
        let Self {
            volume,
            loop_device,
            image_lease: _image_lease,
            ..
        } = self;
        // These exact retained mount/root descriptors must close before normal unmount.
        drop(volume);
        // SAFETY: exact acquired mount; normal unmount refuses active external users.
        if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: clear only this exact now-unmounted owned loop configuration.
        if unsafe { libc::ioctl(loop_device.as_raw_fd(), LOOP_CLR_FD, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub struct LinuxNativeAttempt<'a> {
    owner: &'a LinuxNamespaceCapability,
    epoch: std::sync::Arc<crate::publication_epoch::PublicationEpochState>,
    pair: &'a OutsidePreparationPair,
    deadline: Instant,
    scope: (String, u64),
}
impl LinuxNativeAttempt<'_> {
    pub fn verify(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(refusal("native namespace attempt deadline expired"));
        }
        self.owner.verify_publication_state(&self.epoch)?;
        if self.pair.original_attempt_scope()? != self.scope
            || self
                .epoch
                .attempt_scope
                .lock()
                .map_err(|_| refusal("original attempt scope poisoned"))?
                .as_ref()
                != Some(&self.scope)
        {
            return Err(refusal("original native transaction or ARM scope changed"));
        }
        self.pair
            .verify_original_mount(self.owner.mount_descriptor())?;
        if mount_id(self.owner.mount_descriptor())?
            != self.owner.volume.observation().runtime_mount_id
        {
            return Err(refusal("original native attempt mount changed"));
        }
        if Instant::now() >= self.deadline {
            return Err(refusal(
                "native namespace attempt deadline expired during original verification",
            ));
        }
        Ok(())
    }
    pub fn owner(&self) -> &LinuxNamespaceCapability {
        self.owner
    }
    pub fn transaction_id(&self) -> &str {
        &self.scope.0
    }
    pub fn held_directory(&self, relative: &Path) -> io::Result<HeldPrivateDirectory<'_>> {
        self.verify()?;
        let held = self.owner.volume.directory(relative)?;
        self.verify()?;
        Ok(held)
    }
}
