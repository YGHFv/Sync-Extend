//! Held mount topology observation, not exclusion of writers in other namespaces.
use super::{mount_id, HeldPrivateVolume, PrivateVolumeObservation};
use crate::UnixFileKey;
use std::{
    fs::File,
    io::{self, Read},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};

const MAX_MOUNTINFO_BYTES: usize = 2 * 1024 * 1024;

/// No Clone, deserialize or public constructor. All checks remain observational.
pub struct OriginalPrivateMountTopologyObservation<'v> {
    volume: &'v HeldPrivateVolume,
    namespace: File,
    namespace_key: UnixFileKey,
    mount_record: String,
    original_volume: PrivateVolumeObservation,
}

fn refuse(message: &'static str) -> io::Error {
    super::super::unsupported(message)
}

fn read_bounded(path: &str, max: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(refuse("original kernel topology byte bound"));
    }
    String::from_utf8(bytes).map_err(|_| refuse("original kernel topology encoding"))
}

fn decode_path(value: &str) -> io::Result<String> {
    let mut bytes = Vec::new();
    let input = value.as_bytes();
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\\' {
            let escape = input
                .get(index + 1..index + 4)
                .ok_or_else(|| refuse("mountinfo truncated path escape"))?;
            let decoded = match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(refuse("mountinfo unknown path escape")),
            };
            bytes.push(decoded);
            index += 4;
        } else {
            bytes.push(input[index]);
            index += 1;
        }
    }
    String::from_utf8(bytes).map_err(|_| refuse("mountinfo path encoding"))
}

fn observe(volume: &HeldPrivateVolume) -> io::Result<String> {
    volume.verify()?;
    let text = read_bounded("/proc/self/mountinfo", MAX_MOUNTINFO_BYTES)?;
    if text.lines().count() > 8192 {
        return Err(refuse("original mountinfo record count bound"));
    }
    let id = volume.observation().runtime_mount_id.to_string();
    let mut matched = None;
    let mut device = None;
    for line in text.lines() {
        let (head, tail) = line
            .split_once(" - ")
            .ok_or_else(|| refuse("original mountinfo record delimiter"))?;
        let fields: Vec<_> = head.split_whitespace().collect();
        let filesystem: Vec<_> = tail.split_whitespace().collect();
        if fields.len() < 6 || filesystem.len() != 3 {
            return Err(refuse("original mountinfo record schema"));
        }
        if fields[0] == id {
            if matched.is_some()
                || fields.len() != 6
                || filesystem[0] != "ext4"
                || fields[3] != "/"
                || !fields[5].split(',').any(|option| option == "rw")
                || !filesystem[2].split(',').any(|option| option == "rw")
                || decode_path(fields[4])?
                    != volume
                        .path
                        .to_str()
                        .ok_or_else(|| refuse("original mount point encoding"))?
            {
                return Err(refuse(
                    "original ext4 root must be exact private unpropagated writable mount",
                ));
            }
            let (major, minor) = fields[2]
                .split_once(':')
                .ok_or_else(|| refuse("original mount device schema"))?;
            let major: u64 = major
                .parse()
                .map_err(|_| refuse("original mount device major"))?;
            let minor: u64 = minor
                .parse()
                .map_err(|_| refuse("original mount device minor"))?;
            let original = volume.root.file.metadata()?.dev();
            if major != u64::from(libc::major(original))
                || minor != u64::from(libc::minor(original))
            {
                return Err(refuse("original retained mount device differs"));
            }
            device = Some(fields[2].to_owned());
            matched = Some(line.to_owned());
        }
    }
    let device = device.ok_or_else(|| refuse("original mountinfo record absent"))?;
    if text
        .lines()
        .filter(|line| line.split_whitespace().nth(2) == Some(device.as_str()))
        .count()
        != 1
    {
        return Err(refuse("same-device mount alias in original namespace"));
    }
    matched.ok_or_else(|| refuse("original unique mount record absent"))
}

impl HeldPrivateVolume {
    /// Hold the current namespace file object and inspect this mount record.
    /// Absence of another namespace's holders cannot be certified by mountinfo.
    pub fn observe_original_private_mount_topology(
        &self,
    ) -> io::Result<OriginalPrivateMountTopologyObservation<'_>> {
        self.verify()?;
        let namespace = File::open("/proc/self/ns/mnt")?;
        let initial = File::open("/proc/1/ns/mnt")?;
        let namespace_key = super::super::key(&namespace)?;
        if namespace_key == super::super::key(&initial)? {
            return Err(refuse(
                "separate original mount namespace required before effects",
            ));
        }
        let mount_record = observe(self)?;
        let observation = OriginalPrivateMountTopologyObservation {
            volume: self,
            namespace,
            namespace_key,
            mount_record,
            original_volume: self.observation(),
        };
        observation.verify()?;
        Ok(observation)
    }
}

impl OriginalPrivateMountTopologyObservation<'_> {
    pub fn verify(&self) -> io::Result<()> {
        self.volume.verify()?;
        let current = File::open("/proc/self/ns/mnt")?;
        if super::super::key(&self.namespace)? != self.namespace_key
            || super::super::key(&current)? != self.namespace_key
            || self.volume.observation() != self.original_volume
            || mount_id(&self.volume.root.file)? != self.original_volume.runtime_mount_id
            || observe(self.volume)? != self.mount_record
        {
            return Err(refuse(
                "original retained namespace or mount topology changed",
            ));
        }
        // SAFETY: pointer-free F_GETFD only observes the retained namespace fd.
        if unsafe { libc::fcntl(self.namespace.as_raw_fd(), libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn original_namespace_key(&self) -> UnixFileKey {
        self.namespace_key
    }
    pub fn exact_mount_record(&self) -> &str {
        &self.mount_record
    }
    pub fn namespace_exclusion_certified(&self) -> bool {
        false
    }
}
