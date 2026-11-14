//! Journal performs the native CREATE itself after durable one-shot activation.
#[cfg(windows)]
use super::StorageRetirementAdmission;
use super::{invalid, owner_schema};
#[cfg(windows)]
use crate::storage_inventory::reader::add;
use crate::{storage_inventory::reader::preflight, Journal, Result};
use rusqlite::{Connection, OptionalExtension};
use serde::Serialize;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, EntryId};

const RECEIPT_PEAK: u64 = 384;

type OwnerSqlReceipt = (String, String, String, String, String, u64);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRetirementOwnerReceipt {
    pub request_id: EntryId,
    pub activation_id: EntryId,
    pub tmp_key: String,
    pub owner_key: String,
    pub component: String,
    pub marker_hash: ContentId,
    pub activated_at_ms: u64,
    pub created_at_ms: u64,
}

fn valid_key(value: &str) -> bool {
    value.len() == 49
        && value.as_bytes()[16] == b':'
        && value.bytes().enumerate().all(|(index, byte)| {
            index == 16 || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
        })
}

fn marker(request: &EntryId, activation: &EntryId) -> Vec<u8> {
    format!("{request}:{activation}").into_bytes()
}

pub(crate) fn audit(connection: &Connection) -> Result<Vec<StorageRetirementOwnerReceipt>> {
    owner_schema::validate(connection)?;
    preflight(
        connection,
        owner_schema::TABLES,
        crate::limits::MAX_ENTRIES,
        crate::limits::MAX_ENTRIES as u64 * 1024,
    )?;
    let admissions = super::audit(connection)?;
    let clock: Option<u64> = connection
        .query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )
        .optional()?;
    let activations = connection
        .prepare(
            "SELECT request_id,activation_id,tmp_key,activated_at_ms
             FROM main.storage_retirement_owner_activations ORDER BY request_id",
        )?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                crate::sql_u64(r, 3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut result = Vec::new();
    for (request_id, activation, tmp_key, time) in activations {
        let request_id: EntryId = request_id.parse()?;
        let activation_id: EntryId = activation.parse()?;
        let admission = admissions
            .iter()
            .find(|row| row.request.request_id == request_id)
            .ok_or_else(invalid)?;
        if !valid_key(&tmp_key)
            || activation_id == request_id
            || activation_id == admission.request.original_owner_id
            || time < admission.admitted_at_ms
            || time >= admission.request.expires_at_ms
            || clock.is_none_or(|clock| time > clock)
        {
            return Err(invalid());
        }
        let receipt: Option<OwnerSqlReceipt> = connection
            .query_row(
                "SELECT activation_id,owner_key,parent_key,component,marker_hash,created_at_ms
                 FROM main.storage_retirement_owner_creations WHERE request_id=?1",
                [request_id.as_str()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        crate::sql_u64(r, 5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((exact_activation, owner_key, parent_key, component, hash, created)) = receipt {
            let marker_hash: ContentId = hash.parse()?;
            if exact_activation != activation
                || parent_key != tmp_key
                || !valid_key(&owner_key)
                || owner_key == parent_key
                || component != format!("retirement-{activation_id}.owner")
                || marker_hash != ContentId::hash(&marker(&request_id, &activation_id))
                || created < time
                || clock.is_none_or(|clock| created > clock)
            {
                return Err(invalid());
            }
            result.push(StorageRetirementOwnerReceipt {
                request_id,
                activation_id,
                tmp_key,
                owner_key,
                component,
                marker_hash,
                activated_at_ms: time,
                created_at_ms: created,
            });
        } else if !admission.content_fenced {
            return Err(invalid());
        }
    }
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.storage_retirement_owner_creations c
         LEFT JOIN main.storage_retirement_owner_activations a USING(request_id)
         WHERE a.request_id IS NULL)",
        [],
        |r| r.get(0),
    )?;
    if orphan {
        return Err(invalid());
    }
    super::terminal::validate_releases(connection, &admissions, &result)?;
    Ok(result)
}

pub(crate) fn outstanding(connection: &Connection) -> Result<TreeStorageCharge> {
    audit(connection)?;
    let count: u64 = connection.query_row(
        "SELECT count(*) FROM main.storage_retirement_owner_activations a
         WHERE NOT EXISTS(SELECT 1 FROM main.storage_retirement_owner_creations c
         WHERE c.request_id=a.request_id)",
        [],
        |r| crate::sql_u64(r, 0),
    )?;
    Ok(TreeStorageCharge {
        rows: count,
        logical_bytes: count.checked_mul(RECEIPT_PEAK).ok_or_else(invalid)?,
    })
}

impl Journal {
    /// Metadata replay never reopens or adopts an owner pathname.
    pub fn storage_retirement_owner_receipts(&self) -> Result<Vec<StorageRetirementOwnerReceipt>> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Deferred,
        )?;
        let receipts = audit(&tx)?;
        tx.commit()?;
        Ok(receipts)
    }
}

#[cfg(windows)]
pub struct StorageRetirementOwnerCreation {
    _cas: crate::CasAccessGuard,
    _directories: Vec<sync_extend_platform_fs::LockedDirectory>,
    owner: sync_extend_platform_fs::OwnedFileCreation,
    receipt: StorageRetirementOwnerReceipt,
}

#[cfg(windows)]
impl StorageRetirementOwnerCreation {
    pub fn receipt(&self) -> &StorageRetirementOwnerReceipt {
        &self.receipt
    }
    pub fn verify_original(&self) -> Result<()> {
        use std::io::{Read, Seek, SeekFrom};
        let original = self.owner.original_creation()?;
        original.verify()?;
        self.owner.verify_single_link()?;
        let mut bytes = Vec::new();
        let mut reader = self.owner.reader();
        reader.seek(SeekFrom::Start(0))?;
        reader.take(66).read_to_end(&mut bytes)?;
        if native_key(original.key()?) != self.receipt.owner_key
            || native_key(original.parent_key()?) != self.receipt.tmp_key
            || original.created_component() != self.receipt.component
            || bytes != marker(&self.receipt.request_id, &self.receipt.activation_id)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(windows)]
fn native_key(key: sync_extend_platform_fs::FileKey) -> String {
    format!("{:016x}:{:032x}", key.volume, key.id)
}

#[cfg(windows)]
fn physical_capacity(
    config: &sync_extend_core_model::storage_node::StorageNodeConfig,
    pending: u64,
) -> Result<()> {
    let root = config.data_dir.join("cas");
    let mut count = 0usize;
    let mut bytes = 0u64;
    for directory in [&root, &root.join("objects"), &root.join("tmp")] {
        let metadata = std::fs::symlink_metadata(directory)?;
        use std::os::windows::fs::MetadataExt;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    fn files(
        directory: &std::path::Path,
        count: &mut usize,
        bytes: &mut u64,
        config: &sync_extend_core_model::storage_node::StorageNodeConfig,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            *count = count.checked_add(1).ok_or_else(invalid)?;
            if *count > config.max_metadata_entries {
                return Err(invalid());
            }
            let metadata = std::fs::symlink_metadata(entry?.path())?;
            use std::os::windows::fs::MetadataExt;
            if !metadata.is_file() || metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid());
            }
            *bytes = add(*bytes, metadata.len())?;
        }
        Ok(())
    }
    for bucket in
        std::fs::read_dir(root.join("objects"))?.take(config.max_metadata_entries.saturating_add(1))
    {
        let bucket = bucket?;
        count = count.checked_add(1).ok_or_else(invalid)?;
        if count > config.max_metadata_entries {
            return Err(invalid());
        }
        let held = sync_extend_platform_fs::LockedDirectory::open(&bucket.path())?;
        held.require_local_ntfs(&bucket.path())?;
        held.require_case_insensitive()?;
        files(&bucket.path(), &mut count, &mut bytes, config)?;
    }
    files(&root.join("tmp"), &mut count, &mut bytes, config)?;
    if add(count as u64, pending)? > config.max_metadata_entries as u64
        || add(bytes, pending.checked_mul(65).ok_or_else(invalid)?)? > config.max_stored_bytes
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(windows)]
fn checkpoint(phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{phase}");
        while !std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
            .is_some_and(|path| std::path::Path::new(&path).is_file())
        {
            std::thread::park_timeout(std::time::Duration::from_millis(25));
        }
    }
    let _ = phase;
}

#[cfg(windows)]
impl Journal {
    /// Creates only the original owner marker. Payload quarantine and disposition
    /// require separately implemented durable phases and are unavailable here.
    pub fn create_storage_retirement_owner(
        &self,
        id: &EntryId,
        config: &sync_extend_core_model::storage_node::StorageNodeConfig,
        device: &sync_extend_core_model::DeviceId,
        now: impl Fn() -> Result<u64>,
    ) -> Result<StorageRetirementOwnerCreation> {
        use rusqlite::{params, Transaction, TransactionBehavior};
        use std::io::Write;
        use sync_extend_platform_fs::LockedDirectory;
        if !self.connection.is_autocommit() {
            return Err(invalid());
        }
        let mut cas = self.acquire_cas_coordination()?;
        cas.try_exclusive()?;
        let mut tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let admission: StorageRetirementAdmission = super::audit(&tx)?
            .into_iter()
            .find(|row| row.request.request_id == *id)
            .ok_or_else(invalid)?;
        super::scope(&tx, &admission.request, config, device)?;
        audit(&tx)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.storage_retirement_owner_activations WHERE request_id=?1)",
            [id.as_str()], |r| r.get(0),
        )?;
        if exists || !admission.content_fenced {
            return Err(invalid());
        }
        let tmp = config.data_dir.join("cas/tmp");
        let mut directories = Vec::new();
        for path in tmp.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let held = LockedDirectory::open(path)?;
            held.require_local_ntfs(path)?;
            held.require_case_insensitive()?;
            let expected = if path == config.data_dir {
                Some(&admission.request.data_identity)
            } else if path == config.data_dir.join("cas") {
                Some(&admission.request.cas_identity)
            } else {
                None
            };
            let identity = ContentId::hash(held.key()?.to_string().as_bytes());
            if expected.is_some_and(|expected| identity != *expected) {
                return Err(invalid());
            }
            directories.push(held);
        }
        let parent = directories.last().ok_or_else(invalid)?;
        let tmp_key = native_key(parent.key()?);
        let activation_id = EntryId::random()?;
        if activation_id == *id || activation_id == admission.request.original_owner_id {
            return Err(invalid());
        }
        let component = format!("retirement-{activation_id}.owner");
        let pending = outstanding(&tx)?.rows.checked_add(1).ok_or_else(invalid)?;
        physical_capacity(config, pending)?;
        let limits = self.writer_capacity_limits(config.max_metadata_entries)?;
        let before = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, limits)?;
        if !before.report.coverage_gaps().is_empty() || !before.report.within_accounted_limits() {
            return Err(invalid());
        }
        let time = now()?;
        let clock: u64 = tx.query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )?;
        if time < clock
            || time >= admission.request.expires_at_ms
            || add(before.report.accounted_total().rows, 12)? > limits.max_rows
            || add(
                before.report.accounted_total().logical_bytes,
                121 + RECEIPT_PEAK + 1440,
            )? > limits.max_logical_bytes
        {
            return Err(invalid());
        }
        tx.execute(
            "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
            [crate::sql_integer(time)?],
        )?;
        self.storage_retirement_owner_activation
            .issue(activation_id.to_string(), time, || {
                tx.execute(
                    "INSERT INTO main.storage_retirement_owner_activations VALUES(?1,?2,?3,?4)",
                    params![
                        id.as_str(),
                        activation_id.as_str(),
                        tmp_key,
                        crate::sql_integer(time)?
                    ],
                )?;
                Ok(())
            })?;
        super::unchanged(
            &before,
            &self
                .read_view()
                .audit_storage_receive_capacity(&config.space_id, limits)?,
        )?;
        tx.commit()?;
        checkpoint("storage_retirement_owner_activated");
        let mut owner = parent.create_new_file(&component)?;
        owner.writer().write_all(&marker(id, &activation_id))?;
        owner.writer().sync_all()?;
        owner.verify_single_link()?;
        checkpoint("storage_retirement_owner_created");
        tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        super::scope(&tx, &admission.request, config, device)?;
        let before = self
            .read_view()
            .audit_storage_receive_capacity(&config.space_id, limits)?;
        let created = now()?;
        let clock: u64 = tx.query_row(
            "SELECT observed_at_ms FROM main.storage_retirement_clock WHERE singleton=1",
            [],
            |r| crate::sql_u64(r, 0),
        )?;
        if created < clock {
            return Err(invalid());
        }
        let proof = owner.original_creation()?;
        let owner_key = native_key(proof.key()?);
        if native_key(proof.parent_key()?) != tmp_key || proof.created_component() != component {
            return Err(invalid());
        }
        let marker_hash = ContentId::hash(&marker(id, &activation_id));
        tx.execute(
            "UPDATE main.storage_retirement_clock SET observed_at_ms=?1 WHERE singleton=1",
            [crate::sql_integer(created)?],
        )?;
        self.storage_retirement_owner_receipt.issue(marker_hash.to_string(), created, || {
            tx.execute("INSERT INTO main.storage_retirement_owner_creations VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![id.as_str(),activation_id.as_str(),owner_key,tmp_key,component,
                    marker_hash.as_str(),crate::sql_integer(created)?])?;
            Ok(())
        })?;
        let receipt = audit(&tx)?
            .into_iter()
            .find(|row| row.request_id == *id)
            .ok_or_else(invalid)?;
        super::unchanged(
            &before,
            &self
                .read_view()
                .audit_storage_receive_capacity(&config.space_id, limits)?,
        )?;
        proof.verify()?;
        tx.commit()?;
        checkpoint("storage_retirement_owner_receipted");
        let result = StorageRetirementOwnerCreation {
            _cas: cas,
            _directories: directories,
            owner,
            receipt,
        };
        result.verify_original()?;
        Ok(result)
    }
}
