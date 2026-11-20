//! Public Windows recovered-local entry point.
//!
//! The command is descriptor driven.  A descriptor names every archive,
//! target, history and budget input explicitly; the input descriptor is never
//! rewritten.  Inspection stays immutable, while mutation opens one fresh
//! verified session, performs one bounded operation, closes the history chain,
//! and emits a new descriptor for the next invocation.

use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use sync_extend_core_model::{
    limits::LocalLimits, management::ManagementConfig, webdav::WebDavListener,
};
use sync_extend_core_model::{ContentId, DeviceId, PortablePath, SpaceId};
use sync_extend_journal::{
    JournalCapacityLimits, NodeInspectionBounds, TreeRestoreInventoryLimits,
};
use sync_extend_reconcile::{
    ArchiveBounds, ExplicitManagementCredentialMapping, ExplicitWebDavCredentialMapping,
    FramedNodeArchive, LedgerBounds, NodeRestoreLedger, RecoveredArchiveInspection,
    RecoveredHistoryOperation, VerifiedNodeStateArchive,
};

const DESCRIPTOR_LIMIT: usize = 256 * 1024;
const SOURCE_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Subcommand)]
pub enum Action {
    /// Verify and inspect only immutable archive state.
    Inspect,
    /// Preview preserving archived read lease states and their CAS pins at new roots.
    PreviewReadLeaseMigration,
    /// Restore the original state to new roots after strict history preflight.
    Restore {
        /// Existing directory outside both target roots for the restore ledger.
        #[arg(long)]
        ledger_directory: PathBuf,
    },
    /// Restore to new roots while holding the exact archived read lease owners.
    RestoreReadLeaseHold {
        #[arg(long)]
        expected_hold_digest: ContentId,
        /// Existing directory outside both target roots for the restore ledger.
        #[arg(long)]
        ledger_directory: PathBuf,
    },
    /// Verify an original restore ledger as historical evidence.
    InspectRestore {
        /// Ledger path printed by restore, or use the descriptor's restore ledger.
        #[arg(long)]
        ledger: Option<PathBuf>,
    },
    /// Capture explicitly selected config files from the verified original node.
    Capture {
        #[arg(long)]
        source_data: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        config: Vec<String>,
    },
    /// Establish the first native history chain from original closed frames.
    Start {
        #[arg(long)]
        path: String,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        timestamp: u64,
    },
    /// Create one recovered file from an explicit bounded source file.
    Create {
        #[arg(long)]
        path: String,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        timestamp: u64,
    },
    /// Replace one recovered file from an explicit bounded source file.
    Replace {
        #[arg(long)]
        path: String,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        timestamp: u64,
    },
    /// Retain every supported original history pin plus explicitly held CAS IDs.
    Retain {
        #[arg(long)]
        content: Vec<String>,
    },
    /// Release exactly one immutable mapping after current pins/pending checks.
    Release {
        #[arg(long)]
        mapping: PathBuf,
        #[arg(long)]
        timestamp: u64,
    },
    /// Admit one unpinned CAS object to the production Journal GC mark phase.
    GcMark {
        #[arg(long)]
        content: String,
        #[arg(long, default_value_t = 1)]
        grace_secs: u64,
    },
    /// Map an explicitly captured config to new absolute roots; no install.
    MapConfig {
        #[arg(long)]
        name: String,
        #[arg(long)]
        new_data: PathBuf,
        #[arg(long)]
        new_worktree: PathBuf,
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        max_combined_bytes: usize,
        #[arg(long)]
        install_to: Option<PathBuf>,
        #[arg(long)]
        expected_mapped_digest: Option<ContentId>,
    },
    /// Re-protect a same-user WebDAV credential for a new listener ID; no
    /// plaintext or credential bytes are printed and no target is installed.
    MapWebdavCredential {
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        original_listener: PathBuf,
        #[arg(long)]
        mapped_listener: PathBuf,
        #[arg(long, default_value_t = 4 * 65536)]
        max_aggregate_bytes: usize,
        #[arg(long)]
        install_to: Option<PathBuf>,
        #[arg(long)]
        expected_original_ciphertext: Option<ContentId>,
        #[arg(long)]
        expected_original_listener: Option<ContentId>,
        #[arg(long)]
        expected_mapped_listener: Option<ContentId>,
    },
    /// Re-protect a same-user management credential for a new token path; no
    /// plaintext or credential bytes are printed and no target is installed.
    MapManagementCredential {
        #[arg(long)]
        original: PathBuf,
        #[arg(long)]
        target: PathBuf,
        #[arg(long, default_value_t = 4 * 4096)]
        max_aggregate_bytes: usize,
        #[arg(long)]
        install: bool,
        #[arg(long)]
        expected_original_ciphertext: Option<ContentId>,
        #[arg(long)]
        expected_original_config: Option<ContentId>,
        #[arg(long)]
        expected_target_config: Option<ContentId>,
    },
    /// Map an actual same-user owner/DACL from an exact archived path/snapshot.
    MapAcl {
        #[arg(long)]
        path: String,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        snapshot: String,
        #[arg(long)]
        mapped_worktree: PathBuf,
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_source_bytes: u64,
    },
    /// Observe immutable original content protection predicates. This never
    /// retains or releases a live pin and always reports both authorities false.
    ObservePins {
        #[arg(long)]
        desired_worktree: PathBuf,
        #[arg(long, num_args = 1..)]
        content: Vec<String>,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u32,
    pub archive: PathBuf,
    pub archive_digest: ContentId,
    pub archive_bounds: ArchiveBounds,
    pub expected_space: SpaceId,
    pub expected_device: DeviceId,
    pub worktree: PathBuf,
    pub data: PathBuf,
    pub original_frames: PathBuf,
    pub restore_ledger: PathBuf,
    pub history_chain: PathBuf,
    pub inspection: InspectionDescriptor,
    pub ledger: LedgerDescriptor,
    pub max_content_hash_bytes: u64,
    pub generation: u32,
    pub previous_descriptor_digest: Option<ContentId>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectionDescriptor {
    pub max_entries: usize,
    pub inventory_max_rows: usize,
    pub inventory_max_logical_bytes: u64,
    pub max_rows: u64,
    pub max_logical_bytes: u64,
    pub max_vm_instructions: u64,
    pub max_query_time_secs: u64,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerDescriptor {
    pub max_records: u64,
    pub max_intents: usize,
    pub max_record_bytes: u64,
    pub max_database_bytes: u64,
    pub max_content_bytes: u64,
    pub max_vm_instructions: u64,
    pub max_query_time_secs: u64,
}

impl Descriptor {
    fn validate_paths(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.version != 1 || self.generation == u32::MAX {
            return Err("unsupported recovered-local descriptor version/generation".into());
        }
        let paths = [
            ("archive", &self.archive),
            ("worktree", &self.worktree),
            ("data", &self.data),
            ("original_frames", &self.original_frames),
            ("restore_ledger", &self.restore_ledger),
            ("history_chain", &self.history_chain),
        ];
        for (name, path) in paths {
            if !path.is_absolute() {
                return Err(format!("{name} must be absolute").into());
            }
            if path.components().any(|p| {
                matches!(
                    p,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            }) {
                return Err(format!("{name} must be normalized").into());
            }
            if path.as_os_str().is_empty() {
                return Err(format!("{name} is empty").into());
            }
        }
        if self.worktree == self.data
            || self.worktree.starts_with(&self.data)
            || self.data.starts_with(&self.worktree)
        {
            return Err("recovered-local worktree/data roots overlap".into());
        }
        if self.max_content_hash_bytes == 0 || self.max_content_hash_bytes > 256 * 1024 * 1024 {
            return Err("recovered-local content hash bound".into());
        }
        Ok(())
    }

    fn inspection(&self) -> NodeInspectionBounds {
        NodeInspectionBounds {
            max_entries: self.inspection.max_entries,
            capacity: JournalCapacityLimits {
                inventory: TreeRestoreInventoryLimits {
                    max_rows: self.inspection.inventory_max_rows,
                    max_logical_bytes: self.inspection.inventory_max_logical_bytes,
                },
                max_rows: self.inspection.max_rows,
                max_logical_bytes: self.inspection.max_logical_bytes,
            },
            max_vm_instructions: self.inspection.max_vm_instructions,
            max_query_time: Duration::from_secs(self.inspection.max_query_time_secs),
        }
    }

    fn ledger(&self) -> LedgerBounds {
        LedgerBounds {
            max_records: self.ledger.max_records,
            max_intents: self.ledger.max_intents,
            max_record_bytes: self.ledger.max_record_bytes,
            max_database_bytes: self.ledger.max_database_bytes,
            max_content_bytes: self.ledger.max_content_bytes,
            max_vm_instructions: self.ledger.max_vm_instructions,
            max_query_time: Duration::from_secs(self.ledger.max_query_time_secs),
        }
    }

    fn next(&self, history_chain: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let mut next = self.clone();
        next.generation = self
            .generation
            .checked_add(1)
            .ok_or("descriptor generation overflow")?;
        next.previous_descriptor_digest = Some(ContentId::hash(&serde_json::to_vec(self)?));
        next.history_chain = history_chain;
        Ok(next)
    }
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("bounded input path must be absolute".into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("bounded input must be a regular non-symlink file".into());
    }
    if metadata.len() > maximum {
        return Err("bounded input exceeds declared limit".into());
    }
    let capacity = usize::try_from(maximum.min(256 * 1024 * 1024))?;
    let mut bytes = Vec::with_capacity(capacity.min(metadata.len() as usize));
    File::open(path)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err("bounded input exceeds declared limit".into());
    }
    Ok(bytes)
}

fn load_descriptor(path: &Path) -> Result<Descriptor, Box<dyn std::error::Error>> {
    let bytes = read_bounded(path, DESCRIPTOR_LIMIT as u64)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&read_bounded(
        path,
        DESCRIPTOR_LIMIT as u64,
    )?)?)
}

fn install_parent(
    path: &Path,
) -> Result<(sync_extend_platform_fs::LockedDirectory, String), Box<dyn std::error::Error>> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("installation target must be absolute and normalized".into());
    }
    let parent = path.parent().ok_or("installation parent missing")?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("installation component missing")?;
    Ok((
        sync_extend_platform_fs::LockedDirectory::open(parent)?,
        name.to_owned(),
    ))
}

fn require_digest(
    expected: Option<&ContentId>,
    actual: &ContentId,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if expected != Some(actual) {
        return Err(format!("explicit installation requires reviewed {name} digest").into());
    }
    Ok(())
}

fn load_archive(
    descriptor: &Descriptor,
) -> Result<VerifiedNodeStateArchive, Box<dyn std::error::Error>> {
    descriptor.validate_paths()?;
    let bytes = read_bounded(&descriptor.archive, descriptor.archive_bounds.archive_bytes)?;
    let framed = FramedNodeArchive::verify_framing(
        bytes,
        &descriptor.archive_digest,
        descriptor.archive_bounds,
    )?;
    let verified = framed.verify_node_state(
        descriptor.archive_bounds,
        descriptor.inspection(),
        descriptor.max_content_hash_bytes,
    )?;
    if verified.space() != &descriptor.expected_space
        || verified.device() != &descriptor.expected_device
    {
        return Err("recovered archive identity differs from descriptor".into());
    }
    Ok(verified)
}

fn print(value: &impl Serialize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn restore_original(
    archive: &VerifiedNodeStateArchive,
    descriptor: &Descriptor,
    ledger_directory: &Path,
    expected_hold_digest: Option<&ContentId>,
) -> Result<(), Box<dyn std::error::Error>> {
    let inspection = descriptor.inspection();
    let ledger_bounds = descriptor.ledger();
    let local_limits = LocalLimits {
        max_storage_entries: inspection.max_entries,
        ..LocalLimits::default()
    };
    local_limits.validate()?;
    let prepared = if let Some(digest) = expected_hold_digest {
        archive.prepare_original_node_restore_with_read_lease_hold(
            &descriptor.worktree,
            &descriptor.data,
            inspection,
            ledger_bounds.max_intents,
            ledger_bounds.max_content_bytes,
            ledger_bounds,
            digest,
        )?
    } else {
        archive.prepare_original_node_restore(
            &descriptor.worktree,
            &descriptor.data,
            inspection,
            ledger_bounds.max_intents,
            ledger_bounds.max_content_bytes,
            ledger_bounds,
        )?
    };
    let mut ledger =
        NodeRestoreLedger::create_external_for_prepared(ledger_directory, archive, &prepared)?;
    let roots = prepared.create_original_roots(archive, &mut ledger)?;
    let marker = archive.create_worktree_marker(&roots, &mut ledger)?;
    let directories = archive.create_original_layout_directories(
        &roots,
        &marker,
        &mut ledger,
        prepared.original_layout(),
        prepared.mapped_layout(),
    )?;
    let files = prepared.create_original_files(archive, &directories, &mut ledger, inspection)?;
    files.verify_inventory()?;
    let locks = roots.create_data_locks(&mut ledger)?;
    let local = files
        .into_original_read_assembly(inspection.max_entries, locks)?
        .into_original_local_space(archive, local_limits)?;
    let current = local
        .manifest()?
        .ok_or("restored manifest absent")?
        .root()?;
    let observation = local.observe_original_completion(archive, &prepared, &ledger)?;
    let completion = ledger.commit_original_completion(observation)?;
    print(&serde_json::json!({
        "archive_digest": archive.digest(),
        "hold_digest": expected_hold_digest,
        "snapshot_id": current,
        "completion_digest": completion.completion_digest(),
        "restore_ledger": ledger.path(),
        "worktree": descriptor.worktree,
        "data": descriptor.data,
        "mutation_authority": {
            "native": false,
            "cleanup": false,
            "gc_release": false,
            "pending_resume": false,
            "activate_read_leases": false,
        },
    }))
}

pub fn run(descriptor_path: &Path, action: Action) -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = load_descriptor(descriptor_path)?;
    let archive = load_archive(&descriptor)?;
    let replace_action = matches!(&action, Action::Replace { .. });
    match action {
        Action::Capture {
            source_data,
            output,
            config,
        } => {
            let configs = config
                .iter()
                .map(|value| {
                    let (name, path) = value
                        .split_once('=')
                        .ok_or("captured config must be name=absolute-path")?;
                    let path = PathBuf::from(path);
                    if !path.is_absolute() {
                        return Err("captured config path must be absolute");
                    }
                    Ok((name.to_owned(), path))
                })
                .collect::<Result<Vec<_>, &str>>()?;
            let local = sync_extend_reconcile::LocalSpace::open(&source_data)?;
            if local.space_id != descriptor.expected_space
                || local.device_id != descriptor.expected_device
                || local.worktree_path() != archive.original_worktree()
            {
                return Err(
                    "capture source differs from the verified original node identity".into(),
                );
            }
            let captured = local.capture_node_archive(&configs, descriptor.archive_bounds)?;
            let framed = FramedNodeArchive::verify_framing(
                captured.bytes().to_vec(),
                captured.digest(),
                descriptor.archive_bounds,
            )?;
            let verified = framed.verify_node_state(
                descriptor.archive_bounds,
                descriptor.inspection(),
                descriptor.max_content_hash_bytes,
            )?;
            let (parent, component) = install_parent(&output)?;
            let mut file = parent.create_new_file(&component)?;
            use std::io::Write;
            file.writer().write_all(verified.bytes())?;
            file.writer().sync_all()?;
            file.original_creation()?.verify()?;
            print(&serde_json::json!({
                "archive": output, "archive_digest": verified.digest(),
                "space_id": verified.space(), "device_id": verified.device(),
                "captured_configs": configs.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            }))?;
        }
        Action::Inspect => {
            let inspection: RecoveredArchiveInspection =
                archive.inspect_recovered_archive(descriptor.inspection())?;
            print(&serde_json::json!({
                "descriptor_digest": ContentId::hash(&serde_json::to_vec(&descriptor)?),
                "archive": inspection,
                "mutation_authority": {
                    "native": false,
                    "cleanup": false,
                    "gc_release": false,
                    "pending_resume": false,
                },
            }))?;
        }
        Action::PreviewReadLeaseMigration => {
            let max_image_bytes = descriptor
                .archive_bounds
                .archive_bytes
                .min(256 * 1024 * 1024);
            let preview = archive.preview_read_lease_migration(
                &descriptor.worktree,
                &descriptor.data,
                descriptor.inspection(),
                usize::try_from(max_image_bytes)?,
            )?;
            print(&serde_json::json!({
                "descriptor_digest": ContentId::hash(&serde_json::to_vec(&descriptor)?),
                "migration_preview": preview,
                "mutation_authority": {
                    "native": false,
                    "cleanup": false,
                    "gc_release": false,
                    "pending_resume": false,
                    "activate_read_leases": false,
                },
            }))?;
        }
        Action::Restore { ledger_directory } => {
            restore_original(&archive, &descriptor, &ledger_directory, None)?;
        }
        Action::RestoreReadLeaseHold {
            expected_hold_digest,
            ledger_directory,
        } => {
            restore_original(
                &archive,
                &descriptor,
                &ledger_directory,
                Some(&expected_hold_digest),
            )?;
        }
        Action::InspectRestore { ledger } => {
            let ledger = ledger.as_deref().unwrap_or(&descriptor.restore_ledger);
            let classification = archive.classify_original_node_restart(
                ledger,
                descriptor.ledger(),
                descriptor.inspection(),
            )?;
            print(&serde_json::json!({
                "archive_digest": archive.digest(),
                "restore_ledger": ledger,
                "classification": classification,
                "mutation_authority": {
                    "native": classification.native_restart_authority_available(),
                    "cleanup": classification.cleanup_authority_available(),
                    "gc_release": false,
                    "pending_resume": false,
                    "activate_read_leases": false,
                },
            }))?;
        }
        Action::Start {
            path,
            source,
            timestamp,
        } => {
            let bytes = read_bounded(
                &source,
                descriptor.ledger.max_content_bytes.min(SOURCE_LIMIT),
            )?;
            let path = PortablePath::new(path)?;
            let mut session = archive.reacquire_closed_node_wal_v2_session(
                &descriptor.worktree,
                &descriptor.data,
                &descriptor.original_frames,
                &descriptor.restore_ledger,
                descriptor.inspection(),
                descriptor.ledger(),
            )?;
            session.verify()?;
            session.commit_fresh_session()?;
            let snapshot = session.create_recovered_file_from_bytes(&path, &bytes, timestamp)?;
            let closed_history_chain = session.close_recovered_history_for_chain8()?;
            drop(session);
            let next = descriptor.next(closed_history_chain.clone())?;
            print(&serde_json::json!({
                "snapshot": snapshot, "closed_history_chain": closed_history_chain,
                "next_descriptor": next, "old_descriptor_rewritten": false,
                "old_receipts_rewritten": false, "first_native_write_executed": true,
            }))?;
        }
        Action::Create {
            path,
            source,
            timestamp,
        }
        | Action::Replace {
            path,
            source,
            timestamp,
        } => {
            let bytes = read_bounded(
                &source,
                descriptor.ledger.max_content_bytes.min(SOURCE_LIMIT),
            )?;
            let portable = PortablePath::new(path)?;
            let mut local = archive.open_recovered_local_space(
                &descriptor.worktree,
                &descriptor.data,
                &descriptor.original_frames,
                &descriptor.restore_ledger,
                &descriptor.history_chain,
                descriptor.inspection(),
                descriptor.ledger(),
            )?;
            let snapshot = if replace_action {
                local.replace_file_bytes(&portable, &bytes, timestamp)?
            } else {
                local.create_file(&portable, &bytes, timestamp)?
            };
            let closed_history_chain = local.close()?;
            let next = descriptor.next(closed_history_chain.clone())?;
            print(&serde_json::json!({
                "snapshot": snapshot,
                "closed_history_chain": closed_history_chain,
                "next_descriptor": next,
                "old_descriptor_rewritten": false,
                "old_receipts_rewritten": false,
            }))?;
        }
        Action::MapConfig {
            name,
            new_data,
            new_worktree,
            max_combined_bytes,
            install_to,
            expected_mapped_digest,
        } => {
            let mapping = archive.map_explicit_original_config(
                &name,
                archive
                    .original_config_data()
                    .ok_or("descriptor has no captured config data root")?,
                &new_data,
                &new_worktree,
                max_combined_bytes,
            )?;
            let mut result = serde_json::json!({
                "descriptor_digest": ContentId::hash(&serde_json::to_vec(&descriptor)?),
                "archive_digest": mapping.archive_digest(),
                "original_digest": mapping.original_digest(),
                "mapped_digest": mapping.mapped_digest(),
                "installed": false,
                "credentials_or_acl": "separate explicit protected-object mapping required",
            });
            if let Some(target) = install_to {
                require_digest(
                    expected_mapped_digest.as_ref(),
                    mapping.mapped_digest(),
                    "mapped config",
                )?;
                let (parent, name) = install_parent(&target)?;
                let installed = mapping.install_current_user_config(&parent, &name)?;
                installed.verify_current_user_acl()?;
                result["installed"] = true.into();
                result["target"] = serde_json::to_value(target)?;
                result["installed_digest"] = serde_json::to_value(installed.protected_digest())?;
            }
            print(&result)?;
        }
        Action::MapWebdavCredential {
            source,
            original_listener,
            mapped_listener,
            max_aggregate_bytes,
            install_to,
            expected_original_ciphertext,
            expected_original_listener,
            expected_mapped_listener,
        } => {
            let original: WebDavListener = load_json(&original_listener)?;
            let mapped: WebDavListener = load_json(&mapped_listener)?;
            let mapping = ExplicitWebDavCredentialMapping::from_original_current_user_file(
                &source,
                &original,
                &mapped,
                max_aggregate_bytes,
            )?;
            let mut result = serde_json::json!({
                "descriptor_digest": ContentId::hash(&serde_json::to_vec(&descriptor)?),
                "original_ciphertext_digest": mapping.original_ciphertext_digest(),
                "mapped_ciphertext_digest": mapping.mapped_ciphertext_digest(),
                "original_listener_digest": mapping.original_listener_digest(),
                "mapped_listener_digest": mapping.mapped_listener_digest(),
                "installed": false,
                "plaintext_displayed": false,
                "cross_user_or_acl_adoption": false,
            });
            if let Some(target) = install_to {
                require_digest(
                    expected_original_ciphertext.as_ref(),
                    mapping.original_ciphertext_digest(),
                    "original ciphertext",
                )?;
                require_digest(
                    expected_original_listener.as_ref(),
                    mapping.original_listener_digest(),
                    "original listener",
                )?;
                require_digest(
                    expected_mapped_listener.as_ref(),
                    mapping.mapped_listener_digest(),
                    "mapped listener",
                )?;
                let (parent, name) = install_parent(&target)?;
                let installed = mapping.install_current_user_file(&parent, &name, &mapped)?;
                installed.verify_current_user_acl()?;
                result["installed"] = true.into();
                result["target"] = serde_json::to_value(target)?;
                result["installed_digest"] = serde_json::to_value(installed.protected_digest())?;
            }
            print(&result)?;
        }
        Action::MapManagementCredential {
            original,
            target,
            max_aggregate_bytes,
            install,
            expected_original_ciphertext,
            expected_original_config,
            expected_target_config,
        } => {
            let original_config: ManagementConfig = load_json(&original)?;
            let target_config: ManagementConfig = load_json(&target)?;
            let mapping = ExplicitManagementCredentialMapping::from_original_current_user_file(
                &original_config,
                &target_config,
                max_aggregate_bytes,
            )?;
            let original_config_digest = ContentId::hash(&serde_json::to_vec(&original_config)?);
            let target_config_digest = ContentId::hash(&serde_json::to_vec(&target_config)?);
            let mut result = serde_json::json!({
                "descriptor_digest": ContentId::hash(&serde_json::to_vec(&descriptor)?),
                "original_ciphertext_digest": mapping.original_ciphertext_digest(),
                "mapped_ciphertext_digest": mapping.mapped_ciphertext_digest(),
                "target_path": mapping.target_path(),
                "installed": false,
                "plaintext_displayed": false,
                "address_or_policy_changed": false,
                "cross_user_or_acl_adoption": false,
                "original_config_digest": original_config_digest,
                "target_config_digest": target_config_digest,
            });
            if install {
                require_digest(
                    expected_original_ciphertext.as_ref(),
                    mapping.original_ciphertext_digest(),
                    "original ciphertext",
                )?;
                require_digest(
                    expected_original_config.as_ref(),
                    &original_config_digest,
                    "original management config",
                )?;
                require_digest(
                    expected_target_config.as_ref(),
                    &target_config_digest,
                    "target management config",
                )?;
                let (parent, name) = install_parent(&target_config.token_file)?;
                let installed =
                    mapping.install_current_user_file(&parent, &name, &target_config)?;
                installed.verify_current_user_acl()?;
                result["installed"] = true.into();
                result["installed_digest"] = serde_json::to_value(installed.protected_digest())?;
            }
            print(&result)?;
        }
        Action::MapAcl {
            path,
            source,
            snapshot,
            mapped_worktree,
            max_source_bytes,
        } => {
            let path = PortablePath::new(path)?;
            let snapshot = snapshot.parse()?;
            let mapping = archive.map_explicit_original_acl(
                &path,
                &source,
                &snapshot,
                &mapped_worktree,
                descriptor.inspection(),
                max_source_bytes,
            )?;
            mapping.verify()?;
            print(mapping.evidence())?;
        }
        Action::Retain { content } => {
            let ids = content
                .iter()
                .map(|id| id.parse::<ContentId>())
                .collect::<Result<Vec<_>, _>>()?;
            let mut local = archive.open_recovered_history_operation(
                &descriptor.worktree,
                &descriptor.data,
                &descriptor.original_frames,
                &descriptor.restore_ledger,
                &descriptor.history_chain,
                descriptor.inspection(),
                descriptor.ledger(),
                RecoveredHistoryOperation::Retain(&ids),
            )?;
            let retained = local.retain_history(&archive, &ids)?;
            let closed_history_chain = local.close()?;
            let next = descriptor.next(closed_history_chain.clone())?;
            print(&serde_json::json!({
                "retention": retained, "closed_history_chain": closed_history_chain,
                "next_descriptor": next, "old_descriptor_rewritten": false,
                "old_receipts_rewritten": false, "live_native_retention_executed": true,
            }))?;
        }
        Action::Release { mapping, timestamp } => {
            let mapping: sync_extend_journal::RecoveredRetentionMapping = load_json(&mapping)?;
            let mut local = archive.open_recovered_history_operation(
                &descriptor.worktree,
                &descriptor.data,
                &descriptor.original_frames,
                &descriptor.restore_ledger,
                &descriptor.history_chain,
                descriptor.inspection(),
                descriptor.ledger(),
                RecoveredHistoryOperation::Release(&mapping),
            )?;
            let released = local.release_history(&mapping, timestamp)?;
            let closed_history_chain = local.close()?;
            let next = descriptor.next(closed_history_chain.clone())?;
            print(&serde_json::json!({
                "retention": released, "closed_history_chain": closed_history_chain,
                "next_descriptor": next, "old_descriptor_rewritten": false,
                "old_receipts_rewritten": false, "live_native_release_executed": true,
            }))?;
        }
        Action::GcMark {
            content,
            grace_secs,
        } => {
            if !(1..=604800).contains(&grace_secs) {
                return Err("GC grace must be 1 second through 7 days".into());
            }
            let id = content.parse::<ContentId>()?;
            let mut local = archive.open_recovered_history_operation(
                &descriptor.worktree,
                &descriptor.data,
                &descriptor.original_frames,
                &descriptor.restore_ledger,
                &descriptor.history_chain,
                descriptor.inspection(),
                descriptor.ledger(),
                RecoveredHistoryOperation::GcMark(&id),
            )?;
            let audit = local.admit_history_gc(&id, grace_secs)?;
            let closed_history_chain = local.close()?;
            let next = descriptor.next(closed_history_chain.clone())?;
            print(&serde_json::json!({
                "gc_mark": audit, "closed_history_chain": closed_history_chain,
                "next_descriptor": next, "old_descriptor_rewritten": false,
                "old_receipts_rewritten": false, "live_journal_cas_gc_admission_executed": true,
                "physical_disposal_executed": false,
            }))?;
        }
        Action::ObservePins {
            desired_worktree,
            content,
        } => {
            let ids = content
                .iter()
                .map(|value| value.parse::<ContentId>())
                .collect::<Result<Vec<_>, _>>()?;
            let observations = archive.observe_original_pin_references(
                &desired_worktree,
                &ids,
                descriptor.inspection(),
            )?;
            print(&serde_json::json!({
                "descriptor_digest": ContentId::hash(&serde_json::to_vec(&descriptor)?),
                "observations": observations,
                "live_retain_authority": false,
                "release_authority": false,
            }))?;
        }
    }
    Ok(())
}
