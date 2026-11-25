//! Bounded, read-only production consumer for the schema-69 native history audit.
//!
//! The request is explicit data: one complete image, its original digest, the
//! original space, root mappings and every inspection bound. Output is a
//! compact summary only. It never contains original row contents, credentials
//! or absolute host paths.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path},
    time::Duration,
};
use sync_extend_core_model::SpaceId;
use sync_extend_journal::{
    JournalBackupImage, JournalCapacityLimits, NativeHistoryRootMapping, NodeInspectionBounds,
    TreeRestoreInventoryLimits,
};

const REQUEST_LIMIT: usize = 64 * 1024;
const IMAGE_LIMIT: usize = 256 * 1024 * 1024;
const TABLE_SAMPLE_LIMIT: usize = 4;
const ROOT_SAMPLE_LIMIT: usize = 4;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BoundsRequest {
    pub max_entries: usize,
    pub inventory_max_rows: usize,
    pub inventory_max_logical_bytes: u64,
    pub max_rows: u64,
    pub max_logical_bytes: u64,
    pub max_vm_instructions: u64,
    pub max_query_secs: u64,
}

impl BoundsRequest {
    fn bounds(self) -> NodeInspectionBounds {
        NodeInspectionBounds {
            max_entries: self.max_entries,
            capacity: JournalCapacityLimits {
                inventory: TreeRestoreInventoryLimits {
                    max_rows: self.inventory_max_rows,
                    max_logical_bytes: self.inventory_max_logical_bytes,
                },
                max_rows: self.max_rows,
                max_logical_bytes: self.max_logical_bytes,
            },
            max_vm_instructions: self.max_vm_instructions,
            max_query_time: Duration::from_secs(self.max_query_secs),
        }
    }

    fn validate(self) -> Result<NodeInspectionBounds, Box<dyn std::error::Error>> {
        if self.max_entries == 0
            || self.max_entries > 1_000_000
            || self.max_rows > 1_000_000
            || self.inventory_max_rows > 1_000_000
        {
            return Err("native history audit entry bounds are outside the client limit".into());
        }
        let bounds = self.bounds();
        bounds.validate()?;
        Ok(bounds)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootRequest {
    pub original_worktree: String,
    pub projected_worktree: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRequest {
    pub image: std::path::PathBuf,
    pub image_digest: String,
    pub space: SpaceId,
    pub roots: Vec<RootRequest>,
    pub max_image_bytes: usize,
    pub bounds: BoundsRequest,
}

#[derive(Serialize)]
struct TableSample<'a> {
    table: &'a str,
    rows: u64,
    logical_bytes: u64,
}

#[derive(Serialize)]
struct TablesSummary<'a> {
    count: usize,
    families: usize,
    slices: usize,
    rows: u64,
    logical_bytes: u64,
    sample_limit: usize,
    truncated: bool,
    sample: Vec<TableSample<'a>>,
}

#[derive(Serialize)]
struct RootColumnSample<'a> {
    table: &'a str,
    column: &'a str,
}

#[derive(Serialize)]
struct ProjectionSummary<'a> {
    portable_rows: usize,
    root_columns: usize,
    sample_limit: usize,
    truncated: bool,
    sample: Vec<RootColumnSample<'a>>,
}

#[derive(Serialize)]
struct LimitsSummary {
    max_image_bytes: usize,
    max_entries: usize,
    inventory_max_rows: usize,
    inventory_max_logical_bytes: u64,
    max_rows: u64,
    max_logical_bytes: u64,
    max_vm_instructions: u64,
    max_query_secs: u64,
}

#[derive(Serialize)]
struct AuditOutput<'a> {
    audit: &'static str,
    status: &'static str,
    request_sha256: String,
    schema: u32,
    space: &'a str,
    image_digest: String,
    catalog_digest: String,
    rows_digest: String,
    source_digest: String,
    registry_digest: String,
    tables: TablesSummary<'a>,
    owners: usize,
    projection: ProjectionSummary<'a>,
    limits: LimitsSummary,
    read_only: bool,
    native_authority: bool,
    raw_rows_included: bool,
    host_paths_included: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("native history audit input must be a normalized absolute path".into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("native history audit input must be a regular non-symlink file".into());
    }
    if metadata.len() > maximum {
        return Err("native history audit input exceeds its declared limit".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    File::open(path)?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err("native history audit input exceeds its declared limit".into());
    }
    Ok(bytes)
}

pub fn run(request_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let request_path = request_path.to_path_buf();
    let result = std::thread::Builder::new()
        .name("native-history-audit".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || run_inner(&request_path).map_err(|error| error.to_string()))?
        .join()
        .map_err(|_| "native history audit worker terminated unexpectedly")?;
    result.map_err(|error| -> Box<dyn std::error::Error> { error.into() })
}

fn run_inner(request_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let request_bytes = read_bounded(request_path, REQUEST_LIMIT as u64)?;
    let request: AuditRequest = serde_json::from_slice(&request_bytes)?;
    if request.image_digest.len() != 64
        || !request
            .image_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("native history audit image digest must be lowercase 64-hex".into());
    }
    if request.max_image_bytes == 0 || request.max_image_bytes > IMAGE_LIMIT {
        return Err("native history audit image bound is outside the client limit".into());
    }
    if request.roots.is_empty() || request.roots.len() > 64 {
        return Err("native history audit requires one to 64 explicit root mappings".into());
    }
    let bounds = request.bounds.validate()?;
    let roots: Vec<NativeHistoryRootMapping> = request
        .roots
        .into_iter()
        .map(|root| {
            NativeHistoryRootMapping::worktree(root.original_worktree, root.projected_worktree)
        })
        .collect();
    let image = read_bounded(&request.image, request.max_image_bytes as u64)?;
    let proof = JournalBackupImage::audit_native_history_source(
        image,
        &request.image_digest,
        request.max_image_bytes,
        &request.space,
        &roots,
        bounds,
    )?;

    let table_count = proof.tables().len();
    let sample = proof
        .tables()
        .iter()
        .take(TABLE_SAMPLE_LIMIT)
        .map(|table| TableSample {
            table: table.table(),
            rows: table.rows(),
            logical_bytes: table.logical_bytes(),
        })
        .collect();
    // The sample accounts only for the rows it displays. The source digest
    // still covers every table; report aggregate rows separately below.
    let mut all_rows = 0u64;
    let mut all_bytes = 0u64;
    for table in proof.tables() {
        all_rows = all_rows.saturating_add(table.rows());
        all_bytes = all_bytes.saturating_add(table.logical_bytes());
    }
    let root_columns = proof.projection().root_columns();
    let projection = ProjectionSummary {
        portable_rows: proof.projection().portable_rows().len(),
        root_columns: root_columns.len(),
        sample_limit: ROOT_SAMPLE_LIMIT,
        truncated: root_columns.len() > ROOT_SAMPLE_LIMIT,
        sample: root_columns
            .iter()
            .take(ROOT_SAMPLE_LIMIT)
            .map(|mapping| RootColumnSample {
                table: mapping.table(),
                column: mapping.column(),
            })
            .collect(),
    };
    let registry = proof.registry();
    let output = AuditOutput {
        audit: "native_history_source",
        status: "ok",
        request_sha256: sha256_hex(&request_bytes),
        schema: proof.source_schema(),
        space: proof.space().as_str(),
        image_digest: proof.source_image_digest().to_string(),
        catalog_digest: proof.source_catalog_digest().to_string(),
        rows_digest: proof.source_rows_digest().to_string(),
        source_digest: proof.source_digest().to_string(),
        registry_digest: proof.registry_digest().to_string(),
        tables: TablesSummary {
            count: table_count,
            families: registry.families().len(),
            slices: registry.slices().len(),
            rows: all_rows,
            logical_bytes: all_bytes,
            sample_limit: TABLE_SAMPLE_LIMIT,
            truncated: table_count > TABLE_SAMPLE_LIMIT,
            sample,
        },
        owners: proof.owners().len(),
        projection,
        limits: LimitsSummary {
            max_image_bytes: request.max_image_bytes,
            max_entries: bounds.max_entries,
            inventory_max_rows: bounds.capacity.inventory.max_rows,
            inventory_max_logical_bytes: bounds.capacity.inventory.max_logical_bytes,
            max_rows: bounds.capacity.max_rows,
            max_logical_bytes: bounds.capacity.max_logical_bytes,
            max_vm_instructions: bounds.max_vm_instructions,
            max_query_secs: bounds.max_query_time.as_secs(),
        },
        read_only: true,
        native_authority: false,
        raw_rows_included: false,
        host_paths_included: false,
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
