//! Separate admitted original-creator ledger. No TREE or legacy path adoption.
use crate::{
    storage_inventory::reader::{hash, invalid},
    Journal, JournalStorageColumnValue as Value, JournalStoredRow, PublicationIntent,
    PublicationState, Result,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sync_extend_core_model::{tree_storage_capacity::TreeStorageCharge, ContentId, EntryId};

#[cfg(windows)]
pub(crate) mod creation;
#[cfg(windows)]
pub(crate) mod issuance;
pub(crate) mod schema;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    volume: String,
    id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ancestor {
    path: String,
    key: Key,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: u32,
    intent: PublicationIntent,
    generation: EntryId,
    root: Key,
    parent: Key,
    ancestors: Vec<Ancestor>,
    existing_base: Option<Key>,
    native_peak: TreeStorageCharge,
    worktree_peak_bytes: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct Step {
    component: String,
    kind: &'static str,
}

fn steps(header: &Header) -> Vec<Step> {
    let mut steps = vec![
        Step {
            component: ".sync-tmp".into(),
            kind: "directory",
        },
        Step {
            component: format!("native-{}", header.generation),
            kind: "directory",
        },
        Step {
            component: "owner".into(),
            kind: "file",
        },
    ];
    steps.extend((0..=16).map(|n| Step {
        component: format!("payload-{n}"),
        kind: "file",
    }));
    steps
}
fn valid_key(key: &Key) -> bool {
    [(&key.volume, 16), (&key.id, 32)]
        .into_iter()
        .all(|(s, n)| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn physical(key: &Key) -> Result<ContentId> {
    if !valid_key(key) {
        return Err(invalid("native full identity encoding"));
    }
    let volume =
        u64::from_str_radix(&key.volume, 16).map_err(|_| invalid("native volume encoding"))?;
    let id = u128::from_str_radix(&key.id, 16).map_err(|_| invalid("native id encoding"))?;
    Ok(ContentId::hash(format!("windows:{volume}:{id}").as_bytes()))
}
fn peak(header: &Header) -> Result<TreeStorageCharge> {
    // Every normalized column including PK/integers; unknown future identities
    // have fixed hex widths. Placeholder widths never authorize native effects.
    let mut charge = TreeStorageCharge::default();
    for (index, step) in steps(header).into_iter().enumerate() {
        if index == 0 && header.existing_base.is_some() {
            continue;
        }
        let activation =
            32 + 32 + 8 + 64 + step.component.len() as u64 + step.kind.len() as u64 + 16 + 32;
        charge.rows += 2;
        charge.logical_bytes += activation * 2 + 16 + 32;
        for stage in ["intended", "absent", "terminal"] {
            charge.rows += 1;
            charge.logical_bytes += 32 + 32 + 8 + 64 + stage.len() as u64 + 64 + 8;
        }
    }
    for _ in 0..=16 {
        for phase in ["ready", "publishing", "observed", "final", "cleanup"] {
            charge.rows += 1;
            charge.logical_bytes +=
                32 + 32 + 8 + 64 + phase.len() as u64 + 64 + 64 + 64 + 8 + 16 + 32 + 16 + 32 + 4096;
        }
    }
    Ok(charge)
}
fn field<'a>(row: &'a JournalStoredRow, name: &str) -> Result<&'a str> {
    match row
        .columns()
        .iter()
        .find(|c| c.name == name)
        .map(|c| &c.value)
    {
        Some(Value::Text(s)) => Ok(s),
        _ => Err(invalid("native expected text field")),
    }
}
fn number(row: &JournalStoredRow, name: &str) -> Result<u64> {
    match row
        .columns()
        .iter()
        .find(|c| c.name == name)
        .map(|c| &c.value)
    {
        Some(Value::Integer(n)) => Ok(*n),
        _ => Err(invalid("native expected integer field")),
    }
}
pub(crate) fn obligations(
    rows: &[JournalStoredRow],
    publications: &[crate::Publication],
) -> Result<Vec<crate::JournalCapacityObligation>> {
    let mut out = Vec::new();
    let mut owners = BTreeMap::new();
    for row in rows
        .iter()
        .filter(|r| r.table() == "native_publication_headers")
    {
        let json = field(row, "header")?;
        let header: Header = serde_json::from_str(json)?;
        let id = header.intent.transaction_id.as_str();
        if header.format != 1
            || serde_json::to_string(&header)? != json
            || field(row, "transaction_id")? != id
            || field(row, "space_id")? != header.intent.space_id.as_str()
            || field(row, "generation")? != header.generation.as_str()
            || field(row, "header_hash")? != hash(&header)?.as_str()
            || header.native_peak != peak(&header)?
            || number(row, "reserved_rows")? != header.native_peak.rows
            || number(row, "reserved_bytes")? != header.native_peak.logical_bytes
            || header.intent.root_identity.as_ref() != Some(&physical(&header.root)?)
            || header.intent.parent_identity.as_ref() != Some(&physical(&header.parent)?)
            || header.ancestors.is_empty()
            || header.ancestors.len() > 256
            || header
                .ancestors
                .iter()
                .any(|a| a.path.is_empty() || !valid_key(&a.key))
            || header.existing_base.as_ref().is_some_and(|k| !valid_key(k))
            || header.worktree_peak_bytes
                != 32u64
                    .checked_add(
                        header
                            .intent
                            .content
                            .length
                            .checked_mul(17)
                            .ok_or(invalid("native worktree peak overflow"))?,
                    )
                    .ok_or(invalid("native worktree peak overflow"))?
        {
            return Err(invalid("native header canonical full scope or capacity"));
        }
        header.intent.validate()?;
        let publication = publications
            .iter()
            .find(|p| p.intent.transaction_id == header.intent.transaction_id)
            .ok_or(invalid("native header publication missing"))?;
        if publication.intent != header.intent
            || publication.state != PublicationState::Preparing
            || publication.cleaned
            || header.intent.completion.is_none()
        {
            return Err(invalid("native creator owner cannot use legacy completion"));
        }
        let mut actual = TreeStorageCharge::default();
        let mut activations = BTreeMap::new();
        let mut creators = BTreeMap::new();
        let planned = steps(&header);
        for effect in rows.iter().filter(|r| {
            r.table() != "native_publication_headers"
                && r.table().starts_with("native_publication_")
                && matches!(field(r,"transaction_id"),Ok(value) if value==id)
        }) {
            if effect.table() == "native_publication_phases"
                || effect.table() == "native_publication_dispositions"
            {
                return Err(invalid("native phase issuer not implemented"));
            }
            let index = number(effect, "step")? as usize;
            let step = planned
                .get(index)
                .ok_or(invalid("native step exceeds plan"))?;
            if field(effect, "generation")? != header.generation.as_str()
                || field(effect, "header_hash")? != hash(&header)?.as_str()
                || field(effect, "component")? != step.component
                || field(effect, "kind")? != step.kind
                || (index == 0 && header.existing_base.is_some())
            {
                return Err(invalid("native effect full owner scope"));
            }
            let parent = Key {
                volume: field(effect, "parent_volume")?.into(),
                id: field(effect, "parent_id")?.into(),
            };
            if !valid_key(&parent) {
                return Err(invalid("native parent full identity"));
            }
            if effect.table() == "native_publication_activations" {
                activations.insert(index, parent);
            } else if effect.table() == "native_publication_creators" {
                let key = Key {
                    volume: field(effect, "volume")?.into(),
                    id: field(effect, "full_id")?.into(),
                };
                if !valid_key(&key) || key.volume != parent.volume {
                    return Err(invalid("native creator full identity"));
                }
                creators.insert(index, (parent, key));
            } else {
                return Err(invalid("native effect table unknown"));
            }
            actual.rows += 1;
            actual.logical_bytes = actual
                .logical_bytes
                .checked_add(effect.logical_bytes())
                .ok_or(invalid("native actual bytes overflow"))?;
        }
        for (&index, parent) in &activations {
            let expected = match index {
                0 => &header.parent,
                1 => header
                    .existing_base
                    .as_ref()
                    .or_else(|| creators.get(&0).map(|(_, key)| key))
                    .ok_or(invalid("native owner scaffold receipt missing"))?,
                _ => creators
                    .get(&1)
                    .map(|(_, key)| key)
                    .ok_or(invalid("native child owner receipt missing"))?,
            };
            if parent != expected || (index >= 3 && !creators.contains_key(&(index - 1))) {
                return Err(invalid("native step dependency differs"));
            }
        }
        for (&index, (parent, _)) in &creators {
            if activations.get(&index) != Some(parent) {
                return Err(invalid("native creator activation missing"));
            }
        }
        let keys: std::collections::BTreeSet<_> = creators
            .values()
            .map(|(_, key)| (&key.volume, &key.id))
            .collect();
        if keys.len() != creators.len()
            || creators.values().any(|(_, key)| {
                key == &header.root
                    || key == &header.parent
                    || header.ancestors.iter().any(|ancestor| &ancestor.key == key)
                    || header.existing_base.as_ref() == Some(key)
            })
        {
            return Err(invalid("native original identities alias scope"));
        }
        if owners.insert(id.to_string(), ()).is_some() {
            return Err(invalid("native owner duplicate"));
        }
        out.push(crate::JournalCapacityObligation {
            family: "native_publication_exact_continuation",
            owner_key: vec![id.into()],
            charge: TreeStorageCharge {
                rows: header
                    .native_peak
                    .rows
                    .checked_sub(actual.rows)
                    .ok_or(invalid("native row liability underflow"))?,
                logical_bytes: header
                    .native_peak
                    .logical_bytes
                    .checked_sub(actual.logical_bytes)
                    .ok_or(invalid("native byte liability underflow"))?,
            },
        });
    }
    for row in rows.iter().filter(|r| {
        r.table().starts_with("native_publication_") && r.table() != "native_publication_headers"
    }) {
        if !owners.contains_key(field(row, "transaction_id")?) {
            return Err(invalid("native orphan effect"));
        }
    }
    Ok(out)
}
pub(crate) fn scope(rows: &[JournalStoredRow], connection: &rusqlite::Connection) -> Result<()> {
    let root: Option<String> = connection
        .query_row(
            "SELECT value FROM main.local_state WHERE key='worktree'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    for row in rows
        .iter()
        .filter(|r| r.table() == "native_publication_headers")
    {
        let header: Header = serde_json::from_str(field(row, "header")?)?;
        let root = root
            .as_ref()
            .ok_or(invalid("native root not initialized"))?;
        let root_path = std::path::Path::new(root);
        let parent_path = header
            .intent
            .target_path
            .parent()
            .map_or(root_path.to_path_buf(), |p| root_path.join(p.as_str()));
        let paths = parent_path
            .ancestors()
            .map(|p| p.to_str().ok_or(invalid("native ancestor non-UTF8")))
            .collect::<Result<Vec<_>>>()?;
        if !root_path.is_absolute()
            || paths.len() != header.ancestors.len()
            || paths
                .iter()
                .zip(&header.ancestors)
                .any(|(path, ancestor)| *path != ancestor.path)
            || header.ancestors.first().map(|a| &a.key) != Some(&header.parent)
            || !header
                .ancestors
                .iter()
                .any(|a| a.path == *root && a.key == header.root)
        {
            return Err(invalid("native persisted full ancestor scope"));
        }
    }
    Ok(())
}
pub(crate) fn legacy_gate(connection: &rusqlite::Connection, id: &EntryId) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.native_publication_headers WHERE transaction_id=?1)",
        [id.as_str()],
        |r| r.get(0),
    )?;
    if exists {
        return Err(invalid(
            "original-creator publication pending; legacy path refused",
        ));
    }
    Ok(())
}
pub(crate) fn validate_schema(connection: &rusqlite::Connection) -> Result<()> {
    type Objects = Vec<(String, String, Option<String>)>;
    fn objects(connection: &rusqlite::Connection) -> Result<Objects> {
        let mut statement = connection.prepare(
            "SELECT type,name,sql FROM main.sqlite_schema WHERE
             name LIKE 'native_publication_%' OR tbl_name LIKE 'native_publication_%'
             ORDER BY type,name",
        )?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?;
        Ok(rows)
    }
    let expected = rusqlite::Connection::open_in_memory()?;
    expected.execute_batch(include_str!("migration-034.sql"))?;
    if objects(connection)? != objects(&expected)? {
        return Err(invalid("native publication schema/trigger/index differs"));
    }
    Ok(())
}
impl Journal {
    pub fn require_legacy_publication(&self, id: &EntryId) -> Result<()> {
        legacy_gate(&self.connection, id)
    }
}
