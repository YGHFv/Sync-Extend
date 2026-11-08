//! Immutable baseline descriptions; no creator, Ready, Final or effect grant.
use super::*;
use rusqlite::OptionalExtension;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Key {
    pub volume: String,
    pub id: String,
}
impl Key {
    fn validate(&self) -> Result<()> {
        for (value, width) in [(&self.volume, 16), (&self.id, 32)] {
            if value.len() != width
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("conflict baseline binding full native key"));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Directory {
    pub path: String,
    pub key: Key,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub format: u32,
    pub transaction_id: EntryId,
    pub parent_hash: ContentId,
    pub ancestors: Vec<Directory>,
    pub marker_directory: Key,
    pub marker_file: Key,
    pub existing_base: Option<Key>,
    pub originals: BTreeMap<EntryId, Key>,
}
impl Binding {
    pub(super) fn validate(&self, header: &Header) -> Result<()> {
        if self.format != 1
            || self.transaction_id != header.transaction_id
            || self.parent_hash != hash(header)?
            || self
                .originals
                .keys()
                .ne(header.intent.baseline.entries.keys())
            || self.ancestors.is_empty()
            || self.ancestors.len() > 256
        {
            return Err(invalid(
                "conflict baseline binding complete parent scope differs",
            ));
        }
        let paths: Vec<_> = Path::new(&header.intent.worktree).ancestors().collect();
        if paths.len() != self.ancestors.len() {
            return Err(invalid("conflict baseline binding ancestor scope differs"));
        }
        let mut unique = BTreeSet::new();
        let volume = &self.ancestors[0].key.volume;
        for (ancestor, path) in self.ancestors.iter().zip(paths) {
            ancestor.key.validate()?;
            if path.to_str() != Some(ancestor.path.as_str())
                || ancestor.key.volume != *volume
                || !unique.insert(ancestor.key.clone())
            {
                return Err(invalid(
                    "conflict baseline binding ancestor key or alias differs",
                ));
            }
        }
        for key in std::iter::once(&self.marker_directory)
            .chain(std::iter::once(&self.marker_file))
            .chain(self.existing_base.iter())
            .chain(self.originals.values())
        {
            key.validate()?;
            if key.volume != *volume || !unique.insert(key.clone()) {
                return Err(invalid(
                    "conflict baseline binding file/directory alias or volume",
                ));
            }
        }
        let key = &self.ancestors[0].key;
        let volume = u64::from_str_radix(&key.volume, 16)
            .map_err(|_| invalid("conflict baseline binding root volume"))?;
        let id = u128::from_str_radix(&key.id, 16)
            .map_err(|_| invalid("conflict baseline binding root full ID"))?;
        if ContentId::hash(format!("windows:{volume}:{id}").as_bytes())
            != header.intent.root_identity
        {
            return Err(invalid(
                "conflict baseline binding root description differs",
            ));
        }
        Ok(())
    }
}

pub(super) fn stored(connection: &Connection, header: &Header) -> Result<Option<Binding>> {
    let row: Option<(String, String, String)> = connection.query_row(
        "SELECT parent_hash,binding_hash,binding FROM main.conflict_resolution_native_bindings WHERE transaction_id=?1",
        [header.transaction_id.as_str()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
    ).optional()?;
    row.map(|(parent, digest, json)| {
        let binding: Binding = serde_json::from_str(&json)?;
        binding.validate(header)?;
        if parent != binding.parent_hash.as_str()
            || digest != hash(&binding)?.as_str()
            || json != serde_json::to_string(&binding)?
        {
            return Err(invalid("conflict baseline binding immutable row differs"));
        }
        Ok(binding)
    })
    .transpose()
}
pub(super) fn audit(connection: &Connection) -> Result<()> {
    let count: i64 = connection.query_row(
        "SELECT count(*) FROM main.conflict_resolution_native_bindings",
        [],
        |r| r.get(0),
    )?;
    if count == 0 {
        return Ok(());
    }
    if count != 1 {
        return Err(invalid("conflict baseline binding multiple owners"));
    }
    let json: String = connection.query_row(
        "SELECT a.header FROM main.conflict_resolution_admissions a JOIN main.conflict_resolution_native_bindings b USING(transaction_id)",
        [], |r|r.get(0),
    )?;
    let header: Header = serde_json::from_str(&json)?;
    if stored(connection, &header)?.is_none() {
        return Err(invalid("conflict baseline binding original parent missing"));
    }
    Ok(())
}
