//! Explicit portable source scope. This description confers no native authority.
use crate::{ModelError, PortablePath, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_RESTORE_SELECTION_PATHS: usize = 64;
pub const MAX_RESTORE_SELECTION_PATH_BYTES: usize = 16_384;

/// Current-only entries are preserved unless a replacement layout is requested.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreCurrentExtraPolicy {
    #[default]
    Preserve,
    ReplaceSelectedScope,
}

/// Occupied files require an explicit policy even in an inert description.
/// Type, ancestor and case collisions always remain conflicts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreOccupiedTargetPolicy {
    #[default]
    ReportConflicts,
    ReplaceFiles,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestoreSelection {
    Full,
    File {
        path: PortablePath,
    },
    Directory {
        path: PortablePath,
    },
    /// Each exact historical path selects its file or complete directory subtree.
    Paths {
        paths: Vec<PortablePath>,
    },
}

// An empty struct variant checks every field in the tagged map. Serde's unit
// variant does not enforce deny_unknown_fields for the public Full variant.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RestoreSelectionWire {
    Full {},
    File {
        path: PortablePath,
    },
    Directory {
        path: PortablePath,
    },
    Paths {
        paths: Vec<PortablePath>,
    },
}

impl<'de> Deserialize<'de> for RestoreSelection {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match RestoreSelectionWire::deserialize(deserializer)? {
            RestoreSelectionWire::Full {} => Self::Full,
            RestoreSelectionWire::File { path } => Self::File { path },
            RestoreSelectionWire::Directory { path } => Self::Directory { path },
            RestoreSelectionWire::Paths { paths } => Self::Paths { paths },
        })
    }
}

impl RestoreSelection {
    pub fn validate(&self) -> Result<()> {
        let paths = self.explicit_paths();
        if matches!(self, Self::Paths { .. }) && paths.is_empty()
            || paths.len() > MAX_RESTORE_SELECTION_PATHS
            || paths.iter().map(|path| path.as_str().len()).sum::<usize>()
                > MAX_RESTORE_SELECTION_PATH_BYTES
        {
            return Err(ModelError::InvalidData(
                "bounded explicit restore selection",
            ));
        }
        let mut seen = BTreeSet::new();
        if paths.iter().any(|path| !seen.insert(*path)) {
            return Err(ModelError::InvalidData("duplicate restore selection path"));
        }
        Ok(())
    }

    pub fn explicit_paths(&self) -> Vec<&PortablePath> {
        match self {
            Self::Full => Vec::new(),
            Self::File { path } | Self::Directory { path } => vec![path],
            Self::Paths { paths } => paths.iter().collect(),
        }
    }
}

/// A complete component prefix; selecting `a` never selects `ab` or `a-b`.
pub fn contains_component_path(root: &PortablePath, candidate: &PortablePath) -> bool {
    let mut components = candidate.as_str().split('/');
    root.as_str()
        .split('/')
        .all(|part| components.next() == Some(part))
}

/// Keep the entire portable source path below an independent destination prefix.
pub fn destination_path(
    prefix: Option<&PortablePath>,
    source: &PortablePath,
) -> Result<PortablePath> {
    match prefix {
        Some(prefix) => PortablePath::new(format!("{prefix}/{source}")),
        None => Ok(source.clone()),
    }
}

/// Recover a source-relative name only inside the exact component destination.
pub fn source_relative_path(
    prefix: Option<&PortablePath>,
    destination: &PortablePath,
) -> Option<PortablePath> {
    match prefix {
        None => Some(destination.clone()),
        Some(prefix) if contains_component_path(prefix, destination) => {
            let components = prefix.as_str().split('/').count();
            let remainder = destination
                .as_str()
                .split('/')
                .skip(components)
                .collect::<Vec<_>>()
                .join("/");
            PortablePath::new(remainder).ok()
        }
        Some(_) => None,
    }
}
