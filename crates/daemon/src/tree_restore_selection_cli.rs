//! Explicit TREE selection is a new operation, never authority from a preview.
//! Capability and portable argument checks precede all ordinary startup effects.
use super::{Cli, Command};
use sync_extend_core_model::{
    tree_restore::TreeRestoreSelection, PortablePath, RestoreCurrentExtraPolicy,
    RestoreOccupiedTargetPolicy, RestoreSelection, FORMAT_VERSION,
};

#[derive(Clone, Debug, Default, clap::Args)]
pub struct SelectionArguments {
    #[arg(long, conflicts_with_all = ["directory", "select_path"])]
    pub path: Option<String>,
    #[arg(long, conflicts_with_all = ["path", "select_path"])]
    pub directory: Option<String>,
    #[arg(long, conflicts_with_all = ["path", "directory"])]
    pub select_path: Vec<String>,
    /// Keep the entire historical path below an existing current directory.
    #[arg(long)]
    pub destination_prefix: Option<String>,
    #[arg(long, value_parser = ["preserve", "replace-selected-scope"])]
    pub current_extra_policy: Option<String>,
    #[arg(long, value_parser = ["report-conflicts", "replace-files"])]
    pub occupied_target_policy: Option<String>,
    /// Select Full under the explicit preserve/conflict policy contract.
    #[arg(long)]
    pub selection_v2: bool,
}

impl SelectionArguments {
    pub fn is_explicit(&self) -> bool {
        self.selection_v2
            || self.path.is_some()
            || self.directory.is_some()
            || !self.select_path.is_empty()
            || self.destination_prefix.is_some()
            || self.current_extra_policy.is_some()
            || self.occupied_target_policy.is_some()
    }

    pub fn parse(&self) -> Result<Option<TreeRestoreSelection>, Box<dyn std::error::Error>> {
        if !self.is_explicit() {
            return Ok(None);
        }
        if usize::from(self.path.is_some())
            + usize::from(self.directory.is_some())
            + usize::from(!self.select_path.is_empty())
            > 1
        {
            return Err("TREE selection modes are mutually exclusive".into());
        }
        let selection = if let Some(path) = &self.path {
            RestoreSelection::File {
                path: PortablePath::new(path.clone())?,
            }
        } else if let Some(path) = &self.directory {
            RestoreSelection::Directory {
                path: PortablePath::new(path.clone())?,
            }
        } else if !self.select_path.is_empty() {
            RestoreSelection::Paths {
                paths: self
                    .select_path
                    .iter()
                    .map(|path| PortablePath::new(path.clone()))
                    .collect::<Result<_, _>>()?,
            }
        } else {
            RestoreSelection::Full
        };
        let current_extra_policy = match self.current_extra_policy.as_deref() {
            None | Some("preserve") => RestoreCurrentExtraPolicy::Preserve,
            Some("replace-selected-scope") => RestoreCurrentExtraPolicy::ReplaceSelectedScope,
            Some(_) => return Err("unsupported TREE current extra policy".into()),
        };
        let occupied_target_policy = match self.occupied_target_policy.as_deref() {
            None | Some("report-conflicts") => RestoreOccupiedTargetPolicy::ReportConflicts,
            Some("replace-files") => RestoreOccupiedTargetPolicy::ReplaceFiles,
            Some(_) => return Err("unsupported TREE occupied target policy".into()),
        };
        let selection = TreeRestoreSelection {
            format_version: FORMAT_VERSION,
            selection,
            destination_prefix: self
                .destination_prefix
                .as_ref()
                .map(|path| PortablePath::new(path.clone()))
                .transpose()?,
            current_extra_policy,
            occupied_target_policy,
        };
        selection.validate()?;
        Ok(Some(selection))
    }
}

pub fn precheck(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let Command::TreePrepare { selection, .. } = &cli.command else {
        return Ok(());
    };
    if !selection.is_explicit() {
        return Ok(());
    }
    if !cfg!(windows) {
        return Err("native TREE selection restore is available only on Windows".into());
    }
    // This check reads no pathname, global budget/config, Journal or CAS.
    let _ = selection.parse()?;
    Ok(())
}
