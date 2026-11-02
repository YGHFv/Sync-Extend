use crate::{ModelError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PortablePath(String);

impl PortablePath {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 || value.split('/').count() > 128 {
            return Err(ModelError::InvalidPath("empty or excessive path"));
        }
        if value.nfc().collect::<String>() != value {
            return Err(ModelError::InvalidPath("path must be NFC normalized"));
        }
        for component in value.split('/') {
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.len() > 255
                || component.ends_with(['.', ' '])
                || component
                    .chars()
                    .any(|c| c.is_control() || "<>:\"\\|?*".contains(c))
            {
                return Err(ModelError::InvalidPath("unsafe component"));
            }
            let stem = component.split('.').next().unwrap_or("").to_uppercase();
            if matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
            ) || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
                })
            }) || component.eq_ignore_ascii_case(".sync-tmp")
                || component.eq_ignore_ascii_case(".sync-extend")
                || component.eq_ignore_ascii_case(".git")
                || matches!(
                    stem.as_str(),
                    "COM¹" | "COM²" | "COM³" | "LPT¹" | "LPT²" | "LPT³"
                )
            {
                return Err(ModelError::InvalidPath("reserved component"));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn collision_key(&self) -> String {
        self.0.to_uppercase()
    }

    pub fn parent(&self) -> Option<Self> {
        self.0
            .rsplit_once('/')
            .map(|(parent, _)| Self(parent.to_owned()))
    }
}

impl TryFrom<String> for PortablePath {
    type Error = ModelError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<PortablePath> for String {
    fn from(value: PortablePath) -> String {
        value.0
    }
}

impl fmt::Display for PortablePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
