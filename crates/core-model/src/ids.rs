use crate::{ModelError, Result};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

macro_rules! identifier {
    ($name:ident, $length:expr) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = ModelError;
            fn try_from(value: String) -> Result<Self> {
                if value.len() != $length
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(ModelError::InvalidId);
                }
                Ok(Self(value))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }

        impl FromStr for $name {
            type Err = ModelError;
            fn from_str(value: &str) -> Result<Self> {
                Self::try_from(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier!(SpaceId, 32);
identifier!(EntryId, 32);
identifier!(DeviceId, 64);
identifier!(ContentId, 64);
identifier!(OperationId, 64);
identifier!(SnapshotId, 64);

fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ModelError::Random)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl SpaceId {
    pub fn random() -> Result<Self> {
        random_id()?.parse()
    }
}

impl EntryId {
    pub fn random() -> Result<Self> {
        random_id()?.parse()
    }
}

impl DeviceId {
    pub fn from_public_key(key: &[u8; 32]) -> Self {
        Self(
            blake3::derive_key("SyncExtend device identity v1", key)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
}

impl ContentId {
    pub fn hash(data: &[u8]) -> Self {
        Self(blake3::hash(data).to_hex().to_string())
    }

    pub fn from_hasher(hasher: &blake3::Hasher) -> Self {
        Self(hasher.finalize().to_hex().to_string())
    }
}

impl OperationId {
    pub(crate) fn hash(data: &[u8]) -> Self {
        Self(
            blake3::derive_key("SyncExtend operation v1", data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
}

impl SnapshotId {
    pub fn hash(data: &[u8]) -> Self {
        Self(
            blake3::derive_key("SyncExtend snapshot v1", data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        )
    }
}
