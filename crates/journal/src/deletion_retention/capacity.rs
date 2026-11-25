use crate::{
    JournalError, JournalStorageColumn, JournalStorageColumnValue as Value, Result,
    storage_capacity::CapacitySnapshot,
};
use std::collections::BTreeMap;
use sync_extend_core_model::tree_storage_capacity::TreeStorageCharge;

pub(super) type Key = (String, Vec<String>);
pub(super) type Changes = BTreeMap<Key, Vec<JournalStorageColumn>>;

pub(super) fn text(name: &str, value: &str) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: Value::Text(value.into()),
    }
}

pub(super) fn number(name: &str, value: u64) -> JournalStorageColumn {
    JournalStorageColumn {
        name: name.into(),
        value: Value::Integer(value),
    }
}

fn charge(columns: &[JournalStorageColumn]) -> Result<u64> {
    columns.iter().try_fold(0u64, |sum, column| {
        let bytes = match &column.value {
            Value::Null => 0,
            Value::Integer(_) => 8,
            Value::Text(text) => text.len() as u64,
        };
        sum.checked_add(bytes)
            .ok_or(JournalError::Invariant("retention metadata byte overflow"))
    })
}

pub(super) struct Projection {
    expected: Changes,
    charge: TreeStorageCharge,
}

impl Projection {
    pub(super) fn new(before: &CapacitySnapshot, changes: Changes) -> Result<Self> {
        let mut expected: Changes = before
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().into(), row.primary_key().to_vec()),
                    row.columns().to_vec(),
                )
            })
            .collect();
        let mut total = before.report.accounted_total();
        if !before.report.within_accounted_limits() {
            return Err(JournalError::RetentionAdmissionDeferred(
                "existing journal capacity exhausted",
            ));
        }
        for (key, columns) in changes {
            if !key.0.starts_with("deletion_retention_") {
                return Err(JournalError::Invariant(
                    "retention projection changes unrelated family",
                ));
            }
            let prior = expected.insert(key, columns.clone());
            if let Some(prior) = prior {
                total.logical_bytes = total.logical_bytes.checked_sub(charge(&prior)?).ok_or(
                    JournalError::Invariant("retention metadata charge underflow"),
                )?;
            } else {
                total.rows = total
                    .rows
                    .checked_add(1)
                    .ok_or(JournalError::Invariant("retention metadata row overflow"))?;
            }
            total.logical_bytes = total.logical_bytes.checked_add(charge(&columns)?).ok_or(
                JournalError::Invariant("retention metadata charge overflow"),
            )?;
        }
        let limits = before.report.limits();
        if total.rows > limits.max_rows || total.logical_bytes > limits.max_logical_bytes {
            return Err(JournalError::RetentionAdmissionDeferred(
                "retention metadata peak exceeds capacity",
            ));
        }
        Ok(Self {
            expected,
            charge: total,
        })
    }

    pub(super) fn verify(&self, after: &CapacitySnapshot) -> Result<()> {
        let actual: Changes = after
            .rows
            .iter()
            .map(|row| {
                (
                    (row.table().into(), row.primary_key().to_vec()),
                    row.columns().to_vec(),
                )
            })
            .collect();
        if actual != self.expected
            || after.report.accounted_total() != self.charge
            || !after.report.within_accounted_limits()
        {
            return Err(JournalError::Invariant(
                "retention exact row/logical capacity transition differs",
            ));
        }
        Ok(())
    }
}
