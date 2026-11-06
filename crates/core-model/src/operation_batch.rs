//! Authenticated own-origin log pages; reception is not materialization.
use crate::{ContentId, DeviceId, ModelError, Operation, Result, SpaceId, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

pub const MAX_OPERATION_BATCH: usize = 64;
pub const MAX_OPERATION_BATCH_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationBatch {
    pub protocol_version: u32,
    pub space_id: SpaceId,
    pub origin_device: DeviceId,
    pub after_sequence: u64,
    pub tip_sequence: u64,
    pub operations: Vec<Operation>,
}

impl OperationBatch {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION
            || self.operations.len() > MAX_OPERATION_BATCH
            || self.after_sequence > self.tip_sequence
            || self.tip_sequence > i64::MAX as u64
        {
            return Err(ModelError::InvalidData("operation batch bounds"));
        }
        let mut sequence = self.after_sequence;
        for operation in &self.operations {
            operation.validate()?;
            sequence = sequence
                .checked_add(1)
                .ok_or(ModelError::InvalidData("operation batch sequence overflow"))?;
            if operation.payload.space_id != self.space_id
                || operation.payload.origin_device_id != self.origin_device
                || operation.payload.origin_seq != sequence
                || sequence > self.tip_sequence
            {
                return Err(ModelError::InvalidData(
                    "operation batch origin or continuity",
                ));
            }
        }
        if self.operations.is_empty() && self.after_sequence != self.tip_sequence {
            return Err(ModelError::InvalidData("operation batch falsely empty"));
        }
        if serde_json::to_vec(self)?.len() > MAX_OPERATION_BATCH_BYTES {
            return Err(ModelError::InvalidData("operation batch encoded bytes"));
        }
        Ok(())
    }

    pub fn request_id(&self) -> Result<ContentId> {
        self.validate()?;
        Ok(ContentId::hash(&serde_json::to_vec(&(
            "SyncExtend own-origin operation batch v1",
            self,
        ))?))
    }

    pub fn last_sequence(&self) -> Result<u64> {
        self.validate()?;
        Ok(self
            .operations
            .last()
            .map_or(self.after_sequence, |operation| {
                operation.payload.origin_seq
            }))
    }
}
