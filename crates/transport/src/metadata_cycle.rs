//! Explicit metadata-only cycle negotiation on an already authenticated stream.
use crate::{PeerIdentity, Result, TransportError};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{DeviceId, SpaceId, PROTOCOL_VERSION};

pub const MAX_METADATA_CYCLE_ROUNDS: u32 = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataCycleHello {
    pub protocol_version: u32,
    pub mode: String,
    pub space_id: SpaceId,
    pub initiator_device: DeviceId,
    pub responder_device: DeviceId,
    pub rounds: u32,
}

impl MetadataCycleHello {
    pub fn new(initiator: &PeerIdentity, responder: &PeerIdentity, rounds: u32) -> Result<Self> {
        let hello = Self {
            protocol_version: PROTOCOL_VERSION,
            mode: "own-origin-metadata-only-v1".into(),
            space_id: initiator.space_id.clone(),
            initiator_device: initiator.device_id.clone(),
            responder_device: responder.device_id.clone(),
            rounds,
        };
        hello.validate(initiator, responder, MAX_METADATA_CYCLE_ROUNDS)?;
        Ok(hello)
    }

    pub fn validate(
        &self,
        initiator: &PeerIdentity,
        responder: &PeerIdentity,
        max_rounds: u32,
    ) -> Result<()> {
        initiator.validate()?;
        responder.validate()?;
        if max_rounds == 0
            || max_rounds > MAX_METADATA_CYCLE_ROUNDS
            || self.rounds == 0
            || self.rounds > max_rounds
            || self.protocol_version != PROTOCOL_VERSION
            || self.mode != "own-origin-metadata-only-v1"
            || self.space_id != initiator.space_id
            || self.space_id != responder.space_id
            || self.initiator_device != initiator.device_id
            || self.responder_device != responder.device_id
            || self.initiator_device == self.responder_device
        {
            return Err(TransportError::Authorization(
                "metadata cycle negotiation scope",
            ));
        }
        Ok(())
    }
}
