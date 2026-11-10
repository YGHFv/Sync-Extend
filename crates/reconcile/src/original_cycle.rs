//! Bounded two-way original pages followed by an explicitly opted-in resolution.
use crate::{LocalSpace, OriginalExchangeReceipt, ReconcileError, Result};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::{ContentId, DeviceId, EntryId, SpaceId, PROTOCOL_VERSION};
use sync_extend_transport::{Connection, SignedOriginalConflictTargetReceipt};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    protocol_version: u32,
    space_id: SpaceId,
    initiator: DeviceId,
    receiver: DeviceId,
    channel_binding: ContentId,
    rounds: u32,
    resolve_at_ms: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionChoice {
    transaction: Option<EntryId>,
}

#[derive(Serialize)]
pub struct OriginalPairedCycle {
    pub completed_rounds: u32,
    pub pulled: Vec<OriginalExchangeReceipt>,
    pub served: Vec<OriginalExchangeReceipt>,
    pub retained_resolution_acknowledged: Vec<SignedOriginalConflictTargetReceipt>,
    pub resolution_acknowledged: Option<SignedOriginalConflictTargetReceipt>,
    pub whole_space_converged: bool,
    pub remote_backup_complete: bool,
}

impl LocalSpace {
    pub async fn exchange_original_paired_cycle(
        &mut self,
        connection: &mut Connection,
        rounds: u32,
        resolve_at_ms: Option<u64>,
    ) -> Result<OriginalPairedCycle> {
        let hello = Hello {
            protocol_version: PROTOCOL_VERSION,
            space_id: self.space_id.clone(),
            initiator: self.device_id.clone(),
            receiver: connection.peer_identity().device_id.clone(),
            channel_binding: connection.channel_binding().clone(),
            rounds,
            resolve_at_ms,
        };
        if !(1..=64).contains(&rounds) || resolve_at_ms.is_some_and(|time| time > i64::MAX as u64) {
            return Err(ReconcileError::Invariant(
                "original paired cycle round/time limits",
            ));
        }
        connection.send_json(&hello).await?;
        if connection.receive_json::<Hello>().await? != hello {
            return Err(ReconcileError::Invariant(
                "original paired cycle handshake differs",
            ));
        }
        self.original_paired_cycle_inner(connection, hello, true)
            .await
    }

    pub async fn serve_original_paired_cycle(
        &mut self,
        connection: &mut Connection,
        max_rounds: u32,
        allow_resolution: bool,
    ) -> Result<OriginalPairedCycle> {
        let hello: Hello = connection.receive_json().await?;
        if !(1..=64).contains(&max_rounds)
            || hello.rounds == 0
            || hello.rounds > max_rounds
            || hello.protocol_version != PROTOCOL_VERSION
            || hello.space_id != self.space_id
            || hello.initiator != connection.peer_identity().device_id
            || hello.receiver != self.device_id
            || hello.channel_binding != *connection.channel_binding()
            || hello
                .resolve_at_ms
                .is_some_and(|time| time > i64::MAX as u64 || !allow_resolution)
        {
            return Err(ReconcileError::Invariant(
                "original paired cycle unapproved bounds/resolution",
            ));
        }
        connection.send_json(&hello).await?;
        self.original_paired_cycle_inner(connection, hello, false)
            .await
    }

    async fn original_paired_cycle_inner(
        &mut self,
        connection: &mut Connection,
        hello: Hello,
        initiator: bool,
    ) -> Result<OriginalPairedCycle> {
        self.verify_root()?;
        if self.read_transport_peer(&connection.peer_identity().device_id)?
            != *connection.peer_identity()
        {
            return Err(ReconcileError::Invariant(
                "original paired cycle current approval",
            ));
        }
        let mut result = OriginalPairedCycle {
            completed_rounds: 0,
            pulled: Vec::new(),
            served: Vec::new(),
            retained_resolution_acknowledged: Vec::new(),
            resolution_acknowledged: None,
            whole_space_converged: false,
            remote_backup_complete: false,
        };
        // A lost receipt must not cause the same resolver prefix to be exported
        // as ordinary originals on reconnect. Exchange immutable admissions first.
        for source in [true, false] {
            if initiator == source {
                let mut own = Vec::new();
                for admission in self.conflict_resolution_admissions()? {
                    let proof = self
                        .journal
                        .conflict_resolution_proof(&admission.transaction_id)?;
                    if proof.payload.resolver_device == self.device_id {
                        if !admission.resolution_applied {
                            return Err(ReconcileError::Invariant(
                                "original paired cycle unresolved retained admission",
                            ));
                        }
                        own.push(admission.transaction_id);
                    }
                }
                if own.len() > 1 {
                    return Err(ReconcileError::ResourceLimit(
                        "original paired cycle retained resolution bounds",
                    ));
                }
                let id = own.pop();
                connection
                    .send_json(&ResolutionChoice {
                        transaction: id.clone(),
                    })
                    .await?;
                if let Some(id) = id {
                    result.retained_resolution_acknowledged.push(
                        self.serve_original_conflict_resolution(connection, &id)
                            .await?,
                    );
                }
            } else {
                let choice: ResolutionChoice = connection.receive_json_after_application().await?;
                if choice.transaction.is_some() {
                    result
                        .retained_resolution_acknowledged
                        .push(self.pull_original_conflict_resolution(connection).await?);
                }
            }
        }
        for _ in 0..hello.rounds {
            if initiator {
                let after = self.original_worker_after(&connection.peer_identity().device_id)?;
                result
                    .pulled
                    .push(self.pull_original_exchange(connection, after).await?);
                result
                    .served
                    .push(self.serve_original_exchange(connection).await?);
            } else {
                result
                    .served
                    .push(self.serve_original_exchange(connection).await?);
                let after = self.original_worker_after(&connection.peer_identity().device_id)?;
                result
                    .pulled
                    .push(self.pull_original_exchange(connection, after).await?);
            }
            result.completed_rounds += 1;
        }
        if initiator {
            let candidate = if let Some(time) = hello.resolve_at_ms {
                if !self.conflict_resolution_admissions()?.is_empty() {
                    if result
                        .pulled
                        .iter()
                        .chain(&result.served)
                        .any(|r| r.received.is_some() && r.applied.is_none())
                    {
                        return Err(ReconcileError::Invariant(
                            "original paired cycle new conflict after retained resolution requires explicit policy",
                        ));
                    }
                    connection
                        .send_json(&ResolutionChoice { transaction: None })
                        .await?;
                    self.verify_root()?;
                    return Ok(result);
                }
                let originals = self.retained_original_conflict_bundle(Default::default())?;
                let operations: Vec<_> = originals.iter().map(|s| s.operation.clone()).collect();
                let plan = sync_extend_core_model::conflict_resolution::plan_file_resolution(
                    &self.space_id,
                    &operations,
                    Default::default(),
                )?;
                if plan.events.is_empty() {
                    None
                } else {
                    Some(
                        self.apply_retained_original_file_conflict(time, Default::default())?
                            .transaction_id,
                    )
                }
            } else {
                None
            };
            connection
                .send_json(&ResolutionChoice {
                    transaction: candidate.clone(),
                })
                .await?;
            if let Some(id) = candidate {
                result.resolution_acknowledged = Some(
                    self.serve_original_conflict_resolution(connection, &id)
                        .await?,
                );
            }
        } else {
            // The initiator completes its durable native Final before choosing
            // an export. Keep the application wait bounded, not ordinary 30s I/O.
            let choice: ResolutionChoice = connection.receive_json_after_application().await?;
            if choice.transaction.is_some() && hello.resolve_at_ms.is_none() {
                return Err(ReconcileError::Invariant(
                    "original paired cycle resolution not opted in",
                ));
            }
            if choice.transaction.is_some() {
                result.resolution_acknowledged =
                    Some(self.pull_original_conflict_resolution(connection).await?);
            }
        }
        self.verify_root()?;
        Ok(result)
    }
}
