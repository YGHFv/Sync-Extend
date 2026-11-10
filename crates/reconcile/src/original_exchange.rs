//! One bounded original content/metadata/native exchange, not an unattended loop.
#[cfg(windows)]
use crate::{LocalSpace, OriginalApplyState, ReconcileError, Result};
#[cfg(windows)]
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use sync_extend_core_model::{ContentId, PROTOCOL_VERSION};
#[cfg(windows)]
use sync_extend_transport::{
    Connection, SignedOriginalPageAppliedReceipt, SignedOriginalPageReceiveReceipt,
};

#[cfg(windows)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalExchangeReceipt {
    pub protocol_version: u32,
    pub request_id: ContentId,
    pub received: Option<SignedOriginalPageReceiveReceipt>,
    pub applied: Option<SignedOriginalPageAppliedReceipt>,
    pub target_refusal: Option<String>,
}

#[cfg(windows)]
impl LocalSpace {
    pub async fn serve_original_exchange(
        &self,
        connection: &mut Connection,
    ) -> Result<OriginalExchangeReceipt> {
        let signed = self.serve_original_content_page_inner(connection).await?;
        let outcome: OriginalExchangeReceipt = connection.receive_json_after_application().await?;
        let request = signed
            .page
            .request_id()
            .map_err(|_| ReconcileError::Invariant("original exchange request identity"))?;
        if outcome.protocol_version != PROTOCOL_VERSION
            || outcome.request_id != request
            || outcome
                .target_refusal
                .as_ref()
                .is_some_and(|s| s.len() > 4096)
            || self.read_transport_peer(&connection.peer_identity().device_id)?
                != *connection.peer_identity()
        {
            return Err(ReconcileError::Invariant(
                "original exchange target outcome binding",
            ));
        }
        if let Some(received) = &outcome.received {
            received
                .verify(connection.peer_identity(), &signed.page)
                .map_err(|_| {
                    ReconcileError::Invariant("original received target outcome signature")
                })?;
        }
        if let Some(applied) = &outcome.applied {
            if outcome.received.is_none() || outcome.target_refusal.is_some() {
                return Err(ReconcileError::Invariant(
                    "original applied outcome lacks complete received",
                ));
            }
            applied
                .verify(connection.peer_identity(), &signed.page)
                .map_err(|_| {
                    ReconcileError::Invariant("original applied target outcome signature")
                })?;
        }
        connection.send_json(&request).await?;
        Ok(outcome)
    }

    pub async fn pull_original_exchange(
        &mut self,
        connection: &mut Connection,
        after: u64,
    ) -> Result<OriginalExchangeReceipt> {
        let pulled = self.pull_original_content_page(connection, after).await?;
        let request = pulled.preparation.page_request_id;
        let mut outcome = OriginalExchangeReceipt {
            protocol_version: PROTOCOL_VERSION,
            request_id: request.clone(),
            received: None,
            applied: None,
            target_refusal: None,
        };
        let attempt = (|| -> Result<()> {
            if pulled.signed_page.page.operations.is_empty() {
                return Err(ReconcileError::Invariant(
                    "original exchange idle tip has no new page receipt",
                ));
            }
            let received = self.receive_original_page(&request)?;
            outcome.received = received.signed_receipt;
            if outcome.received.is_none() {
                return Err(ReconcileError::Invariant(
                    "original exchange received gap remains pending",
                ));
            }
            for signed in &pulled.signed_page.page.operations {
                let applied = self.apply_original_operation(&request, &signed.operation.op_id)?;
                if !matches!(
                    applied.state,
                    OriginalApplyState::Applied | OriginalApplyState::AlreadyApplied
                ) {
                    return Err(ReconcileError::Invariant(
                        "original exchange native action remains pending",
                    ));
                }
            }
            outcome.applied = Some(self.original_applied_receipt(&request)?);
            Ok(())
        })();
        if let Err(error) = attempt {
            let mut text = error.to_string();
            while text.len() > 4096 {
                text.pop();
            }
            outcome.target_refusal = Some(text);
        }
        connection.send_json(&outcome).await?;
        let acknowledged: ContentId = connection.receive_json().await?;
        if acknowledged != request {
            return Err(ReconcileError::Invariant(
                "original exchange acknowledgement differs",
            ));
        }
        Ok(outcome)
    }
}
