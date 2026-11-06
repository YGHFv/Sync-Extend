use crate::{
    sql_integer, Journal, JournalError, MutationAction, MutationExecution, MutationState, Result,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sync_extend_core_model::*;

const MAX_CLEANUP_BYTES: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupIntent {
    pub format_version: u32,
    pub transaction_id: EntryId,
    pub space_id: SpaceId,
    pub execution: MutationExecution,
    pub base_identity: ContentId,
    pub created_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Prepared,
    Cancelled,
    Executing,
    Cleaned,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupPlan {
    pub intent: CleanupIntent,
    pub state: CleanupState,
    pub authorized_at_ms: Option<u64>,
    pub cleaned_at_ms: Option<u64>,
}

impl Journal {
    fn validate_cleanup_intent(&self, intent: &CleanupIntent) -> Result<()> {
        self.read_view().validate_cleanup_intent(intent)
    }

    pub fn cleanup_plan(&self, id: &EntryId) -> Result<Option<CleanupPlan>> {
        self.read_view().cleanup_plan(id)
    }

    pub fn cleanup_plans(&self, space: &SpaceId) -> Result<Vec<CleanupPlan>> {
        self.read_view().cleanup_plans(space)
    }

    pub fn prepare_cleanup(&mut self, intent: &CleanupIntent) -> Result<CleanupPlan> {
        self.validate_cleanup_intent(intent)?;
        if let Some(plan) = self.cleanup_plan(&intent.transaction_id)? {
            if plan.intent != *intent {
                return Err(JournalError::Invariant("cleanup plan already exists"));
            }
            return Ok(plan);
        }
        let json = serde_json::to_string(intent)?;
        if json.len() > MAX_CLEANUP_BYTES {
            return Err(JournalError::Invariant("cleanup metadata limit"));
        }
        self.connection.execute(
            "INSERT INTO cleanup_plans(transaction_id,space_id,intent,intent_hash,state)
             VALUES (?1,?2,?3,?4,'prepared')",
            params![
                intent.transaction_id.as_str(),
                intent.space_id.as_str(),
                json,
                ContentId::hash(json.as_bytes()).as_str()
            ],
        )?;
        self.cleanup_plan(&intent.transaction_id)?
            .ok_or(JournalError::Invariant("cleanup plan disappeared"))
    }

    pub fn cancel_cleanup(&mut self, space: &SpaceId, id: &EntryId) -> Result<()> {
        let plan = self.require_cleanup(space, id)?;
        if plan.state == CleanupState::Cancelled {
            return Ok(());
        }
        if plan.state != CleanupState::Prepared || self.connection.execute(
            "UPDATE cleanup_plans SET state='cancelled' WHERE transaction_id=?1 AND state='prepared'",
            [id.as_str()],
        )? != 1 {
            return Err(JournalError::Invariant("only prepared cleanup can cancel"));
        }
        Ok(())
    }

    pub fn start_cleanup(&mut self, space: &SpaceId, id: &EntryId, timestamp: u64) -> Result<()> {
        let plan = self.require_cleanup(space, id)?;
        if matches!(plan.state, CleanupState::Executing | CleanupState::Cleaned) {
            return Ok(());
        }
        if plan.state != CleanupState::Prepared || timestamp < plan.intent.created_at_ms {
            return Err(JournalError::Invariant("only prepared cleanup can execute"));
        }
        if self.connection.execute(
            "UPDATE cleanup_plans SET state='executing',authorized_at_ms=?2
             WHERE transaction_id=?1 AND state='prepared'",
            params![id.as_str(), sql_integer(timestamp)?],
        )? != 1
        {
            return Err(JournalError::Invariant("cleanup state changed"));
        }
        Ok(())
    }

    pub fn finish_cleanup(&mut self, space: &SpaceId, id: &EntryId, timestamp: u64) -> Result<()> {
        let plan = self.require_cleanup(space, id)?;
        if plan.state == CleanupState::Cleaned {
            return Ok(());
        }
        if plan.state != CleanupState::Executing
            || plan.authorized_at_ms.is_none_or(|t| timestamp < t)
        {
            return Err(JournalError::Invariant("cleanup is not authorized"));
        }
        if self.connection.execute(
            "UPDATE cleanup_plans SET state='cleaned',cleaned_at_ms=?2
             WHERE transaction_id=?1 AND state='executing'",
            params![id.as_str(), sql_integer(timestamp)?],
        )? != 1
        {
            return Err(JournalError::Invariant("cleanup state changed"));
        }
        Ok(())
    }

    fn require_cleanup(&self, space: &SpaceId, id: &EntryId) -> Result<CleanupPlan> {
        let plan = self
            .cleanup_plan(id)?
            .ok_or(JournalError::Invariant("cleanup plan does not exist"))?;
        if plan.intent.space_id != *space {
            return Err(JournalError::Invariant("cleanup belongs to another space"));
        }
        Ok(plan)
    }
}

impl crate::JournalReadView<'_> {
    pub(crate) fn validate_cleanup_intent(&self, intent: &CleanupIntent) -> Result<()> {
        let mutation = self.mutation(&intent.transaction_id)?;
        self.verify_mutation_references(&intent.transaction_id)?;
        if intent.format_version != FORMAT_VERSION
            || intent.space_id != mutation.intent.space_id
            || mutation.state != MutationState::Committed
            || !matches!(mutation.intent.action, MutationAction::Move { .. })
            || mutation.execution.as_ref() != Some(&intent.execution)
            || intent.created_at_ms < mutation.intent.created_at_ms
        {
            return Err(JournalError::Invariant(
                "cleanup requires the exact committed Move execution",
            ));
        }
        sql_integer(intent.created_at_ms)?;
        Ok(())
    }

    pub(crate) fn cleanup_plan(&self, id: &EntryId) -> Result<Option<CleanupPlan>> {
        let length: Option<i64> = self
            .connection
            .query_row(
                "SELECT length(CAST(intent AS BLOB)) FROM cleanup_plans WHERE transaction_id=?1",
                [id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        let Some(length) = length else {
            return Ok(None);
        };
        if !(1..=MAX_CLEANUP_BYTES as i64).contains(&length) {
            return Err(JournalError::Invariant("cleanup metadata limit"));
        }
        let (space, json, hash, state, authorized, cleaned): (
            String,
            String,
            String,
            String,
            Option<i64>,
            Option<i64>,
        ) = self.connection.query_row(
            "SELECT space_id,intent,intent_hash,state,authorized_at_ms,cleaned_at_ms
                 FROM cleanup_plans WHERE transaction_id=?1",
            [id.as_str()],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )?;
        let intent: CleanupIntent = serde_json::from_str(&json)?;
        if intent.transaction_id != *id
            || intent.space_id.as_str() != space
            || ContentId::hash(json.as_bytes()).as_str() != hash
        {
            return Err(JournalError::Invariant("cleanup intent integrity mismatch"));
        }
        self.validate_cleanup_intent(&intent)?;
        let state = match state.as_str() {
            "prepared" => CleanupState::Prepared,
            "cancelled" => CleanupState::Cancelled,
            "executing" => CleanupState::Executing,
            "cleaned" => CleanupState::Cleaned,
            _ => return Err(JournalError::Invariant("unsupported cleanup state")),
        };
        let authorized_at_ms = authorized
            .map(u64::try_from)
            .transpose()
            .map_err(|_| JournalError::Invariant("invalid cleanup authorization time"))?;
        let cleaned_at_ms = cleaned
            .map(u64::try_from)
            .transpose()
            .map_err(|_| JournalError::Invariant("invalid cleanup completion time"))?;
        if matches!(state, CleanupState::Executing | CleanupState::Cleaned)
            != authorized_at_ms.is_some()
            || (state == CleanupState::Cleaned) != cleaned_at_ms.is_some()
            || authorized_at_ms.is_some_and(|t| t < intent.created_at_ms)
            || cleaned_at_ms
                .zip(authorized_at_ms)
                .is_some_and(|(c, a)| c < a)
        {
            return Err(JournalError::Invariant("cleanup phase/time mismatch"));
        }
        Ok(Some(CleanupPlan {
            intent,
            state,
            authorized_at_ms,
            cleaned_at_ms,
        }))
    }

    pub(crate) fn cleanup_plans(&self, space: &SpaceId) -> Result<Vec<CleanupPlan>> {
        let mut statement = self.connection.prepare(
            "SELECT transaction_id FROM cleanup_plans WHERE space_id=?1 ORDER BY transaction_id",
        )?;
        let ids: Vec<String> = statement
            .query_map([space.as_str()], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        ids.into_iter()
            .map(|id| {
                self.cleanup_plan(&id.parse()?)?
                    .ok_or(JournalError::Invariant("cleanup plan disappeared"))
            })
            .collect()
    }
}
