//! Pair preparation owns both live helpers; it produces observations only.
use super::{private_duplicate, retained_mount_id, OutsideHelperChild, OutsideHelperProgram};
use std::os::unix::fs::MetadataExt;
use std::{
    fs::File,
    io,
    time::{Duration, Instant},
};

mod terminal_release;
pub use terminal_release::{OriginalPairTerminalRelease, OutsideHelperSession};

pub type HelperPipeBytes<'a> = (&'a [u8], &'a [u8]);
pub type PairPipeBytes<'a> = (HelperPipeBytes<'a>, Option<HelperPipeBytes<'a>>);

pub struct OutsidePreparationPair {
    guardian: OutsideHelperChild,
    supervisor: Option<OutsideHelperChild>,
    single_use_attempted: bool,
    supervisor_prepare_attempted: bool,
    terminal_deadline: Option<Instant>,
    guardian_arm_deadline: Option<Instant>,
    guardian_arm_monotonic_ns: Option<u64>,
    original_transaction: Option<String>,
}

impl OutsideHelperProgram {
    /// Start the guardian without ARM. Failures retain the returned preparation
    /// object so its exact unarmed child can be cancelled and its exit verified.
    pub fn start_preparation_pair(
        &self,
        mount: &File,
        owner: &File,
        owner_control: &File,
        owner_pid: u32,
    ) -> io::Result<OutsidePreparationPair> {
        Ok(OutsidePreparationPair {
            guardian: self.prepare_guardian(mount, owner, owner_control, owner_pid, 2)?,
            supervisor: None,
            single_use_attempted: false,
            supervisor_prepare_attempted: false,
            terminal_deadline: None,
            guardian_arm_deadline: None,
            guardian_arm_monotonic_ns: None,
            original_transaction: None,
        })
    }
}

impl OutsidePreparationPair {
    pub fn prepare_supervisor(
        &mut self,
        program: &OutsideHelperProgram,
        mount: &File,
        owner: &File,
        supervisor_control: &File,
        owner_pid: u32,
    ) -> io::Result<()> {
        if self.supervisor.is_some()
            || self.single_use_attempted
            || self.supervisor_prepare_attempted
        {
            return Err(super::super::refusal(
                "single original unarmed preparation pair required",
            ));
        }
        self.supervisor_prepare_attempted = true;
        self.guardian.boundary.verify()?;
        let boundary = &self.guardian.boundary;
        let observed = mount.metadata()?;
        if owner_pid != boundary.owner_pid
            || observed.dev() != boundary.mount_device
            || observed.ino() != boundary.mount_inode
            || retained_mount_id(mount)? != boundary.mount_id
        {
            return Err(super::super::refusal(
                "pair must retain exact first mount and owner",
            ));
        }
        super::super::pidfd_identity(owner, boundary.owner_pid)?;
        let guardian_control = &self.guardian.boundary.control;
        let observed_control = supervisor_control.metadata()?;
        let first_control = guardian_control.metadata()?;
        if observed_control.dev() == first_control.dev()
            && observed_control.ino() == first_control.ino()
        {
            return Err(super::super::refusal(
                "independent original pair control pipes required",
            ));
        }
        let mount = private_duplicate(&boundary.mount)?;
        let owner = private_duplicate(&boundary.owner)?;
        self.guardian.wait_prepared(Duration::from_secs(1))?;
        let guardian_pid = self.guardian.child().id();
        let guardian = self.guardian.prepared_process()?;
        let supervisor = program.prepare_supervisor(
            &mount,
            &owner,
            guardian,
            supervisor_control,
            (owner_pid, guardian_pid),
            3,
        )?;
        // Keep the real child before reading READY, so a refused/short line
        // never discards the only object that can confirm unarmed cancellation.
        self.supervisor = Some(supervisor);
        self.supervisor
            .as_mut()
            .ok_or_else(|| super::super::refusal("original supervisor not retained"))?
            .wait_prepared(Duration::from_secs(1))
    }

    /// This does not freeze a mount or admit a native transaction. If either
    /// ARM fails, both original helpers remain retained for terminal handling.
    pub fn arm_observation(&mut self) -> io::Result<()> {
        if self.single_use_attempted || self.supervisor.is_none() {
            return Err(super::super::refusal(
                "complete single original pair preparation required",
            ));
        }
        self.guardian.prepared_process()?;
        self.supervisor
            .as_ref()
            .ok_or_else(|| super::super::refusal("complete original supervisor required"))?
            .prepared_process()?;
        self.verify_original_pair()?;
        self.single_use_attempted = true;
        // Arm the longer-lived supervisor first; it watches guardian and owner
        // while the guardian's shorter deadline begins after its own ARM.
        self.supervisor
            .as_mut()
            .ok_or_else(|| super::super::refusal("complete original supervisor required"))?
            .arm(Duration::from_secs(1))?;
        self.guardian_arm_deadline = Some(Instant::now() + Duration::from_secs(2));
        self.guardian_arm_monotonic_ns = Some(super::super::monotonic_ns()?);
        self.guardian.arm(Duration::from_secs(1))?;
        self.guardian.retained_process()?;
        self.supervisor
            .as_ref()
            .ok_or_else(|| super::super::refusal("complete original supervisor required"))?
            .retained_process()?;
        Ok(())
    }

    pub fn cancel_unarmed(&mut self) -> io::Result<()> {
        if self.single_use_attempted {
            return Err(super::super::refusal(
                "ARM-attempted pair requires actual terminal recovery",
            ));
        }
        let supervisor = self
            .supervisor
            .as_mut()
            .map(|child| child.cancel_preparation(Duration::from_secs(4)));
        let guardian = self.guardian.cancel_preparation(Duration::from_secs(4));
        if let Some(result) = supervisor {
            result?;
        }
        guardian
    }

    /// Terminalize only this pair after an incomplete ARM. Closing an
    /// unarmed preparation and observing an armed watchdog are separate paths.
    pub(crate) fn observe_refused_terminals(&mut self) -> io::Result<()> {
        // Close every still-unarmed endpoint before waiting for either child.
        // A child already observed during cancellation is never observed twice.
        self.guardian.preparation.take();
        if let Some(supervisor) = self.supervisor.as_mut() {
            supervisor.preparation.take();
        }
        let deadline = Instant::now() + Duration::from_secs(12);
        let guardian = if self.guardian.terminal_observed {
            Ok(())
        } else {
            self.guardian
                .observe_terminal(deadline.saturating_duration_since(Instant::now()))
                .map(|_| ())
        };
        let supervisor = self.supervisor.as_mut().map(|child| {
            if child.terminal_observed {
                Ok(())
            } else {
                child
                    .observe_terminal(deadline.saturating_duration_since(Instant::now()))
                    .map(|_| ())
            }
        });
        guardian?;
        if let Some(observed) = supervisor {
            observed?;
        }
        Ok(())
    }
}

impl OutsidePreparationPair {
    pub(crate) fn original_guardian_arm_deadline(&self) -> io::Result<Instant> {
        self.guardian_arm_deadline
            .ok_or_else(|| super::super::refusal("original guardian ARM deadline absent"))
    }
    pub fn original_guardian_arm_monotonic_ns(&self) -> Option<u64> {
        self.guardian_arm_monotonic_ns
    }
    /// Inspect both live prepared or armed helper process handles. No mutation,
    /// signal, mount operation or new issuer can be constructed from this pair.
    pub fn verify_original_pair(&self) -> io::Result<()> {
        self.guardian.boundary.verify()?;
        super::super::pidfd_identity(&self.guardian.process, self.guardian.child.id())?;
        if let Some(supervisor) = &self.supervisor {
            supervisor.boundary.verify()?;
            super::super::pidfd_identity(&supervisor.process, supervisor.child.id())?;
            if self.guardian.boundary.mount_device != supervisor.boundary.mount_device
                || self.guardian.boundary.mount_inode != supervisor.boundary.mount_inode
                || self.guardian.boundary.mount_id != supervisor.boundary.mount_id
                || self.guardian.boundary.owner_pid != supervisor.boundary.owner_pid
            {
                return Err(super::super::refusal(
                    "pair original mount/owner scope differs",
                ));
            }
        }
        Ok(())
    }
}

impl OutsidePreparationPair {
    /// Return both real terminal observations; a failed guardian is never
    /// ignored merely because the supervisor successfully thawed the mount.
    pub fn observe_terminals(
        &mut self,
    ) -> io::Result<(
        super::OutsideHelperExitObservation,
        Option<super::OutsideHelperExitObservation>,
    )> {
        let deadline = *self
            .terminal_deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(12));
        let guardian = self
            .guardian
            .observe_terminal(deadline.saturating_duration_since(Instant::now()));
        let supervisor = self.supervisor.as_mut().map(|child| {
            child.observe_terminal(deadline.saturating_duration_since(Instant::now()))
        });
        let guardian = guardian?;
        let supervisor = supervisor.transpose()?;
        Ok((guardian, supervisor))
    }
}

impl OutsidePreparationPair {
    /// Retained evidence is available even when one original helper refuses observation.
    pub fn retained_terminal_bytes(&self) -> PairPipeBytes<'_> {
        (
            self.guardian.retained_terminal_bytes(),
            self.supervisor
                .as_ref()
                .map(OutsideHelperChild::retained_terminal_bytes),
        )
    }
}

impl OutsidePreparationPair {
    /// Original process numbers are diagnostics for independent pidfd observation.
    /// This does not confer any transaction or native mount authority.
    pub fn process_ids(&self) -> (u32, Option<u32>) {
        (
            self.guardian.child.id(),
            self.supervisor.as_ref().map(|child| child.child.id()),
        )
    }
}

impl OutsidePreparationPair {
    /// Allows the owner to acknowledge the guardian's actual thaw to the supervisor.
    pub fn observe_guardian_terminal(
        &mut self,
        timeout: Duration,
    ) -> io::Result<super::OutsideHelperExitObservation> {
        if timeout.is_zero() || timeout > Duration::from_secs(12) {
            return Err(super::super::refusal(
                "bounded original terminal observation required",
            ));
        }
        let deadline = *self
            .terminal_deadline
            .get_or_insert_with(|| Instant::now() + timeout);
        self.guardian
            .observe_terminal(deadline.saturating_duration_since(Instant::now()))
    }
    pub fn observe_supervisor_terminal(
        &mut self,
        timeout: Duration,
    ) -> io::Result<Option<super::OutsideHelperExitObservation>> {
        if timeout.is_zero() || timeout > Duration::from_secs(12) {
            return Err(super::super::refusal(
                "bounded original terminal observation required",
            ));
        }
        let deadline = *self
            .terminal_deadline
            .get_or_insert_with(|| Instant::now() + timeout);
        self.supervisor
            .as_mut()
            .map(|child| child.observe_terminal(deadline.saturating_duration_since(Instant::now())))
            .transpose()
    }
}

impl OutsidePreparationPair {
    /// Actual consumed startup bytes are diagnostics, including one overflow byte.
    pub fn retained_startup_bytes(&self) -> (&[u8], Option<&[u8]>) {
        (
            self.guardian.retained_startup_bytes(),
            self.supervisor
                .as_ref()
                .map(OutsideHelperChild::retained_startup_bytes),
        )
    }
}

impl OutsidePreparationPair {
    /// Verify both originally prepared and armed helpers are bound to this
    /// exact original mount descriptor. This grants no transaction authority.
    pub fn verify_original_mount(&self, mount: &File) -> io::Result<()> {
        self.verify_original_pair()?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or_else(|| super::super::refusal("both original armed helpers required"))?;
        if !self.single_use_attempted
            || !self.guardian.arm_attempted
            || !self.guardian.arm_written
            || !self.guardian.ready
            || !supervisor.arm_attempted
            || !supervisor.arm_written
            || !supervisor.ready
            || self.guardian.terminal_poisoned
            || supervisor.terminal_poisoned
            || self.guardian.terminal_observed
            || supervisor.terminal_observed
        {
            return Err(super::super::refusal(
                "live original both-ARM READY pair required",
            ));
        }
        let metadata = mount.metadata()?;
        let boundary = &self.guardian.boundary;
        if metadata.dev() != boundary.mount_device
            || metadata.ino() != boundary.mount_inode
            || retained_mount_id(mount)? != boundary.mount_id
        {
            return Err(super::super::refusal(
                "original frozen mount and armed pair differ",
            ));
        }
        Ok(())
    }
}
