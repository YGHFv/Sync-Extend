//! Keep one local writer per configured space, shared by polling and HTTP.
use super::Runtime;
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use sync_extend_core_model::{limits::LocalLimits, SpaceId};
use sync_extend_reconcile::{LocalSpace, ReconcileError};

// The listener permits up to 64 exports; multiple exports can share a space.
pub(super) const MAX_SPACES: usize = 64;

pub(super) struct Polling {
    spaces: BTreeMap<SpaceId, Space>,
    interval: Duration,
}

struct Space {
    local: LocalSpace,
    ready: bool,
    next_scan: Instant,
}

impl Polling {
    pub(super) fn open(
        runtime: &Runtime,
        limits: &LocalLimits,
        interval_secs: u64,
    ) -> Result<Self, ReconcileError> {
        let mut spaces = BTreeMap::new();
        for (id, path) in &runtime.spaces {
            let local = LocalSpace::open_with_limits(path, limits.clone())?;
            if &local.space_id != id {
                return Err(ReconcileError::Invariant(
                    "WebDAV polling space identity differs from configuration",
                ));
            }
            spaces.insert(
                id.clone(),
                Space {
                    local,
                    ready: false,
                    next_scan: Instant::now(),
                },
            );
        }
        Ok(Self {
            spaces,
            interval: Duration::from_secs(interval_secs),
        })
    }

    pub(super) fn scan_due(&mut self, shutdown: &AtomicBool) {
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        let Some((id, space)) = self
            .spaces
            .iter_mut()
            .min_by_key(|(_, space)| space.next_scan)
        else {
            return;
        };
        if space.next_scan > Instant::now() {
            return;
        }
        // Take one due space at a time and skip missed ticks, so even a slow
        // scan or several due spaces cannot starve pending HTTP requests.
        space.ready = match space.local.scan() {
            Ok(scan) => {
                super::super::management::observe_local_space(&space.local);
                if let Ok(report) = serde_json::to_string(&scan) {
                    println!("{report}");
                }
                true
            }
            Err(error) => {
                eprintln!("syncd: WebDAV polling deferred for {id}: {error}");
                false
            }
        };
        space.next_scan = Instant::now() + self.interval;
        super::super::shutdown::set_resources_ready(self.spaces.values().all(|space| space.ready));
    }

    pub(super) fn local(&mut self, id: &SpaceId) -> Result<&mut LocalSpace, u16> {
        self.spaces
            .get_mut(id)
            .filter(|space| space.ready)
            .map(|space| &mut space.local)
            .ok_or(503)
    }
}
