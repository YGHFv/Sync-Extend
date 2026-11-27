//! Share only terminal obligations across the runtime's original workers.
use std::sync::{Arc, Mutex};
use sync_extend_platform_fs::{ManagedChild, ManagedRpcOwner};

#[derive(Clone, Default)]
pub(super) struct Terminal(Arc<Mutex<Resources>>);

#[derive(Default)]
struct Resources {
    errors: Vec<&'static str>,
    #[cfg(windows)]
    children: Vec<sync_extend_platform_fs::ManagedChildCloseFailure>,
    #[cfg(windows)]
    handles: Vec<sync_extend_platform_fs::WindowsOriginalResourceCloseFailure>,
}

impl Drop for Resources {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            for original in self.children.drain(..) {
                let _ = original.retain_and_report();
            }
            for original in self.handles.drain(..) {
                original.retain_until_process_exit();
            }
        }
    }
}

impl Terminal {
    pub(super) fn spawn(
        &self,
        command: &mut std::process::Command,
    ) -> std::io::Result<ManagedChild> {
        #[cfg(windows)]
        return ManagedChild::spawn_retaining(command).map_err(|original| {
            let error = std::io::Error::new(original.error.kind(), original.error.to_string());
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .children
                .push(original);
            error
        });
        #[cfg(not(windows))]
        ManagedChild::spawn(command)
    }
    pub(super) fn error(&self, error: &'static str) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .errors
            .push(error);
    }

    pub(super) fn child(&self, original: ManagedChild) {
        #[cfg(windows)]
        if let Err(original) = original.close_retaining() {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .children
                .push(original);
        }
        #[cfg(not(windows))]
        drop(original);
    }

    pub(super) fn rpc(&self, original: ManagedRpcOwner) {
        #[cfg(windows)]
        {
            let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
            original.close_into_attempt(&mut close);
            self.handles(close);
        }
        #[cfg(not(windows))]
        drop(original);
    }

    pub(super) fn rpc_owner(
        &self,
        child: &ManagedChild,
        program: &sync_extend_platform_fs::PinnedProgram,
    ) -> std::io::Result<ManagedRpcOwner> {
        #[cfg(windows)]
        return child.rpc_owner_retaining(program).map_err(|mut original| {
            if let Some(handles) = original.original_resources.take() {
                let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
                close.append_failure(handles);
                self.handles(close);
            }
            original.error
        });
        #[cfg(not(windows))]
        child.rpc_owner(program)
    }

    #[cfg(windows)]
    pub(super) fn pipe(&self, original: impl std::os::windows::io::IntoRawHandle) {
        let mut close = sync_extend_platform_fs::WindowsOriginalCloseAttempt::new();
        close.close_identity_handle(original);
        self.handles(close);
    }

    #[cfg(windows)]
    pub(super) fn handles(&self, close: sync_extend_platform_fs::WindowsOriginalCloseAttempt) {
        if let Err(original) = close.finish() {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .handles
                .push(original);
        }
    }

    pub(super) fn succeeded(&self) -> bool {
        let resources = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = resources.errors.is_empty();
        #[cfg(windows)]
        let valid = valid && resources.children.is_empty() && resources.handles.is_empty();
        valid
    }

    pub(super) fn close_remaining(&self) {
        #[cfg(windows)]
        {
            let mut resources = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            resources.children = std::mem::take(&mut resources.children)
                .into_iter()
                .map(|original| original.close_remaining())
                .collect();
            resources.handles = std::mem::take(&mut resources.handles)
                .into_iter()
                .map(|original| original.close_remaining())
                .collect();
        }
    }

    pub(super) fn has_retained_originals(&self) -> bool {
        #[cfg(windows)]
        {
            let resources = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            resources
                .children
                .iter()
                .any(|original| original.has_retained_originals())
                || resources
                    .handles
                    .iter()
                    .any(|original| original.retained_resource_groups() != 0)
        }
        #[cfg(not(windows))]
        false
    }

    pub(super) fn retain_until_process_exit(self) {
        let _ = Box::leak(Box::new(self));
    }
}
