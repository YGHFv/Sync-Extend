//! Sealed read-only bridge between independently audited final layout variants.
use crate::{
    tree_final_terminal_layout::{TreeFinalTerminalLayoutPlan, TreeFinalTerminalRowsLayout},
    tree_final_transaction::{TreeFinalTransactionFootprint, TreeFinalTransactionRows},
    tree_native_final_layout::TreeNativeFinalLayoutPlan,
    ContentId, EntryId,
};
use std::collections::BTreeSet;

mod private {
    pub trait Sealed {}
    impl Sealed for super::TreeFinalTerminalLayoutPlan {}
    impl Sealed for super::TreeNativeFinalLayoutPlan {}
}

/// A shared layout view, never a trait granting SQL writes or native ownership.
/// External implementations are excluded: every source has private audited state.
pub trait TreeFinalLayoutSource: private::Sealed {
    fn terminal_rows(&self) -> &TreeFinalTerminalRowsLayout;
    fn history_rows(&self) -> &TreeFinalTransactionRows;
    fn history_footprint(&self) -> &TreeFinalTransactionFootprint;
    fn layout_fingerprint(&self) -> &ContentId;
    fn generation_inventory(&self) -> &BTreeSet<EntryId>;
    fn owner_plan_hash(&self) -> &ContentId;
}

impl TreeFinalLayoutSource for TreeFinalTerminalLayoutPlan {
    fn terminal_rows(&self) -> &TreeFinalTerminalRowsLayout {
        self.rows()
    }
    fn history_rows(&self) -> &TreeFinalTransactionRows {
        self.transaction().rows()
    }
    fn history_footprint(&self) -> &TreeFinalTransactionFootprint {
        self.transaction().footprint()
    }
    fn layout_fingerprint(&self) -> &ContentId {
        self.fingerprint()
    }
    fn generation_inventory(&self) -> &BTreeSet<EntryId> {
        self.forbidden_generations()
    }
    fn owner_plan_hash(&self) -> &ContentId {
        self.owner_intent_hash()
    }
}

impl TreeFinalLayoutSource for TreeNativeFinalLayoutPlan {
    fn terminal_rows(&self) -> &TreeFinalTerminalRowsLayout {
        self.rows()
    }
    fn history_rows(&self) -> &TreeFinalTransactionRows {
        self.history().rows()
    }
    fn history_footprint(&self) -> &TreeFinalTransactionFootprint {
        self.history().footprint()
    }
    fn layout_fingerprint(&self) -> &ContentId {
        self.fingerprint()
    }
    fn generation_inventory(&self) -> &BTreeSet<EntryId> {
        self.forbidden_generations()
    }
    fn owner_plan_hash(&self) -> &ContentId {
        self.owner_intent_hash()
    }
}
