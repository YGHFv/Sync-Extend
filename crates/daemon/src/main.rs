fn main() {
    println!(
        "SyncExtend {} (format {}, protocol {}, EasyTier {})",
        env!("CARGO_PKG_VERSION"),
        sync_extend_core_model::FORMAT_VERSION,
        sync_extend_core_model::PROTOCOL_VERSION,
        sync_extend_core_model::EASYTIER_VERSION
    );
}
