pub(crate) fn checkpoint(_phase: &str) {
    #[cfg(feature = "fault-injection")]
    if std::env::var("SYNCEXTEND_PAUSE_AT").ok().as_deref() == Some(_phase) {
        eprintln!("SYNCEXTEND_CHECKPOINT:{_phase}");
        loop {
            if std::env::var_os("SYNCEXTEND_CONTINUE_FILE")
                .is_some_and(|path| std::path::Path::new(&path).is_file())
            {
                break;
            }
            std::thread::park_timeout(std::time::Duration::from_millis(25));
        }
    }
}
