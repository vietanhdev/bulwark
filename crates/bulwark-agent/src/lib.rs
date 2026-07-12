//! Placeholder crate reserving the `bulwark-agent` name on crates.io.
//!
//! This will become Bulwark's background monitoring daemon — the periodic
//! re-scan loop and filesystem watcher, extracted so both `bulwarkctl` and
//! the desktop app can share one process. Its log-analysis half is already
//! built: follow-mode is `bulwark_core::logs::run_log_scan` driven by a
//! following `JournaldSource`, the streaming counterpart of the one-shot
//! `bulwarkctl logs scan`. See https://github.com/vietanhdev/bulwark.
