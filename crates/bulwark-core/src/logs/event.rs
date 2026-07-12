//! The normalized event shape every [`LogSource`](super::source::LogSource) produces, before
//! decoding. A `RawEvent` is source-agnostic: journald, a tailed syslog file, and a test
//! fixture all normalize down to the same handful of fields so the decode/detect/correlate
//! stages never care where a line came from.

use chrono::{DateTime, Utc};

/// One log line, normalized across sources. The `message` is the human-readable payload a
/// decoder's regex runs against; everything else is metadata a decoder can bucket on
/// (`program`) or a rule can reference as a decoded field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    /// When the event was recorded, taken from the source (journald's `__REALTIME_TIMESTAMP`,
    /// or the syslog line's own timestamp) — never `Utc::now()`. Correlation windows are
    /// measured against *this*, so a batch replay of an old log correlates exactly as it would
    /// have live, and tests are deterministic.
    pub timestamp: DateTime<Utc>,
    /// The program/tag that emitted the line (`_COMM` / `SYSLOG_IDENTIFIER` / the `prog` in a
    /// syslog header). This is the coarse bucket a decoder filters on before running any regex.
    pub program: Option<String>,
    /// The systemd unit, when the source knows it (journald `_SYSTEMD_UNIT`). `None` for a
    /// plain syslog line.
    pub unit: Option<String>,
    /// The PID of the emitting process, when known.
    pub pid: Option<u32>,
    /// The host the line was recorded on.
    pub host: Option<String>,
    /// The log message body — what decoders actually parse.
    pub message: String,
}

impl RawEvent {
    /// A bare event with just a timestamp and message — used by sources that carry no
    /// metadata and by tests. Builder-style `with_*` setters fill in the rest.
    pub fn new(timestamp: DateTime<Utc>, message: impl Into<String>) -> Self {
        Self {
            timestamp,
            program: None,
            unit: None,
            pid: None,
            host: None,
            message: message.into(),
        }
    }

    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = Some(program.into());
        self
    }

    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }
}
