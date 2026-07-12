//! Log sources: where raw events come from. Everything downstream (decode/detect/correlate)
//! consumes [`RawEvent`]s through the [`LogSource`] trait, so adding a new source — a tailed
//! file, a socket, a different journal backend — never touches the pipeline.
//!
//! Two sources ship in this slice:
//! - [`JournaldSource`], the real driver on a systemd host (`journalctl -o json`).
//! - [`SyslogLinesSource`], parsing classic `Mon DD HH:MM:SS host prog[pid]: msg` lines from any
//!   `BufRead` — it powers tests, `logs scan --from-file`, and (later) an offset-tracking file
//!   tailer.

use super::event::RawEvent;
use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;
use std::io::{BufRead, BufReader, Lines};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::LazyLock;

/// A pull-based stream of raw log events. `None` ends the stream; `Some(Err(_))` is a per-event
/// error (a malformed line) that the caller records and moves past — a single bad line never
/// aborts a whole scan, matching the engine's "never a silent drop, never a fatal one" stance.
pub trait LogSource {
    fn next_event(&mut self) -> Option<anyhow::Result<RawEvent>>;
}

// ---------------------------------------------------------------------------
// journald
// ---------------------------------------------------------------------------

/// How far back a [`JournaldSource`] batch should read.
#[derive(Debug, Clone)]
pub enum JournalRange {
    /// Everything since the current boot (`journalctl -b`).
    CurrentBoot,
    /// Everything at or after the given `journalctl --since` spec (e.g. `"-1h"`,
    /// `"2026-07-12 00:00:00"`). Passed through verbatim.
    Since(String),
}

/// Reads the systemd journal by spawning `journalctl -o json` and parsing one JSON object per
/// line. Chosen over linking `libsystemd` so `bulwark-core` keeps its "no C deps beyond libc"
/// footprint and stays trivially cross-buildable; the tradeoff is a subprocess and JSON parse
/// per line, which is negligible next to regex decoding.
pub struct JournaldSource {
    // Kept so the child is reaped when the source is dropped; the stdout it owned was moved
    // into `lines`.
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
}

impl JournaldSource {
    /// Spawns `journalctl` for a one-shot batch over `range`. Fails if `journalctl` isn't on
    /// PATH (i.e. not a systemd host) — the CLI turns that into a clear "use --from-file"
    /// message rather than an empty result that looks like "nothing to report."
    pub fn batch(range: JournalRange) -> anyhow::Result<Self> {
        let mut cmd = Command::new("journalctl");
        cmd.arg("-o").arg("json").arg("--no-pager");
        match range {
            JournalRange::CurrentBoot => {
                cmd.arg("-b");
            }
            JournalRange::Since(spec) => {
                cmd.arg("--since").arg(spec);
            }
        }
        Self::spawn(cmd)
    }

    fn spawn(mut cmd: Command) -> anyhow::Result<Self> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::null());
        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to run journalctl ({e}) — not a systemd host? try `logs scan --from-file <path>`"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("journalctl produced no stdout pipe"))?;
        Ok(Self {
            child,
            lines: BufReader::new(stdout).lines(),
        })
    }

    /// Maps one journald JSON object to a `RawEvent`. Returns `Ok(None)` for entries with no
    /// usable `MESSAGE`/timestamp (journald emits metadata-only entries) so the caller skips
    /// rather than errors on them.
    fn parse_entry(line: &str) -> anyhow::Result<Option<RawEvent>> {
        let v: serde_json::Value = serde_json::from_str(line)?;
        let Some(message) = journal_message(&v) else {
            return Ok(None);
        };
        let Some(timestamp) = journal_timestamp(&v) else {
            return Ok(None);
        };
        Ok(Some(RawEvent {
            timestamp,
            program: journal_str(&v, "SYSLOG_IDENTIFIER").or_else(|| journal_str(&v, "_COMM")),
            unit: journal_str(&v, "_SYSTEMD_UNIT"),
            pid: journal_str(&v, "_PID")
                .or_else(|| journal_str(&v, "SYSLOG_PID"))
                .and_then(|s| s.parse().ok()),
            host: journal_str(&v, "_HOSTNAME"),
            message,
        }))
    }
}

impl LogSource for JournaldSource {
    fn next_event(&mut self) -> Option<anyhow::Result<RawEvent>> {
        // Loop past metadata-only entries (Ok(None)) until we get a real event, an error, or EOF.
        loop {
            match self.lines.next() {
                Some(Ok(line)) => match Self::parse_entry(&line) {
                    Ok(Some(ev)) => return Some(Ok(ev)),
                    Ok(None) => continue,
                    Err(e) => return Some(Err(e)),
                },
                Some(Err(e)) => return Some(Err(e.into())),
                None => return None,
            }
        }
    }
}

impl Drop for JournaldSource {
    fn drop(&mut self) {
        // Reap the child; ignore errors — we're tearing down regardless.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A journald string field. journald encodes most fields as JSON strings; a field that came in
/// as raw bytes shows up as an array of byte values, which we decode lossily.
fn journal_str(v: &serde_json::Value, key: &str) -> Option<String> {
    match v.get(key)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(bytes) => Some(bytes_to_string(bytes)),
        _ => None,
    }
}

fn journal_message(v: &serde_json::Value) -> Option<String> {
    journal_str(v, "MESSAGE")
}

fn journal_timestamp(v: &serde_json::Value) -> Option<DateTime<Utc>> {
    let micros: i64 = journal_str(v, "__REALTIME_TIMESTAMP")?.parse().ok()?;
    DateTime::from_timestamp_micros(micros)
}

fn bytes_to_string(bytes: &[serde_json::Value]) -> String {
    let raw: Vec<u8> = bytes
        .iter()
        .filter_map(|b| b.as_u64().map(|n| n as u8))
        .collect();
    String::from_utf8_lossy(&raw).into_owned()
}

// ---------------------------------------------------------------------------
// syslog lines
// ---------------------------------------------------------------------------

/// `Mon DD HH:MM:SS host prog[pid]: message`. The pid group is optional; `prog` stops at the
/// first `[`, `:`, or space so `sshd[1234]:` and `CRON:` both parse. The message is captured
/// verbatim (spacing preserved), unlike a `split_whitespace` reconstruction.
static SYSLOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    )
    .expect("static syslog regex is valid")
});

/// Parses classic RFC3164-style syslog lines from any `BufRead`. syslog headers carry no year,
/// so `assume_year` is supplied explicitly (the CLI passes the current year; tests pass a fixed
/// one) — keeping the parser free of any hidden `Utc::now()` and therefore deterministic.
///
/// Timestamps are interpreted as UTC. syslog local time without a zone is genuinely ambiguous;
/// UTC is the one interpretation that's reproducible, and it only shifts absolute times, not the
/// *relative* deltas correlation windows actually depend on.
pub struct SyslogLinesSource<R: BufRead> {
    lines: Lines<R>,
    assume_year: i32,
}

impl<R: BufRead> SyslogLinesSource<R> {
    pub fn new(reader: R, assume_year: i32) -> Self {
        Self {
            lines: reader.lines(),
            assume_year,
        }
    }

    fn parse_line(&self, line: &str) -> anyhow::Result<Option<RawEvent>> {
        // Blank lines and anything that doesn't match the syslog header shape are skipped, not
        // errored: real log files interleave multi-line payloads and kernel lines we don't model.
        let Some(caps) = SYSLOG_RE.captures(line) else {
            return Ok(None);
        };
        let month = month_number(&caps["mon"])
            .ok_or_else(|| anyhow::anyhow!("unknown month '{}'", &caps["mon"]))?;
        let day: u32 = caps["day"].parse()?;
        let (h, m, s) = parse_hms(&caps["time"])?;
        let naive = chrono::NaiveDate::from_ymd_opt(self.assume_year, month, day)
            .and_then(|d| d.and_hms_opt(h, m, s))
            .ok_or_else(|| anyhow::anyhow!("invalid syslog date/time in '{line}'"))?;
        let timestamp = Utc.from_utc_datetime(&naive);

        Ok(Some(RawEvent {
            timestamp,
            program: Some(caps["prog"].to_string()),
            unit: None,
            pid: caps.name("pid").and_then(|m| m.as_str().parse().ok()),
            host: Some(caps["host"].to_string()),
            message: caps["msg"].to_string(),
        }))
    }
}

impl<R: BufRead> LogSource for SyslogLinesSource<R> {
    fn next_event(&mut self) -> Option<anyhow::Result<RawEvent>> {
        loop {
            match self.lines.next() {
                Some(Ok(line)) => match self.parse_line(&line) {
                    Ok(Some(ev)) => return Some(Ok(ev)),
                    Ok(None) => continue,
                    Err(e) => return Some(Err(e)),
                },
                Some(Err(e)) => return Some(Err(e.into())),
                None => return None,
            }
        }
    }
}

fn month_number(mon: &str) -> Option<u32> {
    Some(match mon {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn parse_hms(t: &str) -> anyhow::Result<(u32, u32, u32)> {
    let mut it = t.split(':');
    let h = it.next().unwrap_or_default().parse()?;
    let m = it.next().unwrap_or_default().parse()?;
    let s = it.next().unwrap_or_default().parse()?;
    Ok((h, m, s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn source(text: &str) -> SyslogLinesSource<Cursor<Vec<u8>>> {
        SyslogLinesSource::new(Cursor::new(text.as_bytes().to_vec()), 2026)
    }

    #[test]
    fn parses_a_standard_sshd_line() {
        let mut s = source(
            "Jul 12 13:45:01 myhost sshd[1234]: Failed password for root from 10.0.0.5 port 2222 ssh2\n",
        );
        let ev = s.next_event().unwrap().unwrap();
        assert_eq!(ev.program.as_deref(), Some("sshd"));
        assert_eq!(ev.pid, Some(1234));
        assert_eq!(ev.host.as_deref(), Some("myhost"));
        assert_eq!(
            ev.message,
            "Failed password for root from 10.0.0.5 port 2222 ssh2"
        );
        assert_eq!(ev.timestamp.to_rfc3339(), "2026-07-12T13:45:01+00:00");
        assert!(s.next_event().is_none());
    }

    #[test]
    fn message_spacing_is_preserved_verbatim() {
        let mut s = source("Jul 12 13:45:01 h cron: run    job   now\n");
        let ev = s.next_event().unwrap().unwrap();
        assert_eq!(ev.message, "run    job   now");
        assert_eq!(ev.pid, None);
    }

    #[test]
    fn single_digit_day_with_padding_parses() {
        let mut s = source(
            "Jul  1 00:00:05 h sshd[9]: Accepted password for u from 1.2.3.4 port 22 ssh2\n",
        );
        let ev = s.next_event().unwrap().unwrap();
        assert_eq!(ev.timestamp.to_rfc3339(), "2026-07-01T00:00:05+00:00");
    }

    #[test]
    fn non_syslog_lines_are_skipped_not_errored() {
        let mut s = source("this is not a syslog line\nJul 12 13:45:01 h sshd[1]: hi\n");
        let ev = s.next_event().unwrap().unwrap();
        assert_eq!(ev.message, "hi");
        assert!(s.next_event().is_none());
    }

    #[test]
    fn journald_entry_maps_to_raw_event() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1752328801000000","MESSAGE":"Failed password for root from 10.0.0.5 port 2222 ssh2","SYSLOG_IDENTIFIER":"sshd","_PID":"1234","_HOSTNAME":"myhost","_SYSTEMD_UNIT":"ssh.service"}"#;
        let ev = JournaldSource::parse_entry(line).unwrap().unwrap();
        assert_eq!(ev.program.as_deref(), Some("sshd"));
        assert_eq!(ev.pid, Some(1234));
        assert_eq!(ev.unit.as_deref(), Some("ssh.service"));
        assert_eq!(
            ev.message,
            "Failed password for root from 10.0.0.5 port 2222 ssh2"
        );
        assert_eq!(ev.timestamp.timestamp(), 1752328801);
    }

    #[test]
    fn journald_metadata_only_entry_is_skipped() {
        // No MESSAGE field — journald emits these; they should map to Ok(None), not an error.
        let line = r#"{"__REALTIME_TIMESTAMP":"1752328801000000","_HOSTNAME":"myhost"}"#;
        assert!(JournaldSource::parse_entry(line).unwrap().is_none());
    }

    #[test]
    fn journald_message_from_byte_array_is_decoded() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1752328801000000","MESSAGE":[104,105],"SYSLOG_IDENTIFIER":"x"}"#;
        let ev = JournaldSource::parse_entry(line).unwrap().unwrap();
        assert_eq!(ev.message, "hi");
    }
}
