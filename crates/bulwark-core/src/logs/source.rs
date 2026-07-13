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
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::LazyLock;

/// A pull-based stream of raw log events. `None` ends the stream; `Some(Err(_))` is a per-event
/// error (a malformed line) that the caller records and moves past — a single bad line never
/// aborts a whole scan, matching the engine's "never a silent drop, never a fatal one" stance.
pub trait LogSource {
    fn next_event(&mut self) -> Option<anyhow::Result<RawEvent>>;
}

/// Max bytes retained for a single log line. Log input can be attacker-influenced (a crafted or
/// corrupt `--from-file`, or an oversized journald record), and a newline-free multi-gigabyte
/// "line" read whole would OOM the process — the same reason the config collectors size-cap their
/// reads. Past this we keep the first `MAX_LINE_BYTES` and discard the rest of that physical line.
const MAX_LINE_BYTES: usize = 1024 * 1024;

/// A `BufRead::lines()`-style iterator that never buffers more than [`MAX_LINE_BYTES`] for one
/// line. It still consumes the whole physical line from the reader (so parsing stays aligned to
/// real line boundaries), it just stops *storing* bytes past the cap.
struct CappedLines<R: BufRead> {
    reader: R,
}

impl<R: BufRead> Iterator for CappedLines<R> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf: Vec<u8> = Vec::new();
        let mut saw_any = false;
        loop {
            let available = match self.reader.fill_buf() {
                Ok(b) => b,
                Err(e) => return Some(Err(e)),
            };
            if available.is_empty() {
                if !saw_any {
                    return None;
                }
                break;
            }
            saw_any = true;
            match available.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    if buf.len() < MAX_LINE_BYTES {
                        let take = pos.min(MAX_LINE_BYTES - buf.len());
                        buf.extend_from_slice(&available[..take]);
                    }
                    self.reader.consume(pos + 1);
                    break;
                }
                None => {
                    let n = available.len();
                    if buf.len() < MAX_LINE_BYTES {
                        let take = n.min(MAX_LINE_BYTES - buf.len());
                        buf.extend_from_slice(&available[..take]);
                    }
                    self.reader.consume(n);
                }
            }
        }
        // Match BufRead::lines(): a trailing CR (from CRLF) is stripped.
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        Some(Ok(String::from_utf8_lossy(&buf).into_owned()))
    }
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
    lines: CappedLines<BufReader<ChildStdout>>,
    stderr: Option<ChildStderr>,
    // Once stdout hits EOF, `journalctl`'s exit status is checked exactly once. A non-zero exit
    // (permission denied without `systemd-journal` group membership, a corrupt journal, a
    // mid-stream death) is otherwise indistinguishable from a clean empty journal — the classic
    // false all-clear. This flips it into a surfaced error instead.
    exit_checked: bool,
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
        // stderr is captured (not nulled) so a failure's actual reason can be reported rather than
        // swallowed.
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to run journalctl ({e}) — not a systemd host? try `logs scan --from-file <path>`"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("journalctl produced no stdout pipe"))?;
        let stderr = child.stderr.take();
        Ok(Self {
            child,
            lines: CappedLines {
                reader: BufReader::new(stdout),
            },
            stderr,
            exit_checked: false,
        })
    }

    /// At end-of-stream, checks `journalctl`'s exit status. Returns `Some(Err(..))` once if it
    /// failed, then `None` thereafter. Called only after stdout EOF.
    fn check_exit(&mut self) -> Option<anyhow::Result<RawEvent>> {
        if self.exit_checked {
            return None;
        }
        self.exit_checked = true;
        match self.child.wait() {
            Ok(status) if status.success() => None,
            Ok(status) => {
                use std::io::Read;
                let mut msg = String::new();
                if let Some(mut err) = self.stderr.take() {
                    let _ = err.read_to_string(&mut msg);
                }
                let detail = msg.lines().next().unwrap_or("").trim();
                Some(Err(anyhow::anyhow!(
                    "journalctl exited unsuccessfully ({status}){}{} — the journal was NOT fully read (permission denied? not in the systemd-journal group? corrupt journal?), so an empty result here is not a clean bill of health",
                    if detail.is_empty() { "" } else { ": " },
                    detail
                )))
            }
            Err(e) => Some(Err(anyhow::anyhow!("waiting on journalctl: {e}"))),
        }
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
                // stdout drained — but that only means "clean" if journalctl actually succeeded.
                None => return self.check_exit(),
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

/// ISO-8601 / RFC5424 header: `2026-07-12T09:15:00[.frac][+00:00|Z] host prog[pid]: message`. This
/// is what modern rsyslog and `journalctl -o short-iso` emit by default on current distros — the
/// classic `Mon DD HH:MM:SS` regex above misses them entirely, so those lines were silently dropped
/// and a genuine brute force in an ISO-timestamped log read as "no findings". The timestamp carries
/// its own year and zone, so (unlike RFC3164) there's no year to infer.
static SYSLOG_ISO_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(?P<host>\S+)\s+(?P<prog>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$",
    )
    .expect("static ISO syslog regex is valid")
});

/// Parses classic RFC3164-style syslog lines from any `BufRead`. syslog headers carry no year, so a
/// `reference` instant is supplied explicitly (the CLI passes the log file's mtime, falling back to
/// now; tests pass a fixed instant) — keeping the parser free of any hidden `Utc::now()` and
/// therefore deterministic. The year of each line is INFERRED from that reference: a line whose
/// month is later than the reference's is dated to the previous year, so an `auth.log` read in
/// January whose entries are from December is stamped in the right year instead of ~11 months in the
/// future (which also kept the events time-sorted for correlation). The single-fixed-year approach
/// that preceded this misdated every cross-boundary log.
///
/// Timestamps are interpreted as UTC. syslog local time without a zone is genuinely ambiguous;
/// UTC is the one interpretation that's reproducible, and it only shifts absolute times, not the
/// *relative* deltas correlation windows actually depend on.
pub struct SyslogLinesSource<R: BufRead> {
    lines: CappedLines<R>,
    reference: chrono::DateTime<Utc>,
}

impl<R: BufRead> SyslogLinesSource<R> {
    pub fn new(reader: R, reference: chrono::DateTime<Utc>) -> Self {
        Self {
            lines: CappedLines { reader },
            reference,
        }
    }

    fn parse_line(&self, line: &str) -> anyhow::Result<Option<RawEvent>> {
        // ISO-8601 / RFC5424 first — the modern default. Its timestamp is self-contained (year +
        // zone), so parse it directly and skip the year-inference the classic branch needs.
        if let Some(caps) = SYSLOG_ISO_RE.captures(line) {
            let timestamp = chrono::DateTime::parse_from_rfc3339(&caps["ts"])
                .map_err(|e| anyhow::anyhow!("invalid ISO timestamp in '{line}': {e}"))?
                .with_timezone(&Utc);
            return Ok(Some(RawEvent {
                timestamp,
                program: Some(caps["prog"].to_string()),
                unit: None,
                pid: caps.name("pid").and_then(|m| m.as_str().parse().ok()),
                host: Some(caps["host"].to_string()),
                message: caps["msg"].to_string(),
            }));
        }
        // Blank lines and anything that doesn't match the syslog header shape are skipped, not
        // errored: real log files interleave multi-line payloads and kernel lines we don't model.
        let Some(caps) = SYSLOG_RE.captures(line) else {
            return Ok(None);
        };
        let month = month_number(&caps["mon"])
            .ok_or_else(|| anyhow::anyhow!("unknown month '{}'", &caps["mon"]))?;
        let day: u32 = caps["day"].parse()?;
        let (h, m, s) = parse_hms(&caps["time"])?;
        // Infer the omitted year: a month later than the reference month means the line predates the
        // reference and so belongs to the previous year (a December line seen from January).
        use chrono::Datelike;
        let year = if month > self.reference.month() {
            self.reference.year() - 1
        } else {
            self.reference.year()
        };
        let naive = chrono::NaiveDate::from_ymd_opt(year, month, day)
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
        SyslogLinesSource::new(
            Cursor::new(text.as_bytes().to_vec()),
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 12, 31, 0, 0, 0).unwrap(),
        )
    }

    #[test]
    fn a_december_line_read_in_january_is_dated_to_the_previous_year() {
        // Reference is mid-January 2026 (e.g. the log's mtime). A December entry predates it, so it
        // belongs to 2025 — not ~11 months in the *future*, which the old fixed-current-year logic
        // produced, misdating the finding and breaking time-order for correlation.
        let mut s = SyslogLinesSource::new(
            Cursor::new(
                b"Dec 31 23:59:59 h sshd[1]: Failed password for root from 1.2.3.4 port 2 ssh2\n"
                    .to_vec(),
            ),
            chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 1, 15, 0, 0, 0).unwrap(),
        );
        let ev = s.next_event().unwrap().unwrap();
        assert_eq!(ev.timestamp.to_rfc3339(), "2025-12-31T23:59:59+00:00");
    }

    #[test]
    fn parses_an_iso_timestamped_line_the_modern_default() {
        // journalctl -o short-iso / modern rsyslog. These were silently dropped before, turning a
        // real brute force into "no findings".
        let mut s = source(
            "2026-07-12T09:15:00.123456+00:00 myhost sshd[42]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        );
        let ev = s.next_event().unwrap().unwrap();
        assert_eq!(ev.program.as_deref(), Some("sshd"));
        assert_eq!(ev.pid, Some(42));
        assert_eq!(ev.host.as_deref(), Some("myhost"));
        assert_eq!(
            ev.timestamp.to_rfc3339(),
            "2026-07-12T09:15:00.123456+00:00"
        );
        assert!(ev.message.contains("Failed password"));
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
    fn an_oversized_line_is_capped_and_the_next_line_still_parses() {
        // A newline-free "line" far larger than the cap, followed by a real line. The giant line
        // must not be buffered whole (memory bound) and must not swallow the following line.
        let huge = "A".repeat(MAX_LINE_BYTES + 5_000);
        let text = format!("{huge}\nJul 12 13:45:01 h sshd[7]: hello\n");
        let mut lines = CappedLines {
            reader: Cursor::new(text.into_bytes()),
        };
        let first = lines.next().unwrap().unwrap();
        assert_eq!(
            first.len(),
            MAX_LINE_BYTES,
            "the giant line is truncated to the cap"
        );
        let second = lines.next().unwrap().unwrap();
        assert_eq!(second, "Jul 12 13:45:01 h sshd[7]: hello");
        assert!(lines.next().is_none());
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
