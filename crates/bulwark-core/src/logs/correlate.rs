//! Threshold correlation over keyed sliding windows.
//!
//! This is the piece that turns a stream of individually-boring events ("a failed login") into
//! a finding ("8 failed logins from one IP in 60s"). It is deliberately *not* built like OSSEC's
//! correlator, which scans a single global backward-linked event list per rule and mutates a
//! counter on the shared rule object (forcing single-threading and silently losing events when
//! the list trims). Instead each `(rule_id, group_key)` owns its own bounded window of event
//! timestamps — an honest group-by, O(1) amortized per event, and trivially shardable later.
//!
//! The clock is always the *event's own timestamp*, never wall-clock time, so replaying a batch
//! of yesterday's logs correlates exactly as it would have live, and tests are deterministic.

use std::collections::{HashMap, VecDeque};

/// The correlation spec attached to a log rule (its `correlate:` block). Absent ⇒ the rule fires
/// once per matching event and never touches this module.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CorrelateSpec {
    /// How many matching events within `window_secs` trigger the rule. `count: 8` fires on the
    /// 8th — no off-by-two surprise (contrast OSSEC's documented `frequency + 2`).
    pub count: u32,
    /// The sliding window width, in seconds.
    pub window_secs: i64,
    /// Fields whose values form the group-by key (e.g. `[srcip]`). Events are counted per
    /// distinct key, so a burst from one IP isn't diluted by unrelated traffic.
    /// Omitted/empty ⇒ a single global window for the rule.
    #[serde(default)]
    pub by: Vec<String>,
    /// After the rule fires for a key, suppress further firings for that key for this many
    /// seconds (flood control). Omitted ⇒ no suppression (it can re-fire as soon as the window
    /// again holds `count` events).
    #[serde(default)]
    pub suppress_secs: Option<i64>,
}

/// Per-key state for one rule: the timestamps still inside the window, and when suppression
/// (if any) lifts.
#[derive(Default)]
struct KeyState {
    window: VecDeque<i64>,
    suppressed_until: Option<i64>,
}

/// Holds the sliding-window state for every `(rule_id, group_key)` seen so far. One instance is
/// threaded through a whole `run_log_scan`.
#[derive(Default)]
pub struct CorrelationState {
    keys: HashMap<(String, String), KeyState>,
}

/// Hard cap on distinct live `(rule_id, group_key)` entries. A rule keyed by `srcip` inserts one
/// entry per source IP that ever matches, so a crafted log with many (spoofable) source addresses
/// would otherwise grow this map without bound. Set far above any realistic host's IP diversity.
const MAX_LIVE_KEYS: usize = 200_000;

/// A key whose most recent event is older than this (in the log's own time) can't contribute to
/// any reasonable correlation window anymore and is evicted when space is needed — one day of
/// log-time dwarfs the window widths correlation rules actually use (seconds to minutes).
const GC_HORIZON_SECS: i64 = 24 * 3600;

impl CorrelationState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Frees entries that can no longer affect any result: those with no timestamps left (already
    /// fired and not suppressed) or whose newest event is older than [`GC_HORIZON_SECS`] and which
    /// aren't actively suppressing. If that still doesn't get under the cap, evict the entries with
    /// the oldest activity as a hard backstop. Only ever called when the map hits the cap.
    fn gc(&mut self, now_epoch: i64) {
        let horizon = now_epoch - GC_HORIZON_SECS;
        self.keys.retain(|_, st| {
            let suppressing = st.suppressed_until.is_some_and(|u| u > now_epoch);
            let recent = st.window.back().is_some_and(|&ts| ts >= horizon);
            suppressing || recent
        });
        if self.keys.len() < MAX_LIVE_KEYS {
            return;
        }
        // Backstop: still at the cap after horizon GC — drop the least-recently-active tenth so a
        // pathological single-window flood of distinct keys can't pin us at the ceiling forever.
        let mut newest: Vec<((String, String), i64)> = self
            .keys
            .iter()
            .map(|(k, st)| (k.clone(), st.window.back().copied().unwrap_or(i64::MIN)))
            .collect();
        newest.sort_unstable_by_key(|(_, ts)| *ts);
        for (k, _) in newest.into_iter().take(MAX_LIVE_KEYS / 10) {
            self.keys.remove(&k);
        }
    }

    /// Records one matching event for `rule_id` at `now_epoch` (the event's own Unix timestamp),
    /// under `group_key`, and reports whether this event pushes the window to the rule's
    /// threshold. Returns `true` at most once per burst per key while suppression holds.
    ///
    /// Semantics:
    /// - Evict timestamps older than `now - window_secs` first, so the window is a true sliding
    ///   window, not a fixed bucket.
    /// - If suppressed for this key, record the event (so the count stays honest) but return
    ///   `false`.
    /// - Fire when the window reaches `count`; on firing, reset the window for this key (so the
    ///   next burst must again reach `count` from scratch) and arm suppression if configured.
    pub fn observe(
        &mut self,
        rule_id: &str,
        spec: &CorrelateSpec,
        group_key: &str,
        now_epoch: i64,
    ) -> bool {
        // Bound memory before inserting a brand-new key: if we're at the cap and this event would
        // add yet another distinct key, garbage-collect first.
        let key = (rule_id.to_string(), group_key.to_string());
        if self.keys.len() >= MAX_LIVE_KEYS && !self.keys.contains_key(&key) {
            self.gc(now_epoch);
        }
        let state = self.keys.entry(key).or_default();

        let cutoff = now_epoch - spec.window_secs;
        while let Some(&front) = state.window.front() {
            if front < cutoff {
                state.window.pop_front();
            } else {
                break;
            }
        }
        state.window.push_back(now_epoch);

        if let Some(until) = state.suppressed_until {
            if now_epoch < until {
                return false;
            }
            state.suppressed_until = None;
        }

        if state.window.len() as u32 >= spec.count {
            state.window.clear();
            if let Some(secs) = spec.suppress_secs {
                state.suppressed_until = Some(now_epoch + secs);
            }
            true
        } else {
            false
        }
    }
}

/// Builds a group-by key string from the `by` fields of a decoded fact. A missing field
/// contributes an empty segment so distinct shapes don't collide; the segments are joined with a
/// control char that can't appear in a field value.
pub fn group_key(by: &[String], fact: &crate::models::Fact) -> String {
    if by.is_empty() {
        return String::new();
    }
    by.iter()
        .map(|f| match fact.get(f) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        })
        .collect::<Vec<_>>()
        .join("\u{1f}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(count: u32, window_secs: i64, by: &[&str], suppress: Option<i64>) -> CorrelateSpec {
        CorrelateSpec {
            count,
            window_secs,
            by: by.iter().map(|s| s.to_string()).collect(),
            suppress_secs: suppress,
        }
    }

    #[test]
    fn fires_exactly_once_on_the_nth_event_within_window() {
        let mut state = CorrelationState::new();
        let s = spec(8, 60, &["srcip"], None);
        let mut fires = 0;
        for i in 0..8 {
            // Eight events one second apart — all inside the 60s window.
            if state.observe("R", &s, "10.0.0.5", 1000 + i) {
                fires += 1;
                assert_eq!(i, 7, "should fire on the 8th event, not before");
            }
        }
        assert_eq!(fires, 1);
    }

    #[test]
    fn does_not_fire_when_events_are_spread_beyond_the_window() {
        let mut state = CorrelationState::new();
        let s = spec(8, 60, &["srcip"], None);
        let mut fired = false;
        for i in 0..8 {
            // 30s apart: the window never holds more than 2 at once.
            fired |= state.observe("R", &s, "10.0.0.5", 1000 + i * 30);
        }
        assert!(!fired);
    }

    #[test]
    fn distinct_keys_are_counted_independently() {
        let mut state = CorrelationState::new();
        let s = spec(3, 60, &["srcip"], None);
        // Interleave two IPs; neither alone reaches 3 until its own 3rd event.
        assert!(!state.observe("R", &s, "1.1.1.1", 1000));
        assert!(!state.observe("R", &s, "2.2.2.2", 1001));
        assert!(!state.observe("R", &s, "1.1.1.1", 1002));
        assert!(!state.observe("R", &s, "2.2.2.2", 1003));
        assert!(state.observe("R", &s, "1.1.1.1", 1004)); // 1.1.1.1's 3rd
        assert!(state.observe("R", &s, "2.2.2.2", 1005)); // 2.2.2.2's 3rd
    }

    #[test]
    fn suppression_blocks_a_second_fire_within_the_suppression_window() {
        let mut state = CorrelationState::new();
        let s = spec(3, 60, &["srcip"], Some(300));
        // First burst fires at t=1002.
        assert!(!state.observe("R", &s, "1.1.1.1", 1000));
        assert!(!state.observe("R", &s, "1.1.1.1", 1001));
        assert!(state.observe("R", &s, "1.1.1.1", 1002));
        // A second burst inside the 300s suppression window does not fire.
        assert!(!state.observe("R", &s, "1.1.1.1", 1100));
        assert!(!state.observe("R", &s, "1.1.1.1", 1101));
        assert!(!state.observe("R", &s, "1.1.1.1", 1102));
        // After suppression lifts, a fresh burst fires again.
        assert!(!state.observe("R", &s, "1.1.1.1", 1400));
        assert!(!state.observe("R", &s, "1.1.1.1", 1401));
        assert!(state.observe("R", &s, "1.1.1.1", 1402));
    }

    #[test]
    fn group_key_joins_fields_and_tolerates_missing() {
        let mut fact = crate::models::Fact::new();
        fact.insert("srcip".into(), serde_json::Value::String("1.2.3.4".into()));
        assert_eq!(group_key(&["srcip".into()], &fact), "1.2.3.4");
        assert_eq!(
            group_key(&["srcip".into(), "user".into()], &fact),
            "1.2.3.4\u{1f}"
        );
        assert_eq!(group_key(&[], &fact), "");
    }
}
