//! Matching what someone typed after `--place` to a place a finding is really at.
//!
//! A single-finding ignore is keyed on the finding's location exactly as
//! `bulwark_core::finding_location` writes it (the desktop app's `ignoreKeyOf` writes the same
//! string). That key is right for the app, which fills it in itself, and unforgiving for a person
//! at a terminal: the banner rule's place is `issue`, not `/etc/issue`; a kernel module's is
//! `module=dccp`, not `dccp`. An ignore stored under a string no finding has does nothing, and it
//! used to be accepted without a word.
//!
//! Nothing here changes the key. It only decides which stored key the typed text means, when
//! exactly one does — and otherwise lists the places that exist, so the next try works.

use bulwark_core::{finding_location, Finding};

/// How `--place` was understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlaceMatch {
    /// A finding is at exactly this place.
    Exact(String),
    /// No finding is at the text as typed, and exactly one is at a place it clearly means.
    Understood(String),
    /// Nothing matches (or more than one does). `existing` is every place the rule is found at.
    NotFound { existing: Vec<String> },
}

/// Whether `given` is an obvious other spelling of the stored location `location`.
fn means(given: &str, location: &str, home: Option<&str>) -> bool {
    let given = given.trim();
    if given.eq_ignore_ascii_case(location) {
        return true;
    }
    // `dccp` for `module=dccp`; `file=issue` for `issue`.
    if location
        .split_once('=')
        .is_some_and(|(_, value)| !location.contains(" · ") && value == given)
        || given
            .split_once('=')
            .is_some_and(|(_, value)| value == location)
    {
        return true;
    }
    // `/etc/issue` for `issue`, `known_hosts` for `/home/me/.ssh/known_hosts`.
    let file_name = |p: &str| p.rsplit(['/', '\\']).next().map(str::to_string);
    let is_path = |p: &str| p.contains('/') || p.contains('\\');
    if (is_path(given) && !is_path(location) && file_name(given).as_deref() == Some(location))
        || (is_path(location) && !is_path(given) && file_name(location).as_deref() == Some(given))
    {
        return true;
    }
    // `~/.npmrc` for `/home/me/.npmrc`.
    if let (Some(rest), Some(home)) = (given.strip_prefix("~/"), home) {
        if location
            .strip_prefix(home)
            .map(|l| l.trim_start_matches('/'))
            == Some(rest)
        {
            return true;
        }
    }
    // `port 6379`, or just `6379`, for `port 6379 on 0.0.0.0`.
    if let Some((port, _)) = location.split_once(" on ") {
        if port == given || port.strip_prefix("port ") == Some(given) {
            return true;
        }
    }
    false
}

/// Which place of `findings` (the open findings of one rule) the typed `given` means.
pub(crate) fn match_place(given: &str, findings: &[&Finding], home: Option<&str>) -> PlaceMatch {
    let mut existing: Vec<String> = Vec::new();
    for f in findings {
        let location = finding_location(f);
        if !existing.contains(&location) {
            existing.push(location);
        }
    }
    if existing.iter().any(|l| l == given) {
        return PlaceMatch::Exact(given.to_string());
    }
    let mut candidates: Vec<&String> = existing.iter().filter(|l| means(given, l, home)).collect();
    // The title, typed for a finding whose place is something shorter.
    for f in findings {
        if f.title == given.trim() {
            let location = finding_location(f);
            if let Some(l) = existing.iter().find(|l| **l == location) {
                if !candidates.contains(&l) {
                    candidates.push(l);
                }
            }
        }
    }
    match candidates.as_slice() {
        [only] => PlaceMatch::Understood((*only).clone()),
        _ => PlaceMatch::NotFound { existing },
    }
}

/// The same matching against places that are already ignored, for lifting an ignore.
pub(crate) fn match_ignored(given: &str, ignored: &[String], home: Option<&str>) -> Option<String> {
    if ignored.iter().any(|l| l == given) {
        return Some(given.to_string());
    }
    let candidates: Vec<&String> = ignored.iter().filter(|l| means(given, l, home)).collect();
    match candidates.as_slice() {
        [only] => Some((*only).clone()),
        _ => None,
    }
}

/// The warning for a place nothing is found at: what it means, and the places that would work.
pub(crate) fn not_found_warning(rule_id: &str, given: &str, existing: &[String]) -> String {
    let mut out = format!(
        "warning: no open finding of {rule_id} is at '{}', so this ignores nothing right now.",
        crate::term_safe(given)
    );
    if existing.is_empty() {
        out.push_str(&format!(
            "\n  {rule_id} has no open findings in the last saved scan. `bulwarkctl scan --all` \
             lists each place on a line starting with `·` under the problem."
        ));
    } else {
        out.push_str(&format!("\n  {rule_id} is currently found at:"));
        for place in existing {
            out.push_str(&format!("\n    {}", crate::term_safe(place)));
        }
        out.push_str("\n  Use one of those with --place, exactly as written.");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn finding(rule: &str, title: &str, context: serde_json::Value) -> Finding {
        const NIL: &str = "00000000-0000-0000-0000-000000000000";
        const NOW: &str = "2026-11-01T00:00:00Z";
        serde_json::from_value(json!({
            "id": NIL, "rule_id": rule, "severity": "info", "title": title,
            "explanation": "e", "fix_hint": "f", "context": context,
            "first_seen": NOW, "last_seen": NOW, "status": "open", "scan_run_id": NIL,
        }))
        .unwrap()
    }

    /// The tester's three: `/etc/issue` matched nothing (the place is `issue`), a kernel module
    /// needed `module=dccp`, and the docs say "a place is the file".
    #[test]
    fn the_obvious_spellings_find_the_one_place_they_mean() {
        let issue = finding(
            "BLWK-BANN-001",
            "No custom legal warning banner is set (/etc/issue)",
            json!({"file": "issue"}),
        );
        let issue_net = finding(
            "BLWK-BANN-001",
            "No custom legal warning banner is set (/etc/issue.net)",
            json!({"file": "issue.net"}),
        );
        let banners = [&issue, &issue_net];
        let understood = |s: &str| PlaceMatch::Understood(s.to_string());
        assert_eq!(
            match_place("issue", &banners, None),
            PlaceMatch::Exact("issue".into())
        );
        assert_eq!(
            match_place("/etc/issue", &banners, None),
            understood("issue")
        );
        assert_eq!(
            match_place("file=issue", &banners, None),
            understood("issue")
        );
        assert_eq!(
            match_place("/etc/issue.net", &banners, None),
            understood("issue.net")
        );
        assert_eq!(
            match_place(
                "No custom legal warning banner is set (/etc/issue)",
                &banners,
                None
            ),
            understood("issue")
        );

        let dccp = finding("BLWK-KERNEL-020", "t: dccp", json!({"module": "dccp"}));
        let sctp = finding("BLWK-KERNEL-020", "t: sctp", json!({"module": "sctp"}));
        assert_eq!(
            match_place("dccp", &[&dccp, &sctp], None),
            understood("module=dccp")
        );

        let npmrc = finding("BLWK-DEV-007", "t", json!({"path": "/home/me/.npmrc"}));
        assert_eq!(
            match_place("~/.npmrc", &[&npmrc], Some("/home/me")),
            understood("/home/me/.npmrc")
        );
        assert_eq!(
            match_place(".npmrc", &[&npmrc], None),
            understood("/home/me/.npmrc")
        );

        let redis = finding(
            "BLWK-NET-003",
            "t",
            json!({"port": 6379, "listen_address": "0.0.0.0"}),
        );
        assert_eq!(
            match_place("port 6379", &[&redis], None),
            understood("port 6379 on 0.0.0.0")
        );
        assert_eq!(
            match_place("6379", &[&redis], None),
            understood("port 6379 on 0.0.0.0")
        );
    }

    /// A guess is only taken when it can mean one place. Anything else is "not found", with the
    /// places that exist — never a silent pick, never a silent no-op.
    #[test]
    fn a_place_nothing_is_at_is_reported_with_the_places_that_exist() {
        let a = finding("R", "t", json!({"path": "/srv/a/.npmrc"}));
        let b = finding("R", "t", json!({"path": "/srv/b/.npmrc"}));
        // Two files share the name: `.npmrc` could be either, so it is neither.
        assert_eq!(
            match_place(".npmrc", &[&a, &b], None),
            PlaceMatch::NotFound {
                existing: vec!["/srv/a/.npmrc".into(), "/srv/b/.npmrc".into()]
            }
        );
        assert_eq!(
            match_place("/nowhere", &[&a], None),
            PlaceMatch::NotFound {
                existing: vec!["/srv/a/.npmrc".into()]
            }
        );
        assert_eq!(
            match_place("anything", &[], None),
            PlaceMatch::NotFound { existing: vec![] }
        );
        // An identity made of several facts is not guessed from one of them.
        let cron = finding(
            "R",
            "t",
            json!({"source": "/etc/crontab", "command": "curl x | sh"}),
        );
        assert!(matches!(
            match_place("/etc/crontab", &[&cron], None),
            PlaceMatch::NotFound { .. }
        ));

        let warning = not_found_warning("R", "/nowhere\nFAKE", &["/srv/a/.npmrc".into()]);
        assert!(warning.contains("ignores nothing right now"), "{warning}");
        assert!(warning.contains("\n    /srv/a/.npmrc"), "{warning}");
        assert!(
            !warning.contains("\nFAKE"),
            "typed text is printed as one line"
        );
        assert!(not_found_warning("R", "x", &[]).contains("bulwarkctl scan --all"));
    }

    #[test]
    fn an_ignore_can_be_lifted_by_the_same_spellings() {
        let ignored = vec!["issue".to_string(), "module=dccp".to_string()];
        assert_eq!(
            match_ignored("/etc/issue", &ignored, None).as_deref(),
            Some("issue")
        );
        assert_eq!(
            match_ignored("dccp", &ignored, None).as_deref(),
            Some("module=dccp")
        );
        assert_eq!(match_ignored("issue.net", &ignored, None), None);
    }
}
