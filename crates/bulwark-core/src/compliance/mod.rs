//! Mapping Bulwark's rules onto external compliance standards (PCI DSS, HIPAA, ISO 27001).
//!
//! # Why the mappings are embedded rather than shipped in `rules/`
//!
//! `rules/` is walked by [`crate::engine::load_rules`] and every `.yaml` under it is parsed as a
//! [`crate::models::Rule`], so a standard definition living there would surface as a
//! `RuleLoadError`. But the deeper reason is editorial: a control mapping is a *claim this
//! project makes* about what satisfies someone else's standard. Rules are user-extensible on
//! purpose ("no Rust required to
//! add a rule"); a compliance claim should not be, because silently editing the mapping changes
//! the meaning of a report someone may hand to an auditor. Standards are versioned, rare, and
//! claim-bearing, so they compile in — following the same `include_str!` precedent as the
//! vendored secret pack in `ai_scan::secrets`.
//!
//! # Why "not assessed" is not "passing"
//!
//! This is the load-bearing invariant, and it is the same one
//! [`crate::store::Store::persist_and_reconcile`] relies on. A control is only scored if at least
//! one of its mapped rules is in the scan's `rules_evaluated` set — the rules that demonstrably
//! ran (collector applicable, privileged enough, no error). A control whose rules were all
//! skipped is [`ControlStatus::NotAssessed`] and is excluded from the denominator entirely.
//!
//! Counting a skipped control as passing would be the single most damaging bug this module could
//! have: an unprivileged scan skips most collectors, so "we couldn't look" would render as a
//! higher compliance score than a privileged scan that actually found problems. Scores would rise
//! as visibility fell. `not_assessed_is_excluded_from_the_score` and
//! `a_control_whose_rules_never_ran_is_not_passing` pin it.
//!
//! # What a score means, and what it does not
//!
//! The score is `passing / assessed` over *mapped* controls only. Every report therefore carries
//! `scope_note`, `mapped_controls` and (where known) `catalog_size`, so the partiality travels
//! with the number instead of living in a footnote. None of these standards is mostly
//! host-testable — HIPAA and ISO 27001 are largely administrative — and a host scanner cannot
//! produce a compliance verdict. Callers rendering a score must render the scope alongside it.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How binding a control is on the entity being assessed.
///
/// This exists because HIPAA's three-way distinction is genuinely load-bearing and collapsing it
/// misstates the law. Under 45 CFR §164.306(c)-(d): *standards* are unconditionally mandatory,
/// and the Required/Addressable split applies **only** to implementation specifications beneath
/// them. So §164.312(b) "Audit controls" is a standard with no implementation specifications at
/// all — calling it "Required" is merely loose, but calling it "Addressable" is a category error
/// that would tell a user they may opt out of something they may not.
///
/// "Addressable" does not mean optional either: an entity may implement an equivalent alternative,
/// but must document why. A failing addressable control is therefore a prompt to produce that
/// documentation, not automatically a violation — a distinction any report showing these results
/// needs to preserve.
///
/// Left `None` for standards that do not draw this distinction (PCI DSS, ISO 27001) rather than
/// inventing one for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Obligation {
    /// A standard in its own right; mandatory, and the R/A split does not apply to it.
    Standard,
    /// An implementation specification the entity must implement.
    Required,
    /// An implementation specification the entity must implement *or* document an equivalent
    /// alternative for. Not optional.
    Addressable,
}

/// One control (or implementation specification) within a standard, and the Bulwark rules whose
/// outcome is treated as evidence for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    /// The identifier as written in the standard, e.g. `8.3.6`, `164.312(b)`, `A.8.9`.
    pub id: String,
    /// A short paraphrase written for this project. Deliberately *not* the standard's own text:
    /// ISO/IEC and the PCI SSC hold copyright in theirs. (HIPAA is US federal regulation and
    /// public domain, so that file may quote directly.)
    pub title: String,
    /// How binding this control is, where its standard draws the distinction. See [`Obligation`].
    #[serde(default)]
    pub obligation: Option<Obligation>,
    /// Rules whose findings are evidence for this control. Note which rules are absent: the
    /// "could not determine" rules (`BLWK-FIM-007`, `BLWK-FIM-008`, `BLWK-SSH-013`) encode
    /// *undetermined*, not *failed*, so mapping them would convert a failure to observe into a
    /// compliance failure — the exact confusion this module exists to prevent.
    pub rules: Vec<String>,
}

/// A compliance standard and the subset of its controls Bulwark can speak to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Standard {
    pub id: String,
    pub name: String,
    pub version: String,
    pub source_url: String,
    /// An honest statement of what this mapping does *not* cover. Required, non-empty, and
    /// carried through into every report — see the module docs.
    pub scope_note: String,
    /// Total controls in the standard at the granularity we map, where that number is
    /// well-defined and verifiable (ISO 27001:2022 Annex A has exactly 93). Left unset rather
    /// than guessed: a fabricated denominator is worse than an absent one.
    #[serde(default)]
    pub catalog_size: Option<u32>,
    pub controls: Vec<Control>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    /// Every mapped rule that ran came back clean.
    Pass,
    /// At least one mapped rule that ran is currently open.
    Fail,
    /// No mapped rule ran, so this scan says nothing either way. Excluded from the score.
    NotAssessed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlResult {
    pub control_id: String,
    pub title: String,
    /// Carried through from the mapping so a caller can render "addressable" alongside a failure
    /// instead of presenting every failed control as an outright violation.
    pub obligation: Option<Obligation>,
    pub status: ControlStatus,
    /// Rules mapped to this control that actually ran in this scan.
    pub assessed_rules: Vec<String>,
    /// The subset of those currently open — i.e. why this control failed.
    pub failing_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandardReport {
    pub standard_id: String,
    pub name: String,
    pub version: String,
    pub source_url: String,
    pub scope_note: String,
    /// `passing / assessed`, 0-100. `None` when nothing was assessed — deliberately not `0`,
    /// which would read as total failure rather than "no data".
    pub score: Option<u8>,
    pub assessed: usize,
    pub passing: usize,
    pub failing: usize,
    pub not_assessed: usize,
    /// How many controls this mapping covers at all.
    pub mapped_controls: usize,
    /// How many controls the standard contains, where known. `mapped_controls` over this is the
    /// honest measure of how partial the score is.
    pub catalog_size: Option<u32>,
    pub controls: Vec<ControlResult>,
}

const EMBEDDED: &[(&str, &str)] = &[
    ("pci-dss-4.0", include_str!("standards/pci-dss-4.0.yaml")),
    (
        "hipaa-security-rule",
        include_str!("standards/hipaa-security-rule.yaml"),
    ),
    (
        "iso-27001-2022",
        include_str!("standards/iso-27001-2022.yaml"),
    ),
];

/// Every standard compiled into this binary.
///
/// Panics only on a malformed embedded file, which is a build-time authoring error caught by
/// `every_embedded_standard_parses` — it cannot be triggered by anything a user does at runtime.
pub fn all_standards() -> Vec<Standard> {
    EMBEDDED
        .iter()
        .map(|(id, text)| {
            serde_yaml::from_str::<Standard>(text)
                .unwrap_or_else(|e| panic!("embedded standard {id} is malformed: {e}"))
        })
        .collect()
}

pub fn standard_by_id(id: &str) -> Option<Standard> {
    all_standards().into_iter().find(|s| s.id == id)
}

/// Score one standard against a scan.
///
/// `evaluated_rules` must be the scan's `rules_evaluated` set — the rules that demonstrably ran.
/// Passing every known rule id here instead would silently convert skipped controls into passing
/// ones; see the module docs.
pub fn evaluate(
    standard: &Standard,
    evaluated_rules: &BTreeSet<String>,
    open_rule_ids: &BTreeSet<String>,
) -> StandardReport {
    let controls: Vec<ControlResult> = standard
        .controls
        .iter()
        .map(|control| {
            let assessed_rules: Vec<String> = control
                .rules
                .iter()
                .filter(|r| evaluated_rules.contains(*r))
                .cloned()
                .collect();
            let failing_rules: Vec<String> = assessed_rules
                .iter()
                .filter(|r| open_rule_ids.contains(*r))
                .cloned()
                .collect();

            let status = if assessed_rules.is_empty() {
                ControlStatus::NotAssessed
            } else if failing_rules.is_empty() {
                ControlStatus::Pass
            } else {
                ControlStatus::Fail
            };

            ControlResult {
                control_id: control.id.clone(),
                title: control.title.clone(),
                obligation: control.obligation,
                status,
                assessed_rules,
                failing_rules,
            }
        })
        .collect();

    let passing = controls
        .iter()
        .filter(|c| c.status == ControlStatus::Pass)
        .count();
    let failing = controls
        .iter()
        .filter(|c| c.status == ControlStatus::Fail)
        .count();
    let not_assessed = controls
        .iter()
        .filter(|c| c.status == ControlStatus::NotAssessed)
        .count();
    let assessed = passing + failing;

    // Integer math, rounded half-up, and never 100 unless genuinely every assessed control passes
    // (nor 0 unless none do) — a score that rounds to a reassuring 100 while something is open
    // would undermine the whole report.
    let score = if assessed == 0 {
        None
    } else {
        Some(((passing * 200 + assessed) / (assessed * 2)) as u8)
    };

    StandardReport {
        standard_id: standard.id.clone(),
        name: standard.name.clone(),
        version: standard.version.clone(),
        source_url: standard.source_url.clone(),
        scope_note: standard.scope_note.clone(),
        score,
        assessed,
        passing,
        failing,
        not_assessed,
        mapped_controls: standard.controls.len(),
        catalog_size: standard.catalog_size,
        controls,
    }
}

/// Score every embedded standard against one scan.
pub fn evaluate_all(
    evaluated_rules: &BTreeSet<String>,
    open_rule_ids: &BTreeSet<String>,
) -> Vec<StandardReport> {
    all_standards()
        .iter()
        .map(|s| evaluate(s, evaluated_rules, open_rule_ids))
        .collect()
}

/// Rules referenced by at least one standard, keyed by rule id, with the controls citing them.
/// Used by the coverage test below and useful for a future "which standards does this rule serve?"
/// view in either front-door.
pub fn rules_to_controls() -> BTreeMap<String, Vec<(String, String)>> {
    let mut map: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for standard in all_standards() {
        for control in &standard.controls {
            for rule in &control.rules {
                map.entry(rule.clone())
                    .or_default()
                    .push((standard.id.clone(), control.id.clone()));
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rules_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
    }

    fn shipped_rules() -> Vec<crate::models::Rule> {
        let (loaded, errors) = crate::engine::load_rules(&rules_dir());
        assert!(errors.is_empty(), "rule pack failed to load: {errors:?}");
        loaded.into_iter().map(|l| l.rule).collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn fixture() -> Standard {
        Standard {
            id: "test-std".into(),
            name: "Test".into(),
            version: "1".into(),
            source_url: "https://example.invalid".into(),
            scope_note: "partial".into(),
            catalog_size: Some(10),
            controls: vec![
                Control {
                    id: "C-1".into(),
                    title: "one".into(),
                    obligation: None,
                    rules: vec!["R-A".into(), "R-B".into()],
                },
                Control {
                    id: "C-2".into(),
                    title: "two".into(),
                    obligation: None,
                    rules: vec!["R-C".into()],
                },
                Control {
                    id: "C-3".into(),
                    title: "three".into(),
                    obligation: None,
                    rules: vec!["R-D".into()],
                },
            ],
        }
    }

    #[test]
    fn every_embedded_standard_parses() {
        let standards = all_standards();
        assert_eq!(standards.len(), EMBEDDED.len());
        for s in &standards {
            assert!(!s.controls.is_empty(), "{} has no controls", s.id);
            assert!(
                !s.scope_note.trim().is_empty(),
                "{} must carry a scope note — a score without stated scope is the failure mode \
                 this field exists to prevent",
                s.id
            );
            assert!(s.source_url.starts_with("https://"), "{}", s.id);
        }
    }

    #[test]
    fn embedded_ids_match_their_filenames() {
        for ((declared, text), parsed) in EMBEDDED.iter().zip(all_standards()) {
            assert_eq!(
                *declared,
                parsed.id,
                "the id inside the file disagrees with its key; text starts: {:?}",
                &text[..40.min(text.len())]
            );
        }
    }

    /// The drift guard, and the reason this module is testable at all: a mapping that cites a rule
    /// id which no longer exists silently drops that control's evidence, and the control then
    /// reports `NotAssessed` forever — a compliance report quietly going blind rather than erroring.
    /// Renaming or removing a rule must fail here.
    #[test]
    fn every_mapped_rule_id_exists_in_the_shipped_pack() {
        let known: BTreeSet<String> = shipped_rules().into_iter().map(|r| r.id).collect();
        let mut missing = Vec::new();
        for standard in all_standards() {
            for control in &standard.controls {
                for rule in &control.rules {
                    if !known.contains(rule) {
                        missing.push(format!("{}/{} -> {}", standard.id, control.id, rule));
                    }
                }
            }
        }
        assert!(
            missing.is_empty(),
            "mappings cite unknown rules: {missing:#?}"
        );
    }

    /// The "could not determine" rules encode *undetermined*, not *failed*. Mapping one would make
    /// a failure to observe register as a compliance failure — inverting the collector invariant
    /// this project treats as load-bearing.
    #[test]
    fn undetermined_rules_are_never_used_as_control_evidence() {
        const UNDETERMINED: &[&str] = &["BLWK-FIM-007", "BLWK-FIM-008", "BLWK-SSH-013"];
        let mapped = rules_to_controls();
        for rule in UNDETERMINED {
            assert!(
                !mapped.contains_key(*rule),
                "{rule} reports that a check could not be performed; it must not count for or \
                 against a control"
            );
        }
    }

    /// HIPAA draws a legally meaningful three-way distinction, so every control mapped from it must
    /// state which it is. A missing obligation would leave a UI with nothing to say about whether a
    /// failure is a violation or a documentation prompt.
    #[test]
    fn every_hipaa_control_declares_its_obligation() {
        let hipaa = standard_by_id("hipaa-security-rule").expect("hipaa standard is embedded");
        for control in &hipaa.controls {
            assert!(
                control.obligation.is_some(),
                "{} has no obligation; see 45 CFR 164.306(c)-(d)",
                control.id
            );
        }
    }

    /// The category error worth pinning: §164.312(b) and §164.312(d) are *standards* with no
    /// implementation specifications, so Required/Addressable does not apply to them. Marking
    /// either "addressable" would tell a user they may opt out of something they may not.
    #[test]
    fn hipaa_standards_are_not_labelled_required_or_addressable() {
        const ARE_STANDARDS: &[&str] = &[
            "164.312(a)(1)",
            "164.312(b)",
            "164.312(c)(1)",
            "164.312(d)",
            "164.312(e)(1)",
        ];
        let hipaa = standard_by_id("hipaa-security-rule").unwrap();
        for id in ARE_STANDARDS {
            let control = hipaa
                .controls
                .iter()
                .find(|c| c.id == *id)
                .unwrap_or_else(|| panic!("{id} missing from the mapping"));
            assert_eq!(
                control.obligation,
                Some(Obligation::Standard),
                "{id} is a standard in its own right, not an implementation specification"
            );
        }
    }

    /// PCI DSS and ISO 27001 do not draw this distinction, so inventing one for them would be
    /// fabricated metadata.
    #[test]
    fn standards_without_an_obligation_concept_do_not_declare_one() {
        for id in ["pci-dss-4.0", "iso-27001-2022"] {
            let standard = standard_by_id(id).unwrap();
            for control in &standard.controls {
                assert_eq!(
                    control.obligation, None,
                    "{}/{} declares an obligation, but {id} has no such concept",
                    standard.id, control.id
                );
            }
        }
    }

    #[test]
    fn obligation_is_carried_into_the_report() {
        let hipaa = standard_by_id("hipaa-security-rule").unwrap();
        let report = evaluate(&hipaa, &BTreeSet::new(), &BTreeSet::new());
        let audit = report
            .controls
            .iter()
            .find(|c| c.control_id == "164.312(b)")
            .unwrap();
        assert_eq!(audit.obligation, Some(Obligation::Standard));
    }

    #[test]
    fn control_ids_are_unique_within_a_standard() {
        for standard in all_standards() {
            let mut seen = BTreeSet::new();
            for control in &standard.controls {
                assert!(
                    seen.insert(control.id.clone()),
                    "{} declares control {} twice — the later would shadow the earlier in any \
                     id-keyed view",
                    standard.id,
                    control.id
                );
            }
        }
    }

    #[test]
    fn a_control_never_lists_the_same_rule_twice() {
        for standard in all_standards() {
            for control in &standard.controls {
                let unique: BTreeSet<_> = control.rules.iter().collect();
                assert_eq!(
                    unique.len(),
                    control.rules.len(),
                    "{}/{} repeats a rule",
                    standard.id,
                    control.id
                );
            }
        }
    }

    #[test]
    fn mapped_controls_never_exceed_the_declared_catalog_size() {
        for standard in all_standards() {
            if let Some(size) = standard.catalog_size {
                assert!(
                    standard.controls.len() as u32 <= size,
                    "{} maps {} controls but claims a catalog of {size}",
                    standard.id,
                    standard.controls.len()
                );
            }
        }
    }

    #[test]
    fn a_control_passes_when_every_evaluated_rule_is_clean() {
        let r = evaluate(&fixture(), &set(&["R-A", "R-B"]), &BTreeSet::new());
        assert_eq!(r.controls[0].status, ControlStatus::Pass);
        assert_eq!(r.controls[0].assessed_rules, vec!["R-A", "R-B"]);
        assert!(r.controls[0].failing_rules.is_empty());
    }

    #[test]
    fn one_open_rule_fails_the_whole_control() {
        let r = evaluate(&fixture(), &set(&["R-A", "R-B"]), &set(&["R-B"]));
        assert_eq!(r.controls[0].status, ControlStatus::Fail);
        assert_eq!(r.controls[0].failing_rules, vec!["R-B"]);
    }

    /// The invariant from the module docs. An unprivileged scan skips collectors; if skipped
    /// controls counted as passing, seeing less would score higher.
    #[test]
    fn a_control_whose_rules_never_ran_is_not_passing() {
        let r = evaluate(&fixture(), &BTreeSet::new(), &BTreeSet::new());
        for c in &r.controls {
            assert_eq!(
                c.status,
                ControlStatus::NotAssessed,
                "{} scored without evidence",
                c.control_id
            );
        }
        assert_eq!(r.score, None, "a scan that assessed nothing has no score");
        assert_eq!(r.assessed, 0);
        assert_eq!(r.not_assessed, 3);
    }

    #[test]
    fn not_assessed_is_excluded_from_the_score() {
        // C-1 passes, C-2 fails, C-3 never ran. 1 of 2 assessed => 50, not 33.
        let r = evaluate(&fixture(), &set(&["R-A", "R-B", "R-C"]), &set(&["R-C"]));
        assert_eq!(r.controls[2].status, ControlStatus::NotAssessed);
        assert_eq!(r.assessed, 2);
        assert_eq!(r.passing, 1);
        assert_eq!(r.failing, 1);
        assert_eq!(r.not_assessed, 1);
        assert_eq!(r.score, Some(50));
    }

    /// Visibility must not inflate the score: assessing strictly more controls, with the newly
    /// assessed one failing, can only move the score down.
    #[test]
    fn assessing_more_controls_never_raises_the_score_when_they_fail() {
        let narrow = evaluate(&fixture(), &set(&["R-A", "R-B"]), &BTreeSet::new());
        let wide = evaluate(&fixture(), &set(&["R-A", "R-B", "R-C"]), &set(&["R-C"]));
        assert_eq!(narrow.score, Some(100));
        assert!(wide.score.unwrap() < narrow.score.unwrap());
    }

    #[test]
    fn an_open_rule_that_did_not_run_cannot_fail_a_control() {
        // A stale open finding from an earlier privileged scan must not fail a control in a scan
        // where that rule never ran — the reconciler's own "skipped proves nothing" rule.
        let r = evaluate(&fixture(), &set(&["R-A"]), &set(&["R-C"]));
        assert_eq!(r.controls[1].status, ControlStatus::NotAssessed);
        assert_eq!(r.controls[0].status, ControlStatus::Pass);
    }

    #[test]
    fn score_is_rounded_half_up_and_saturates_only_when_earned() {
        let two_of_three = Standard {
            controls: vec![
                Control {
                    id: "a".into(),
                    title: "a".into(),
                    obligation: None,
                    rules: vec!["R-A".into()],
                },
                Control {
                    id: "b".into(),
                    title: "b".into(),
                    obligation: None,
                    rules: vec!["R-B".into()],
                },
                Control {
                    id: "c".into(),
                    title: "c".into(),
                    obligation: None,
                    rules: vec!["R-C".into()],
                },
            ],
            ..fixture()
        };
        let evaluated = set(&["R-A", "R-B", "R-C"]);
        assert_eq!(
            evaluate(&two_of_three, &evaluated, &set(&["R-C"])).score,
            Some(67),
            "2/3 rounds half-up to 67"
        );
        assert_eq!(
            evaluate(&two_of_three, &evaluated, &BTreeSet::new()).score,
            Some(100)
        );
        assert_eq!(
            evaluate(&two_of_three, &evaluated, &set(&["R-A", "R-B", "R-C"])).score,
            Some(0)
        );
    }

    #[test]
    fn evaluate_all_covers_every_embedded_standard() {
        let reports = evaluate_all(&BTreeSet::new(), &BTreeSet::new());
        assert_eq!(reports.len(), EMBEDDED.len());
        for r in &reports {
            assert!(!r.scope_note.trim().is_empty());
            assert_eq!(r.mapped_controls, r.controls.len());
        }
    }

    /// Every rule must be either mapped to a control or *explicitly* exempted with a reason.
    ///
    /// A percentage-threshold version of this test ("at least half the pack is mapped") was tried
    /// first and thrown away: at the time it was written the pack was 58/65 mapped and the
    /// threshold would still have passed at 33/65, so it could not have caught the thing it
    /// existed to catch. Worse, it let two genuine oversights (`BLWK-SSH-006`, `BLWK-ACCT-001`)
    /// sit unmapped while showing green. Forcing a per-rule decision is the only version of this
    /// that does any work: adding a rule now fails here until someone says which controls it
    /// serves, or writes down why it serves none.
    #[test]
    fn every_rule_is_either_mapped_or_deliberately_exempt() {
        // Reason -> rules. Each entry is a claim someone had to make on purpose.
        const EXEMPT: &[(&str, &[&str])] = &[
            (
                "reports that a check could not be performed; undetermined is not evidence \
                 for or against a control (see undetermined_rules_are_never_used_as_control_evidence)",
                &["BLWK-FIM-007", "BLWK-FIM-008", "BLWK-SSH-013"],
            ),
            (
                "not a Linux host control; these standards are mapped here only against the \
                 Linux host configuration Bulwark audits",
                &["BLWK-PERSIST-003", "BLWK-PERSIST-004"],
            ),
        ];

        let exempt: BTreeSet<String> = EXEMPT
            .iter()
            .flat_map(|(_, rules)| rules.iter().map(|r| r.to_string()))
            .collect();
        let all: BTreeSet<String> = shipped_rules().into_iter().map(|r| r.id).collect();
        let mapped: BTreeSet<String> = rules_to_controls().keys().cloned().collect();

        let undecided: Vec<&String> = all
            .difference(&mapped)
            .filter(|r| !exempt.contains(*r))
            .collect();
        assert!(
            undecided.is_empty(),
            "these rules are neither mapped to a control nor listed as exempt: {undecided:#?}"
        );

        // The exemption list must not rot either: an entry naming a rule that no longer exists is
        // a stale claim, and one naming a rule that *is* mapped is a contradiction.
        let stale: Vec<&String> = exempt.iter().filter(|r| !all.contains(*r)).collect();
        assert!(
            stale.is_empty(),
            "exemptions name unknown rules: {stale:#?}"
        );
        let contradictory: Vec<&String> = exempt.intersection(&mapped).collect();
        assert!(
            contradictory.is_empty(),
            "these rules are both mapped and exempt: {contradictory:#?}"
        );
    }
}
