---
description: >-
  Lynis, rkhunter, chkrootkit, AIDE, OpenSCAP, or Bulwark — a practical guide to which Linux
  security scanner actually fits your situation, desktop or server.
---

# Choosing a Linux security scanner

"Which Linux security tool should I run" doesn't have one right answer — the established options
aren't competing for the same job. Below is a practical breakdown of five widely-used tools plus
[Bulwark](/), based on what each actually does rather than what its landing page says. Each tool
links to its own documentation, so you can check any claim here against the source.

## The short version

| Tool | What it actually is | Best fit |
|---|---|---|
| **[Lynis](https://cisofy.com/lynis/)** | Broad, unprivileged-friendly configuration auditor | You want the widest single-tool coverage and don't mind a CLI-only, report-file workflow |
| **[rkhunter](https://rkhunter.sourceforge.net/)** | Rootkit/backdoor signature scanner | You specifically want rootkit signature detection, and can run it as root |
| **[chkrootkit](https://www.chkrootkit.org/)** | Rootkit/backdoor signature scanner | Same niche as rkhunter, often run alongside it for a second detection engine |
| **[AIDE](https://aide.github.io/)** | File-integrity baseline-and-diff | You want to monitor broad filesystem trees for tampering, not just a curated set of files |
| **[OpenSCAP](https://www.open-scap.org/)** | CIS/compliance benchmark evaluator | You need a formal compliance score (e.g. CIS Level 1) against a specific, matched OS version |
| **[Bulwark](/)** | Desktop-native scanner + CLI + continuous monitoring + AV | You want a GUI on your own Linux machine, or one CLI over SSH, with checks re-run automatically as config changes |

None of these fully substitute for another — the realistic setup for someone who wants broad
coverage is Lynis (or Bulwark) for configuration auditing, plus a rootkit scanner, plus
file-integrity monitoring, layered together. What follows is what actually distinguishes them.

## Lynis: the established generalist

[Lynis](https://cisofy.com/lynis/) is the closest thing to a single default answer, and for good
reason: it runs unprivileged out of the box, covers an enormous surface (services, filesystem,
kernel, auth, logging — hundreds of individual tests), and has been battle-tested for well over a
decade. Its own `--pentest` mode explicitly supports running without root, which is unusually
practitioner-friendly for this category of tool.

Its real limitation isn't coverage — it's presentation and extensibility. Lynis reports findings
into a flat log/report-file format meant to be grepped or read end-to-end, not queried or filtered
interactively, and there's no GUI. A finding like "one or more sysctl values differ from the scan
profile" arrives as a single aggregate line; you have to dig into the log to see *which* keys are
wrong. Extending it with a genuinely new check class also means writing a shell plugin against its
own scripting conventions, not just describing a condition declaratively.

## rkhunter and chkrootkit: signature-based, root-only

Both are narrowly scoped to one job — detecting known rootkits and backdoors by signature — and
both are architecturally "root or nothing": neither will do anything useful without it, on a
philosophy that a rootkit scan is meaningless without full filesystem/process visibility. This is a
reasonable design choice for what they do, but it means neither fits into a low-friction,
run-it-whenever workflow the way Lynis's unprivileged mode does. Running both together isn't
redundant — they use different signature/heuristic engines and occasionally disagree, which is
itself useful as a cross-check. Their output takes real interpretation, though: see
[reading rkhunter and chkrootkit output](/articles/rkhunter-chkrootkit-false-positives) for which
warnings are routinely environment artifacts rather than findings.

## AIDE: broad file-integrity monitoring

[AIDE](https://aide.github.io/)'s whole job is baseline-and-diff: hash a wide set of files once,
then flag anything that changes on a later check. Its default configuration walks entire directory
trees (`/boot`, `/bin`, `/sbin`, `/lib`, `/etc`, and more) — thousands of files, not a curated
handful. That breadth is the right choice if your goal is catching *any* unexpected filesystem
change, anywhere the tool is configured to watch. The tradeoff is signal-to-noise: monitoring
everything means more legitimate churn (package updates, log rotation) shows up as change too, and
needs a maintained exclude-list to stay quiet.

Bulwark's own file-integrity monitoring takes the opposite bet deliberately — a curated list of the
files that actually matter for this threat model (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, PAM
configs, `sshd_config`) rather than whole directory trees. Neither is more correct; they're tuned
for different tolerance for noise.

## OpenSCAP: formal compliance, strictly scoped

[OpenSCAP](https://www.open-scap.org/) evaluates a host against a specific SCAP content bundle —
e.g. the CIS Ubuntu Level 1 Server Benchmark — and produces a numeric compliance score against that
exact standard. This is the right tool when you need to *prove* compliance against a named benchmark
for an audit, not just get general hardening advice. Its sharp edge is version-pinning: SCAP content
is tied to a specific OS release, and a mismatch between your host's actual version and the content's
target version doesn't degrade gracefully — it reports everything as "notapplicable," a silent,
easy-to-miss failure mode worth knowing about before you rely on it.

## Where Bulwark fits

Bulwark's premise is that config auditing, rootkit-adjacent detection, and file integrity
monitoring shouldn't require three separate CLI tools with three separate report formats for
someone who isn't already a security engineer. Concretely, it differs from the above in three ways:

1. **A native desktop GUI, not just a CLI.** This is the gap in the list above: every other tool
   here assumes you're comfortable reading a report file. Bulwark's desktop app is the front door —
   it scans the Linux machine you're actually using, explains each finding in plain language with
   the live value interpolated, and gives you a one-line fix. The same rule engine also ships as
   `bulwarkctl`, so a headless server over SSH gets identical checks and identical findings; both
   share one local scan history.
2. **Continuous, not just on-demand.** A background loop re-scans on an interval, and a file watcher
   on the specific sensitive paths its rules actually read (`sshd_config`, systemd units, sudoers,
   cron) triggers an immediate re-check on change, with findings reconciled across runs so a
   recurring issue doesn't duplicate. Nothing here has to be remembered or cron'd.
3. **Declarative rules with live-value explanations.** Each rule is a plain
   [YAML file](https://github.com/vietanhdev/bulwark/tree/main/rules) — a condition, a
   plain-language explanation template, a fix — evaluated against facts a Rust collector produces. A
   finding like "PASS_MAX_DAYS is 99999" interpolates the actual live value rather than a generic
   "check your password policy" line, and adding a new rule doesn't require touching collector code.
   Each rule also carries its CIS/ATT&CK references as structured data (see
   [the mapping](/articles/cis-mitre-mapping)).

It deliberately does **not** try to out-cover Lynis's hundreds of tests, replace rootkit signature
scanning (it shells out to ClamAV instead of reimplementing detection — see
[what ClamAV actually catches](/articles/does-linux-need-antivirus)), or replace OpenSCAP's formal
compliance scoring. See the [architecture doc](/guide/architecture)'s non-goals section for the
explicit boundary.

## The decision rule

- **Hardening the Linux desktop in front of you** and you'd never otherwise read a Lynis log:
  Bulwark, in the GUI.
- **A server or two over SSH, want plain-language findings and fixes:** Bulwark's CLI, or Lynis if
  you want maximum breadth and don't mind the report-file workflow.
- **Maximum single-tool coverage, CLI-first, on a fleet you already script against:** Lynis.
- **Suspected rootkit, or you want signature-based rootkit detection specifically:** rkhunter and
  chkrootkit, both, as root.
- **Catch any change anywhere in the system trees:** AIDE.
- **Prove compliance against a named benchmark for an auditor:** OpenSCAP, with matched content for
  your exact OS release.

## References

- [Lynis](https://cisofy.com/lynis/) — CISOfy's documentation, including the unprivileged `--pentest` mode.
- [rkhunter](https://rkhunter.sourceforge.net/) and [chkrootkit](https://www.chkrootkit.org/) — the two signature-based rootkit scanners.
- [AIDE](https://aide.github.io/) — the file-integrity tool's own docs and default configuration scope.
- [OpenSCAP](https://www.open-scap.org/) — SCAP content, profiles, and the version-pinning behavior described above.
- [Bulwark's rule pack](https://github.com/vietanhdev/bulwark/tree/main/rules) and [architecture doc](/guide/architecture) — the declarative rules and the explicit non-goals.
