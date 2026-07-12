---
description: >-
  Lynis, rkhunter, chkrootkit, AIDE, OpenSCAP, or Bulwark — a practical guide to which Linux
  security scanner actually fits your situation, based on a real hands-on comparison.
---

# Choosing a Linux security scanner

"Which Linux security tool should I run" doesn't have one right answer — the established
options aren't competing for the same job. Below is a practical breakdown of five widely-used
tools plus [Bulwark](/), based on actually running all of them against the same machine (see the
[full benchmark](/research/lynis-benchmark) for raw output and methodology) rather than reading
their marketing pages.

## The short version

| Tool | What it actually is | Best fit |
|---|---|---|
| **Lynis** | Broad, unprivileged-friendly configuration auditor | You want the widest single-tool coverage and don't mind a CLI-only, report-file workflow |
| **rkhunter** | Rootkit/backdoor signature scanner | You specifically want rootkit signature detection, and can run it as root |
| **chkrootkit** | Rootkit/backdoor signature scanner | Same niche as rkhunter, often run alongside it for a second detection engine |
| **AIDE** | File-integrity baseline-and-diff | You want to monitor broad filesystem trees for tampering, not just a curated set of files |
| **OpenSCAP** | CIS/compliance benchmark evaluator | You need a formal compliance score (e.g. CIS Level 1) against a specific, matched OS version |
| **Bulwark** | GUI-native scanner + continuous monitoring + AV | You want a desktop app, not just a CLI, and want checks re-run automatically as config changes |

None of these fully substitute for another — the realistic setup for someone who wants broad
coverage is Lynis (or Bulwark) for configuration auditing, plus a rootkit scanner, plus
file-integrity monitoring, layered together. What follows is what actually distinguishes them.

## Lynis: the established generalist

Lynis is the closest thing to a single default answer, and for good reason: it runs
unprivileged out of the box, covers an enormous surface (services, filesystem, kernel, auth,
logging — hundreds of individual tests), and has been battle-tested for well over a decade. Its
own `--pentest` mode explicitly supports running without root, which is unusually
practitioner-friendly for this category of tool.

Its real limitation isn't coverage — it's presentation and extensibility. Lynis reports findings
into a flat log/report-file format meant to be grepped or read end-to-end, not queried or
filtered interactively, and there's no GUI. A finding like "one or more sysctl values differ
from the scan profile" is a single aggregate line; you have to dig into the log to see *which*
keys are wrong. Extending it with a genuinely new check class also means writing a shell
plugin against its own scripting conventions, not just describing a condition declaratively.

## rkhunter and chkrootkit: signature-based, root-only

Both are narrowly scoped to one job — detecting known rootkits and backdoors by signature — and
both are architecturally "root or nothing": neither will do anything useful without it, on a
philosophy that a rootkit scan is meaningless without full filesystem/process visibility. This
is a reasonable design choice for what they do, but it means neither fits into a low-friction,
run-it-whenever workflow the way Lynis's unprivileged mode does. Running both together isn't
redundant — they use different signature/heuristic engines and occasionally disagree, which is
itself useful as a cross-check.

## AIDE: broad file-integrity monitoring

AIDE's whole job is baseline-and-diff: hash a wide set of files once, then flag anything that
changes on a later check. Its default configuration walks entire directory trees (`/boot`,
`/bin`, `/sbin`, `/lib`, `/etc`, and more) — thousands of files, not a curated handful. That
breadth is the right choice if your goal is catching *any* unexpected filesystem change,
anywhere the tool is configured to watch. The tradeoff is signal-to-noise: monitoring
everything means more legitimate churn (package updates, log rotation) shows up as change too,
and needs a maintained exclude-list to stay quiet.

## OpenSCAP: formal compliance, strictly scoped

OpenSCAP evaluates a host against a specific SCAP content bundle — e.g. the CIS Ubuntu 22.04
Level 1 Server Benchmark — and produces a numeric compliance score against that exact standard.
This is the right tool when you need to *prove* compliance against a named benchmark for an
audit, not just get general hardening advice. Its sharp edge is version-pinning: SCAP content is
tied to a specific OS release, and a mismatch between your host's actual version and the
content's target version doesn't degrade gracefully — it just reports everything as
"notapplicable," a silent, easy-to-miss failure mode worth knowing about before you rely on it.

## Where Bulwark fits

Bulwark's premise is that config auditing, rootkit-adjacent detection, and file integrity
monitoring shouldn't require three separate CLI tools with three separate report formats for
someone who isn't already a security engineer. Concretely, it differs from the above in three
ways:

1. **A native GUI, not just a CLI.** The same rule engine and finding model back a desktop app
   (Tauri) and a CLI, sharing one local scan history — useful for a headless server over SSH,
   and approachable for a desktop user who'd never otherwise read a Lynis log.
2. **Continuous, not just on-demand.** A background loop re-scans on an interval and a file
   watcher on the specific sensitive paths its rules actually read (`sshd_config`, systemd
   units, sudoers, cron) triggers an immediate re-check on change, with findings reconciled
   across runs so a recurring issue doesn't duplicate.
3. **Declarative rules with live-value explanations.** Each rule is a plain YAML file — a
   condition, a plain-language explanation template, a fix — evaluated against facts a Rust
   collector produces. A finding like "PASS_MAX_DAYS is 99999" interpolates the actual live
   value rather than a generic "check your password policy" line, and adding a new rule doesn't
   require touching collector code.

It deliberately does **not** try to out-cover Lynis's hundreds of tests, replace rootkit
signature scanning (it shells out to ClamAV instead of reimplementing detection), or replace
OpenSCAP's formal compliance scoring. See the [architecture doc](/guide/architecture)'s
non-goals section for the explicit boundary, and the [Lynis benchmark](/research/lynis-benchmark)
for exactly which findings overlap and which don't, verified by actually running both against
the same machine.
