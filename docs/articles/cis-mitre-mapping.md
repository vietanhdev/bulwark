---
description: >-
  How Bulwark's 109 rules map to CIS Benchmark controls and MITRE ATT&CK techniques — the
  real numbers, pulled directly from the rule pack, not a marketing claim.
---

# Mapping Bulwark's rule pack to CIS Benchmarks and MITRE ATT&CK

"CIS-mapped" and "MITRE ATT&CK-aligned" show up on a lot of security-tool marketing pages as an
unverifiable claim. [Bulwark](/)'s rule pack carries these references as a structured field on
every rule YAML file, not prose — which means the mapping below isn't a summary, it's a direct
count pulled from [`rules/*/*.yaml`](https://github.com/vietanhdev/bulwark/tree/main/rules) right
now. Every number on this page is one command away from being checked, and the commands are at the
bottom.

## The real numbers

Bulwark ships **109 rules** across 15 categories. Of those, **102 rules** carry at least one
external reference — 35 distinct CIS Benchmark control IDs and 50 distinct MITRE ATT&CK technique
IDs between them, 17 rules citing both. The remaining **7 rules** deliberately carry no external
reference at all, and it's worth being upfront about which and why, rather than only showing the
numbers that look complete. (The 23 AI-agent checks are separate, native detectors with their own
references; they are listed in the [agent security guide](/guide/agent-security) and not counted
here.)

## What maps to CIS

CIS Benchmark controls dominate the `kernel-hardening`, `accounts-services`, and
`ssh-remote-access` categories — the parts of a Linux host CIS's own benchmarks cover in the most
granular detail:

- **CIS §1.5.x** (kernel/memory hardening: ASLR, kptr_restrict, sysrq, unprivileged BPF,
  perf_event_paranoid, suid_dumpable, hardlink/symlink/FIFO/regular-file protections) — 9 distinct
  sub-controls covering 10 `kernel-hardening` rules; one control (§1.5.9) covers both the FIFO
  and regular-file protection rules, so it's a 10-to-9 mapping, not strictly one-to-one.
- **CIS §3.1–3.2** (network kernel parameters: SYN cookies, ICMP redirects, source routing,
  martian logging, reverse-path filtering) — 5 sub-controls, one of them (§3.2.1) covering both
  the accept- and send-redirects rules.
- **CIS §5.2.x** (SSH daemon configuration) — 8 sub-controls, covering the same directives as the
  [SSH hardening checklist](/articles/ssh-hardening-checklist), plus the section as a whole
  (`CIS-5.2`) on the two rules about SSH private keys without a passphrase.
- **CIS §6.1–6.2** (file permissions and password-aging policy) — 5 sub-controls.
- **CIS §1.1.1, §1.4, §1.4.1, §1.7.1, §3.5, §4.1, §4.6** — one each, covering kernel module
  blacklisting, mandatory access control enforcement, GRUB boot password, legal banners, the host
  firewall, `auditd` presence, and process accounting respectively.

The newer categories — credential exposure, developer tools, macOS and Windows — carry almost no
CIS reference: the CIS IDs used here come from the Linux distribution benchmarks, which do not
cover a developer's `~/.npmrc` or a Mac's Gatekeeper setting.

## What maps to MITRE ATT&CK

ATT&CK technique references cluster around a handful of tactics that map directly onto Bulwark's
own category names:

- **Persistence** — `T1543.002` (Create or Modify System Process: Systemd Service) on the
  reverse-tunnel unit from the [persistence walkthrough](/articles/linux-persistence-techniques)
  (its messaging-API sibling carries the two exfiltration techniques below instead); `T1546.018`
  (Python startup hooks) on the rule about a hook that runs code in every Python process; and
  `T1053.003` (Scheduled
  Task/Job: Cron) on the cron-downloader rule, which lives in `accounts-services`, not
  `persistence` — the categories group rules by what they *check*, not by which ATT&CK tactic
  they map to, and the two don't always line up. Worth stating plainly rather than quietly
  reshuffling the count to look tidier.
- **Persistence, on other platforms** — two more `persistence` rules declare a target platform in
  the rule file and never run on a Linux scan: `T1543.001` (the *macOS* Launch Agent/Daemon
  sibling of `.002`), a working check on a Mac, and `T1547.001` (the *Windows* registry Run-key),
  whose collector is still a skeleton and never fires anywhere. Both are counted in the 109
  because they're real rules that ship; the second is called out here because a mapping table that
  let you infer Windows coverage from it would be lying.
- **Credential Access** — `T1003`, `T1003.007` (`/proc` memory access via ptrace),
  `T1003.008` (`/etc/shadow`), `T1110` (brute force, on the SSH rate-limiting rules).
- **Privilege Escalation** — `T1068` (exploiting a kernel privesc primitive), `T1548.003`
  (sudo/sudo caching abuse), `T1078` (valid accounts), `T1055` (process injection, on the ASLR
  rule — weakened address-space randomization is what makes injection reliable).
- **Defense Evasion** — `T1070`/`T1070.003` (indicator/history removal), `T1222` (file permission
  modification), `T1556` (auth-process modification), `T1601` (kexec-based system-image patching).
- **Command and Control / Exfiltration** — `T1071.001` (application-layer C2 protocol),
  `T1090` (proxy/tunneling, on the ngrok and SSH-tunnel rules specifically), `T1572` (protocol
  tunneling), `T1041` (exfil over C2 channel), `T1563` (remote-service session hijacking),
  `T1219` (remote access software — the VNC-listener rule; a distinct technique from `T1090`
  despite the surface similarity, since this one covers a full remote-desktop tool rather than a
  tunnel).
- **Discovery / Collection** — `T1040` (network sniffing, the promiscuous-interface check),
  `T1557` (adversary-in-the-middle, ICMP redirects), `T1542` (boot/pre-OS tampering, the GRUB
  password rule), `T1098`/`T1556` (account/auth manipulation, on the file-integrity rules watching
  `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, and PAM configs).
- **The categories added since** — the developer-machine and non-Linux rules bring 22 more
  technique IDs. The largest groups: `T1552.x` (unsecured credentials: `.001` credentials in
  files on nine `credential-exposure` rules, `.003` shell history, `.004` private keys, `.002`
  the Windows registry); `T1195.001`/`.002` (supply-chain compromise, on the registry, TLS and
  install-script rules in `developer-tools`); `T1133` (external remote services, on the
  exposed-service and firewall rules); and `T1562.001`/`.004` (disabling security tools or the
  firewall, on the macOS and Windows rules).

## The 7 rules with no reference — and why

`BLWK-LOG-002` (no remote log forwarding configured), `BLWK-AV-001`/`BLWK-AV-002` (ClamAV missing
or its signature database stale), `BLWK-FIM-009` (no file-integrity baseline recorded yet),
`BLWK-FIM-003` (a watched file the baseline doesn't cover) and `BLWK-FIM-007`/`BLWK-FIM-008` (a
watched file that couldn't be verified) —
all seven are checks about Bulwark's or the host's own tooling *state*, not a specific
misconfiguration or attack technique either framework catalogs directly. There's no CIS control
number or ATT&CK technique ID that means "your file-integrity tool has no baseline yet" — that's
a prerequisite-for-detection gap, not a vulnerability or a technique. Leaving the reference field
empty for these, rather than reaching for a loosely-related ID to fill it in, keeps the mapping
that does exist trustworthy — every reference actually present in the rule pack corresponds to a
specific, real cross-check, not a plausible-sounding decoration. It's also worth being precise in
the other direction: not every rule with a reference has *both* — `BLWK-KERNEL-008` (the kexec
rule), for instance, carries `ATTACK-T1601` but no CIS control at all, since not every ATT&CK
technique this rule pack tracks has a matching CIS Benchmark control to cite.

```mermaid
pie title Rules per category (of 109 total)
    "kernel-hardening" : 21
    "ssh-remote-access" : 14
    "developer-tools" : 11
    "credential-exposure" : 10
    "windows-hardening" : 10
    "file-integrity" : 9
    "macos-hardening" : 6
    "accounts-services" : 5
    "network-egress" : 5
    "persistence" : 5
    "logging-auditing" : 4
    "rootkit-malware" : 4
    "filesystem-permissions" : 2
    "privilege-escalation" : 2
    "defense-evasion" : 1
```

## Why this matters beyond the count

A rule mapping is only useful if it lets you answer a real question directly: *for a given
framework, what's actually covered, and what's failing right now?* Because the reference field is
structured data on every rule rather than a separate document to keep in sync by hand, Bulwark's
Compliance view cross-references it against open findings automatically — showing per-framework
pass/fail coverage that updates the moment a scan re-runs, not a static mapping table that drifts
out of date the first time a rule changes. It's the difference between a finding that says "some
sysctl values differ from the profile" and one that says *this* kernel setting is wrong, here's its
live value, here's the CIS control and the ATT&CK technique it belongs to, here's the fix. That's
also why the desktop app can render a compliance view at all rather than a wall of log lines — and
why `bulwarkctl scan --json` on a server emits the same references in machine-readable form, for
whatever you pipe it into.

## Check every number on this page yourself

The rule pack is [plain YAML in the repository](https://github.com/vietanhdev/bulwark/tree/main/rules).
Nothing above is a claim you have to take on trust:

```bash
git clone https://github.com/vietanhdev/bulwark && cd bulwark

ls rules/*/*.yaml | wc -l                              # 109 rules
grep -ho 'CIS-[A-Za-z0-9._-]*' rules/*/*.yaml | sort -u | wc -l    # 35 distinct CIS control IDs
grep -ho 'ATTACK-T[0-9.]*'     rules/*/*.yaml | sort -u | wc -l    # 50 distinct ATT&CK technique IDs
grep -l 'references: \[\]'     rules/*/*.yaml                      # the 7 rules with no reference
```

Or, without cloning anything, `bulwarkctl rules list` prints the same rule set with its references
straight from the binary you're already running.

## References

- [Bulwark's rule pack](https://github.com/vietanhdev/bulwark/tree/main/rules) — the source of every count on this page; each rule's `references:` field is what's being counted.
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) — the control numbering (§1.5.x, §3.1–3.2, §5.2.x, §6.1–6.2) cited by the `CIS-*` references.
- [MITRE ATT&CK](https://attack.mitre.org/) — the technique IDs cited by the `ATTACK-T*` references; each `T####` above links from ATT&CK's own catalog.
- [Bulwark's architecture doc](/guide/architecture) — how the rule engine reads these fields and what the Compliance view does with them.
