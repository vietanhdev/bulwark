# Article topic candidates for docs/articles — three independent research passes, cross-referenced

Three parallel research agents investigated this from different angles: (1) what competitor/adjacent
tools and security blogs currently publish, to find gaps; (2) real recurring questions on Server
Fault / Unix & Linux SE / Security SE / HN, using vote and view counts as a recurrence proxy; (3)
currently-timely 2026 Linux security news, CVEs, and compliance-framework updates. This report
cross-references their findings against Bulwark's actual rule pack (`rules/`) to flag which
candidates fill a real, currently-uncovered rule category — the same grounding the three existing
articles (`docs/articles/`) use.

## Rule-pack coverage gap (checked directly against `rules/`)

| Category | Rules | Dedicated article? |
|---|---|---|
| ssh-remote-access | 11 | ✅ `ssh-hardening-checklist.md` |
| persistence | 4 | ✅ `linux-persistence-techniques.md` |
| (cross-tool comparison) | — | ✅ `choosing-a-linux-security-scanner.md` |
| **kernel-hardening** | **20** | ❌ none — largest rule category with zero dedicated content |
| accounts-services | 5 | ❌ |
| file-integrity | 5 | ❌ (only covered inside the Lynis benchmark report, not a reader-facing article) |
| logging-auditing | 4 | ❌ |
| rootkit-malware | 3 | ❌ |
| privilege-escalation | 2 | ❌ |
| filesystem-permissions | 2 | ❌ |
| network-egress | 2 | ❌ |
| defense-evasion | 1 | ❌ |

kernel-hardening is the single biggest miss: it's the largest rule category in the whole pack (20
of 59 rules) and has never been written up.

## Where all three research angles agreed (strongest signal)

- **Sudoers/privilege-escalation auditing** — flagged independently by the competitor-gap pass (no
  defensive, audit-focused sudoers content exists, only offensive GTFOBins-style posts), the
  pain-point pass (`sudo -l` privesc auditing, Unix SE), and the news pass (CVE-2025-32463, a
  critical "chroot-to-root" sudo bug still unpatched on many hosts). Maps directly to Bulwark's
  `privilege-escalation` category (currently 2 rules, uncovered).
- **sysctl/kernel hardening, with tradeoffs called out** — competitor-gap pass and pain-point pass
  both surfaced this; HN explicitly complains that most hardening guides copy-paste stale/wrong
  sysctl advice without noting what breaks (e.g. `unprivileged_userns_clone=0` breaking rootless
  Podman). Maps to the 20-rule `kernel-hardening` category — the single best-supported, least-served
  topic in the whole set.
- **"Is my Linux server hacked?" incident-response playbook** — competitor-gap pass and pain-point
  pass both found the top-ranking Server Fault threads answering this are from 2011 and OS-agnostic
  (636 pts/175K views on one, 59K views on a companion thread), with no current Linux-specific
  practical guide. Ties together `rootkit-malware`, `persistence`, and `file-integrity`.
- **auditd rules cheat sheet** — both the competitor-gap and pain-point passes found the de-facto
  reference is a single unofficial 2018 personal gist, not a maintained article. Maps to
  `logging-auditing` (4 rules, uncovered).

## Recommended shortlist, prioritized

**Tier 1 — write first (converged signal + fills the largest coverage gaps):**

1. **"sysctl kernel hardening: every parameter, with the tradeoffs nobody lists"** — kernel-hardening,
   20 rules, zero prior coverage. Differentiate by actually testing what each sysctl change breaks
   (matches the site's hands-on-verified style), not just listing recommended values.
2. **"Sudoers hardening checklist"** — companion to the SSH article; cover NOPASSWD auditing,
   `use_pty`/`log_input`, GTFOBins cross-referencing from the defensive side, and CVE-2025-32463 as
   a concrete "why this matters now" hook.
3. **"Is my Linux server hacked? A first-hour response checklist"** — highest-recurrence pain point
   found, weakest existing content (14-year-old top answer). Natural showcase for Bulwark's
   rootkit/AV/FIM/persistence checks working together as an actual response tool, not just theory.
4. **"auditd rules cheat sheet for host security monitoring"** — logging-auditing, uncovered;
   displaces a single unmaintained gist as the go-to reference.

**Tier 2 — strong second wave:**

5. **"Reading rkhunter/chkrootkit output without panicking"** — real, recurring confusion (false
   positives on Security SE, Unix SE); pairs naturally with the existing scanner-comparison article
   and the uncovered `rootkit-malware` category.
6. **"Does a Linux server need antivirus? What ClamAV actually catches"** — recurring skeptical
   debate with no consensus online (21K-view Server Fault thread); good differentiator since Bulwark
   ships real ClamAV integration, not just a config scanner.
7. **"systemd service sandboxing: a directive-by-directive checklist"** (`NoNewPrivileges`,
   `ProtectSystem`, `CapabilityBoundingSet`, etc.) — complements the existing persistence article
   from the hardening (not attacker) side; current best reference is a personal gist.
8. **"Bulwark vs. Wazuh: lightweight scanner vs. full SIEM/XDR"** — extends the existing
   scanner-comparison article; this specific comparison currently only exists buried inside generic
   "CrowdStrike alternatives" listicles.

**Tier 3 — compliance/mapping angle (distinct audience, leverages existing rule metadata):**

9. **"Mapping Bulwark's rule pack to CIS Benchmarks v2.0 and MITRE ATT&CK for Linux"** — every rule
   already carries CIS/MITRE references (`rules/`), so this is close to a direct writeup of existing
   data rather than new research. CIS shipped v2.0 rewrites for Ubuntu 24.04 and Debian 12/13 across
   Jan–Jun 2026, making this timely.
10. **"fail2ban vs. CrowdSec vs. denyhosts: which SSH brute-force defense actually works"** — huge
    existing search volume (800K+ views across related threads) with no current, decisive
    comparison; extends the thin `network-egress` category.

**Tier 4 — news-hook pieces (highest traffic potential, but verify every fact before publishing):**

11. CVE-driven pieces surfaced by the trend-scan pass: the sudo CVE-2025-32463 "chroot-to-root" bug,
    recent kernel ptrace privilege-escalation CVEs, an OpenSSH CVE roundup, and reports of PAM-module
    backdoors and a supply-chain rootkit incident in AUR packages. These would drive real,
    timely traffic and natural backlinks (news-hook content gets cited), but **every CVE number,
    disclosure date, and technical claim needs to be independently re-verified against NVD/vendor
    advisories directly before publishing** — this pass came from a single web-search sweep, and
    getting a CVE detail wrong in security content is reputationally costly in a way it isn't for the
    other topics.

## Not recommended

- Generic "chmod 777 mistakes" content — pain-point pass flagged this as saturated with beginner
  blogspam with no unique angle Bulwark can add.
- Broad "cybersecurity trends 2026" pieces — doesn't leverage Bulwark's specific, narrow, verifiable
  host-auditing capability the way every topic above does.

## Sources

Full source URLs (Server Fault/Unix SE/Security SE threads with vote/view counts, HN discussions,
CVE advisories, vendor blog posts) are preserved in the three research-agent transcripts from this
session; pull the specific citations back out per-topic when drafting each article rather than
duplicating the full list here.
