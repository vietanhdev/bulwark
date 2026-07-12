---
description: >-
  How to read rkhunter and chkrootkit output without panicking — real warnings from a real
  run, and which ones turned out to be container/environment artifacts, not rootkits.
---

# Reading rkhunter and chkrootkit output without panicking

`rkhunter` and `chkrootkit` both work the same fundamental way: a large battery of signature and
heuristic checks against known rootkit/backdoor patterns, printed as a plain "OK / Warning"
report with essentially no built-in context about *why* something fired. A "Warning" in either
tool's output means "this matched a suspicious pattern," not "this is confirmed malware" — and
distinguishing the two is the actual skill, one that's poorly documented because most writeups
either explain the tools' internals or just tell you to panic. Below is real output from actually
running both — not a hypothetical — with each warning explained, from
[Bulwark's own benchmark run](/research/lynis-benchmark) of five established Linux security
tools against a real machine.

## What actually happened when we ran them

Both `rkhunter` and `chkrootkit` are architecturally "root or nothing" — on an unprivileged
account, both refuse to run at all (`rkhunter`: "You must be the root user to run this program.";
`chkrootkit`: "./chkrootkit needs root privileges") rather than degrading to a partial
unprivileged mode the way Lynis does. Run with real root inside a disposable container:

- **rkhunter 1.4.6** checked 461 rootkit signatures and 116 file properties in 49 seconds.
  It raised warnings in three distinct categories, and confirmed zero rootkits:
  - `postfix` user and group present in `/etc/passwd`/`/etc/group` — this was rkhunter itself
    pulling in `postfix` as a package dependency during install inside the test container, not a
    finding about the host. A rootkit-scanner warning about an account that its own installation
    just created is a real, if slightly absurd, false-positive category worth knowing about.
  - No running syslog daemon — a genuine minimal-container artifact (no init/syslog stack at all
    in a bare `docker run`), not something a normal server would trigger.
  - One rootkit — Suckit — flagged for "additional checks," not confirmed. This is rkhunter's own
    documented false-positive category for its LKM-hiding heuristic on non-standard kernels or
    containerized environments, where the normal signal it looks for doesn't cleanly apply.
- **chkrootkit** (`0.53-github2`) ran its full suite — `aliens`, `bindshell`, `lkm`, `sniffer`,
  `chkutmp`, plus dozens of named signature checks (ShKit, Ebury, BPF Door, and more) — and
  raised exactly four `WARNING`s, all explainable as environment artifacts, zero confirmed:
  - 3 stray `.document` files under `/usr/lib/ruby` — a well-known chkrootkit false-positive
    pattern specifically on Ruby installations (the `aliens` test flags leftover empty marker
    files Ruby's gem system creates, which happen to match a pattern chkrootkit watches).
  - A BTRFS-incompatibility notice from the `chkdirs` test — the filesystem type, not a finding.
  - `ifpromisc` flagged an interface, with no actual promiscuous interface on the host — a
    detection artifact of the container's virtual networking, not a real finding.
  - `chkutmp` failed to open `utmp` — because a minimal container has no populated `utmp` at all,
    not because anything tampered with it.

## The pattern worth internalizing

Every single warning above traces back to one of three explainable causes: **the tool's own
installation** (the postfix dependency), **the environment it's running in** (a minimal
container missing normal init/logging infrastructure), or **a documented heuristic limitation**
(Suckit's LKM-hiding check, the Ruby `.document` pattern). None were an actual rootkit. That's
not a knock on either tool — signature and heuristic rootkit detection inherently trades false
positives for not missing real ones, and both tools are explicit in their own documentation about
which checks are heuristic versus confirmed-signature matches. The mistake is treating every
"Warning" line as equally serious without reading what it's actually claiming.

## A practical triage process

1. **Read what the specific check does**, not just its warning text. `rkhunter --check --sk`
   (skip-keypress mode, for scripted runs) writes a detailed log to
   `/var/log/rkhunter.log` — the summary line and the log entry for the same finding often carry
   very different amounts of context.
2. **Check whether it's a known false-positive pattern for that specific check.** rkhunter's own
   FAQ and changelog document several recurring ones (the Suckit LKM heuristic above is one);
   chkrootkit's `aliens` test against Ruby's `.document` files is another well-known one. A quick
   search for `<tool> <specific warning text>` usually surfaces whether this is a common,
   already-triaged pattern before you assume the worst.
3. **After a legitimate system change** (a package update that replaced a binary chkrootkit or
   rkhunter fingerprints, a deliberate config change), re-baseline rather than re-panicking:
   `rkhunter --propupd` updates rkhunter's stored file-property baseline to the current
   (trusted) state.
4. **Keep signatures current** — `rkhunter --update` before each run; a rootkit scanner running
   against a stale signature database gives you false confidence on genuinely new threats while
   still generating the same volume of environment-noise warnings on old ones.
5. **Cross-check with a second tool when a warning is ambiguous.** rkhunter and chkrootkit use
   different signature/heuristic engines and occasionally disagree — running both isn't
   redundant, it's a real second opinion, which is exactly why the benchmark above ran both
   rather than treating one as sufficient.

```mermaid
flowchart TD
    A["rkhunter/chkrootkit prints a WARNING"] --> B{"Known false-positive pattern\nfor this exact check?"}
    B -- Yes --> C["Re-baseline / document\nand move on"]
    B -- No / unsure --> D{"Recent legitimate\nsystem change?"}
    D -- Yes --> E["rkhunter --propupd\nre-baseline, re-check"]
    D -- No --> F["Investigate: cross-check\nwith the other tool"]
```

## Where a scheduled scan fits alongside these

[Bulwark](/) deliberately doesn't reimplement rootkit signature scanning — its `rootkit-malware`
category shells out to ClamAV for signature-based detection and adds a small set of scoped,
low-false-positive indicators of its own (like the promiscuous-network-interface check,
`BLWK-ROOTKIT-001`, verified against the same real chkrootkit `sniffer`-test behavior referenced
above). For full signature-based rootkit coverage, rkhunter and chkrootkit — read with the triage
process above, not just their raw warning count — remain the right dedicated tools; see the
[full scanner comparison](/articles/choosing-a-linux-security-scanner) for how all of these fit
together.
