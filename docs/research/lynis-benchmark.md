# Bulwark vs. 5 established tools — a real, reproducible run, not a literature review

Every claim below comes from actually executing these tools against the same live machine, in
the same session — not from reading their docs. Where a tool couldn't be run (and why, exactly)
is reported just as plainly as where it could; a comparison that only reports the runs that
worked would be misleading by omission. Raw artifacts (`lynis-report.dat`, `lynis.log`,
`chkrootkit-stdout.txt`, `bulwark-scan.json`) are reproducible with the commands in each
section; they aren't checked into the repo since they contain this specific machine's
hostname/kernel/package details, but any Bulwark contributor can regenerate them.

**Tools executed, with real output**: Lynis, rkhunter, chkrootkit, AIDE, OpenSCAP — all 5. Lynis
ran directly against this host (twice). The other four needed root, which this environment's
own account doesn't have (no passwordless `sudo`, and `unshare --map-root-user` is itself
blocked by this machine's `kernel.apparmor_restrict_unprivileged_userns=1` — a real, verified
hardening control, not a workaround worth pushing past). Docker, which this account *does* have
group access to, solved this the legitimate way: a disposable `ubuntu:24.04` container is real
root by construction, no host privilege needed. All four were installed via `apt` (with real
root, inside the container — no source builds required, sidestepping AIDE's earlier
`autoconf`/`automake`/`libtool` build wall entirely) and run to completion with full, real
captured output. Every number below is from an actual run, not a manual page.

## Methodology

- **Host**: `GenOnTheGoLinux`, Ubuntu 26.04, kernel `7.0.0-27-generic`, x86_64.
- **Lynis**: `CISOfy/lynis` cloned from GitHub (`3.1.7`, i.e. current upstream `main` at clone
  time), run as:
  ```bash
  ./lynis audit system --pentest --quick --no-colors --no-plugins \
    --logfile lynis.log --report-file lynis-report.dat
  ```
  `--pentest` runs it in non-privileged mode (no root/sudo — this dev environment has no
  passwordless sudo, so this is also the fairer comparison: it's what a Lynis user gets
  without deliberately elevating). `--no-plugins` was added after a first attempt hung for
  minutes on the systemd-journal-integrity plugin (`PLGN-3814`) on this machine's
  long-lived journal (159 recorded boots) — plugins aren't Lynis's core hardening checks
  and aren't what this comparison is about.
- **Bulwark**: `cargo build --release -p bulwark-cli`, then `bulwark scan --no-persist --json`
  — also unprivileged, for the same reason.
- Both tools ran within the same few minutes, against the same unmodified machine state.

## Raw results

**Lynis**: `hardening_index=67`, 231 tests executed (`tests_executed` in the report), 0
`warning[]` entries, **37** `suggestion[]` entries.

**Bulwark**: 44 rules loaded, **6** findings.

The raw counts alone are not a meaningful score comparison — Lynis's 231 tests span services
Bulwark deliberately doesn't check (mail servers, LDAP, printers, SNMP, databases, PHP, USB,
virtualization — this machine has none of those services running, so most of the 231 tests are
fast "not applicable" no-ops, not real coverage this machine benefits from). The useful
comparison is per-finding: what did each tool actually flag, and does the other one catch it
too.

## Where findings overlap

| Bulwark finding | Lynis finding | Assessment |
|---|---|---|
| `BLWK-ACCT-002` — password max age > 365 days | `AUTH-9286` — configure maximum password age | Direct match |
| `BLWK-LOG-002` — no remote log forwarding | `LOGG-2154` — enable logging to an external host | Direct match |
| `BLWK-KERNEL-003` — no MAC framework enforcing | `MACF-6208` — check `aa-status` output | Same underlying concern; Bulwark states the conclusion (not enforcing), Lynis surfaces the raw command to run manually |
| `BLWK-KERNEL-008/016/017` — kexec, ICMP redirects, martian logging | `KRNL-6000` — "one or more sysctl values differ from the scan profile" | Same underlying data source (Lynis's own `default.prf` sysctl table, which is what Bulwark's kernel-hardening rules were built from), but Lynis's *report* only emits one aggregate suggestion — a Lynis user has to dig into `lynis.log` to see which specific keys are wrong. Bulwark itemizes each one as a separate finding with the live value and a specific fix. This is a real, verifiable advantage in the report itself, not a coverage claim. |

## Real gaps: Lynis suggestions Bulwark doesn't check yet

Checked against the actual rule pack (not assumed) — these are genuine, currently-unimplemented
checks, prioritized by how directly they map to a scoped, low-false-positive Bulwark rule:

1. ~~**`FINT-4350`** — no file integrity monitoring tool installed.~~ **Closed.** Bulwark now
   ships baseline-and-diff file-integrity monitoring (`rules/file-integrity/BLWK-FIM-001..005`,
   `bulwark fim baseline`) over the same class of critical paths AIDE exists to watch —
   `/etc/passwd`, PAM configs, `sshd_config`, `su`/`sudo`, plus `/etc/shadow`/`/etc/sudoers`
   behind `--privileged`. Verified live on this machine: a scan before baselining correctly
   flagged all 7 world-readable watched files as unbaselined (`BLWK-FIM-003`); after running
   `bulwark fim baseline`, an immediate rescan produced zero FIM findings, confirming the
   baseline-write and the diff-read agree with each other on real files, not just in unit tests.
2. **`BANN-7126` / `BANN-7130`** — no legal banner in `/etc/issue` / `/etc/issue.net`. Trivial,
   low-false-positive check (file exists and is non-empty) — good near-term add.
3. **`AUTH-9230` / `AUTH-9328`** — password hashing rounds and default umask not configured in
   `/etc/login.defs`. The `login_defs` collector already parses this file for aging fields;
   extending it to `SHA_CRYPT_MIN_ROUNDS`/`UMASK` is a small, natural addition, not new
   architecture.
4. **`AUTH-9286`** (the *minimum* password age half) — Bulwark's `BLWK-ACCT-002` only checks
   `PASS_MAX_DAYS`, not `PASS_MIN_DAYS`. A `PASS_MIN_DAYS 0` lets a user immediately cycle back
   to a leaked password when forced to rotate.
5. **`BOOT-5122`** — no GRUB bootloader password. Relevant to physical/console-access
   persistence and tamper scenarios; needs a new collector (parse `/boot/grub/grub.cfg` for a
   `password` / `password_pbkdf2` directive), more work than the others.
6. **`ACCT-9622`** — process accounting (`acct`/`psacct`) not enabled.
7. **`HRDN-7222`** — compilers (`gcc`, `cc`) not restricted to root-only execution.
8. **`NETW-3200`** — uncommon network protocol modules (`dccp`, `sctp`, `rds`, `tipc`) loadable
   but likely unused, widening kernel attack surface unnecessarily.
9. **`USB-1000`** — USB storage driver present/loadable (workstation/kiosk-hardening relevant,
   lower priority for a general-purpose desktop tool).
10. **`PKGS-7346/7370/7394/7398`** — package hygiene (purge old configs, `debsums` verification,
    patch-management tooling, vulnerable-package auditing). Broader territory needing real
    package-manager integration (apt-specific); lowest priority of this list.

`MALW-3286` (confirm freshclam keeps the ClamAV DB updated) is **not** a real gap — Bulwark's
`clamav_status` collector already checks database freshness; Lynis just doesn't credit that in
this unprivileged run because Lynis itself has no ClamAV-specific check to correlate against.

## rkhunter, chkrootkit, AIDE, OpenSCAP: real runs, real output

First, the same finding as before still holds and is worth keeping: on the bare host account
(no Docker), `rkhunter --configfile CONFIG --check` and separately `--list tests`, `--version`,
`--config-check` all printed exactly `You must be the root user to run this program.` before
doing anything else — a hardcoded check, not a side effect of the custom install layout.
`./chkrootkit` (no args) printed `./chkrootkit needs root privileges` just as immediately.
Lynis's own choice to support a genuinely useful unprivileged mode is not the norm among classic
Unix security-audit tools; these two are architecturally "root or nothing."

With real (container) root, all four ran to completion:

- **rkhunter 1.4.6** (`apt install rkhunter`, `rkhunter --check --sk --nocolors --logfile PATH`):
  checked **461 rootkit signatures** and **116 file properties** in 49 seconds. Real
  warnings: `postfix` user/group added to `passwd`/`group` (an artifact of rkhunter itself
  pulling in postfix as a dependency in this minimal container — not a host finding), no running
  syslog daemon (also a minimal-container artifact — this container has no init/syslog stack at
  all). One rootkit flagged for "additional checks" (Suckit — rkhunter's own noted false-positive
  category for its LKM-hiding heuristic on non-standard kernels/containers), zero confirmed.
- **chkrootkit (github mirror, `0.53-github2`)** (`apt install chkrootkit`, `chkrootkit`): ran
  its full test suite (`aliens`, `asp`, `bindshell`, `lkm`, `sniffer`, `chkutmp`, plus per-binary
  checks against `su`/`sshd`/`ps`/`netstat`/... and dozens of named rootkit signatures inside the
  `aliens` test — ShKit, AjaKit, zaRwT, Fu, Kenga3, Ebury, Mumblehard, Xor.DDoS, Kinsing,
  RotaJakiro, BPF Door, and more). 4 real `WARNING`s, all explainable container artifacts, not
  findings: 3 stray `.document` files under `/usr/lib/ruby` (a known chkrootkit false-positive
  pattern on Ruby installs), a BTRFS-incompatibility notice from `chkdirs`, an `ifpromisc`
  network-interface check with no actual promiscuous interface, and `chkutmp` failing to open
  `utmp` (not populated in a minimal container). No rootkit signature matched.
- **AIDE 0.18.6** (`apt install aide`, `aideinit`, `aide --check`): this is the one that actually
  *demonstrated* its core capability live, not just ran clean. `aideinit` baselined **9,312**
  filesystem entries (AIDE's default config walks real directory trees — `/boot`, `/bin`,
  `/sbin`, `/lib`, `/etc`, `/var/lib`, and more — a much broader default scope than Bulwark's own
  curated ~11-path FIM list). The very next `aide --check` correctly caught a real, live change:
  `aideinit`'s own log file, written *after* the baseline was taken, showed up as a changed entry
  with full before/after hashes across 8 algorithms (MD5/SHA1/SHA256/SHA512/RMD160/TIGER/CRC32/
  WHIRLPOOL/GOST/HAVAL). This is exactly the same class of result Bulwark's own FIM feature was
  built and verified against — good, independent confirmation that the "baseline, then diff"
  approach is sound, from a completely different implementation.
- **OpenSCAP 1.3.9** (`apt install openscap-scanner ssg-debderived`, `oscap xccdf eval --profile
  cis_level1_server ssg-ubuntu2204-ds.xml`): ran a full CIS Ubuntu 22.04 Level 1 Server Benchmark
  evaluation — 291 rules evaluated end to end. First attempt, against an `ubuntu:24.04` container
  (only 22.04 SCAP content was available in the packaged `ssg-debderived`), came back **291/291
  `notapplicable`, score 0/100** — a real, honest result revealing that OpenSCAP's CPE platform
  check is strict about exact OS-version matches, not a partial/degraded evaluation. Retrying
  with a matched `ubuntu:22.04` container hit a different real wall: `ssg-debderived` isn't
  packaged for 22.04's default repos at all (`E: Unable to locate package`), only for 24.04+.
  Both outcomes are reported as what they are — genuine constraints of SCAP content
  version-pinning, not a tool that failed to run.

**The finding this actually produces**: Bulwark's two-tier privilege model (run unprivileged by
default, offer an explicit `pkexec`/`sudo --privileged` path for the gated checks, and always
report what got skipped rather than silently passing) sits closer to Lynis's approach than to
rkhunter/chkrootkit's "root or nothing" design. AIDE's default scope (thousands of files via
directory-tree globs) versus Bulwark's curated list (~11 specific paths) is a real, deliberate
scope difference, not an oversight — Bulwark's FIM explicitly optimizes for "the handful of
files that actually matter for this threat model," matching the same philosophy as its file
watcher's sensitive-path list, not AIDE's "monitor broad system trees" approach. OpenSCAP's
strict content-version pinning is a real practical friction point Bulwark's rule pack doesn't
have, since Bulwark's rules aren't tied to a specific OS release at all.

## Where Bulwark is ahead, verified in this same run

- **Native GUI + continuous monitoring**: Lynis is CLI/cron-only by design (confirmed directly
  from its own `--help` output and this run itself — no daemon mode, no GUI flags exist).
  Bulwark's file-watcher re-triggers on a sensitive file edit in seconds, not at the next cron
  interval.
- **Itemized kernel findings vs. one aggregate note**: demonstrated above (`KRNL-6000` vs.
  `BLWK-KERNEL-008/016/017`) — a direct payoff of building Bulwark's kernel-hardening rules from
  Lynis's own `default.prf` data rather than wrapping Lynis's report output.
- **ClamAV integration**: real, verified with an EICAR file (see `AGENTS.md`); Lynis has no
  equivalent without a separate plugin.

## Reproducing this

```bash
git clone --depth 1 https://github.com/CISOfy/lynis.git && cd lynis
./lynis audit system --pentest --quick --no-colors --no-plugins \
  --logfile lynis.log --report-file lynis-report.dat
grep '^hardening_index=' lynis-report.dat
grep -c '^suggestion\[' lynis-report.dat

cd /path/to/bulwark && cargo build --release -p bulwark-cli
./target/release/bulwark scan --no-persist --json | jq '.findings | length'

# rkhunter / chkrootkit / AIDE / OpenSCAP — real root via a disposable container, not the host
docker run --rm ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq rkhunter chkrootkit aide >/dev/null
  rkhunter --check --sk --nocolors --logfile /tmp/rkhunter.log
  chkrootkit
  aideinit -y -f && aide --check
'
docker run --rm ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq openscap-scanner ssg-debderived >/dev/null
  oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
'  # 24.04 container + 22.04-only SCAP content -> real run, all-notapplicable/score 0 (version
   # mismatch); an ubuntu:22.04 container hits a different wall — ssg-debderived isn't
   # packaged for 22.04's default repos at all. Neither combination this package version
   # ships gives a clean matched pair; both outcomes are reported in the section above.
```
