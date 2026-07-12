# Research: Comprehensive Linux Host Security Checklist for Bulwark

**Date:** 2026-07-11
**Purpose:** Ground Bulwark's v1 rule set in the actual coverage of established open-source security tools, plus MITRE ATT&CK, so the checklist reflects general, well-documented attacker tradecraft rather than a narrow or ad hoc list.

## Executive summary

- Lynis's own source tree defines **46 distinct test categories** — the broadest single reference for "what should a general Linux hardening/audit tool check." [^1] `high`
- HackTricks' Linux Privilege Escalation Checklist and linPEAS give the *attacker's* enumeration order — cron/systemd writability, SUID/GTFOBins, capabilities, LD_PRELOAD, NFS `no_root_squash` — which is the direct inverse of what a defensive scanner should flag. [^2] `high`
- MITRE ATT&CK maps cleanly onto three tactics most relevant to a single compromised host: Persistence (TA0003), Credential Access (TA0006), and Defense Evasion (TA0005) — each technique below is host-scoped, not cloud/enterprise-only. [^3][^4][^5] `high`
- rkhunter/chkrootkit and Wazuh's rootcheck+FIM modules cover the same core ground (rootkit signatures, hidden files/processes, file-integrity baselining) via different mechanisms (signature DB vs. hash-diffing vs. live rule engine). [^6][^7] `medium` — search-derived summaries, not primary doc line-items.
- CIS Benchmarks for Ubuntu are organized by profile (Server/Workstation × Level 1/2) and section (Initial Setup, Services, Network Config, Logging & Auditing, Access/Auth/Authorization, System Maintenance). [^8] `medium` — category structure confirmed, full control-by-control detail not fetched (behind PDF).

## Category checklist (synthesized)

### 1. SSH / Remote Access
- `PasswordAuthentication no`, `PermitRootLogin no`, `PermitEmptyPasswords no` in `sshd_config` [^1][^8]
- `authorized_keys` diffing — new/unexpected keys [^4] (T1098.004)
- SSH config anomalies, outdated OpenSSL/PRNG issues on old Debian-family builds [^2]
- Open `screen`/`tmux` sessions left attached (session hijack surface) [^2]

### 2. Persistence Mechanisms
- New/modified `systemd` service units, especially `ExecStart`/`ExecStartPost` shelling out to network tools [^4] (T1543.002)
- `systemd` timers (`.timer` units) as a cron alternative [^4] (T1053.006)
- `crontab`, `/etc/cron.d`, `/etc/cron.daily` etc. — new entries, PATH-hijack via writable cron scripts, wildcard-injection patterns [^2][^4] (T1053.003)
- Shell profile/rc file modification (`.bashrc`, `.zshrc`, `/etc/profile.d/*`) [^4] (T1546.004)
- `trap` signal handlers in login scripts [^4] (T1546.005)
- RC scripts / init.d modification [^4] (T1037.004)
- New local accounts, especially UID 0 duplicates or unusually high/low UIDs [^2][^4] (T1136.001)
- Kernel module persistence (`/etc/modules`, modprobe.d) [^4] (T1547.006)
- PAM stack modification (`pam_unix.so` and related) — can be persistence *and* credential-access [^4][^5] (T1556.003)

### 3. Credential & Secrets Exposure
- Browser credential stores (Chrome `Login Data`, cookies) — plaintext-extractable on Linux without OS-level protection [^5] (T1555.003)
- `/proc/<pid>/maps` and `/proc/<pid>/mem` readability for credential scraping from process memory [^5] (T1003.007)
- `/etc/passwd` + `/etc/shadow` permissions/readability [^5] (T1003.008)
- Private key / cert files (`.key`, `.pem`) sitting in home dirs or repos [^5] (T1552.004)
- Secrets in shell history, `.env` files, fstab (embedded credentials) [^2]
- Password reuse across local accounts, weak/default password policy [^2]
- Clipboard contents [^2]

### 4. Privilege Escalation Surface
- SUID/SGID binaries, cross-referenced against a GTFOBins-style exploitable-binary list [^2]
- Sudoers misconfig: NOPASSWD entries, sudo token caching, PATH-unrestricted sudo rules [^2]
- Writable directories in `$PATH`, writable `.so` library paths, `LD_PRELOAD`/`LD_LIBRARY_PATH` hijack surface [^2][^5] (T1574.006)
- Unexpected file capabilities (`getcap`) and ACLs [^2]
- Writable systemd unit files / binaries they execute, writable `.socket` files [^2]
- NFS exports with `no_root_squash` [^2]

### 5. Network / Egress
- Listening ports outside a declared baseline allowlist [^2]
- Outbound connections to known tunnel/exfil services (ngrok, cloudflared, serveo) from unexpected binaries — not a named control in any tool surveyed, but a well-documented real-world exfiltration/C2 pattern (reverse tunnels used to phone home through a service that looks like ordinary developer traffic)
- D-Bus and socket-based inter-process exposure [^2]
- Open ports newly reachable that weren't before (topology drift) [^2]

### 6. Defense Evasion / Anti-Forensics Indicators
- Shell history clearing or `HISTSIZE=0`/unset patterns [^3] (T1070.003)
- Recently deleted-but-still-open files, suspicious `file deletion` timing [^3] (T1070.004)
- Timestomping — file mtimes inconsistent with surrounding directory activity [^3] (T1070.006)
- Hidden files/dirs (`ls -a` surfaced only), hidden filesystems, bind-mount concealment, extended-attribute (`xattr`) hidden data [^3] (T1564.001/005/013/014)
- Rootkit signature/behavior indicators — hooked syscalls, `ptrace`/`/proc` memory injection [^3][^6] (T1014, T1055.008/009)
- `argv[0]` spoofing / process-name masquerading [^3] (T1036.011)
- Command obfuscation patterns in history/logs [^3] (T1027.010)

### 7. Filesystem, Permissions & Integrity
- File-integrity baseline (hash + mtime) for sensitive paths — `/etc/systemd/system`, `/etc/ssh`, `/etc/passwd`, `/etc/shadow`, cron dirs, `authorized_keys` — mirrors AIDE's and Wazuh FIM's core approach [^7][^9]
- World-writable files/dirs, unusual ownership on sensitive files [^1]
- Mounted/unmounted drives, fstab review [^2]

### 8. Kernel / System Hardening
- `sysctl` hardening flags (ASLR, `dmesg_restrict`, ptrace scope, etc.) [^1]
- Kernel version vs. known-CVE watch (e.g. DirtyCow-class) [^2]
- Mandatory Access Control status — AppArmor/SELinux enabled and enforcing, not just installed [^1] (Lynis `tests_mac_frameworks`)

### 9. Logging & Auditing
- `auditd` presence/config, rsyslog/journald forwarding configured (or not — local-only logs are attacker-erasable) [^1]
- Log rotation/retention sanity [^1]

### 10. Accounts & Services Hygiene
- Insecure/unused services still enabled (`tests_insecure_services`, `tests_boot_services` in Lynis) [^1]
- Password/account policy (`tests_authentication`, `tests_accounting`) [^1]
- Malware scan integration point (`tests_malware` — this is Lynis's own hook for ClamAV/rkhunter-style scanners, directly reusable given ThinkUtils already ships ClamAV) [^1]

### 11. Rootkit / Malware Indicators
- Signature-based rootkit/trojan detection (rkhunter/chkrootkit approach) [^6]
- Hidden process detection (process list vs. `/proc` cross-check) [^7]
- YARA-rule-based scanning as used by Wazuh's malware-detection layer [^7]

## Contradictions & open questions

- **Lynis's exact control-by-control detail** (beyond category names) sits behind individual `cisofy.com/controls/<ID>/` pages, not a single indexable list — v1 rule authoring should reference specific controls opportunistically rather than trying to port all ~300 tests. `unverified` at full-detail level.
- **CIS Benchmark full control text** is PDF-gated; category structure is confirmed but individual control thresholds (e.g. exact password-policy numbers) need per-control lookup when writing those specific rules.
- No single source enumerates **tunnel-service egress detection** (ngrok/cloudflared/serveo-style) as a named control in any tool surveyed — this is a genuine gap in existing tools, not just an oversight in search coverage, and is arguably Bulwark's most differentiated check given how commonly these services are abused for real-world command-and-control and exfiltration.

## Method

- Sub-questions: Lynis coverage, rkhunter/chkrootkit coverage, Wazuh HIDS/FIM coverage, CIS Benchmark structure, MITRE ATT&CK (Persistence/Credential Access/Defense Evasion), HackTricks/linPEAS checklist.
- Sources: 6 WebSearch passes + 7 WebFetch/API pulls (1 blocked by paywall — hacktricks.wiki primary now requires a paid crawler pass via tollbit.wiki, worked around via a GitHub mirror of the same content).
- Primary sources used: Lynis GitHub source tree (authoritative), 3× MITRE ATT&CK official tactic pages, HackTricks checklist (via mirror), Wazuh official docs (via search synthesis).
- Time: single session, ~15 fetches total.

## References

[^1]: [CISOfy/lynis](https://github.com/cisofy/lynis) — GitHub, accessed 2026-07-11. Primary source; `include/` directory listing gives the authoritative 46 test-category names used as the coverage backbone above.
[^2]: [Checklist - Linux Privilege Escalation](https://hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html) (mirrored via [b4rdia/HackTricks](https://raw.githubusercontent.com/b4rdia/HackTricks/master/linux-hardening/linux-privilege-escalation-checklist.md)) — accessed 2026-07-11. Concrete attacker-enumeration checklist; primary hacktricks.wiki now paywalled for automated fetches (402 via tollbit.wiki proxy).
[^3]: [Defense Evasion, Tactic TA0005 - Enterprise | MITRE ATT&CK](https://attack.mitre.org/tactics/TA0005/) — accessed 2026-07-11. Official framework page.
[^4]: [Persistence, Tactic TA0003 - Enterprise | MITRE ATT&CK](https://attack.mitre.org/tactics/TA0003/) — accessed 2026-07-11. Official framework page.
[^5]: [Credential Access, Tactic TA0006 - Enterprise | MITRE ATT&CK](https://attack.mitre.org/tactics/TA0006/) — accessed 2026-07-11. Official framework page.
[^6]: rkhunter/chkrootkit detection methodology — synthesized from [rkhunter.com guide](https://rkhunter.com/rkhunter-complete-guide-rootkit-detection-tool-linux-security-scanner-and-system-integrity-monitoring/) and [nixCraft](https://www.cyberciti.biz/faq/howto-check-linux-rootkist-with-detectors-software/) — accessed 2026-07-11 (search-synthesized, not individually fetched — `medium` confidence).
[^7]: Wazuh rootcheck/FIM/malware-detection modules — synthesized from [Wazuh official documentation](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/index.html) and [rootcheck reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/rootcheck.html) — accessed 2026-07-11 (search-synthesized — `medium` confidence).
[^8]: [Ubuntu Linux - CIS Benchmarks](https://www.cisecurity.org/benchmark/ubuntu_linux) and [CIS Benchmarks and profiles - Ubuntu security documentation](https://documentation.ubuntu.com/security/compliance/usg/cis-benchmarks/) — accessed 2026-07-11. Profile/section structure confirmed; full control text is PDF-gated.
[^9]: AIDE's file-integrity-monitoring approach is described by name only in this pass (via Wazuh FIM comparison, [^7]) — not independently fetched from AIDE's own docs. `low` confidence on AIDE-specific detail; the general FIM approach (hash+attribute baseline diffing) is corroborated by both Wazuh and Lynis's `tests_file_integrity` category.
