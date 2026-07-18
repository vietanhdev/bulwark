# Snap Store — classic confinement request for `bulwark`

Post this in the **Store requests** category:
<https://forum.snapcraft.io/c/store-requests/19>

Title suggestion: **Classic confinement request for bulwark**

Prerequisite: register the name first — `snapcraft register bulwark`. Ensure the
`snapcraft.yaml` link below points at a committed file on the default branch.

---

**name:** bulwark

**description:** Local Linux host security & misconfiguration scanner (desktop GUI)

**snapcraft:** https://github.com/vietanhdev/bulwark/blob/main/snap/snapcraft.yaml

**upstream:** https://github.com/vietanhdev/bulwark

**upstream-relation:** I am the upstream author and maintain both the project and the snap packaging.

**supported-category:** system-administration / security-audit tool that must read arbitrary, build-time-unknown host configuration across the whole filesystem and elevate to root via polkit to inspect root-only state (same bucket as backup and antivirus/host-scanning tools).

**reasoning:**

Bulwark is a local Linux host security auditor. It scans the machine it runs on for security misconfigurations and intrusion indicators — sshd configuration, account and password policy, systemd units, cron jobs, kernel sysctls, permissions on sensitive files, file-integrity baselines, promiscuous interfaces, and more — and explains each finding in plain language with a suggested fix. It runs entirely locally; there is no network component and no telemetry.

Strict confinement does not fit, for two concrete reasons:

1. **Arbitrary, unenumerable read paths.** The purpose of the tool is to inspect host state wherever it lives, and that set is not fixed. sshd `Include` drop-ins, systemd units and cron entries can live under many different directories; kernel and account policy is read from `/etc`, `/proc`, and `/sys`; each rule added to the pack introduces new absolute paths. Running under strict with `snappy-debug`, the denials never converge into a fixed list — they keep coming for new paths as the rule pack grows. `home`, `system-files` and `personal-files` cannot enumerate arbitrary absolute paths across `/etc`, `/var`, `/proc`, `/sys`, and `/lib/systemd`, which is exactly what an auditor needs to read.

2. **Root elevation via polkit.** Some checks require reading root-only state (e.g. the mode and ownership of `/etc/shadow`, `/etc/sudoers`, and other privileged files). The GUI elevates by launching `pkexec <bundled-cli> scan --privileged`, prompting once via the system polkit agent. A strict sandbox cannot run `pkexec` at all — no setuid, no access to the system polkit agent on the system bus — so privileged scans are impossible under strict, and no interface (or combination) grants "run a polkit-elevated helper".

**On isolation:** Bulwark is a **read-oriented** auditor — a scan reports findings and suggested fixes; it does not modify host state. The only writes are explicit, opt-in remediations the user runs deliberately from a separate command, never during a scan. It also has **no network access whatsoever**, which bounds the blast radius of the broad read access (nothing it reads can leave the machine). Classic means the tool can read whatever the invoking user — and, via the single `pkexec` prompt, root — can already read; users wanting a tighter boundary can point Bulwark at a remote host over SSH or run it inside a container, but the primary use case is auditing the local host it is installed on, which is precisely what strict confinement prevents.
