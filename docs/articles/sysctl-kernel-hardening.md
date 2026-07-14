---
description: >-
  Every kernel-hardening sysctl worth setting on Linux — what each one actually mitigates,
  and the real, documented tradeoffs most hardening guides leave out.
---

# sysctl kernel hardening: every parameter, with the tradeoffs nobody lists

Most Linux hardening guides give you a wall of `sysctl -w` commands to copy-paste and move on.
The problem isn't the advice — it's the missing half: several of these settings have real,
documented cases of breaking legitimate things, and a guide that doesn't mention that isn't
actually helping you make a decision, just handing you a script. Below are the kernel and
network sysctls [Bulwark](/)'s `kernel-hardening` category checks — 18 of its 20 rules are
sysctl-based (the other two, mandatory access control enforcement and kernel-module
blacklisting, work through different mechanisms entirely and aren't sysctls) — grouped by what
they actually protect against, with the genuine tradeoffs called out wherever one exists and
cited, not invented for the sake of balance. Every default, level and behavior below links to the
kernel's own documentation or the source, because most of the corrections here are corrections of
things widely repeated without one. A few closely-related sysctls that aren't yet a Bulwark rule
are included too, flagged as such, where they round out the same family of setting.

## Local privilege-escalation primitives

These four all guard the same class of bug: a local, unprivileged user turning a race condition
or a permission gap into root.

- **`fs.protected_hardlinks=1`**, **`fs.protected_symlinks=1`** — without these, any user can
  hardlink to a file they don't own, or follow a symlink they don't own inside a world-writable
  sticky directory like `/tmp`. Both are classic TOCTOU privilege-escalation primitives. No known
  tradeoff — every mainstream distro (Debian, Ubuntu, RHEL, Fedora) has shipped both `1` by
  default for over a decade; if you're seeing `0`, something explicitly turned it off.
- **`fs.protected_fifos=1`**, **`fs.protected_regular=1`** — the same protection extended to
  FIFOs and regular files in sticky directories, closing a narrower version of the same
  interception/tampering class. These two are *not* as free as the hardlink/symlink pair above,
  despite usually being lumped in with them: they only became default-on with
  [systemd 241](https://github.com/systemd/systemd/blob/v241/NEWS) (February 2019), whose release
  notes flagged them as exactly that risk — "it is technically a backwards incompatible change" —
  and they did break real software that legitimately wrote to another user's FIFO in a shared
  directory ([snapcast#452](https://github.com/snapcast/snapcast/issues/452)). Almost certainly still
  worth having — just don't believe anyone who tells you they're free.
- **`fs.suid_dumpable=0`** — a crashed setuid process dumping core lets the invoking unprivileged
  user read whatever secrets were in that process's memory at crash time.
  [Per the kernel's own docs](https://docs.kernel.org/admin-guide/sysctl/fs.html), `0` (the default)
  suppresses core dumps for setuid/privileged processes entirely; `2` ("suidsafe") lets them dump
  but only through a controlled handler — a pipe handler or fully-qualified `core_pattern`, i.e.
  `systemd-coredump` or `apport` — with the dump written as root. Either is fine. `1` ("debug") is
  the dangerous one, and the danger isn't quite the "world-readable file" it's often described as:
  the docs say the dump is "owned by the current user and no security is applied," which is worse
  and more direct.

## Kernel-exploit-development friction

- **`kernel.randomize_va_space=2`** — full ASLR. Worth being precise about what the levels
  actually do, since `1` is usually described as "partial" in a way that implies it's much weaker
  than it is: [per the kernel docs](https://docs.kernel.org/admin-guide/sysctl/kernel.html), `1`
  already randomizes "mmap base, stack and VDSO page" and "implies that shared libraries will be
  loaded to random addresses." The *only* thing `2` adds on top is heap (`brk`) randomization —
  the docs describe it in one line: "Additionally enable heap randomization." That's still worth
  having — but the gap between 1 and 2 is one region, not "no ASLR vs. ASLR." Every mainstream
  distro ships `2` by default, so anything lower means something deliberately lowered it.
- **`kernel.kptr_restrict=1`** (or `2`) — restricts kernel pointers printed via the `%pK` format
  specifier (`/proc/kallsyms` and friends), one of the easiest ways to defeat KASLR locally. The
  common framing — "0 leaks raw kernel addresses" — hasn't been true since kernel 4.15, which
  [hashed `%p`/`%pK` addresses before printing](https://github.com/torvalds/linux/commit/ad67b74d2469);
  [the current docs](https://docs.kernel.org/admin-guide/sysctl/kernel.html) say it outright: "When
  `kptr_restrict` is set to 0 (the default) the address is hashed before printing." `1` zeroes them
  for anyone without `CAP_SYSLOG`; `2` zeroes them for everyone regardless of privilege. Still worth
  setting; just a smaller win than it's usually sold as. (If you check this against an older
  kernel's *documentation* rather than its behavior, note the docs themselves said otherwise until
  Linux 5.2 — the behavior changed two years before the text describing it did.)
- **`kernel.dmesg_restrict=1`** — restricts `dmesg` to `CAP_SYSLOG`, since the kernel ring buffer
  routinely contains addresses and driver-internal state useful for exploit development. Not
  currently one of Bulwark's 20 rules, but the same family of setting as `kptr_restrict` above
  and worth setting alongside it.
- **`kernel.perf_event_paranoid`** — this is the one hardening guides most consistently describe
  incorrectly, so it's worth stating what it does *not* do. Level `2` does **not** restrict
  `perf_event_open()` to `CAP_PERFMON`/`CAP_SYS_ADMIN`; per
  [the kernel docs](https://docs.kernel.org/admin-guide/sysctl/kernel.html) it only means "disallow
  kernel profiling by users without `CAP_PERFMON`," while unprivileged users can still call
  `perf_event_open()` against their own userspace processes. The same page states that **2 is
  already the upstream default**, so "set it to 2" is usually a no-op you can verify rather than a
  change you need to make. The levels that actually lock the syscall down are *downstream distro
  patches* that were [rejected upstream](https://lwn.net/Articles/696216/) — level `3` comes from
  [Debian's own kernel patch](https://sources.debian.org/src/linux/latest/debian/patches/features/all/security-perf-allow-further-restriction-of-perf_event_open.patch/),
  and Ubuntu's kernel goes further still, defaulting to `4`. So if you're relying on that behavior,
  you're relying on your distro's kernel, not Linux's, and you should check
  `sysctl kernel.perf_event_paranoid` rather than assume.

## The ones with a real, documented tradeoff

This is the part most checklists skip. Each of these is a legitimate hardening step — but each
has caused genuine breakage somewhere, and you should decide with that in mind rather than find
out afterward.

- **`kernel.yama.ptrace_scope=1`** (Bulwark's own recommended fix, and the sensible default for
  almost everyone) restricts `ptrace()` to a process's own *descendants*, blocking the
  `/proc/<pid>/mem` credential-scraping technique this rule exists for. The cost at this level is
  narrow but real, and it's the inverse of what you might expect: tracing something *below* you
  still works — what breaks is tracing a **non-descendant**, including your own *parent*. That's
  exactly the shape of a crash handler that forks a dedicated dumper process to trace its own
  crashing parent, which is why the kernel's
  [Yama documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html) names the exemption and
  who uses it: `prctl(PR_SET_PTRACER, pid, ...)` "is used by KDE, Chromium, and Firefox's crash
  handlers." Software that does this correctly keeps working; software that doesn't, silently stops
  producing crash dumps. Going further to `2` restricts `ptrace` to `CAP_SYS_PTRACE` only — no
  `PR_SET_PTRACER` exemption helps at that point, so `strace`/`gdb` genuinely stop working for
  anyone but root, and tools that shell out to them break with it
  ([firejail#3237](https://github.com/netblue30/firejail/issues/3237) is exactly this, at scope 2
  and 3). `3` disables `ptrace` entirely, root included, and — in the docs' words — "once set, this
  sysctl value cannot be changed" without a reboot. `1` is the right choice for almost everyone;
  `2`+ is for hosts where interactive debugging by anyone other than root truly shouldn't happen at
  all.
- **`net.ipv4.conf.all.rp_filter=1`** (strict mode) blocks IP-spoofed traffic whose source
  address couldn't plausibly have arrived on that interface — but it's a real, reported cause of
  dropped traffic on asymmetric-routing setups: multi-homed servers with return traffic on a
  different path than the request lose reachability, and Cilium's kube-proxy-free NodePort load
  balancing hits the same wall ([cilium#13130](https://github.com/cilium/cilium/issues/13130)). If
  this host does asymmetric routing on purpose, `2` (loose mode) still blocks the worst spoofing
  while tolerating it.

  There's a second-order trap here that almost nobody writes down. The kernel takes the **numeric
  maximum** of `conf/all/rp_filter` and `conf/<iface>/rp_filter` —
  [ip-sysctl.rst](https://docs.kernel.org/networking/ip-sysctl.html) puts it exactly that way: "The
  max value from conf/{all,interface}/rp_filter is used when doing source validation on the
  {interface}." The values are 0 = off, 1 = strict, 2 = loose, so `all=1` forces strict mode onto
  every interface that is *off*, and you **cannot turn an individual interface back to 0** — 1
  outranks it, and `all` wins. (You *can* still move an interface to loose, because 2 is numerically
  greater than 1 — that's the one escape hatch, and it's an accident of the encoding rather than a
  designed one.) This is why systemd's own
  [`50-default.conf`](https://github.com/systemd/systemd/blob/main/sysctl.d/50-default.conf)
  deliberately sets `net.ipv4.conf.default.rp_filter=2`, globs `net.ipv4.conf.*.rp_filter=2` onto
  existing interfaces, and explicitly *excludes* `all` rather than hardening it. If you need
  per-interface control, set `default` and the specific interfaces — not `all`.
- **`kernel.kexec_load_disabled=1`** stops a privileged process from `kexec`-loading an
  unverified kernel image and switching to it live — a real defense-evasion technique for
  surviving a reboot with a backdoored kernel. Two tradeoffs, both real: it's a one-way switch
  until the next reboot ([the docs](https://docs.kernel.org/admin-guide/sysctl/kernel.html): "Once
  true, kexec can no longer be used, and the toggle cannot be set back to false"), and it breaks
  `kdump`, whose crash-capture kernel is loaded through the same `kexec_load` path. That second one
  is structural rather than a bug someone might fix:
  [`kexec_load_permitted()`](https://github.com/torvalds/linux/blob/master/kernel/kexec_core.c)
  checks `kexec_load_disabled` *before* it distinguishes a crash kernel from a normal one, so
  there's no exemption to configure — and `systemd-sysctl` applies sysctls
  [before `sysinit.target`](https://github.com/systemd/systemd/blob/main/units/systemd-sysctl.service.in),
  long before any distro's kdump unit gets to load the crash kernel, so the sysctl always wins and
  the load fails with `kexec_load failed: Operation not permitted`. Skip this one on hosts where
  you rely on `kdump`.
- **`user.max_user_namespaces=0`** (or the older `kernel.unprivileged_userns_clone=0`) — not
  currently one of Bulwark's 20 rules, but included here because it's the one hardening guides
  most often get wrong in the other direction: it closes off a real kernel attack-surface-widening
  feature, but breaks rootless Podman/Docker, Flatpak, and `bubblewrap`-based sandboxing outright —
  [bubblewrap#324](https://github.com/containers/bubblewrap/issues/324) and
  [flatpak#5839](https://github.com/flatpak/flatpak/issues/5839) are exactly this failure mode.
  If this host runs any rootless container tooling, leave user namespaces enabled and rely on
  `kernel.yama.ptrace_scope` and MAC confinement (AppArmor/SELinux) instead.
- **`kernel.unprivileged_bpf_disabled=1`** — two things worth knowing, and the second is the one
  that bites. First, this is mostly already done for you: Debian
  ([since 5.10.46-4, in bullseye](https://sources.debian.org/data/main/l/linux/5.10.46-4/debian/linux-image.NEWS))
  and Ubuntu ([Focal/Bionic, March 2022](https://discourse.ubuntu.com/t/unprivileged-ebpf-disabled-by-default-for-ubuntu-20-04-lts-18-04-lts-16-04-esm/27047))
  both ship kernels built with `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y`, which sets this sysctl to `2` out
  of the box — so explicitly setting it mostly affects CI pipelines or legacy BCC-based tools, not a
  production workload you'd notice breaking. Second, and less widely known: **`1` and `2` are not
  the same knob at different strengths.**
  [The kernel docs](https://docs.kernel.org/admin-guide/sysctl/kernel.html) are explicit — writing
  `1` means "once set to 1, this can't be cleared from the running kernel anymore," while at `2` "an
  admin can still change this setting later on." `1` is a one-way switch you cannot undo without
  rebooting, exactly like `kexec_load_disabled`. If you're setting this at all, `2` gets you the
  same protection while leaving yourself a way back.

## The ones that won't break anything — but still have a gotcha

Nothing in this group has a tradeoff that should stop you from setting it, and it's worth saying
so plainly rather than inventing balance for its own sake. What they *do* have is a detail that's
usually copied wrong — a precondition, a cost that isn't zero, or in one case a widely-recommended
magic number that doesn't do what everyone says it does.

- **`net.ipv4.tcp_syncookies=1`** — SYN-flood connection-table exhaustion protection. Its one
  historical cost (losing TCP options like SACK and window scaling on a cookie-validated
  handshake) is largely moot on a modern kernel, which packs window scale, SACK, and ECN back into
  the low bits of the cookie's timestamp. But that recovery has a precondition worth knowing,
  because it's one hardening guides routinely break: as
  [`syncookies.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/syncookies.c) says, this
  works only "when syncookies are in effect **and tcp timestamps are enabled**" — i.e. it needs
  **`net.ipv4.tcp_timestamps=1`**. Plenty of checklists tell you to set `tcp_timestamps=0` (to hide
  uptime), and doing so silently reinstates exactly the option loss this bullet says you don't have
  to worry about. Pick one.
- **`net.ipv4.conf.all.accept_source_route=0`** — rejects packets that specify their own route, a
  spoofing/routing-bypass primitive with no legitimate use on an end host. Per
  [ip-sysctl.rst](https://docs.kernel.org/networking/ip-sysctl.html) the default is "TRUE (router)"
  and "FALSE (host)" — so on any normal server it's already `0` and this is belt-and-braces.
- **`net.ipv4.conf.all.log_martians=1`** — logs (doesn't drop) packets with impossible source
  addresses. No behavior change for the host, and the cost is smaller than it's often made out to
  be: the logging goes through a `printk` path gated by
  [`net_ratelimit()`](https://github.com/torvalds/linux/blob/master/net/core/utils.c), which is
  capped at 10 messages every 5 seconds regardless of how hard a flood pushes. So a spoofed-source
  flood won't drown your journal — but you still pay the per-packet check, and the trickle
  accumulates indefinitely. Cheap, but not quite free.
- **`kernel.sysrq`** set to a restricted bitmask rather than the fully-open `1`, so that the
  magic-SysRq keys available to anyone at the keyboard or console are limited to the genuinely
  useful ones. Be careful with the number you copy here, though — Ubuntu's default of
  [**`176`**](https://git.launchpad.net/ubuntu/+source/procps/plain/debian/sysctl.d/10-magic-sysrq.conf?h=applied/ubuntu/noble)
  is widely recommended as "the safe one" and it is **not** as safe as it's usually described. Per
  [the kernel's sysrq documentation](https://docs.kernel.org/admin-guide/sysrq.html),
  `176 = 128 + 32 + 16`: sync (16) and remount-read-only (32), which are the two you actually want
  on a hung system — **plus reboot/poweroff (128)**, which it keeps rather than drops. It does drop
  debug dumps (8), process signalling/kill (64), and console/keyboard control (2/4). If what you
  want is "sync and remount read-only, but nobody gets to power-cycle this box from the keyboard,"
  the value you want is **`48`**, not 176. (For reference, upstream systemd's own
  [`50-default.conf`](https://github.com/systemd/systemd/blob/main/sysctl.d/50-default.conf) sets
  `kernel.sysrq = 16` — sync only.)
- **`net.ipv4.conf.all.accept_redirects=0`** and **`net.ipv4.conf.all.send_redirects=0`** — reject,
  and stop sending, unauthenticated ICMP route-manipulation packets, respectively. The one
  caveat, which Bulwark's own `send_redirects` rule states directly: skip disabling that half on
  a host that's intentionally acting as a router — a non-router server has no legitimate reason
  to touch either setting.

```mermaid
flowchart TB
    A["sysctl kernel hardening"] --> B["Privilege-escalation primitives"]
    A --> C["Exploit-development friction"]
    A --> D["Tradeoff-bearing settings"]
    A --> E["Safe to set — but copied wrong"]

    B --> B1["fs.protected_hardlinks"]
    B --> B2["fs.protected_symlinks"]
    B --> B3["fs.protected_fifos"]
    B --> B4["fs.protected_regular"]
    B --> B5["fs.suid_dumpable"]

    C --> C1["kernel.randomize_va_space"]
    C --> C2["kernel.kptr_restrict"]
    C --> C3["kernel.perf_event_paranoid"]

    D --> D1["kernel.yama.ptrace_scope<br/>blocks tracing a non-descendant;<br/>strace/gdb break past level 1"]
    D --> D2["net.ipv4.conf.all.rp_filter<br/>breaks asymmetric routing/Cilium NodePort;<br/>'all' wins by numeric max"]
    D --> D3["kernel.kexec_load_disabled<br/>breaks kdump; one-way until reboot"]
    D --> D4["user.max_user_namespaces<br/>breaks rootless Podman/Flatpak/bubblewrap"]
    D --> D5["kernel.unprivileged_bpf_disabled<br/>'1' is one-way; already 2 on many distros"]

    E --> E1["net.ipv4.tcp_syncookies<br/>needs tcp_timestamps=1"]
    E --> E2["net.ipv4.conf.all.accept_redirects/send_redirects"]
    E --> E3["net.ipv4.conf.all.accept_source_route"]
    E --> E4["net.ipv4.conf.all.log_martians<br/>rate-limited, but accumulates"]
    E --> E5["kernel.sysrq<br/>176 KEEPS reboot — use 48"]
```

## Applying and checking what's actually loaded

```bash
# check the current value of anything above
sysctl kernel.yama.ptrace_scope net.ipv4.conf.all.rp_filter

# persist a change
echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/60-hardening.conf
sudo sysctl --system
```

`sysctl --system` re-reads every drop-in under `/etc/sysctl.d/`, `/run/sysctl.d/`, and
`/usr/lib/sysctl.d/` in priority order — if a value doesn't stick, check for a conflicting file
with a name that sorts later. [Bulwark](/)'s `kernel-hardening` rule category runs every check
above automatically and reports each one individually with the live value interpolated, rather than
a single aggregate "some sysctl values differ from profile" line you have to go digging for. On a
**desktop** that runs in the GUI, continuously — the file watcher re-checks the moment something
under `/etc/sysctl.d/` changes; on a **server**, `bulwarkctl scan` gives you the identical rule set
over SSH.

## References

Kernel behavior is versioned; the docs links below track mainline, and were checked on 12 July 2026.

- [sysctl/kernel.rst](https://docs.kernel.org/admin-guide/sysctl/kernel.html) — the defaults and level semantics for `randomize_va_space`, `kptr_restrict`, `perf_event_paranoid`, `unprivileged_bpf_disabled`, and `kexec_load_disabled`.
- [sysctl/fs.rst](https://docs.kernel.org/admin-guide/sysctl/fs.html) — `suid_dumpable` modes 0/1/2.
- [networking/ip-sysctl.rst](https://docs.kernel.org/networking/ip-sysctl.html) — the `rp_filter` max() rule and the `accept_source_route` router/host defaults.
- [LSM/Yama.rst](https://docs.kernel.org/admin-guide/LSM/Yama.html) — `ptrace_scope` levels, `PR_SET_PTRACER`, and the KDE/Chromium/Firefox crash-handler exemption.
- [admin-guide/sysrq.rst](https://docs.kernel.org/admin-guide/sysrq.html) — the SysRq bitmask values behind 176 and 48.
- [`kernel/kexec_core.c`](https://github.com/torvalds/linux/blob/master/kernel/kexec_core.c), [`net/ipv4/syncookies.c`](https://github.com/torvalds/linux/blob/master/net/ipv4/syncookies.c), [`net/core/utils.c`](https://github.com/torvalds/linux/blob/master/net/core/utils.c) — the kexec permission check ordering, the syncookie/timestamp dependency, and the 10-per-5s `net_ratelimit()` cap.
- [commit ad67b74d2469](https://github.com/torvalds/linux/commit/ad67b74d2469) — "printk: hash addresses printed with %p" (Linux 4.15).
- [systemd 241 NEWS](https://github.com/systemd/systemd/blob/v241/NEWS) — `protected_regular`/`protected_fifos` default-on, and the backwards-incompatibility warning.
- [systemd `50-default.conf`](https://github.com/systemd/systemd/blob/main/sysctl.d/50-default.conf) and [`systemd-sysctl.service`](https://github.com/systemd/systemd/blob/main/units/systemd-sysctl.service.in) — the `rp_filter` policy, `kernel.sysrq = 16`, and the early ordering.
- Distro-specific defaults: [Debian linux-image NEWS](https://sources.debian.org/data/main/l/linux/5.10.46-4/debian/linux-image.NEWS) and [Ubuntu's unprivileged-eBPF announcement](https://discourse.ubuntu.com/t/unprivileged-ebpf-disabled-by-default-for-ubuntu-20-04-lts-18-04-lts-16-04-esm/27047) (BPF), [Debian's perf_event_open patch](https://sources.debian.org/src/linux/latest/debian/patches/features/all/security-perf-allow-further-restriction-of-perf_event_open.patch/) and [LWN on its upstream rejection](https://lwn.net/Articles/696216/), [Ubuntu's magic-sysrq default](https://git.launchpad.net/ubuntu/+source/procps/plain/debian/sysctl.d/10-magic-sysrq.conf?h=applied/ubuntu/noble).
- Real-world breakage: [snapcast#452](https://github.com/snapcast/snapcast/issues/452) (protected_fifos), [cilium#13130](https://github.com/cilium/cilium/issues/13130) (rp_filter), [firejail#3237](https://github.com/netblue30/firejail/issues/3237) (ptrace_scope), [bubblewrap#324](https://github.com/containers/bubblewrap/issues/324) and [flatpak#5839](https://github.com/flatpak/flatpak/issues/5839) (user namespaces).
