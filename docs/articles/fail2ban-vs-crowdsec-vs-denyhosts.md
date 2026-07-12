---
description: >-
  fail2ban vs CrowdSec vs denyhosts — which SSH brute-force defense actually works in
  2026, including one still widely recommended that silently blocks nothing at all.
---

# fail2ban vs. CrowdSec vs. denyhosts: which SSH brute-force defense actually works

Any internet-facing SSH port gets probed within hours of going live — this isn't targeted, it's
background noise from constantly-scanning botnets. All three tools below exist to react to that
automatically, but they are not equivalent, and one of them — still routinely recommended in
guides and still installable from your distro's repos — has a blocking mechanism that modern
OpenSSH stopped honoring over a decade ago. It runs, it logs, it reports success, and it blocks
nothing.

## fail2ban: the established default

fail2ban (GPL-2.0-or-later) works by tailing log files (`/var/log/auth.log`, journald output,
etc.), matching failed-login patterns against regex "filters," and triggering an "action" — almost
always a firewall rule update — once a threshold is crossed. It's been around since 2004, over two
decades of production use, and it's still under active development: commits land on its `master`
branch as recently as June 2026. Both halves of the next sentence are true and worth holding at
once, though: its most recent *tagged release* is still **v1.1.0, from April 2024** — well over
two years without a formal release, while `master` carries `1.1.1-dev`. If you install from your
distro's package rather than tracking `master`, what you're running is the 2024 release.

Which matters for the one practical gotcha here, because it's mid-flip. In **released 1.1.0**,
the default ban action is `iptables-multiport` — iptables-based, which works on nftables-only
systems through the `iptables-nft` compatibility shim, but isn't native. On **`master`**, that
default has already been changed to `nftables`. So on a modern, purely nftables setup running the
current *release*, set the action explicitly:

```ini
# jail.local
[DEFAULT]
banaction = nftables
banaction_allports = nftables[type=allports]
```

Use `nftables`, not the `nftables-multiport` action you'll see recommended in older guides — that
one still exists but its own config file marks it obsolete, superseded by `nftables[type=multiport]`.

Its real structural limitation is that it's **reactive and log-dependent** — detection lags
behind whatever polling interval reads the log, a log-format change or a journald misconfiguration
can silently break detection with no obvious failure signal, and each host only reacts to attacks
it personally sees. An attacker who spreads a slow, low-volume brute-force across many source IPs
against one host, or who's already been banned on a thousand other servers, gets no benefit
passed to yours — every fail2ban instance starts from zero.

## CrowdSec: the same idea, with shared intelligence

CrowdSec (MIT license) works similarly at the detection layer — parsing logs against scenarios —
but adds a real, structural difference: participating agents report anonymized attack signals to a
central "consensus engine," which filters for false positives and redistributes a curated Community
Blocklist back to participants. In practice that means a host running CrowdSec can start blocking
an IP flagged as hostile elsewhere, before that IP has ever touched your machine.

Be precise about the sharing model, because it's easy to get backwards in either direction:
signal-sharing is **on by default and opt-*out***, not opt-in. If you don't want it, you disable it
explicitly:

```yaml
# config.yaml
api:
  server:
    online_client:
      sharing: false
```

The part that's genuinely to CrowdSec's credit is that sharing and receiving are *independent*: you
can turn sharing off and still pull the Community Blocklist. Contributing isn't the price of
admission — though you do have to register with the central API to pull the list at all, so this is
"free-riding permitted," not "no account needed."

It's actively and heavily maintained, and the release cadence is the sharpest contrast with
fail2ban: v1.7.8 shipped in May 2026, with roughly 14,000 GitHub stars. The free Console tier gives
you a 3,000-IP community blocklist, 500 alerts, 2-month retention, one user seat, and up to three
blocklist subscriptions; "Console Premium" raises that to a 50,000-IP blocklist, webhooks, up to a
year of retention, and five team seats, billed per enrolled engine. Its firewall bouncer supports
four native backends — `nftables` (IPv4 and IPv6), `iptables`, `ipset`, and `pf` — with no
compatibility-shim caveat of the kind the current fail2ban release carries.

## denyhosts: check the date before you install this

denyhosts is SSH-specific and blocks by writing to TCP wrappers' `/etc/hosts.deny` rather than by
touching the firewall. That isn't merely dated — on a modern system it **does not work at all**,
and this deserves to be the headline rather than a footnote.

**OpenSSH removed TCP-wrappers (`libwrap`) support entirely in OpenSSH 6.7, released October
2014.** On any stock `sshd` from the last decade, writing an IP into `/etc/hosts.deny` has no
effect on SSH whatsoever. DenyHosts' primary blocking mechanism is therefore inert by default:
it will faithfully parse your auth log, correctly identify the attacker, dutifully append them to
`hosts.deny` — and the attacker will keep right on connecting. Unless you enable its
optional/legacy iptables path, it is a tool that appears to be working while blocking nothing.
(systemd dropped `tcpwrap` support in 2014 too, Fedora deprecated TCP wrappers, and RHEL 8 dropped
the package outright.) There is no native nftables support.

Maintenance status compounds it. Its last tagged release was **v3.1, in December 2015** — over a
decade ago. The version published on PyPI is far older still (2.6, from May 2012), and that release
now has *zero* distribution files attached, so `pip install DenyHosts` doesn't install something
ancient so much as fail to install anything at all. GitHub activity since then is sparse and
strictly maintenance: a `urllib3` security bump in February 2025, Python 3.8–3.13 compatibility
fixes in October 2025, against 61 open issues and 8 stale pull requests. Someone is keeping it
*installable*; nobody is developing it.

For a new setup in 2026, that combination — a primary blocking mechanism modern `sshd` ignores, no
release in a decade — is disqualifying, not a nostalgic footnote.

## Which one to actually run

First, the thing that outranks all three: **none of them is the primary fix.** They're reactive
log-parsers that respond to an attack already in progress. Setting `PasswordAuthentication no` and
`PermitRootLogin no` (see the [SSH hardening checklist](/articles/ssh-hardening-checklist)) doesn't
*mitigate* SSH password brute-forcing — it deletes the attack class outright. Do that first. What
these tools then buy you is log-noise reduction, defense for whatever else you expose, and a check
against a key being compromised. That's worth having; it just isn't the foundation.

With that said:

```mermaid
flowchart TD
  A{"Key-only SSH auth\nalready enforced?"} -->|"No"| A2["Do that first — it deletes the\npassword brute-force class outright"]
  A -->|"Yes"| B{"Already running denyhosts?"}
  A2 --> B
  B -->|"Yes"| C["Treat the host as UNPROTECTED —\nhosts.deny is inert on modern sshd"]
  B -->|"No"| D{"Managing more than one host?"}
  C --> D
  D -->|"Just one host"| E{"Pure nftables setup?"}
  D -->|"Multiple hosts /\nwant shared threat intel"| F["CrowdSec — benefits from\nattacks seen elsewhere"]
  E -->|"Yes"| H["fail2ban with banaction = nftables\n(the 1.1.0 release still defaults to iptables),\nor SSHGuard for native nftables"]
  E -->|"No"| I["fail2ban — the default\niptables action works fine"]
```

- **One host, want the well-documented, battle-tested default:** fail2ban, with `banaction = nftables`
  set explicitly if you're on a modern nftables-native setup.
- **One host, want native nftables without the config caveat:** SSHGuard is a genuine third option
  the usual comparisons skip. BSD-licensed, actively maintained (latest release April 2025, commits
  through 2026), with native nftables, iptables, pf, and ipfw backends. It's narrower than fail2ban
  — less extensible, fewer filters — but for the specific job of "block SSH brute-forcers on an
  nftables host," it does it without a compatibility shim.
- **Multiple hosts, or want to benefit from attacks already seen elsewhere:** CrowdSec — the
  shared-intelligence model is a real, meaningful difference once you're not defending in isolation,
  and it's the only one of the four with a current release cadence.
- **denyhosts:** skip it. Not because it's old, but because its blocking mechanism doesn't function
  on a modern `sshd`. If you've inherited a host running it, treat that host as *unprotected* until
  you've migrated, not as protected-but-dated.

## Blocking is one layer; knowing your exposure is another

None of these three do what [Bulwark](/) does, and Bulwark doesn't do what they do — it's a
config-audit and detection tool, not an active blocking layer. Bulwark's `ssh-remote-access` rules
catch the *configuration* gaps that make brute-forcing worth attempting in the first place
(password auth left enabled, no `MaxAuthTries` cap — see the
[SSH hardening checklist](/articles/ssh-hardening-checklist)), and `network-egress` rules catch
unexpected listening services. fail2ban/CrowdSec are the layer that actively responds to an
attack in progress; Bulwark is the layer that tells you, on a schedule, whether that response
layer is even necessary and whether the rest of the host's SSH exposure is sane.
