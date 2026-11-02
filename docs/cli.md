---
title: The Bulwark command line
description: bulwarkctl, Bulwark's single-file command line for Linux, macOS and Windows. Check AI agent setups, the computer and servers over SSH; preview and apply fixes; JSON and exit codes for CI.
---

# The command line

`bulwarkctl` is one file with every check built in. Copy it anywhere and run it. The report
is short on purpose: the problems worth fixing first, worst first, each with why and how.

<CliDemo />

## Commands

| Command | What it does |
|---|---|
| `bulwarkctl ai scan` | AI agent settings and keys leaked into agent files, across your projects |
| `bulwarkctl ai scan --target .` | The same, for this repository only |
| `bulwarkctl scan` | This computer: SSH, firewall, exposed services, persistence, malware signs |
| `sudo bulwarkctl scan --privileged` | Adds the checks that read root-only files |
| `bulwarkctl scan --ssh user@host` | A server, over the SSH you already use. [More →](/guide/remote-monitoring) |
| `bulwarkctl logs scan` | Signs of attack in system logs: brute force, root logins, sudo abuse |
| `bulwarkctl fix list` | Preview every fix for this computer |
| `bulwarkctl ai redact` | Preview removing leaked keys from agent files |
| `bulwarkctl agent install` | Give your AI coding agents the Bulwark skill. [More →](/agents) |

Every fix and redaction only previews until you add `--apply`. Add `--all` to any scan to see
low-priority items and every place a problem was found.

## In scripts and CI

`--json` prints the full result. The exit code is `0` when nothing medium or worse is open, `1`
for medium or high, and `2` for critical:

```bash
bulwarkctl ai scan --target . || echo "fix the agent setup before merging"
```

[Install the CLI →](/download#cli)
