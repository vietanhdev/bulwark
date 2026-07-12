---
description: >-
  A practical, directive-by-directive SSH hardening checklist for Linux — what each
  sshd_config setting actually does, why the default is risky, and the exact fix.
---

# SSH hardening on Linux: a practical checklist

SSH is the most common way into a Linux host, and its defaults are tuned for compatibility, not
security. Most of the settings below ship in a state that's convenient but genuinely
exploitable. This checklist covers eleven `sshd_config` directives — what each one controls, the
specific risk of leaving it at its default, and the exact fix. It's the same list [Bulwark](/)'s
`ssh-remote-access` rule category checks automatically, reproduced here as a standalone
reference.

## The two that matter most

### `PasswordAuthentication`

```
PasswordAuthentication no
```

If this is `yes` (often the default on a fresh install), anyone who can reach port 22 can
attempt to log in with a guessed password — no key required. Password guessing against SSH is
not a theoretical risk; it's one of the most common opportunistic attacks against any
internet-facing Linux host, automated and constant. Set this to `no` and rely on key-based auth
only. If you must keep password auth for a specific reason, pair it with `fail2ban` or an
equivalent rate-limiter, but disabling it outright is strictly better.

### `PermitRootLogin`

```
PermitRootLogin no
```

Direct root login over SSH means a single compromised credential — password or key — is full
system control, with no intermediate `sudo` step to log or gate. Set this to `no`, or
`prohibit-password` if you specifically need scripted root access via key only. Either way, an
interactive human should be logging in as an unprivileged user and elevating with `sudo`, not
authenticating as root directly.

## Everything else, grouped by what it actually does

### Credential and login bypass

- **`PermitEmptyPasswords no`** — with this at `yes`, any account with a blank password can log
  in with no credential at all. This should never be enabled; it's a pure oversight if it's set.
- **`StrictModes yes`** — controls whether `sshd` verifies that your home directory and key
  files have sane ownership/permissions before trusting them. With `StrictModes` off, a
  world-writable home directory or key file becomes a usable login bypass instead of a rejected,
  obviously-broken config.
- **`MaxAuthTries 3`** (up to 6) — caps how many authentication attempts are allowed per TCP
  connection. The default is often higher than necessary; a low ceiling meaningfully slows an
  online password-guessing attempt.

### Tunneling and pivoting

These four are the ones people don't think about, because they're not about *logging in* — 
they're about what an already-authenticated session can do.

- **`AllowTcpForwarding no`** — lets any SSH user open arbitrary local or remote port tunnels
  through the host. This is the exact mechanism used to pivot into internal networks, or to
  reach services (like an internal admin panel or a VNC port) that are only supposed to be
  reachable from localhost.
- **`PermitTunnel no`** — a step beyond TCP forwarding: gives the client a full virtual network
  interface (`tun`/`tap`) into the host's network, functioning like a VPN. Far more capability
  than almost anyone needs, and rarely intentional when enabled.
- **`GatewayPorts no`** — by default, a port an SSH client forwards to the host is only
  reachable from localhost. With `GatewayPorts` on, it's reachable from anywhere on the network
  — turning one user's ad-hoc tunnel into an accidental network-wide exposure.
- **`AllowAgentForwarding no`** (unless deliberately needed) — lets anyone with root on the host
  use the *connecting client's* SSH agent to authenticate onward as that client, without ever
  seeing the private key. This is a well-documented lateral-movement technique on multi-hop SSH
  setups — compromise one host in a chain, and agent forwarding lets you walk the chain forward.

### Session environment and display

- **`X11Forwarding no`** (unless remote GUI apps are a real requirement) — exposes the local X
  server to whatever runs on the remote end. X11 has a history of protocol-level compromise:
  keystroke injection, screen capture, and clipboard access from the remote side.
- **`PermitUserEnvironment no`** — lets an SSH client set arbitrary environment variables for its
  session via `~/.ssh/environment` or `SendEnv`, including ones like `LD_PRELOAD` that can
  hijack the behavior of programs the session later runs.

## Applying and verifying

After editing `/etc/ssh/sshd_config`, restart the daemon:

```bash
sudo systemctl restart sshd
```

Then verify the *effective* configuration rather than just re-reading the file you edited —
directives you didn't touch fall back to OpenSSH's compiled-in defaults, which aren't always
what you'd assume:

```bash
sudo sshd -T | grep -iE 'passwordauthentication|permitrootlogin|x11forwarding'
```

If you'd rather this ran automatically — on a schedule, with plain-language explanations and a
one-line fix per finding — that's exactly what [Bulwark](/)'s `ssh-remote-access` rule category
does, alongside checks for persistence, kernel hardening, and rootkit indicators. See the
[architecture doc](/guide/architecture) for how the rule engine works, or the
[Lynis benchmark](/research/lynis-benchmark) for how its findings compare to an established tool
on the same real machine.
