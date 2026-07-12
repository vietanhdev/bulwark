---
description: >-
  A practical, directive-by-directive SSH hardening checklist for Linux — what each
  sshd_config setting actually does, why the default is risky, and the exact fix.
---

# SSH hardening on Linux: a practical checklist

SSH is the most common way into a Linux host, and its defaults are tuned for compatibility, not
security. Most of the settings below ship in a state that's convenient but genuinely exploitable.
This checklist covers eleven `sshd_config` directives — what each one controls, the specific risk of
leaving it at its default, and the exact fix. Every default named here is
OpenSSH's own compiled-in default, as documented in
[`sshd_config(5)`](https://man.openbsd.org/sshd_config.5), which is worth checking yourself rather
than trusting any checklist, this one included. It's the same list [Bulwark](/)'s
`ssh-remote-access` rule category checks automatically, reproduced here as a standalone reference.

## The two that matter most

### `PasswordAuthentication`

```
PasswordAuthentication no
```

OpenSSH's [default is `yes`](https://man.openbsd.org/sshd_config.5), which means anyone who can
reach port 22 can attempt to log in with a guessed password — no key required. Password guessing
against SSH is not a theoretical risk; it's one of the most common opportunistic attacks against any
internet-facing Linux host, automated and constant. Set this to `no` and rely on key-based auth
only. If you must keep password auth for a specific reason, pair it with `fail2ban` or an equivalent
rate-limiter (see the [comparison](/articles/fail2ban-vs-crowdsec-vs-denyhosts)), but disabling it
outright is strictly better.

One trap worth knowing before you "fix" this: some images already disable it somewhere you're not
looking. Ubuntu's cloud images ship
[`/etc/ssh/sshd_config.d/60-cloudimg-settings.conf`](https://git.launchpad.net/livecd-rootfs/tree/live-build/ubuntu-cpc/hooks.d/chroot/052-ssh_authentication.chroot)
with `PasswordAuthentication no` in it, and a drop-in like that beats whatever you edit into the main
`sshd_config`. Always confirm with `sshd -T` (below) rather than by reading the file you just
changed.

### `PermitRootLogin`

```
PermitRootLogin no
```

Direct root login over SSH means a single compromised credential — password or key — is full system
control, with no intermediate `sudo` step to log or gate. OpenSSH's default here is
`prohibit-password` rather than a flat `yes`, so key-based root login *is* permitted out of the box.
Set this to `no`, or leave it at `prohibit-password` only if you specifically need scripted root
access via key. Either way, an interactive human should be logging in as an unprivileged user and
elevating with `sudo` (see the [sudoers checklist](/articles/sudoers-hardening-checklist)), not
authenticating as root directly.

## Everything else, grouped by what it actually does

### Credential and login bypass

- **`PermitEmptyPasswords no`** — the default is already `no`; with this at `yes`, any account with a
  blank password can log in with no credential at all. This should never be enabled; it's a pure
  oversight if it's set.
- **`StrictModes yes`** — on by default, and worth confirming rather than assuming. It controls
  whether `sshd` verifies that your home directory and key files have sane ownership/permissions
  before trusting them. With `StrictModes` off, a world-writable home directory or key file becomes a
  usable login bypass instead of a rejected, obviously-broken config.
- **`MaxAuthTries 3`** — caps how many authentication attempts are allowed per TCP connection.
  [The default is 6](https://man.openbsd.org/sshd_config.5); a lower ceiling meaningfully slows an
  online password-guessing attempt.

### Tunneling and pivoting

These four are the ones people don't think about, because they're not about *logging in* — 
they're about what an already-authenticated session can do. Two of the four default to *on*.

- **`AllowTcpForwarding no`** — defaults to `yes`, letting any SSH user open arbitrary local or
  remote port tunnels through the host. This is the exact mechanism used to pivot into internal
  networks, or to reach services (like an internal admin panel or a VNC port) that are only supposed
  to be reachable from localhost.
- **`PermitTunnel no`** — a step beyond TCP forwarding: gives the client a full virtual network
  interface (`tun`/`tap`) into the host's network, functioning like a VPN. Far more capability than
  almost anyone needs, and rarely intentional when enabled. Defaults to `no` — keep it there.
- **`GatewayPorts no`** — the default. By default, a port an SSH client forwards to the host is only
  reachable from localhost; with `GatewayPorts` on, it's reachable from anywhere on the network —
  turning one user's ad-hoc tunnel into an accidental network-wide exposure.
- **`AllowAgentForwarding no`** (unless deliberately needed) — defaults to `yes`. OpenSSH's own
  documentation is explicit about the risk: [users who can bypass file permissions on the remote
  host "can access the local agent through the forwarded connection... they can perform operations on
  the keys that enable them to authenticate using the identities loaded into the
  agent"](https://man.openbsd.org/ssh_config.5) — without ever obtaining the private key itself.
  That's the lateral-movement technique on multi-hop SSH setups: compromise one host in a chain, and
  agent forwarding lets you walk the chain forward. (Worth pairing with the caveat
  [`sshd_config(5)`](https://man.openbsd.org/sshd_config.5) adds: disabling agent forwarding "does
  not improve security unless users are also denied shell access, as they can always install their
  own forwarders.")

### Session environment and display

- **`X11Forwarding no`** — already the default, and worth keeping unless remote GUI apps are a real
  requirement: it exposes the local X server to whatever runs on the remote end, and X11 has a
  history of protocol-level compromise — keystroke injection, screen capture, and clipboard access
  from the remote side.
- **`PermitUserEnvironment no`** — the default. If enabled, it lets an SSH client set arbitrary
  environment variables for its session via `~/.ssh/environment`, including ones like `LD_PRELOAD`
  that can hijack the behavior of programs the session later runs.

## Applying and verifying

After editing `/etc/ssh/sshd_config`, restart the daemon:

```bash
sudo systemctl restart sshd
```

Then verify the *effective* configuration rather than just re-reading the file you edited —
directives you didn't touch fall back to OpenSSH's compiled-in defaults, and drop-ins under
`/etc/ssh/sshd_config.d/` can override what you wrote. [`sshd -T`](https://man.openbsd.org/sshd.8)
exists precisely for this: it "output[s] the effective configuration to stdout."

```bash
sudo sshd -T | grep -iE 'passwordauthentication|permitrootlogin|x11forwarding'
```

If you'd rather this ran automatically — on a schedule, with plain-language explanations and a
one-line fix per finding — that's exactly what [Bulwark](/)'s `ssh-remote-access` rule category does,
alongside checks for persistence, kernel hardening, and rootkit indicators. Use the desktop app on
the Linux machine in front of you (it re-checks the moment `sshd_config` changes, rather than waiting
for you to remember), or `bulwarkctl scan` over SSH on the servers you administer — same rules, same
findings, same fixes. See the [architecture doc](/guide/architecture) for how the rule engine works.

## References

- [`sshd_config(5)`](https://man.openbsd.org/sshd_config.5) — the compiled-in default for every directive above (`PasswordAuthentication yes`, `PermitRootLogin prohibit-password`, `MaxAuthTries 6`, `AllowTcpForwarding yes`, `AllowAgentForwarding yes`, `PermitEmptyPasswords no`, `StrictModes yes`, `X11Forwarding no`, `GatewayPorts no`, `PermitTunnel no`, `PermitUserEnvironment no`).
- [`ssh_config(5)`](https://man.openbsd.org/ssh_config.5) — the agent-forwarding risk, in OpenSSH's own words.
- [`sshd(8)`](https://man.openbsd.org/sshd.8) — `sshd -T` and the effective configuration.
- [Ubuntu livecd-rootfs `052-ssh_authentication.chroot`](https://git.launchpad.net/livecd-rootfs/tree/live-build/ubuntu-cpc/hooks.d/chroot/052-ssh_authentication.chroot) — the cloud-image drop-in that disables password authentication.
