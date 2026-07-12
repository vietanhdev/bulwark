---
description: >-
  How to contribute to Bulwark — adding a security rule, working on the engine or UI, and the
  AGPL-3.0-or-later license and contributor terms that apply to every pull request.
---

# Contributing

Thanks for considering a contribution. Most contributions are a new rule — a YAML file under
`rules/<category>/`, no Rust required.

## Adding a rule

Rules are YAML files under `rules/<category>/`:

```yaml
id: BLWK-SSH-004
title: SSH X11 forwarding is enabled
category: ssh-remote-access
severity: low
collector: sshd_config
condition: x11_forwarding == "yes"
explain: "X11Forwarding is set to \"{{ sshd.x11_forwarding }}\" in sshd_config..."
fix: "Set 'X11Forwarding no' in /etc/ssh/sshd_config and run 'systemctl restart sshd'."
references: [CIS-5.2.4]
```

See the project's `AGENTS.md` for the full condition grammar and testing expectations.

## Engine, collector, or UI changes

See the repository's `README.md` for the build/quick-start commands, and the
[Architecture & design](./architecture) guide for the design rationale — read that before an
architectural change, not just this page.

## License

Bulwark is licensed under [AGPL-3.0-or-later](https://github.com/vietanhdev/bulwark/blob/main/LICENSE).
By contributing, your changes are licensed under the same terms.

## Contributor License Agreement (CLA)

Bulwark may, in the future, offer a commercial or dual-licensed edition (for example, a hosted
or enterprise tier) alongside the open-source AGPL edition. To keep that possible without having
to track down every past contributor for permission, we ask for a lightweight grant alongside
the AGPL license itself.

**By submitting a pull request, you agree that:**

1. You wrote the contribution yourself, or otherwise have the right to submit it under this
   agreement.
2. You license your contribution to the project under `AGPL-3.0-or-later`, the same as the rest
   of the codebase.
3. You additionally grant Viet Anh Nguyen (the project maintainer) a perpetual, worldwide,
   non-exclusive, royalty-free license to relicense your contribution — alone or as part of the
   combined work — under different terms, including proprietary or commercial licenses, at the
   maintainer's discretion.
4. You keep your own copyright and are free to reuse your contribution elsewhere; this grant is
   non-exclusive.

No separate signature or bot is required while the project is early-stage — opening a PR is
your agreement to the terms above. If external contribution volume grows, a CLA-assistant-style
bot may be added later to record this per-PR instead of relying on this document alone.

This isn't a substitute for legal advice; if a contribution is tied to your employer's IP policy
or you have any doubt about your right to grant the above, check before submitting.

The full text lives in [`CONTRIBUTING.md`](https://github.com/vietanhdev/bulwark/blob/main/CONTRIBUTING.md)
at the repository root.
