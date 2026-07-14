---
description: >-
  How to contribute to Bulwark — adding a security rule, working on the engine or UI, and the
  Apache-2.0 license and contributor terms that apply to every pull request.
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

Bulwark is licensed under [Apache-2.0](https://github.com/vietanhdev/bulwark/blob/main/LICENSE).
By contributing, your changes are licensed under the same terms.

## Contributions (inbound = outbound)

Bulwark follows the standard **inbound = outbound** model. Per Section 5 of the Apache License
2.0, any contribution you intentionally submit for inclusion in the project is licensed under the
same Apache-2.0 terms as the rest of the codebase — no separate CLA, signature, or bot required.

**By submitting a pull request, you affirm that:**

1. You wrote the contribution yourself, or otherwise have the right to submit it under the
   Apache License 2.0.
2. You license your contribution to the project under `Apache-2.0`, the same as the rest of the
   codebase — including the patent grant in Section 3 of that license.
3. You keep your own copyright and are free to reuse your contribution elsewhere; the license you
   grant here is non-exclusive.

Opening a PR is your agreement to the terms above.

This isn't a substitute for legal advice; if a contribution is tied to your employer's IP policy
or you have any doubt about your right to grant the above, check before submitting.

The full text lives in [`CONTRIBUTING.md`](https://github.com/vietanhdev/bulwark/blob/main/CONTRIBUTING.md)
at the repository root.
