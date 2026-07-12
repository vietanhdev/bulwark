---
description: >-
  Bulwark is open source and looking for collaborators — rule and decoder authors, collector
  porters, testers, designers, and writers. Here's where help matters most, and how to get in touch.
---

# Collaborate on Bulwark

Bulwark is open source (AGPL-3.0-or-later) and built in the open. It started as one developer's
tool sharpened into something anyone running Linux can use — and it grows fastest when people who
hit real problems bring real fixes back. If Linux security is something you care about, there's a
place for you here, whether or not you write Rust.

## Where help matters most

- **Security rules** — the heart of Bulwark. A rule is a single YAML file under `rules/<category>/`
  with a condition, a plain-language explanation, and a concrete fix. No Rust required. If you know
  a misconfiguration worth catching, you can add a check for it in an afternoon. See
  [Contributing](/guide/contributing).
- **Log decoders & detection rules** — Bulwark now has a decode → detect → correlate log-analysis
  pipeline (`bulwarkctl logs scan`). Teaching it a new log format is a YAML **decoder**; catching a
  new attack pattern is a YAML **log rule** with an optional correlation window. Both are data, not
  code — an easy, high-impact place to start.
- **Collectors for macOS and Windows** — the rule/collector model is already OS-aware; the
  non-Linux collectors are honest stubs waiting to be filled in. Porting Bulwark beyond Linux is a
  well-scoped, high-leverage project.
- **The background agent** — continuous, follow-mode log monitoring (the streaming counterpart of
  the one-shot `logs scan`) is the next milestone for the `bulwark-agent` daemon.
- **Testing on real distros** — run Bulwark on your Debian, Fedora, Arch, or Ubuntu box and tell us
  where a check misfires, a path is wrong, or a finding reads badly. Ground-truth reports are gold.
- **Design & writing** — the desktop app, the docs, and the plain-language explanations that make a
  finding *actionable* rather than cryptic all deserve care. If that's your craft, we'd love it.

## How to get in touch

The fastest way to start collaborating is to **email [vietanh@nrl.ai](mailto:vietanh@nrl.ai?subject=Collaborating%20on%20Bulwark)** —
tell us what you'd like to work on, or just what you're running Bulwark on and what you'd want it to
catch. No formal proposal needed; a couple of sentences is plenty.

You can also:

- Open an issue or pull request on [GitHub](https://github.com/vietanhdev/bulwark).
- Read [Contributing](/guide/contributing) for the rule format, condition grammar, and the license
  and contributor terms that apply to every change.

Every contribution — a one-line rule, a bug report, a typo fix, a whole new collector — genuinely
moves this forward. We're glad you're here.
