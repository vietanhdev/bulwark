# Contributing to Bulwark

Thanks for considering a contribution. Most contributions are a new rule — a YAML file under
`rules/<category>/`, no Rust required. See `AGENTS.md`'s "adding a new check" section for the
condition grammar and testing expectations, and the README's "Adding a rule" section for a
minimal example.

Log-analysis content is just as approachable and also needs no Rust: a **decoder** (`decoders/*.yaml`)
teaches Bulwark to pull fields out of a log format, and a **log rule** (`log-rules/<category>/*.yaml`)
says what a decoded event means, using the same condition DSL plus an optional `correlate:` block.
See the "Log-analysis pipeline" section of `docs/guide/architecture.md` for the schema, and
`bulwarkctl logs decoders validate <dir>` / `logs rules validate <dir>` to lint your additions.

For engine/collector/UI changes, see `README.md`'s Quick start for the build commands and
`docs/guide/architecture.md` for the design rationale — read that before an architectural
change, not just this file.

## License

Bulwark is licensed under [Apache-2.0](LICENSE). By contributing, your changes are
licensed under the same terms.

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
