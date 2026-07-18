<!-- ⚠️⚠️  Submission pull request MUST be made against the `new-pr` **base branch** ⚠️⚠️  -->

### Please confirm your submission meets all the criteria

- [X] Please describe the application briefly. < Bulwark scans a Linux host for security
      misconfigurations and intrusion indicators using a native Rust rule engine over
      declarative YAML rules, and explains each finding in plain language with a suggested
      fix. It checks SSH and sudo configuration, kernel sysctls, cron and systemd
      persistence, sensitive file permissions, file integrity against a recorded baseline,
      AI coding-assistant artifacts (API keys leaked into transcripts, and agent
      configuration a prompt injection could turn into code execution), and — when ClamAV
      is installed — viruses. Everything runs locally: the engine makes no network calls
      and sends no telemetry. Source: https://github.com/vietanhdev/bulwark >

- [ ] Please attach a video showcasing the application on Linux using the Flatpak.
      < TODO: record a short screen capture of `flatpak run com.vietanhdev.bulwark`
        running a scan, and paste it here >

- [X] The Flatpak ID follows all the rules listed in the [Application ID requirements][appid].
      < com.vietanhdev.bulwark — vietanhdev.com is a domain owned by the submitter, and the
        ID matches the .desktop file, the metainfo `id`, and the manifest filename. >

- [ ] I have read and followed all the [Submission requirements][reqs] and the
      [Submission guide][reqs2] and I agree to them.

- [ ] I am an author/developer/upstream contributor to the project.

<!-- ⚠️⚠️  Please DO NOT modify anything below this line ⚠️⚠️  -->

[appid]: https://docs.flathub.org/docs/for-app-authors/requirements#application-id
[reqs]: https://docs.flathub.org/docs/for-app-authors/requirements
[reqs2]: https://docs.flathub.org/docs/for-app-authors/submission

---

## Note on sandbox permissions (for the reviewer)

`--filesystem=host:ro` is the one non-default permission and it is the app's entire
function: Bulwark is a host security auditor, and it reads (never writes) host
configuration under `/etc` to check it. Full rationale, including why the narrower
alternatives do not work, is in `flathub-permissions-rationale.md` in the upstream repo.
Privileged scans are *not* available in the sandbox; the app says so in its own
description and directs users to the distribution packages for those.
