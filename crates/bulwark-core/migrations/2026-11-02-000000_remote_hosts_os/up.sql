-- What a remote machine runs, as last seen by a successful connection: `os_kind` is a short key the
-- app draws an icon from (`ubuntu`, `debian`, `fedora`, `arch`, `linux`, `wsl`, `macos`, `windows`,
-- …) and `os_name` the human-readable version ("Ubuntu 24.04.1 LTS", "macOS 15.6"). Both NULL
-- until the machine has been reached once; a separate migration because 2026-11-01's has shipped
-- to databases that will never re-run it.
ALTER TABLE remote_hosts ADD COLUMN os_kind TEXT;
ALTER TABLE remote_hosts ADD COLUMN os_name TEXT;
