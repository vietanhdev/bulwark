-- Remote machines that Bulwark monitors over SSH.
--
-- Bulwark's remote model is agentless: nothing is installed on, or listens on, a monitored machine
-- between scans. This table is the whole of the "fleet" — the list of machines to reach, how to
-- reach them, and the outcome of the last attempt. Each machine's *findings* live in their own
-- per-host database (`remotes/<id>.db`, next to this one), never in this database's `findings`
-- table, because that table has no host column by design: reconciliation would otherwise resolve
-- this machine's findings against another machine's scan.
--
-- `jump_host` is a ProxyJump chain (`user@bastion[:port][,…]`), validated like an address. It is
-- the one routing option offered directly, because it is common and, unlike ProxyCommand, cannot
-- run a local command.
--
-- Deliberately absent: free-form ssh `-o` options. Options such as ProxyCommand or LocalCommand run
-- arbitrary local commands, and a background scheduler would replay them on every tick. Anything
-- beyond port and key file belongs in the user's own ~/.ssh/config, referenced by its Host alias.
--
-- `expected_hostname` pins the machine's identity (its /etc/hostname, learned on the first
-- successful scan). If an address later answers with a different hostname — a DHCP lease moved, a
-- DNS record was repointed — its scan must not be reconciled into this machine's history, where it
-- would mark real findings resolved.
--
-- `last_status` is 'ok' or a `fleet::RemoteErrorKind` in snake_case. NULL means never attempted.
CREATE TABLE remote_hosts (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL UNIQUE,
    spec TEXT NOT NULL,
    port BIGINT,
    identity_file TEXT,
    jump_host TEXT,
    privileged BOOLEAN NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    interval_minutes BIGINT NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL,
    expected_hostname TEXT,
    last_attempt_at TEXT,
    last_success_at TEXT,
    last_status TEXT,
    last_error TEXT,
    consecutive_failures BIGINT NOT NULL DEFAULT 0,
    engine TEXT
);
