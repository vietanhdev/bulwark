-- Rule suppressions: a user's explicit, reasoned decision to accept the risk a rule reports.
--
-- Two tables, and the split is the whole point.
--
--   * `rule_suppressions` is *current state* — which rules are muted right now. Rows come and go.
--   * `rule_suppression_events` is the *audit log* — append-only, never updated, never deleted,
--     not even when the suppression it records is lifted. It answers the question the state table
--     structurally cannot: "who accepted this risk, when, why, and when did they change their
--     mind?" A mute button without this is just a way to lose information quietly, which is the
--     opposite of what a security tool is for.
--
-- Note what is deliberately NOT here: a way to stop a rule from running. Suppression is an overlay
-- on presentation, never a filter on evaluation. The engine keeps checking a suppressed rule every
-- scan and keeps writing its findings; the UI just doesn't shout about them. That means the moment
-- a suppression is lifted the user sees the *current* truth rather than a stale one, and it means a
-- suppression can never silently rot into a blind spot.

CREATE TABLE rule_suppressions (
    rule_id    TEXT PRIMARY KEY NOT NULL,
    -- NOT NULL and enforced non-blank in `store` — an unexplained suppression is worthless six
    -- months later, when the person who made it is the one asking why it's there.
    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE rule_suppression_events (
    id      TEXT PRIMARY KEY NOT NULL,
    rule_id TEXT NOT NULL,
    -- 'suppressed' | 'unsuppressed'
    action  TEXT NOT NULL,
    reason  TEXT NOT NULL,
    actor   TEXT NOT NULL,
    at      TEXT NOT NULL
);

-- The audit view is always "this rule's history, oldest to newest", so index for exactly that.
CREATE INDEX idx_rule_suppression_events_rule_at
    ON rule_suppression_events (rule_id, at);
