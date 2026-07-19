//! The database schema, as Diesel sees it.
//!
//! Kept in sync with `migrations/` by hand rather than by `diesel print-schema`, so that building
//! this crate never requires the `diesel` CLI or a live database — the migrations are embedded
//! into the binary (see `store::MIGRATIONS`) and applied at runtime, and this file is simply the
//! typed view of what they create. If you add a migration, add the columns here too; the compiler
//! will catch every query that needed updating, which is the entire reason this crate uses an ORM
//! rather than hand-written SQL strings.
//!
//! Timestamps are stored as RFC 3339 `TEXT` and UUIDs as `TEXT`, rather than using Diesel's
//! chrono/uuid column types. That keeps the on-disk format human-readable (`sqlite3 bulwark.db
//! "select * from findings"` is legible without decoding), which matters for a security tool
//! whose database a user may reasonably want to inspect or grep themselves. Conversion lives in
//! `store`'s row structs.

diesel::table! {
    scan_runs (id) {
        id -> Text,
        started_at -> Text,
        finished_at -> Nullable<Text>,
        host_fingerprint -> Text,
        rules_loaded -> BigInt,
        rules_failed -> BigInt,
        collectors_failed -> BigInt,
        rule_load_errors -> Text,
        collector_errors -> Text,
        privileged_skipped -> Text,
        total_findings -> BigInt,
        // JSON array of the rule IDs that demonstrably ran in this scan. Added by
        // 2026-07-19-000000_scan_rules_evaluated; '[]' on every row written before it, which
        // reads as "no evidence kept" rather than "nothing ran clean". See that migration.
        rules_evaluated -> Text,
    }
}

diesel::table! {
    findings (id) {
        id -> Text,
        scan_run_id -> Text,
        rule_id -> Text,
        severity -> Text,
        title -> Text,
        explanation -> Text,
        fix_hint -> Text,
        context -> Text,
        first_seen -> Text,
        last_seen -> Text,
        status -> Text,
    }
}

diesel::table! {
    settings (key) {
        key -> Text,
        value -> Text,
    }
}

diesel::table! {
    log_scan_runs (id) {
        id -> Text,
        started_at -> Text,
        finished_at -> Nullable<Text>,
        host_fingerprint -> Text,
        events_read -> BigInt,
        events_decoded -> BigInt,
        decoders_loaded -> BigInt,
        rules_loaded -> BigInt,
        total_findings -> BigInt,
        decoder_load_errors -> Text,
        rule_load_errors -> Text,
        read_errors -> Text,
        rule_eval_errors -> Text,
    }
}

diesel::table! {
    log_findings (id) {
        id -> Text,
        log_scan_run_id -> Text,
        rule_id -> Text,
        severity -> Text,
        category -> Text,
        title -> Text,
        explanation -> Text,
        fix_hint -> Text,
        group_key -> Text,
        match_count -> BigInt,
        context -> Text,
        refs -> Text,
        observed_at -> Text,
        first_seen -> Text,
        last_seen -> Text,
        occurrences -> BigInt,
    }
}

diesel::table! {
    ai_scan_runs (id) {
        id -> Text,
        started_at -> Text,
        finished_at -> Nullable<Text>,
        host_fingerprint -> Text,
        workspaces_scanned -> Text,
        artifacts_scanned -> BigInt,
        total_findings -> BigInt,
        workspaces_capped -> Bool,
        scan_errors -> Text,
    }
}

diesel::table! {
    ai_findings (id) {
        id -> Text,
        ai_scan_run_id -> Text,
        rule_id -> Text,
        severity -> Text,
        tool -> Text,
        title -> Text,
        explanation -> Text,
        fix_hint -> Text,
        file -> Text,
        line -> Nullable<BigInt>,
        evidence -> Text,
        refs -> Text,
        redactable -> Bool,
    }
}

diesel::table! {
    rule_suppressions (rule_id) {
        rule_id -> Text,
        reason -> Text,
        created_at -> Text,
        created_by -> Text,
    }
}

diesel::table! {
    rule_suppression_events (id) {
        id -> Text,
        rule_id -> Text,
        action -> Text,
        reason -> Text,
        actor -> Text,
        at -> Text,
    }
}

diesel::joinable!(findings -> scan_runs (scan_run_id));
diesel::joinable!(log_findings -> log_scan_runs (log_scan_run_id));
diesel::joinable!(ai_findings -> ai_scan_runs (ai_scan_run_id));

diesel::allow_tables_to_appear_in_same_query!(
    scan_runs,
    findings,
    settings,
    log_scan_runs,
    log_findings,
    ai_scan_runs,
    ai_findings,
    rule_suppressions,
    rule_suppression_events,
);
