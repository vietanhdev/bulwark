//! The one place YAML is parsed: rule packs, the compliance mappings, and the config files of AI
//! agents found in a scanned home folder.
//!
//! That last group is written by whoever owns the folder and is read by a root scan, so every
//! document, trusted or not, is parsed under the same limits:
//!
//! - **What a document may produce.** The parser counts every value and every byte of text it
//!   hands over, including each copy an alias (`*name`) makes, and stops at [`MAX_NODES`] and
//!   [`MAX_SCALAR_BYTES`]. Callers also cap the input (1 MiB for a pack file, 4 MiB for an agent
//!   file), but a cap on the input does not bound the output: one large anchored value named
//!   again and again grows with the square of the file size.
//! - **How deep it may nest.** [`MAX_DEPTH`] levels. Reading recurses once per level, and an
//!   unoptimised build needs about 23 KiB of stack for each: 64 levels, the parser's own default
//!   limit, take 1.5 MiB of the 2 MiB a worker thread has and do not fit the 1 MiB of the main
//!   thread on Windows. A document is therefore parsed on a thread of its own with
//!   [`PARSER_STACK_BYTES`] of stack, never on whatever the caller has left. A panic in the parser
//!   ends that thread and comes back as an [`Error`].
//! - **What it may reach.** Nothing. The crate is built without its `include` and `properties`
//!   features, so a document cannot name a file to read or a variable to expand.
//!
//! The options keep the reading `serde_yaml` 0.9 gave, which every rule file and detector was
//! written against: `yes`/`no`/`on`/`off` are text and only `true`/`false` are booleans, `0644`
//! and `1_000` are text while `0o644` and `0x1F` are numbers, `<<` is an ordinary key, a `!!binary`
//! value stays as written, and a key given twice keeps its last value (a typed struct refuses it).
//! `tests::documents_read_the_way_rules_and_detectors_expect` pins each of these; the two tests
//! after it pin where this parser reads more than that one did, and where it reads less.

use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// The deepest nesting of lists and mappings a document may have.
pub(crate) const MAX_DEPTH: usize = 128;

/// The most values (scalars, lists and mappings) one document may produce, alias copies included.
pub(crate) const MAX_NODES: usize = 250_000;

/// The most scalar text one document may produce, alias copies included.
pub(crate) const MAX_SCALAR_BYTES: usize = 8 * 1024 * 1024;

/// Stack of the thread a document is parsed on. [`MAX_DEPTH`] levels need about 3 MiB in an
/// unoptimised build; `the_deepest_document_fits_a_quarter_of_the_parser_stack` keeps the margin.
pub(crate) const PARSER_STACK_BYTES: usize = 16 * 1024 * 1024;

fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_depth: MAX_DEPTH,
            max_nodes: MAX_NODES,
            max_events: 4 * MAX_NODES,
            max_aliases: MAX_NODES,
            max_anchors: MAX_NODES,
            max_total_scalar_bytes: MAX_SCALAR_BYTES,
            max_recorded_anchor_events: MAX_NODES,
            max_recorded_anchor_bytes: MAX_SCALAR_BYTES,
            // The limits above bound what aliases can produce. This heuristic adds nothing to
            // them and refuses an ordinary file that names one anchor a hundred times.
            enforce_alias_anchor_ratio: false,
        },
        alias_limits: serde_saphyr::alias_limits! {
            max_total_replayed_events: MAX_NODES,
            max_replay_stack_depth: MAX_DEPTH,
        },
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::PassThrough,
        merge_keys: serde_saphyr::options::MergeKeyPolicy::AsOrdinary,
        strict_booleans: true,
        leading_zero_numbers_as_strings: true,
        underscored_numbers_as_strings: true,
        ignore_binary_tag_for_string: true,
        // `.inf` and `.nan` have no JSON form; they become null, as they always have.
        non_finite_float_policy: serde_saphyr::options::NonFiniteFloatPolicy::PassThrough,
        // A message is one line. A snippet would also copy lines of the file into it.
        with_snippet: false,
    }
}

/// Why a document could not be read: one line, with the line and column when they are known, and
/// safe to print (see [`crate::engine::display_safe`]; a message can quote the file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl Error {
    fn new(message: String) -> Self {
        Error(crate::engine::display_safe(&message).into_owned())
    }

    fn from_parser(err: &serde_saphyr::Error) -> Self {
        use serde_saphyr::budget::BudgetBreach;
        use serde_saphyr::{Error as E, MessageFormatter, UserMessageFormatter};

        // An error met while expanding an alias is wrapped with both places; describe the cause.
        let mut cause = err;
        while let E::AliasError { error, .. } | E::WithSnippet { error, .. } = cause {
            cause = error;
        }
        let too_complex =
            || format!("too large to read: more than {MAX_NODES} values once aliases are expanded");
        let mut message = match cause {
            E::Budget { breach, .. } => match breach {
                BudgetBreach::Depth { .. } => {
                    format!("too deeply nested: more than {MAX_DEPTH} levels")
                }
                BudgetBreach::ScalarBytes { .. } | BudgetBreach::RecordedAnchorBytes { .. } => {
                    format!(
                        "too large to read: more than {} MiB of text once aliases are expanded",
                        MAX_SCALAR_BYTES / (1024 * 1024)
                    )
                }
                _ => too_complex(),
            },
            E::AliasReplayLimitExceeded { .. }
            | E::AliasReplayStackDepthExceeded { .. }
            | E::AliasExpansionLimitExceeded { .. }
            | E::AliasReplayCounterOverflow { .. } => too_complex(),
            E::NullIntoString { .. } => {
                "a value is required here (write \"\" for empty text)".to_owned()
            }
            E::MultipleDocuments { .. } => {
                "more than one YAML document in the file; only one is supported".to_owned()
            }
            E::Unexpected { expected, .. } => format!(
                "expected {}",
                match *expected {
                    "sequence start" => "a list",
                    "mapping start" => "a mapping",
                    "string scalar" => "text",
                    other => other,
                }
            ),
            other => {
                let text = UserMessageFormatter.format_message(other).into_owned();
                // The one spelling people do write that the specification forbids.
                if text == "invalid indentation in multiline quoted scalar" {
                    "a quoted value continues on a line that is not indented under its key"
                        .to_owned()
                } else {
                    text
                }
            }
        };
        // A missing field is nowhere in particular; the place the parser gives is the last entry.
        let placed = !matches!(cause, E::SerdeMissingField { .. });
        if let Some(at) = err.location().filter(|at| placed && at.line() > 0) {
            message.push_str(&format!(" at line {} column {}", at.line(), at.column()));
        }
        Error::new(message)
    }
}

/// The line and column an error message names, if it names one (see the `at line … column …`
/// suffix added above). Callers that must not show the message, which can quote the document, use
/// this instead.
pub(crate) fn error_position(e: &Error) -> Option<(usize, usize)> {
    let text = e.to_string();
    let rest = &text[text.rfind(" at line ")? + " at line ".len()..];
    let (line, column) = rest.split_once(" column ")?;
    Some((line.trim().parse().ok()?, column.trim().parse().ok()?))
}

/// Reads one YAML document as `T`.
pub(crate) fn from_str<T: DeserializeOwned + Send>(text: &str) -> Result<T, Error> {
    from_str_on_stack(text, PARSER_STACK_BYTES)
}

/// Reads one YAML document whose shape is not known in advance, as the JSON value the detectors
/// work on. Mapping keys become text as written (`1`, `true`); a null key becomes `null`.
pub(crate) fn to_json(text: &str) -> Result<Value, Error> {
    to_json_on_stack(text, PARSER_STACK_BYTES)
}

fn to_json_on_stack(text: &str, stack: usize) -> Result<Value, Error> {
    from_str_on_stack::<Tree>(text, stack).map(|tree| tree.0)
}

fn from_str_on_stack<T: DeserializeOwned + Send>(text: &str, stack: usize) -> Result<T, Error> {
    std::thread::scope(|scope| {
        let parser = std::thread::Builder::new()
            .name("yaml".to_owned())
            .stack_size(stack)
            .spawn_scoped(scope, || {
                serde_saphyr::from_str_with_options(text, options())
                    .map_err(|e| Error::from_parser(&e))
            })
            .map_err(|e| Error::new(format!("could not start the YAML parser: {e}")))?;
        parser.join().unwrap_or_else(|_| {
            Err(Error::new(
                "the YAML parser stopped unexpectedly".to_owned(),
            ))
        })
    })
}

/// A JSON value read from YAML. `serde_json::Value` can be read directly, but it asks for every
/// mapping key as a string, and this parser refuses to turn a null key (`~: x`, `null: x`) into
/// one. That would let a single such key hide a whole file from the checks.
struct Tree(Value);

impl<'de> serde::Deserialize<'de> for Tree {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(TreeVisitor).map(Tree)
    }
}

struct TreeVisitor;

impl<'de> Visitor<'de> for TreeVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(TreeVisitor)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Tree(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key_seed(Key)? {
            let Tree(v) = map.next_value()?;
            out.insert(key, v);
        }
        Ok(Value::Object(out))
    }
}

/// A mapping key as text.
struct Key;

impl<'de> DeserializeSeed<'de> for Key {
    type Value = String;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_option(Key)
    }
}

impl<'de> Visitor<'de> for Key {
    type Value = String;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a mapping key")
    }

    fn visit_none<E>(self) -> Result<String, E> {
        Ok("null".to_owned())
    }

    fn visit_unit<E>(self) -> Result<String, E> {
        Ok("null".to_owned())
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_str(Key)
    }

    fn visit_str<E>(self, v: &str) -> Result<String, E> {
        Ok(v.to_owned())
    }

    fn visit_string<E>(self, v: String) -> Result<String, E> {
        Ok(v)
    }
}

/// Documents built to exhaust memory, time or the stack, for this module's tests and for the
/// detectors that read YAML from a home folder. None is larger than the 4 MiB an agent file may
/// be, and each is sized so that a parser with no limits at all would still not hurt the machine
/// running the tests.
#[cfg(test)]
pub(crate) mod hostile {
    use std::time::Duration;

    /// Far above the slowest document (a few seconds unoptimised), far below what a parser that
    /// re-reads its input takes: `serde_yaml` needed 98 s for `{a: ` repeated 100,000 times.
    pub(crate) const DEADLINE: Duration = Duration::from_secs(60);

    /// Nine anchors, each a list naming the one before it nine times: 9⁹ values from 400 bytes.
    pub(crate) fn billion_laughs() -> String {
        let mut doc = String::from("a0: &a0 [x,x,x,x,x,x,x,x,x]\n");
        for i in 1..9 {
            let alias = format!("*a{}", i - 1);
            doc.push_str(&format!(
                "a{i}: &a{i} [{}]\n",
                [alias.as_str(); 9].join(",")
            ));
        }
        doc
    }

    /// One anchored scalar of `kib` KiB named `times` more times. The input grows with
    /// `kib + times`, the text it stands for with `kib × times`.
    pub(crate) fn repeated_scalar(kib: usize, times: usize) -> String {
        let mut doc = format!("a: &a {}\nb:\n", "x".repeat(kib * 1024));
        doc.push_str(&"- *a\n".repeat(times));
        doc
    }

    /// One anchored list of `len` items named `times` more times: `len × times` values.
    pub(crate) fn repeated_list(len: usize, times: usize) -> String {
        let mut doc = format!("a: &a [{}]\nb:\n", vec!["x"; len].join(","));
        doc.push_str(&"- *a\n".repeat(times));
        doc
    }

    /// What a caller that reads bytes as lossy UTF-8 hands over for a file that is not UTF-8.
    pub(crate) fn not_utf8() -> String {
        String::from_utf8_lossy(b"na\xffme: \xfe\xfd\n\xc3(: [\xf0\x28\x8c\x28, ok]\n").into_owned()
    }

    /// The cases every caller must survive: an alias bomb, text multiplied through aliases, very
    /// deep nesting, a multi-megabyte scalar, bytes that were not UTF-8, and anchors that contain
    /// themselves.
    pub(crate) fn essentials() -> Vec<(&'static str, String)> {
        vec![
            ("billion laughs", billion_laughs()),
            ("256 KiB scalar named 200 times", repeated_scalar(256, 200)),
            ("100,000 open brackets", "[".repeat(100_000)),
            (
                "100,000 nested lists",
                format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)),
            ),
            ("3 MiB scalar", format!("a: {}\n", "x".repeat(3 << 20))),
            ("not UTF-8", not_utf8()),
            ("NUL bytes", "a: \0\0\nb\0: 1\n".to_owned()),
            ("list inside itself", "a: &a [*a]\n".to_owned()),
            ("mapping inside itself", "a: &a {b: *a}\n".to_owned()),
            (
                "two anchors inside each other",
                "a: &a {b: &b {c: *a, d: *b}}\n".to_owned(),
            ),
        ]
    }

    /// [`essentials`] plus the shapes that cost a parser the most per byte.
    pub(crate) fn documents() -> Vec<(&'static str, String)> {
        let mut docs = essentials();
        let mut merges = String::from("a0: &a0 {k: v}\n");
        for i in 1..40 {
            merges.push_str(&format!("a{i}: &a{i}\n  <<: [*a{}, *a{}]\n", i - 1, i - 1));
        }
        let mut ladder = String::new();
        for depth in 0..2000 {
            ladder.push_str(&" ".repeat(depth));
            ladder.push_str("a:\n");
        }
        docs.extend([
            ("2,000 items named 2,000 times", repeated_list(2000, 2000)),
            ("merge keys doubling 40 times", merges),
            ("100,000 open braces", "{a: ".repeat(100_000)),
            ("100,000 nested block lists", "- ".repeat(100_000) + "x"),
            ("2,000 nested block mappings", ladder),
            (
                "3 MiB quoted scalar",
                format!("a: \"{}\"\n", "x".repeat(3 << 20)),
            ),
            ("3 MiB key", format!("{}: 1\n", "k".repeat(3 << 20))),
            ("3 MiB comment", format!("a: 1 # {}\n", "c".repeat(3 << 20))),
            ("3 MiB tag", format!("a: !{} b\n", "t".repeat(3 << 20))),
            (
                "3 MiB anchor name",
                format!("a: &{} b\n", "n".repeat(3 << 20)),
            ),
            ("a million list items", "- a\n".repeat(1 << 20)),
            (
                "200,000 anchors",
                (0..200_000).map(|i| format!("k{i}: &a{i} 1\n")).collect(),
            ),
            (
                "500,000 aliases of one value",
                format!("a: &a 1\nb: [{}]\n", "*a,".repeat(500_000)),
            ),
            ("a million documents", "---\n".repeat(1 << 20)),
            ("1 MiB of colons", ":".repeat(1 << 20)),
            ("1 MiB of quotes", "\"".repeat(1 << 20)),
            ("1 MiB of question marks", "? ".repeat(1 << 19)),
            (
                "1 MiB of backslashes",
                format!("a: \"{}\"\n", "\\\\".repeat(1 << 19)),
            ),
            ("4 MiB of newlines", "\n".repeat(4 << 20)),
        ]);
        docs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;
    use std::time::Instant;

    /// (values, bytes of text) in a tree, keys included.
    fn size(v: &Value) -> (usize, usize) {
        match v {
            Value::String(s) => (1, s.len()),
            Value::Array(a) => a
                .iter()
                .map(size)
                .fold((1, 0), |x, y| (x.0 + y.0, x.1 + y.1)),
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| {
                    let (n, b) = size(v);
                    (n + 1, b + k.len())
                })
                .fold((1, 0), |x, y| (x.0 + y.0, x.1 + y.1)),
            _ => (1, 0),
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Typed {
        text: String,
        #[serde(default)]
        flag: bool,
        #[serde(default)]
        count: u32,
        #[serde(default)]
        list: Vec<String>,
        #[serde(default)]
        severity: Option<crate::models::Severity>,
    }

    fn typed(doc: &str) -> Result<Typed, String> {
        from_str::<Typed>(doc).map_err(|e| e.to_string())
    }

    /// The reading every shipped rule and every detector was written against. A change in any of
    /// these silently changes what a scan reports, so an update of the parser that moves one of
    /// them must fail here.
    #[test]
    fn documents_read_the_way_rules_and_detectors_expect() {
        let cases = [
            // YAML 1.1 booleans are text; only true/false in three spellings are booleans.
            (
                "a: [yes, no, on, off, y, n]",
                json!({"a": ["yes", "no", "on", "off", "y", "n"]}),
            ),
            (
                "a: [true, True, TRUE, false, False, FALSE]",
                json!({"a": [true, true, true, false, false, false]}),
            ),
            ("a: tRuE", json!({"a": "tRuE"})),
            // A file mode written 0644 stays text; only the 0o form is octal.
            (
                "a: [0644, 0600, 08, 00, -007]",
                json!({"a": ["0644", "0600", "08", "00", "-007"]}),
            ),
            (
                "a: [0o644, 0x1F, 0b101, +12, -3]",
                json!({"a": [420, 31, 5, 12, -3]}),
            ),
            ("a: 1_000", json!({"a": "1_000"})),
            (
                "a: [1.5, 1e3, 1.10, 4.0]",
                json!({"a": [1.5, 1000.0, 1.1, 4.0]}),
            ),
            (
                "a: [1.2.3, 2026-11-13, 12:30, 127.0.0.1]",
                json!({"a": ["1.2.3", "2026-11-13", "12:30", "127.0.0.1"]}),
            ),
            (
                "a: 18446744073709551615",
                json!({"a": 18446744073709551615u64}),
            ),
            (
                "a: [~, null, Null, NULL, ]",
                json!({"a": [null, null, null, null]}),
            ),
            ("a:\nb: 1", json!({"a": null, "b": 1})),
            ("a: [.inf, -.inf, .nan]", json!({"a": [null, null, null]})),
            (
                "a: ['0644', \"yes\", '', \"null\"]",
                json!({"a": ["0644", "yes", "", "null"]}),
            ),
            // Keys are text as written.
            (
                "1: a\ntrue: b\n0x1F: c\n1.5: d",
                json!({"1": "a", "true": "b", "0x1F": "c", "1.5": "d"}),
            ),
            ("null: a", json!({"null": "a"})),
            // A key given twice keeps its last value.
            ("a: 1\na: 2", json!({"a": 2})),
            // Aliases are expanded; a merge key is an ordinary key.
            ("a: &x [1, 2]\nb: *x", json!({"a": [1, 2], "b": [1, 2]})),
            (
                "x: &b {k: 1}\ny:\n  <<: *b\n  z: 2",
                json!({"x": {"k": 1}, "y": {"<<": {"k": 1}, "z": 2}}),
            ),
            // A standard tag does not rewrite the value under it.
            (
                "a: !!str 123\nb: !!binary aGVsbG8=",
                json!({"a": "123", "b": "aGVsbG8="}),
            ),
            // Scalar styles.
            (
                "a: |\n  x\n  y\nb: >\n  x\n  y\nc: \"x\\ty\\u00e9\"\nd: 'it''s'",
                json!({"a": "x\ny\n", "b": "x y\n", "c": "x\ty\u{e9}", "d": "it's"}),
            ),
            (
                "a: \"{{ collector.field }}\"",
                json!({"a": "{{ collector.field }}"}),
            ),
            // JSON is YAML.
            (
                "{\"a\":1,\"b\":[true,null,\"x\"]}",
                json!({"a": 1, "b": [true, null, "x"]}),
            ),
            // Nothing, a comment, or a bare marker is a null document.
            ("", json!(null)),
            ("# only a comment\n", json!(null)),
            ("---\n", json!(null)),
            ("a: 1\r\nb: 2\r\n", json!({"a": 1, "b": 2})),
        ];
        for (doc, expected) in cases {
            assert_eq!(
                to_json(doc).map_err(|e| e.to_string()),
                Ok(expected),
                "{doc:?}"
            );
        }
        for refused in [
            "a: 1\n---\nb: 2\n",
            "a: [1, 2",
            "a: b: c",
            "a: *missing",
            "a:\n\t- b",
            "a: {{ x }}",
        ] {
            assert!(to_json(refused).is_err(), "{refused:?}");
        }
    }

    /// Where this parser reads a file `serde_yaml` gave up on. An agent's file that cannot be read
    /// gets only the checks that work on its text, so each of these used to leave one mostly
    /// unchecked.
    #[test]
    fn a_tag_a_byte_order_mark_or_a_null_key_does_not_make_a_file_unreadable() {
        let cases = [
            (
                "a: !secret abc\nb: !thing {c: 1}\nc: ! 12",
                json!({"a": "abc", "b": {"c": 1}, "c": "12"}),
            ),
            ("\u{feff}a: 1\r\nb: 2\r\n", json!({"a": 1, "b": 2})),
            (
                "m: {~: {command: npx}}",
                json!({"m": {"null": {"command": "npx"}}}),
            ),
            (
                "a: 18446744073709551616",
                json!({"a": 18446744073709551616.0}),
            ),
            ("a: \"\\ud83d\\ude00\"", json!({"a": "\u{1f600}"})),
        ];
        for (doc, expected) in cases {
            assert_eq!(
                to_json(doc).map_err(|e| e.to_string()),
                Ok(expected),
                "{doc:?}"
            );
        }
    }

    /// Where this parser follows the YAML specification and `serde_yaml` did not: these were read
    /// before and are refused now. Recorded so the list in `docs/guide/architecture.md` §10 stays
    /// true, not because refusing is wanted. If one starts to parse after an update, that is good
    /// news: move it out of this test and out of that list.
    #[test]
    fn spellings_outside_the_specification_are_refused() {
        for doc in [
            // A quoted value continued on a line indented no deeper than its key.
            "a: \"first\nsecond\"\n",
            "a:\n  b: 'first\n  second'\n",
            // A comment with nothing between it and a closing quote or bracket.
            "a: \"x\"# note\n",
            "a: [1, 2]# note\n",
            // A lone dash as a value inside brackets or braces.
            "a: [-]\n",
            "a: {b: -}\n",
        ] {
            assert!(to_json(doc).is_err(), "{doc:?}");
        }
        // Written the way the specification asks, each is read.
        for (doc, expected) in [
            ("a: \"first\n  second\"\n", json!({"a": "first second"})),
            ("a: \"x\" # note\n", json!({"a": "x"})),
            ("a: [\"-\"]\n", json!({"a": ["-"]})),
        ] {
            assert_eq!(
                to_json(doc).map_err(|e| e.to_string()),
                Ok(expected),
                "{doc:?}"
            );
        }
    }

    #[test]
    fn typed_fields_take_what_they_did_before() {
        // Text keeps the spelling in the file, whatever it looks like.
        for raw in [
            "0644",
            "1.10",
            "yes",
            "true",
            "2026-11-13",
            "8.3.6",
            "164.312(b)",
        ] {
            assert_eq!(typed(&format!("text: {raw}")).unwrap().text, raw);
        }
        assert!(typed("text: t\nflag: True").unwrap().flag);
        for not_a_boolean in ["yes", "on", "1", "tRuE"] {
            assert!(typed(&format!("text: t\nflag: {not_a_boolean}")).is_err());
        }
        assert_eq!(typed("text: t\ncount: 0x10").unwrap().count, 16);
        for not_a_count in ["010", "-1", "1.5", "4294967296", "many"] {
            assert!(typed(&format!("text: t\ncount: {not_a_count}")).is_err());
        }
        assert_eq!(
            typed("text: t\nseverity: high").unwrap().severity,
            Some(crate::models::Severity::High)
        );
        assert_eq!(typed("text: t\nseverity:").unwrap().severity, None);
        // An unknown key is ignored, however deep its value; a repeated known one is refused.
        assert!(typed("text: t\nunknown: {a: [1, {b: 2}]}").is_ok());
        assert!(typed("text: t\ntext: u")
            .unwrap_err()
            .contains("duplicate field `text`"));
        assert!(typed("").is_err() && typed("- text").is_err());
    }

    #[test]
    fn an_error_is_one_printable_line_with_the_place() {
        let doc = "text: t\nlist: [a]\nseverity: hgih\n";
        assert_eq!(
            typed(doc).unwrap_err(),
            "unknown variant `hgih`, expected one of info, low, medium, high, critical at line 3 column 11"
        );
        assert_eq!(
            typed("text: t\nlist: nope").unwrap_err(),
            "expected a list at line 2 column 7"
        );
        assert_eq!(
            typed("flag: true\ncount: 1\n").unwrap_err(),
            "missing field `text`"
        );
        assert_eq!(
            typed("text: t: u").unwrap_err(),
            "mapping values are not allowed in this context at line 1 column 8"
        );
        assert_eq!(
            typed("text: \"first\nsecond\"\n").unwrap_err(),
            "a quoted value continues on a line that is not indented under its key at line 2 column 1"
        );
        // A required value left blank, or written as null, is refused in words a rule author can
        // act on.
        for blank in ["text:\nflag: true", "text: ~", "text: null"] {
            let e = typed(blank).unwrap_err();
            assert!(
                e.starts_with("a value is required here (write \"\" for empty text) at line 1 "),
                "{blank:?}: {e}"
            );
        }
        assert!(typed("text: t\n---\ntext: u")
            .unwrap_err()
            .starts_with("more than one YAML document in the file"));
        // A message can quote the file. It never carries a control character from it, and never
        // more than one line.
        let hostile = typed("text: t\nseverity: \"\\e[31mred\\nsecond line\"").unwrap_err();
        assert!(hostile.contains("unknown variant"), "{hostile}");
        assert!(!hostile.chars().any(char::is_control), "{hostile:?}");
    }

    #[test]
    fn a_document_cannot_reach_outside_itself() {
        let doc =
            "a: !include /etc/hostname\nb: ${HOME}\nc: $HOME\nd: !!python/object:os.system x\n";
        assert_eq!(
            to_json(doc).unwrap(),
            json!({"a": "/etc/hostname", "b": "${HOME}", "c": "$HOME", "d": "x"})
        );
    }

    #[test]
    fn hostile_documents_end_in_time_with_an_error_or_a_bounded_result() {
        for (name, doc) in hostile::documents() {
            assert!(doc.len() <= 4 << 20, "{name}: {} bytes", doc.len());
            let started = Instant::now();
            let result = to_json(&doc);
            let took = started.elapsed();
            assert!(took < hostile::DEADLINE, "{name} took {took:?}");
            match result {
                Ok(v) => {
                    let (values, bytes) = size(&v);
                    assert!(values <= MAX_NODES + 1, "{name}: {values} values");
                    assert!(bytes <= MAX_SCALAR_BYTES, "{name}: {bytes} bytes of text");
                }
                Err(e) => assert!(!e.to_string().is_empty(), "{name}"),
            }
        }
        // A typed struct meets the same documents as the value of a field it does not know.
        for (name, doc) in hostile::essentials() {
            let started = Instant::now();
            let _ = typed(&format!(
                "text: t\nunknown:\n  {}",
                doc.replace('\n', "\n  ")
            ));
            assert!(started.elapsed() < hostile::DEADLINE, "{name} (typed)");
        }
    }

    #[test]
    fn aliases_cannot_multiply_values_or_text_past_the_limits() {
        let too_many = format!("more than {MAX_NODES} values once aliases are expanded");
        let laughs = to_json(&hostile::billion_laughs()).unwrap_err().to_string();
        assert!(laughs.contains(&too_many), "{laughs}");
        let squared = to_json(&hostile::repeated_list(2000, 2000))
            .unwrap_err()
            .to_string();
        assert!(squared.contains(&too_many), "{squared}");

        // 264 KiB of input standing for 51 MiB of text.
        let text = to_json(&hostile::repeated_scalar(256, 200))
            .unwrap_err()
            .to_string();
        assert!(
            text.contains("more than 8 MiB of text once aliases are expanded"),
            "{text}"
        );

        // Ordinary reuse is untouched: one anchor named 300 times, well inside the limits.
        let reuse = to_json(&hostile::repeated_scalar(1, 300)).unwrap();
        assert_eq!(reuse["b"].as_array().map(Vec::len), Some(300));
        assert_eq!(reuse["b"][299], reuse["a"]);
    }

    #[test]
    fn an_anchor_inside_itself_is_refused() {
        for doc in [
            "a: &a [*a]",
            "a: &a {b: *a}",
            "a: &a {b: &b {c: *a, d: *b}}",
        ] {
            assert!(to_json(doc).is_err(), "{doc}");
        }
    }

    #[test]
    fn a_large_scalar_is_read_whole_and_odd_bytes_never_panic() {
        let big = "x".repeat(3 << 20);
        assert_eq!(
            to_json(&format!("a: {big}\n")).unwrap()["a"].as_str(),
            Some(big.as_str())
        );
        // A file that was not UTF-8 arrives with U+FFFD in place of the bad bytes.
        let lossy = to_json(&hostile::not_utf8()).unwrap();
        assert!(lossy
            .as_object()
            .unwrap()
            .keys()
            .any(|k| k.contains('\u{fffd}')));
        assert!(to_json("a: \0\0\nb\0: 1\n").is_err());
        for c in [
            '\u{1}', '\u{7}', '\u{1b}', '\u{7f}', '\u{85}', '\u{2028}', '\u{feff}', '\u{fffe}',
        ] {
            let _ = to_json(&format!("a{c}: b{c}\n{c}c: [d{c}]\n"));
        }
    }

    /// One document per way of nesting, `depth` levels deep in total.
    fn nested(depth: usize) -> Vec<(&'static str, String)> {
        let mut block = String::new();
        for level in 0..depth {
            block.push_str(&" ".repeat(level));
            block.push_str("a:\n");
        }
        // The root mapping is one level and `a0` a second; each further anchor adds one.
        let mut chain = String::from("a0: &a0 [x]\n");
        for i in 1..depth - 1 {
            chain.push_str(&format!("a{i}: &a{i} [*a{}]\n", i - 1));
        }
        vec![
            (
                "flow lists",
                format!("{}x{}", "[".repeat(depth), "]".repeat(depth)),
            ),
            (
                "flow mappings",
                format!("{}x{}", "{a: ".repeat(depth), "}".repeat(depth)),
            ),
            ("block lists", "- ".repeat(depth) + "x"),
            ("block mappings", block),
            (
                "lists and mappings",
                format!("{}x{}", "[{a: ".repeat(depth / 2), "}]".repeat(depth / 2)),
            ),
            ("aliases", chain),
        ]
    }

    #[test]
    fn nesting_is_followed_to_the_limit_and_refused_past_it() {
        for (name, doc) in nested(MAX_DEPTH) {
            assert!(to_json(&doc).is_ok(), "{name}: {:?}", to_json(&doc).err());
        }
        for (name, doc) in nested(MAX_DEPTH + 2) {
            let e = to_json(&doc).unwrap_err().to_string();
            assert!(
                e.starts_with(&format!("too deeply nested: more than {MAX_DEPTH} levels")),
                "{name}: {e}"
            );
        }
        for doc in [
            "[".repeat(100_000),
            "{a: ".repeat(100_000),
            "- ".repeat(100_000),
        ] {
            let started = Instant::now();
            assert!(to_json(&doc).is_err());
            assert!(started.elapsed() < hostile::DEADLINE);
        }
    }

    /// Reading recurses once per level, so the limit on depth is only as good as the stack behind
    /// it. A stack too small aborts the whole process; this runs the deepest documents allowed on
    /// a quarter of the stack the parser really gets, so the margin cannot erode unnoticed (a
    /// newer compiler or parser with larger frames fails here long before it fails for a user).
    #[test]
    fn the_deepest_document_fits_a_quarter_of_the_parser_stack() {
        let stack = PARSER_STACK_BYTES / 4;
        for (name, doc) in nested(MAX_DEPTH) {
            assert!(to_json_on_stack(&doc, stack).is_ok(), "{name}");
            // The same value met as an unknown field of a typed struct, which skips it.
            let inner = nested(MAX_DEPTH - 1)
                .into_iter()
                .find(|(n, _)| *n == name)
                .map(|(_, d)| d.replace('\n', "\n  "))
                .unwrap();
            let typed = format!("text: t\nunknown:\n  {inner}\n");
            assert_eq!(
                from_str_on_stack::<Typed>(&typed, stack).map(|t| t.text),
                Ok("t".to_owned()),
                "{name}"
            );
        }
    }

    #[test]
    fn a_panic_while_reading_comes_back_as_an_error() {
        #[derive(Debug)]
        struct Panics;
        impl<'de> Deserialize<'de> for Panics {
            fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
                panic!("deliberate, to prove a parser panic cannot take a scan down")
            }
        }
        assert_eq!(
            from_str::<Panics>("a: 1").unwrap_err().to_string(),
            "the YAML parser stopped unexpectedly"
        );
    }
}
