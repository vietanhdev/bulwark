use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct LoginDefsCollector;

/// One file in `login.defs` format: where it is and what it says.
pub(crate) struct DefsFile {
    pub path: String,
    pub text: String,
}

/// A value in force and the file whose line set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Setting {
    pub raw: String,
    pub file: String,
}

/// What the login tools end up with after reading every file, in order.
#[derive(Debug, Default)]
pub(crate) struct Settings {
    values: BTreeMap<String, Setting>,
    /// Keys whose value cannot be known, with the file and the reason.
    unclear: BTreeMap<String, (String, String)>,
}

impl Settings {
    pub(crate) fn get(&self, key: &str) -> Option<&Setting> {
        self.values.get(key)
    }

    /// The number in force for `key`: `None` when no file sets it, or sets something that is not a
    /// whole number (the tools then use their default).
    pub(crate) fn number(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|s| s.raw.parse::<i64>().ok())
    }
}

/// Applies `files` in order, the way shadow-utils does (see [`crate::etc`] for how each rule was
/// measured).
///
/// * Without libeconf (Debian, Ubuntu) there is one file, every line is read, and the **last** line
///   for a key wins. The value is the rest of the line, so `30 # x` is not a number.
/// * With libeconf (openSUSE, Fedora) a `#` anywhere starts a comment, the **first** line for a key
///   wins within one file, and each later file (the drop-ins) overrides the earlier ones key by
///   key. A drop-in that sets one key twice with different values is the one case the versions
///   disagree on (libeconf 0.7 keeps the last, 0.8 the first), so that key is left unclear.
pub(crate) fn read_settings(files: &[DefsFile], econf: bool) -> Settings {
    let mut settings = Settings::default();
    for (index, file) in files.iter().enumerate() {
        let mut in_file: BTreeMap<String, String> = BTreeMap::new();
        let mut conflicting: Vec<String> = Vec::new();
        for line in file.text.lines() {
            let mut line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if econf {
                line = line.split('#').next().unwrap_or_default().trim_end();
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let key = parts.next().unwrap_or_default();
            let value = parts.next().unwrap_or_default().trim();
            if value.is_empty() {
                continue;
            }
            match in_file.get(key).cloned() {
                Some(earlier) if econf => {
                    if earlier != value && !conflicting.iter().any(|k| k == key) {
                        conflicting.push(key.to_string());
                    }
                }
                _ => {
                    in_file.insert(key.to_string(), value.to_string());
                }
            }
        }
        let drop_in = econf && index > 0;
        for (key, raw) in in_file {
            if drop_in && conflicting.contains(&key) {
                settings.values.remove(&key);
                settings.unclear.insert(
                    key.clone(),
                    (
                        file.path.clone(),
                        format!(
                            "{} sets {key} more than once, to different values, and versions of \
                             the login tools disagree on which one counts. Keep one line",
                            file.path
                        ),
                    ),
                );
                continue;
            }
            settings.unclear.remove(&key);
            settings.values.insert(
                key,
                Setting {
                    raw,
                    file: file.path.clone(),
                },
            );
        }
    }
    settings
}

/// What the `<key>_from` fact says when no file sets a password age.
const NOT_SET: &str = "no file: it is not set, which means no limit";

/// Turns what the login tools read into the facts the rules use: password aging, plus two
/// presence-only settings (`SHA_CRYPT_MIN_ROUNDS`, `UMASK`) that Debian/Ubuntu leave commented out
/// by default. A rule reading a numeric threshold on either would hit `MissingField` on most real
/// systems (a noisy collector_error every scan, not a real "misconfigured" reading), so instead of
/// numeric fields, these two are always-present booleans (`..._configured`) — "left at the distro
/// default" is itself the finding, and a boolean field can never be missing.
///
/// `umask_via_pam` folds in whether `pam_umask` is active in the PAM configuration (see
/// [`pam_configures_umask`]): on modern Debian/Ubuntu the default umask is set through PAM, not an
/// explicit `UMASK` line, so treating a missing `login.defs` UMASK as "unconfigured" without
/// checking PAM is a false positive. `umask_configured` is therefore true when *either* source sets
/// it.
///
/// `pass_max_days_from` and `pass_min_days_from` name the file that set each value, so a finding
/// says where to change it; `config_file` is the main file in use.
fn build_fact(settings: &Settings, main: &str, umask_via_pam: bool) -> Fact {
    let mut fact = Fact::new();
    fact.insert("config_file".to_string(), Value::from(main));
    fact.insert(
        "sha_crypt_min_rounds_configured".to_string(),
        Value::Bool(settings.get("SHA_CRYPT_MIN_ROUNDS").is_some()),
    );
    fact.insert(
        "umask_configured".to_string(),
        Value::Bool(umask_via_pam || settings.get("UMASK").is_some()),
    );
    // Which crypt scheme new passwords use. SHA_CRYPT_MIN_ROUNDS only has any effect under the
    // sha256/sha512 schemes; under yescrypt or bcrypt (the modern Debian/Ubuntu default) it is
    // silently ignored, so a rule about it must not fire. Absent means "distro default", which on
    // current systems is yescrypt — so default to a method for which sha-crypt rounds do not apply.
    let encrypt_method = settings
        .get("ENCRYPT_METHOD")
        .map(|s| s.raw.to_ascii_lowercase())
        .unwrap_or_else(|| "unset".to_string());

    // Why a value is not known, with the file that holds the line.
    let mut unclear: Vec<(&str, String, String)> = Vec::new();
    for key in [
        "PASS_MAX_DAYS",
        "PASS_MIN_DAYS",
        "PASS_WARN_AGE",
        "PASS_MIN_LEN",
    ] {
        let field = key.to_ascii_lowercase();
        if let Some((file, reason)) = settings.unclear.get(key) {
            unclear.push((key, file.clone(), reason.clone()));
            continue;
        }
        let Some(setting) = settings.get(key) else {
            continue;
        };
        if let Ok(n) = setting.raw.parse::<i64>() {
            fact.insert(field.clone(), Value::from(n));
            fact.insert(format!("{field}_from"), Value::from(setting.file.as_str()));
        } else if number_then_comment(&setting.raw) {
            // `PASS_MAX_DAYS 30 # x` read without libeconf: what this means depends on the
            // shadow-utils installed. Measured with `useradd` and `/etc/shadow`: 4.13 (Ubuntu 24.04)
            // prints "cannot parse PASS_MAX_DAYS value" and applies no limit at all, while 4.18
            // (Fedora 43, through libeconf) reads 30. Neither answer is safe to assume, so the value
            // is left out and the rule that reads it reports the line.
            unclear.push((
                key,
                setting.file.clone(),
                format!(
                    "the {key} line has a comment after its number; older versions of the login \
                     tools then ignore the whole line and newer ones read the number, so the value \
                     in effect is not known. Move the comment to a line of its own"
                ),
            ));
        }
        // Anything else (`7 8`, a word) is rejected by every version, which then uses the default:
        // handled below like a missing line.
    }
    // A missing or negative PASS_MAX_DAYS / PASS_MIN_DAYS means "no limit": login.defs(5) says -1
    // is assumed when the line is absent, and that it disables the restriction. Arch ships neither
    // line, and a rule comparing a number that was not there reported a condition error on every
    // scan instead of the plain answer. Store what the system does: passwords never expire (the
    // 99999 other distributions write for the same thing), no minimum age.
    for (key, no_limit) in [("PASS_MAX_DAYS", 99_999), ("PASS_MIN_DAYS", 0)] {
        let field = key.to_ascii_lowercase();
        let limited = fact
            .get(&field)
            .and_then(Value::as_i64)
            .is_some_and(|n| n >= 0);
        if !limited && !unclear.iter().any(|(k, _, _)| *k == key) {
            fact.insert(field.clone(), Value::from(no_limit));
            fact.entry(format!("{field}_from"))
                .or_insert_with(|| Value::from(NOT_SET));
        }
    }
    if !unclear.is_empty() {
        // The row says why a value is missing, so the scan shows one plain line for this file
        // instead of a bare "missing field" (see `homefs::COULD_NOT_READ`).
        fact.insert("path".to_string(), Value::from(unclear[0].1.as_str()));
        let reasons: Vec<String> = unclear.into_iter().map(|(_, _, reason)| reason).collect();
        fact.insert(
            crate::homefs::COULD_NOT_READ.to_string(),
            Value::from(reasons.join("; ")),
        );
    }
    // SHA_CRYPT_MIN_ROUNDS is actionable only when the hashing scheme actually consults it.
    let sha_crypt_applies = matches!(encrypt_method.as_str(), "sha256" | "sha512");
    fact.insert("encrypt_method".to_string(), Value::from(encrypt_method));
    fact.insert(
        "sha_crypt_applies".to_string(),
        Value::Bool(sha_crypt_applies),
    );
    fact
}

/// `30 # x`, `30\t#x`, `30#x`: a whole number followed by a `#` comment.
fn number_then_comment(value: &str) -> bool {
    match value.split_once('#') {
        Some((number, _)) => number.trim().parse::<i64>().is_ok(),
        None => false,
    }
}

/// Reads the files that make up `login.defs` on this system, in the order they apply.
pub(crate) fn read_files(files: &crate::etc::LoginDefsFiles) -> anyhow::Result<Vec<DefsFile>> {
    std::iter::once(&files.main)
        .chain(&files.drop_ins)
        .map(|path| {
            Ok(DefsFile {
                path: path.display().to_string(),
                text: crate::etc::read_config_file(path)?,
            })
        })
        .collect()
}

/// True if any active (uncommented) line across the PAM service files in effect pulls in
/// `pam_umask` — the mechanism that sets the default umask on modern Debian/Ubuntu (and on
/// openSUSE, from `/usr/lib/pam.d/common-session`), where `login.defs` carries no explicit `UMASK`.
fn pam_configures_umask(files: &[PathBuf]) -> bool {
    files.iter().any(|path| {
        std::fs::read_to_string(path).is_ok_and(|text| {
            text.lines()
                .map(str::trim)
                .any(|l| !l.starts_with('#') && l.contains("pam_umask"))
        })
    })
}

impl Collector for LoginDefsCollector {
    fn name(&self) -> &'static str {
        "login_defs"
    }

    /// `/etc/login.defs`, or the vendor's copy in `/usr/etc` on a system that has no `/etc` one
    /// (see [`crate::etc`]).
    fn is_applicable(&self) -> bool {
        crate::etc::LOGIN_DEFS.in_use().is_some()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let files = crate::etc::login_defs_files()?
            .ok_or_else(|| anyhow::anyhow!("no login.defs: it was removed during the scan"))?;
        let settings = read_settings(&read_files(&files)?, files.econf);
        let umask_via_pam = pam_configures_umask(&crate::etc::pam_service_files());
        Ok(vec![build_fact(
            &settings,
            &files.main.display().to_string(),
            umask_via_pam,
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> DefsFile {
        DefsFile {
            path: path.to_string(),
            text: text.to_string(),
        }
    }

    /// One `/etc/login.defs`, read the way shadow-utils without libeconf reads it.
    fn parse_login_defs(text: &str) -> Fact {
        build_with_pam(text, false)
    }

    fn build_with_pam(text: &str, umask_via_pam: bool) -> Fact {
        let settings = read_settings(&[file("/etc/login.defs", text)], false);
        build_fact(&settings, "/etc/login.defs", umask_via_pam)
    }

    /// Files read the way shadow-utils with libeconf reads them; the first is the main file.
    fn econf(files: &[(&str, &str)]) -> Fact {
        let files: Vec<DefsFile> = files.iter().map(|(p, t)| file(p, t)).collect();
        build_fact(&read_settings(&files, true), &files[0].path, false)
    }

    #[test]
    fn parses_password_aging_fields() {
        let text = "# comment\nPASS_MAX_DAYS\t99999\nPASS_MIN_LEN\t8\n";
        let fact = parse_login_defs(text);
        assert_eq!(fact.get("pass_max_days").unwrap(), &Value::from(99999));
        assert_eq!(fact.get("pass_min_len").unwrap(), &Value::from(8));
    }

    #[test]
    fn absent_password_ages_mean_no_limit_not_a_missing_value() {
        // Arch's stock login.defs has neither line. login.defs(5): -1 is assumed, which disables
        // the restriction. The rules compare numbers, so the fact must carry what the system does.
        let arch = parse_login_defs("PASS_MIN_LEN\t5\nENCRYPT_METHOD YESCRYPT\n");
        assert_eq!(arch.get("pass_max_days").unwrap(), &Value::from(99_999));
        assert_eq!(arch.get("pass_min_days").unwrap(), &Value::from(0));
        // Written out as -1, the same thing.
        let explicit = parse_login_defs("PASS_MAX_DAYS -1\nPASS_MIN_DAYS -1\n");
        assert_eq!(explicit.get("pass_max_days").unwrap(), &Value::from(99_999));
        assert_eq!(explicit.get("pass_min_days").unwrap(), &Value::from(0));
        // A real limit is kept as written.
        let set = parse_login_defs("PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\n");
        assert_eq!(set.get("pass_max_days").unwrap(), &Value::from(90));
        assert_eq!(set.get("pass_min_days").unwrap(), &Value::from(1));
    }

    #[test]
    fn sha_crypt_and_umask_default_to_not_configured() {
        // The real, distro-default case (verified absent on this project's own dev machine)
        // — must read as a defined `false`, never as a missing field a rule would error on.
        let fact = parse_login_defs("PASS_MAX_DAYS\t99999\n");
        assert_eq!(
            fact.get("sha_crypt_min_rounds_configured").unwrap(),
            &Value::Bool(false)
        );
        assert_eq!(fact.get("umask_configured").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn detects_sha_crypt_and_umask_when_present() {
        let text = "SHA_CRYPT_MIN_ROUNDS\t5000\nUMASK\t027\n";
        let fact = parse_login_defs(text);
        assert_eq!(
            fact.get("sha_crypt_min_rounds_configured").unwrap(),
            &Value::Bool(true)
        );
        assert_eq!(fact.get("umask_configured").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn sha_crypt_applies_only_under_sha_schemes() {
        // yescrypt (the modern default): SHA_CRYPT_MIN_ROUNDS is ignored, so the rule must not fire.
        let yescrypt = parse_login_defs("ENCRYPT_METHOD YESCRYPT\n");
        assert_eq!(
            yescrypt.get("sha_crypt_applies").unwrap(),
            &Value::Bool(false)
        );
        assert_eq!(
            yescrypt.get("encrypt_method").unwrap(),
            &Value::from("yescrypt")
        );

        // Absent ENCRYPT_METHOD → distro default is yescrypt today; do not flag (avoid the FP).
        let unset = parse_login_defs("PASS_MAX_DAYS 99999\n");
        assert_eq!(unset.get("sha_crypt_applies").unwrap(), &Value::Bool(false));

        // sha512: the one case where SHA_CRYPT_MIN_ROUNDS is actionable.
        let sha = parse_login_defs("ENCRYPT_METHOD SHA512\n");
        assert_eq!(sha.get("sha_crypt_applies").unwrap(), &Value::Bool(true));
        // And with it unset, the rule's precondition (applies && !configured) holds.
        assert_eq!(
            sha.get("sha_crypt_min_rounds_configured").unwrap(),
            &Value::Bool(false)
        );
    }

    #[test]
    fn pam_umask_counts_as_configured_even_without_a_login_defs_line() {
        // No UMASK in login.defs, but pam_umask is active → umask IS configured (not a finding).
        let fact = build_with_pam("PASS_MAX_DAYS 99999\n", /*umask_via_pam=*/ true);
        assert_eq!(fact.get("umask_configured").unwrap(), &Value::Bool(true));
        // Neither source configures it → the finding stands.
        let bare = build_with_pam("PASS_MAX_DAYS 99999\n", false);
        assert_eq!(bare.get("umask_configured").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn pam_configures_umask_reads_a_real_pam_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("common-session"),
            "session optional pam_umask.so\n",
        )
        .unwrap();
        assert!(pam_configures_umask(&[dir.path().join("common-session")]));

        // A commented-out reference does not count.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::write(
            dir2.path().join("common-session"),
            "# session pam_umask.so\n",
        )
        .unwrap();
        assert!(!pam_configures_umask(&[dir2.path().join("common-session")]));
    }

    /// The benign side of the libeconf work: a stock Debian file reads exactly as before, the last
    /// line for a key still wins, and `30 # x` is still reported as unclear.
    #[test]
    fn without_libeconf_the_last_line_wins_and_a_trailing_comment_is_unclear() {
        let fact = parse_login_defs("PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 30\nPASS_MIN_DAYS 0\n");
        assert_eq!(fact["pass_max_days"], 30);
        assert_eq!(fact["pass_max_days_from"], "/etc/login.defs");
        assert_eq!(fact["pass_min_days"], 0);
        assert!(!fact.contains_key(crate::homefs::COULD_NOT_READ));

        let fact = parse_login_defs("PASS_MAX_DAYS 30 # monthly\n");
        assert!(!fact.contains_key("pass_max_days"));
        assert_eq!(fact["path"], "/etc/login.defs");
        assert!(fact[crate::homefs::COULD_NOT_READ]
            .as_str()
            .unwrap()
            .contains("PASS_MAX_DAYS"));
    }

    /// Measured on Tumbleweed, Leap 16 and Fedora 44 with `useradd` and the fields it writes:
    /// within one file the first line wins, a `#` anywhere is a comment, a later drop-in overrides.
    #[test]
    fn with_libeconf_the_first_line_wins_and_drop_ins_override_key_by_key() {
        let fact = econf(&[(
            "/etc/login.defs",
            "PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 30\nPASS_MIN_DAYS 1 # a day\n",
        )]);
        assert_eq!(fact["pass_max_days"], 99999);
        assert_eq!(fact["pass_min_days"], 1);
        assert!(!fact.contains_key(crate::homefs::COULD_NOT_READ));

        let fact = econf(&[
            ("/usr/etc/login.defs", "PASS_MAX_DAYS 99999\nUMASK 022\n"),
            (
                "/usr/etc/login.defs.d/50-vendor.defs",
                "PASS_MAX_DAYS 120\n",
            ),
            ("/etc/login.defs.d/90-site.defs", "PASS_MIN_DAYS 2\n"),
        ]);
        assert_eq!(fact["config_file"], "/usr/etc/login.defs");
        assert_eq!(fact["pass_max_days"], 120);
        assert_eq!(
            fact["pass_max_days_from"],
            "/usr/etc/login.defs.d/50-vendor.defs"
        );
        assert_eq!(fact["pass_min_days"], 2);
        assert_eq!(fact["pass_min_days_from"], "/etc/login.defs.d/90-site.defs");
        assert_eq!(fact["umask_configured"], true);
    }

    #[test]
    fn a_drop_in_that_sets_a_key_twice_differently_is_unclear_until_a_later_file_sets_it() {
        // libeconf 0.7 (Leap 16) keeps the last of the two, 0.8 (Tumbleweed) the first.
        let fact = econf(&[
            ("/usr/etc/login.defs", "PASS_MAX_DAYS 99999\n"),
            (
                "/etc/login.defs.d/50-x.defs",
                "PASS_MAX_DAYS 10\nPASS_MAX_DAYS 20\nPASS_MIN_DAYS 1\nPASS_MIN_DAYS 1\n",
            ),
        ]);
        assert!(!fact.contains_key("pass_max_days"));
        assert_eq!(fact["path"], "/etc/login.defs.d/50-x.defs");
        assert_eq!(
            fact["pass_min_days"], 1,
            "the same value twice is no conflict"
        );

        let fact = econf(&[
            ("/usr/etc/login.defs", ""),
            (
                "/etc/login.defs.d/50-x.defs",
                "PASS_MAX_DAYS 10\nPASS_MAX_DAYS 20\n",
            ),
            ("/etc/login.defs.d/60-y.defs", "PASS_MAX_DAYS 60\n"),
        ]);
        assert_eq!(fact["pass_max_days"], 60);
        assert!(!fact.contains_key(crate::homefs::COULD_NOT_READ));
    }

    #[test]
    fn an_unset_password_age_names_no_file() {
        // Tumbleweed's vendor login.defs sets neither.
        let fact = econf(&[("/usr/etc/login.defs", "ENCRYPT_METHOD SHA512\n")]);
        assert_eq!(fact["pass_max_days"], 99_999);
        assert_eq!(fact["pass_max_days_from"], NOT_SET);
        assert_eq!(fact["pass_min_days_from"], NOT_SET);
    }
}
