//! What a command line actually runs.
//!
//! Two checks need the same answer. An MCP server entry is a command and its arguments: is the
//! thing it starts a shell, a package fetched from a registry (and which one, at which version), a
//! container with the host mounted into it? And a permission entry such as `Bash(sh -c *)` is a
//! command with a hole in it: can the hole be filled with any program at all?
//!
//! Matching the first argument that does not start with `-` gets both wrong: `uvx --with dep==1.0
//! thing` runs `thing`, not `dep`; `npx -y --registry URL pkg@1.2.3` is pinned, and its registry
//! URL is not a package. So every runner here has its own table of the flags that take a value,
//! copied from that tool's `--help` (versions in the comments), and a wrapper such as `env` or
//! `cmd /c` is taken off before anything is judged.

/// Splits a command line into words the way a POSIX shell does: whitespace separates, single and
/// double quotes group, a backslash escapes the next character. Nothing is expanded.
pub(crate) fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                started = true;
                for n in chars.by_ref() {
                    if n == '\'' {
                        break;
                    }
                    word.push(n);
                }
            }
            '"' => {
                started = true;
                while let Some(n) = chars.next() {
                    match n {
                        '"' => break,
                        '\\' => word.extend(chars.next()),
                        _ => word.push(n),
                    }
                }
            }
            '\\' => {
                started = true;
                word.extend(chars.next());
            }
            c if c.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            c => {
                started = true;
                word.push(c);
            }
        }
    }
    if started {
        out.push(word);
    }
    out
}

/// A program as its name: the last path component (either separator), lower-cased, without a
/// Windows launcher suffix. `/usr/local/bin/npx`, `npx.cmd` and `C:\nodejs\NPX.EXE` are all `npx`.
pub(crate) fn program_name(command: &str) -> String {
    let base = command
        .trim()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    for suffix in [".exe", ".cmd", ".bat", ".ps1", ".com"] {
        if let Some(stem) = base.strip_suffix(suffix) {
            return stem.to_string();
        }
    }
    base
}

/// A command line with its wrappers taken off.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Launch {
    /// See [`program_name`].
    pub program: String,
    pub args: Vec<String>,
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The command a config entry starts, from its `command` and `args`.
///
/// - A `command` that is a whole command line (`"npx -y thing"`) is split into words.
/// - `env [NAME=value]… program …` and `cmd /c program …` (the documented way to start an
///   `npx` server on Windows) are wrappers: what they run is what counts.
pub(crate) fn launch(command: &str, args: &[String]) -> Launch {
    // A path with spaces in a directory name is one program; anything else with a space in its
    // last component is a command line.
    let mut tokens: Vec<String> = if program_name(command).contains(char::is_whitespace) {
        words(command)
    } else {
        vec![command.trim().to_string()]
    };
    tokens.extend(args.iter().cloned());

    // Wrappers can nest (`cmd /c env X=1 npx …`); a few rounds are plenty.
    for _ in 0..4 {
        let Some(first) = tokens.first() else { break };
        match program_name(first).as_str() {
            "env" => {
                let mut i = 1;
                while i < tokens.len() {
                    let t = &tokens[i];
                    if matches!(t.as_str(), "-u" | "--unset" | "-C" | "--chdir") {
                        i += 2;
                    } else if t.starts_with('-') || is_assignment(t) {
                        i += 1;
                    } else {
                        break;
                    }
                }
                if i >= tokens.len() {
                    break;
                }
                tokens.drain(..i);
            }
            "cmd" => {
                // `/c` or `/k` carries the command; other switches (`/d`, `/s`, `/q`) come first.
                let Some(carrier) = tokens
                    .iter()
                    .skip(1)
                    .position(|t| t.eq_ignore_ascii_case("/c") || t.eq_ignore_ascii_case("/k"))
                else {
                    break;
                };
                if !tokens[1..=carrier].iter().all(|t| t.starts_with('/')) {
                    break;
                }
                tokens.drain(..carrier + 2);
                // The rest may have been written as one string.
                if tokens.len() == 1 && tokens[0].contains(char::is_whitespace) {
                    tokens = words(&tokens[0]);
                }
                if tokens.is_empty() {
                    return Launch {
                        program: "cmd".to_string(),
                        args: Vec::new(),
                    };
                }
            }
            _ => break,
        }
    }
    let mut tokens = tokens.into_iter();
    Launch {
        program: tokens.next().map(|p| program_name(&p)).unwrap_or_default(),
        args: tokens.collect(),
    }
}

const POSIX_SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh",
];
const POWERSHELLS: &[&str] = &["pwsh", "powershell"];

/// If this launch hands a shell a command string to interpret (`bash -c …`, `sh -ec …`,
/// `zsh -lic …`, `pwsh -Command …`): how to describe it, and the string.
pub(crate) fn shell_command(launch: &Launch) -> Option<(String, &str)> {
    let program = launch.program.as_str();
    let position = if POSIX_SHELLS.contains(&program) {
        // A cluster of single-letter options with `c` among them: `-c`, `-lc`, `-ec`, `-ic`.
        launch.args.iter().position(|a| {
            a.len() >= 2
                && a.starts_with('-')
                && !a.starts_with("--")
                && a[1..].chars().all(|c| c.is_ascii_alphabetic())
                && a.contains('c')
        })?
    } else if POWERSHELLS.contains(&program) {
        // PowerShell takes any unambiguous prefix: `-c`, `-Command`, `-e`, `-EncodedCommand`.
        launch.args.iter().position(|a| {
            let lower = a.to_ascii_lowercase();
            lower.len() >= 2
                && (("-command".starts_with(&lower) && lower != "-")
                    || "-encodedcommand".starts_with(&lower))
        })?
    } else {
        return None;
    };
    let flag = &launch.args[position];
    Some((
        format!("{program} {flag}"),
        launch.args.get(position + 1).map_or("", String::as_str),
    ))
}

/// Which registry a package spec is read against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Registry {
    Npm,
    PyPi,
}

/// One tool that fetches a package and runs it, and how to read its command line.
struct Runner {
    /// Options followed by a value that is not the package.
    value_flags: &'static [&'static str],
    /// Options whose value names the package to install. When one is given, the first plain
    /// argument is a command inside that package, not a package.
    package_flags: &'static [&'static str],
    /// Options whose value is a command line to run; with no package option, its first word is
    /// the package.
    call_flags: &'static [&'static str],
    /// Options that mean the first plain argument is a local path, not a package.
    local_flags: &'static [&'static str],
    registry: Registry,
}

/// `npx` / `npm exec` / `npm x` (npm 10.9: `npm exec --help`, plus the npm settings that take a
/// value and are commonly given on an `npx` line). npm reads an option it does not know as a
/// switch, so anything not listed takes no value.
const NPM_EXEC: Runner = Runner {
    value_flags: &[
        "-w",
        "--workspace",
        "--registry",
        "--cache",
        "--prefix",
        "-C",
        "--userconfig",
        "--globalconfig",
        "--loglevel",
        "--node-options",
        "--node-arg",
        "--shell",
        "--script-shell",
        "--tag",
        "--otp",
        "--before",
        "--min-release-age",
        "--cafile",
        "--cert",
        "--key",
        "--proxy",
        "--https-proxy",
        "--noproxy",
        "--fetch-timeout",
        "--fetch-retries",
        "--maxsockets",
        "--scope",
        "--access",
        "--omit",
        "--include",
        "--location",
        "--user-agent",
        "--local-address",
    ],
    package_flags: &["-p", "--package"],
    call_flags: &["-c", "--call"],
    local_flags: &[],
    registry: Registry::Npm,
};

/// `bunx` / `bun x` (bun 1.4: `bunx --help`).
const BUNX: Runner = Runner {
    value_flags: &[
        "--cwd",
        "--env-file",
        "--minimum-release-age",
        "--registry",
        "--ca",
        "--cafile",
    ],
    package_flags: &["-p", "--package"],
    call_flags: &[],
    local_flags: &[],
    registry: Registry::Npm,
};

/// `pnpm dlx` / `pnpx` (pnpm 9.15: `pnpm help dlx`, plus pnpm's own options that take a value).
/// `-c` here is `--shell-mode`, a switch.
const PNPM_DLX: Runner = Runner {
    value_flags: &[
        "--reporter",
        "--registry",
        "-C",
        "--dir",
        "--filter",
        "--loglevel",
        "--store-dir",
        "--cache-dir",
        "--allow-build",
    ],
    package_flags: &["--package"],
    call_flags: &[],
    local_flags: &[],
    registry: Registry::Npm,
};

/// `yarn dlx` (yarn 4.5: `yarn dlx --help`).
const YARN_DLX: Runner = Runner {
    value_flags: &[],
    package_flags: &["-p", "--package"],
    call_flags: &[],
    local_flags: &[],
    registry: Registry::Npm,
};

/// `uvx` / `uv tool run` (uv 0.13: `uvx --help`). `--with` adds packages beside the tool; the
/// tool itself is `--from`, or else the command.
const UVX: Runner = Runner {
    value_flags: &[
        "-w",
        "--with",
        "--with-editable",
        "--with-requirements",
        "-c",
        "--constraints",
        "-b",
        "--build-constraints",
        "--overrides",
        "--env-file",
        "--python-platform",
        "--torch-backend",
        "--index",
        "--default-index",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--index-strategy",
        "--keyring-provider",
        "-P",
        "--upgrade-package",
        "--upgrade-group",
        "--resolution",
        "--prerelease",
        "--prerelease-package",
        "--fork-strategy",
        "--exclude-newer",
        "--exclude-newer-package",
        "--no-sources-package",
        "--reinstall-package",
        "--link-mode",
        "-C",
        "--config-setting",
        "--config-settings-package",
        "--no-build-isolation-package",
        "--no-build-package",
        "--no-binary-package",
        "--cache-dir",
        "--refresh-package",
        "-p",
        "--python",
        "--color",
        "--allow-insecure-host",
        "--directory",
        "--project",
        "--config-file",
    ],
    package_flags: &["--from"],
    call_flags: &[],
    local_flags: &[],
    registry: Registry::PyPi,
};

/// `pipx run` (pipx 1.18: `pipx run --help`).
const PIPX_RUN: Runner = Runner {
    value_flags: &[
        "--python-args",
        "--with",
        "--python",
        "--fetch-python",
        "-i",
        "--index-url",
        "--pip-args",
        "--cooldown",
        "--backend",
    ],
    package_flags: &["--spec"],
    call_flags: &[],
    local_flags: &["--path"],
    registry: Registry::PyPi,
};

/// uv's own options that take a value and may come before its subcommand.
const UV_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "--color",
    "--allow-insecure-host",
    "--directory",
    "--project",
    "--config-file",
    "--cache-dir",
];

/// Index of the first plain argument, stepping over options and the values of the options
/// `takes_value` names.
fn first_plain(args: &[String], takes_value: impl Fn(&str) -> bool) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if takes_value(a) {
            i += 2;
        } else if a.starts_with('-') && a.len() > 1 {
            i += 1;
        } else {
            return Some(i);
        }
    }
    None
}

impl Runner {
    /// Whether `flag`, written on its own, is followed by a value.
    fn takes_value(&self, flag: &str) -> bool {
        self.value_flags.contains(&flag)
            || self.package_flags.contains(&flag)
            || self.call_flags.contains(&flag)
    }

    /// The package specs this command line installs. Empty when it names none.
    fn packages(&self, args: &[String]) -> Vec<String> {
        let mut packages = Vec::new();
        let mut call = None;
        let mut plain = None;
        let mut local = false;
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if a == "--" {
                plain = args.get(i + 1);
                break;
            }
            if let Some((flag, value)) = a.split_once('=').filter(|_| a.starts_with('-')) {
                if self.package_flags.contains(&flag) {
                    packages.push(value.to_string());
                } else if self.call_flags.contains(&flag) {
                    call = Some(value.to_string());
                }
                i += 1;
            } else if self.package_flags.contains(&a) {
                packages.extend(args.get(i + 1).cloned());
                i += 2;
            } else if self.call_flags.contains(&a) {
                call = args.get(i + 1).cloned();
                i += 2;
            } else if self.value_flags.contains(&a) {
                i += 2;
            } else if a.starts_with('-') && a.len() > 1 {
                local |= self.local_flags.contains(&a);
                i += 1;
            } else {
                plain = Some(&args[i]);
                break;
            }
        }
        if packages.is_empty() && !local {
            match (plain, call) {
                (Some(p), _) => packages.push(p.clone()),
                (None, Some(c)) => packages.extend(words(&c).into_iter().next()),
                (None, None) => {}
            }
        }
        packages
    }
}

/// A registry package a command line runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Package {
    pub spec: String,
    pub registry: Registry,
}

/// If this launch fetches packages from a registry and runs them: the runner, as the user wrote
/// it (`npx`, `pnpm dlx`, `uv tool run`), and the packages. `None` for every other command,
/// including the same tools doing something else (`npm test`, `uv run script.py`).
pub(crate) fn runner_packages(launch: &Launch) -> Option<(&'static str, Vec<Package>)> {
    let args = launch.args.as_slice();
    // For a multi-purpose tool: its arguments with the subcommand words taken out, if the
    // subcommand is `words`. Options may come before the subcommand (`pnpm --package=x dlx y`), so
    // they are kept.
    let after = |runner: &Runner, words: &[&str]| -> Option<Vec<String>> {
        let takes_value =
            |flag: &str| runner.takes_value(flag) || UV_GLOBAL_VALUE_FLAGS.contains(&flag);
        let mut rest = args.to_vec();
        let mut from = 0;
        for word in words {
            let at = from + first_plain(&rest[from..], takes_value)?;
            if rest[at] != *word {
                return None;
            }
            rest.remove(at);
            from = at;
        }
        Some(rest)
    };
    let (name, runner, rest): (&'static str, &Runner, Vec<String>) = match launch.program.as_str() {
        "npx" => ("npx", &NPM_EXEC, args.to_vec()),
        "bunx" => ("bunx", &BUNX, args.to_vec()),
        "pnpx" => ("pnpx", &PNPM_DLX, args.to_vec()),
        "uvx" => ("uvx", &UVX, args.to_vec()),
        "npm" => (
            "npm exec",
            &NPM_EXEC,
            after(&NPM_EXEC, &["exec"]).or_else(|| after(&NPM_EXEC, &["x"]))?,
        ),
        "pnpm" => ("pnpm dlx", &PNPM_DLX, after(&PNPM_DLX, &["dlx"])?),
        "yarn" => ("yarn dlx", &YARN_DLX, after(&YARN_DLX, &["dlx"])?),
        "bun" => ("bun x", &BUNX, after(&BUNX, &["x"])?),
        "uv" => ("uv tool run", &UVX, after(&UVX, &["tool", "run"])?),
        "pipx" => ("pipx run", &PIPX_RUN, after(&PIPX_RUN, &["run"])?),
        _ => return None,
    };
    let packages = runner
        .packages(&rest)
        .into_iter()
        .map(|spec| Package {
            spec,
            registry: runner.registry,
        })
        .collect();
    Some((name, packages))
}

/// `MAJOR.MINOR.PATCH`, with an optional pre-release or build suffix: one build, not a range.
/// `1`, `1.2`, `^1.2.3`, `1.x`, `*` and a dist-tag such as `latest` all name a moving target.
fn exact_version(version: &str) -> bool {
    let version = version.strip_prefix('v').unwrap_or(version);
    let core = version.split(['-', '+']).next().unwrap_or("");
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() >= 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn is_local_path(spec: &str) -> bool {
    spec.starts_with(['.', '/', '~'])
        || spec.starts_with("file:")
        || spec.as_bytes().get(1) == Some(&b':') && spec.as_bytes().get(2) == Some(&b'\\')
}

/// A commit, written as 7 to 40 hex digits.
fn is_commit(reference: &str) -> bool {
    (7..=40).contains(&reference.len()) && reference.chars().all(|c| c.is_ascii_hexdigit())
}

/// An npm package spec as (name, version), where the version is whatever follows the name's `@`.
pub(crate) fn npm_name_version(spec: &str) -> (&str, Option<&str>) {
    let spec = spec.strip_prefix("npm:").unwrap_or(spec);
    let at = match spec.strip_prefix('@') {
        Some(rest) => rest.find('@').map(|i| i + 1),
        None => spec.find('@'),
    };
    match at {
        Some(i) => (&spec[..i], Some(&spec[i + 1..])),
        None => (spec, None),
    }
}

impl Package {
    /// Whether this spec names one fixed build. A local path is not fetched from anywhere and
    /// counts as fixed; a package with no version, a range, a dist-tag or a branch does not.
    pub(crate) fn is_pinned(&self) -> bool {
        let spec = self.spec.trim();
        if spec.is_empty() || is_local_path(spec) {
            return true;
        }
        match self.registry {
            Registry::Npm => {
                let from_git = spec.contains("://")
                    || ["github:", "gitlab:", "bitbucket:", "gist:", "git+", "git@"]
                        .iter()
                        .any(|p| spec.starts_with(p))
                    // `user/repo`, npm's GitHub shorthand.
                    || (!spec.starts_with('@') && spec.contains('/'));
                if from_git {
                    return spec.rsplit_once('#').is_some_and(|(_, r)| is_commit(r));
                }
                npm_name_version(spec).1.is_some_and(exact_version)
            }
            Registry::PyPi => {
                if spec.contains("://") {
                    // A built archive is one build; a repository is whatever its branch holds,
                    // unless a tag or a commit is named after the last `@`.
                    let archive = [".whl", ".tar.gz", ".zip"]
                        .iter()
                        .any(|ext| spec.split(['#', '?']).next().unwrap_or("").ends_with(ext));
                    let reference = spec
                        .rsplit_once('@')
                        .map(|(_, r)| r.split('#').next().unwrap_or(r))
                        .filter(|r| !r.contains('/'));
                    return archive
                        || reference.is_some_and(|r| r.chars().any(|c| c.is_ascii_digit()));
                }
                // Environment markers and extras are not part of the version.
                let requirement = spec.split(';').next().unwrap_or(spec).trim();
                if let Some((_, version)) = requirement.split_once("==") {
                    let version = version.trim_start_matches('=').trim();
                    return !version.is_empty() && !version.contains(['*', ',']);
                }
                // uvx's `name@version`.
                requirement.split_once('@').is_some_and(|(_, v)| {
                    v.starts_with(|c: char| c.is_ascii_digit()) && !v.contains('*')
                })
            }
        }
    }
}

/// The first three numbers of a version, for comparing. Range operators in front are ignored, so
/// `^0.1.30` reads as its lower bound.
pub(crate) fn version_numbers(version: &str) -> Option<(u64, u64, u64)> {
    let start = version.find(|c: char| c.is_ascii_digit())?;
    // Only operators may come before the first digit; `latest2` is a tag, not a version.
    if !version[..start]
        .chars()
        .all(|c| matches!(c, '^' | '~' | '>' | '<' | '=' | 'v' | ' '))
    {
        return None;
    }
    let mut numbers = version[start..]
        .split(|c: char| !c.is_ascii_digit())
        .take(3)
        .map(|n| n.parse::<u64>().unwrap_or(0));
    Some((
        numbers.next()?,
        numbers.next().unwrap_or(0),
        numbers.next().unwrap_or(0),
    ))
}

const CONTAINER_ENGINES: &[&str] = &["docker", "podman", "nerdctl"];

/// What a host path mounted into a container gives away, if anything.
fn host_path_risk(path: &str) -> Option<&'static str> {
    let path = path.trim().trim_matches(['"', '\'']);
    if ["docker.sock", "podman.sock", "containerd.sock"]
        .iter()
        .any(|sock| path.trim_end_matches('/').ends_with(sock))
    {
        Some("the Docker socket")
    } else if !path.is_empty() && path.chars().all(|c| c == '/') {
        Some("a root-filesystem mount")
    } else {
        None
    }
}

/// How a container command line reaches the host, if it does: `--privileged`, the container
/// engine's socket, or the host's root directory, mounted with `-v`, `--volume` or `--mount` in
/// any of the spellings the engine accepts (`-v X`, `-v=X`, `-vX`, `--volume=X`,
/// `--mount type=bind,source=X,…`).
pub(crate) fn container_host_access(launch: &Launch) -> Option<&'static str> {
    if !CONTAINER_ENGINES.contains(&launch.program.as_str()) {
        return None;
    }
    let args = &launch.args;
    for (i, a) in args.iter().enumerate() {
        let next = || args.get(i + 1).map(String::as_str);
        // The value of an option, attached with `=` or given as the next word.
        let value_of = |long: &str| -> Option<&str> {
            if a == long {
                next()
            } else {
                a.strip_prefix(long).and_then(|v| v.strip_prefix('='))
            }
        };
        if a == "--privileged"
            || a.strip_prefix("--privileged=")
                .is_some_and(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0"))
        {
            return Some("--privileged");
        }
        let volume = value_of("--volume").or_else(|| {
            if a == "-v" {
                next()
            } else if !a.starts_with("--") {
                a.strip_prefix("-v")
                    .map(|v| v.strip_prefix('=').unwrap_or(v))
            } else {
                None
            }
        });
        if let Some(spec) = volume {
            // `host:container[:options]`. A volume with no `:` is an anonymous volume.
            if let Some((host, _)) = spec.split_once(':') {
                if let Some(risk) = host_path_risk(host) {
                    return Some(risk);
                }
            }
        }
        if let Some(spec) = value_of("--mount") {
            let field = |names: &[&str]| {
                spec.split(',').find_map(|kv| {
                    kv.split_once('=')
                        .filter(|(k, _)| names.contains(&k.trim()))
                        .map(|(_, v)| v)
                })
            };
            // A named volume has a source too; only a bind mount's source is a host path.
            let bind = field(&["type"]).is_none_or(|t| t == "bind");
            if let Some(risk) = field(&["source", "src"])
                .filter(|s| bind && s.starts_with('/'))
                .and_then(host_path_risk)
            {
                return Some(risk);
            }
        }
    }
    None
}

/// Whether a directory handed to a filesystem server is a whole account, or more: `/`, a drive, a
/// home directory by any of its names (`~`, `$HOME`, `%USERPROFILE%`), the folder that holds
/// every home (`/home`, `/Users`), or any account's home root (`/home/alice`, `/Users/alice`,
/// `/root`, `C:\Users\alice`). A folder *inside* a home is a scoped choice. `home` is this
/// account's own home, wherever it is.
pub(crate) fn is_broad_root(arg: &str, home: Option<&str>) -> bool {
    let normal = |p: &str| {
        p.trim()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_string()
    };
    let arg = arg.trim().trim_matches(['"', '\'']);
    let path = normal(arg);
    if path.is_empty() {
        // Nothing but slashes.
        return !arg.is_empty();
    }
    let lower = path.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "~" | "$home"
            | "${home}"
            | "%userprofile%"
            | "%homepath%"
            | "$env:userprofile"
            | "$env:home"
            | "/home"
            | "/users"
            | "/root"
            | "/var/root"
    ) {
        return true;
    }
    // A drive root, and the same paths on a drive.
    let (drive, rest) = match path.as_bytes() {
        [d, b':', ..] if d.is_ascii_alphabetic() => (true, &path[2..]),
        _ => (false, path.as_str()),
    };
    if drive && rest.is_empty() {
        return true;
    }
    let account_home = ["/home/", "/Users/", "/users/"].iter().any(|parent| {
        rest.strip_prefix(parent)
            .is_some_and(|name| !name.is_empty() && !name.contains('/'))
    });
    account_home || home.is_some_and(|h| !normal(h).is_empty() && normal(h) == path)
}

const INTERPRETERS: &[&str] = &[
    "python",
    "python2",
    "python3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "osascript",
    "rscript",
];
const DOWNLOADERS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat"];
/// Commands that run the command they are given.
const WRAPPERS: &[&str] = &[
    "sudo", "doas", "env", "xargs", "exec", "eval", "nohup", "time", "timeout", "nice", "command",
    "builtin", "watch",
];
/// Two-word forms that run the command they are given.
const WRAPPER_PAIRS: &[(&str, &str)] = &[
    ("uv", "run"),
    ("pnpm", "exec"),
    ("yarn", "exec"),
    ("poetry", "run"),
    ("pipenv", "run"),
    ("bun", "run"),
    ("deno", "run"),
    ("deno", "eval"),
];

/// A program name for the lists above: [`program_name`], and `python3.12` as `python3`.
fn executor_name(word: &str) -> String {
    let name = program_name(word);
    let unversioned = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    for candidate in [name.as_str(), unversioned] {
        if [
            POSIX_SHELLS,
            POWERSHELLS,
            INTERPRETERS,
            DOWNLOADERS,
            WRAPPERS,
        ]
        .iter()
        .any(|list| list.contains(&candidate))
        {
            return candidate.to_string();
        }
    }
    // `python3.12` → `python3.` → `python3` is covered above; anything else stays as written.
    name
}

/// Whether a program is a general-purpose executor: a shell, an interpreter, a downloader, a
/// command that runs its arguments, a package runner, or `rm`. Allowing one by name allows
/// whatever is handed to it.
pub(crate) fn is_executor(word: &str) -> bool {
    let name = executor_name(word);
    let name = name.as_str();
    [
        POSIX_SHELLS,
        POWERSHELLS,
        INTERPRETERS,
        DOWNLOADERS,
        WRAPPERS,
    ]
    .iter()
    .any(|list| list.contains(&name))
        || matches!(name, "cmd" | "rm" | "npx" | "bunx" | "pnpx" | "uvx")
}

/// Whether a command whose fixed words are `fixed`, with anything allowed after them, can run any
/// program at all: `sh -c …`, `curl …`, `python3 -c …`, `npx …`, `sudo …`, `rm -rf …`.
///
/// What matters is whether the fixed words pin down *what runs*. `python -m pytest …` runs pytest;
/// `npx prettier …` runs prettier; `bash scripts/build.sh …` runs that script; `git …` and
/// `bulwarkctl scan …` are not executors to begin with. None of those is this finding. `bash -c …`
/// pins nothing.
pub(crate) fn admits_any_program(fixed: &[String]) -> bool {
    let mut words = fixed;
    // Each round takes one wrapper off the front.
    for _ in 0..8 {
        while words.first().is_some_and(|w| is_assignment(w)) {
            words = &words[1..];
        }
        let Some(first) = words.first() else {
            return true; // Nothing is fixed: any command at all.
        };
        let program = executor_name(first);
        let program = program.as_str();
        let rest = &words[1..];
        // The first word that is not an option. `cmd` writes its options with a slash.
        let is_option = |w: &String| w.starts_with('-') || (program == "cmd" && w.starts_with('/'));
        let pinned = rest.iter().position(|w| !is_option(w));

        if let Some(i) = pinned {
            if WRAPPER_PAIRS.contains(&(program, rest[i].as_str())) {
                // What follows the pair's own options is the command it runs.
                let after = &rest[i + 1..];
                let options = after.iter().take_while(|w| w.starts_with('-')).count();
                words = &after[options..];
                continue;
            }
        }
        if WRAPPERS.contains(&program) {
            match pinned {
                None => return true,
                Some(i) => {
                    words = &rest[i..];
                    continue;
                }
            }
        }
        if let Some((_, packages)) = runner_packages(&Launch {
            program: program.to_string(),
            args: rest.to_vec(),
        }) {
            return packages.is_empty();
        }
        if !is_executor(program) {
            return false;
        }
        if pinned.is_none() {
            return true;
        }
        // A word that is not an option is not always what the executor runs: it can be the value
        // of an option that comes before the part left open.
        if DOWNLOADERS.contains(&program) {
            // `curl -H 'X: y' …` and `curl -o out.txt …` fix a header and a file name; the address
            // is still anyone's. An address is fixed when a word is one (`https://…`), or when a
            // plain word follows another plain word or the program itself (`nc host 80`).
            let address = rest.iter().enumerate().any(|(i, w)| {
                !is_option(w) && (w.contains("://") || i == 0 || !is_option(&rest[i - 1]))
            });
            return !address;
        }
        // `bash -o pipefail -c …`, `python -W ignore -c …`: the last fixed word asks for code.
        let asks_for_code = rest.last().is_some_and(|last| {
            let shell = POSIX_SHELLS.contains(&program);
            (shell
                && last.len() >= 2
                && last.starts_with('-')
                && !last.starts_with("--")
                && last.contains('c'))
                || (!shell
                    && matches!(
                        last.as_str(),
                        "-c" | "-e"
                            | "-r"
                            | "-m"
                            | "-p"
                            | "--eval"
                            | "--print"
                            | "-Command"
                            | "-command"
                            | "/c"
                            | "/C"
                            | "/k"
                            | "/K"
                    ))
        });
        return asks_for_code;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn run(command: &str, list: &[&str]) -> Launch {
        launch(command, &args(list))
    }

    fn specs(command: &str, list: &[&str]) -> Option<(&'static str, Vec<String>)> {
        runner_packages(&run(command, list))
            .map(|(name, packages)| (name, packages.into_iter().map(|p| p.spec).collect()))
    }

    #[test]
    fn words_follow_shell_quoting() {
        assert_eq!(
            words(r#"bash -c "node x.js --flag" 'a b' c\ d"#),
            ["bash", "-c", "node x.js --flag", "a b", "c d"]
        );
        assert_eq!(words("  "), Vec::<String>::new());
        assert_eq!(words("a ''"), ["a", ""]);
    }

    #[test]
    fn a_program_is_known_by_its_name_wherever_it_is_installed() {
        for written in [
            "npx",
            "/usr/local/bin/npx",
            "npx.cmd",
            r"C:\Program Files\nodejs\NPX.CMD",
            "NPX.EXE",
        ] {
            assert_eq!(program_name(written), "npx", "{written}");
        }
    }

    #[test]
    fn wrappers_come_off() {
        // Windows: `cmd /c npx …` is how an npx server is started there.
        assert_eq!(
            run("cmd", &["/c", "npx", "-y", "thing"]),
            run("npx", &["-y", "thing"])
        );
        assert_eq!(
            run("cmd.exe", &["/d", "/s", "/C", "npx -y thing"]),
            run("npx", &["-y", "thing"])
        );
        assert_eq!(
            run("/usr/bin/env", &["-i", "FOO=1", "bash", "-c", "x"]),
            run("bash", &["-c", "x"])
        );
        // A command written as one string.
        assert_eq!(run("npx -y thing", &[]), run("npx", &["-y", "thing"]));
        assert_eq!(
            run("bash -c \"node x.js\"", &[]),
            run("bash", &["-c", "node x.js"])
        );
        // A path with a space in a directory is one program.
        assert_eq!(
            run(r"C:\Program Files\nodejs\npx.cmd", &["-y", "thing"]),
            run("npx", &["-y", "thing"])
        );
        // `cmd` with no command to run stays `cmd`.
        assert_eq!(run("cmd", &["/q"]).program, "cmd");
    }

    #[test]
    fn a_shell_given_a_command_string_is_recognised_in_every_spelling() {
        for (command, list) in [
            ("bash", vec!["-c", "x"]),
            ("bash", vec!["-lc", "npx -y thing"]),
            ("sh", vec!["-ec", "node x.js"]),
            ("zsh", vec!["-i", "-c", "node x.js"]),
            ("/usr/bin/env", vec!["bash", "-c", "node x.js"]),
            ("dash", vec!["-c", "x"]),
            ("fish", vec!["-c", "x"]),
            ("bash", vec!["--login", "-c", "x"]),
            ("pwsh", vec!["-Command", "node x.js"]),
            ("powershell.exe", vec!["-NoProfile", "-c", "node x.js"]),
            ("powershell", vec!["-EncodedCommand", "AAAA"]),
            ("bash -c \"node x.js\"", vec![]),
        ] {
            assert!(
                shell_command(&run(command, &list)).is_some(),
                "{command} {list:?}"
            );
        }
        for (command, list) in [
            ("bash", vec!["./start.sh"]),
            ("bash", vec!["--login", "./start.sh"]),
            ("node", vec!["-c", "x.js"]),
            ("pwsh", vec!["-File", "start.ps1"]),
            ("pwsh", vec!["-NoProfile", "-File", "x.ps1"]),
            // `cmd /c` is a launcher, not a script interpreter: what it starts is judged.
            ("cmd", vec!["/c", "node", "x.js"]),
        ] {
            assert!(
                shell_command(&run(command, &list)).is_none(),
                "{command} {list:?}"
            );
        }
        assert_eq!(
            shell_command(&run("bash", &["-lc", "npx -y thing"])),
            Some(("bash -lc".to_string(), "npx -y thing"))
        );
    }

    #[test]
    fn each_runner_finds_its_package_past_the_options_that_take_a_value() {
        for (command, list, runner, packages) in [
            ("npx", vec!["-y", "thing"], "npx", vec!["thing"]),
            (
                "npx",
                vec![
                    "-y",
                    "--registry",
                    "https://registry.example.invalid",
                    "thing@1.2.3",
                ],
                "npx",
                vec!["thing@1.2.3"],
            ),
            (
                "npx",
                vec!["--registry=https://r.invalid", "thing"],
                "npx",
                vec!["thing"],
            ),
            // With `-p`, the package is named there and the plain word is a command in it.
            (
                "npx",
                vec!["-p", "thing@1.0.0", "-c", "thing-bin"],
                "npx",
                vec!["thing@1.0.0"],
            ),
            (
                "npx",
                vec!["--package=a@1.0.0", "--package", "b", "cmd"],
                "npx",
                vec!["a@1.0.0", "b"],
            ),
            ("npx", vec!["-c", "cowsay hi"], "npx", vec!["cowsay"]),
            ("npx", vec!["--", "thing"], "npx", vec!["thing"]),
            (
                "npm",
                vec!["exec", "--yes", "thing"],
                "npm exec",
                vec!["thing"],
            ),
            (
                "npm",
                vec!["x", "--", "thing@1.0.0"],
                "npm exec",
                vec!["thing@1.0.0"],
            ),
            (
                "npm",
                vec!["--registry", "https://r.invalid", "exec", "thing"],
                "npm exec",
                vec!["thing"],
            ),
            (
                "pnpm",
                vec!["dlx", "@acme/thing@1.2.3"],
                "pnpm dlx",
                vec!["@acme/thing@1.2.3"],
            ),
            (
                "pnpm",
                vec!["--package", "thing", "dlx", "cmd"],
                "pnpm dlx",
                vec!["thing"],
            ),
            (
                "pnpm",
                vec!["--package=yo@4.3.1", "dlx", "yo"],
                "pnpm dlx",
                vec!["yo@4.3.1"],
            ),
            (
                "pnpm",
                vec!["dlx", "--package=thing@2.0.0", "cmd"],
                "pnpm dlx",
                vec!["thing@2.0.0"],
            ),
            ("pnpx", vec!["thing"], "pnpx", vec!["thing"]),
            (
                "yarn",
                vec!["dlx", "-p", "typescript", "-p", "ts-node", "ts-node"],
                "yarn dlx",
                vec!["typescript", "ts-node"],
            ),
            ("yarn", vec!["dlx", "thing"], "yarn dlx", vec!["thing"]),
            ("bunx", vec!["--bun", "thing"], "bunx", vec!["thing"]),
            (
                "bunx",
                vec![
                    "--registry",
                    "https://r.invalid",
                    "-p",
                    "@angular/cli",
                    "ng",
                ],
                "bunx",
                vec!["@angular/cli"],
            ),
            ("bun", vec!["x", "thing"], "bun x", vec!["thing"]),
            ("uvx", vec!["thing==1.0.0"], "uvx", vec!["thing==1.0.0"]),
            (
                "uvx",
                vec!["--with", "dep==1.0", "thing"],
                "uvx",
                vec!["thing"],
            ),
            (
                "uvx",
                vec!["--python", "3.12", "thing==1.0.0"],
                "uvx",
                vec!["thing==1.0.0"],
            ),
            (
                "uvx",
                vec!["--from", "git+https://github.com/acme/thing", "thing"],
                "uvx",
                vec!["git+https://github.com/acme/thing"],
            ),
            (
                "uvx",
                vec!["--from=thing==2.0.0", "thing"],
                "uvx",
                vec!["thing==2.0.0"],
            ),
            (
                "uv",
                vec!["tool", "run", "thing"],
                "uv tool run",
                vec!["thing"],
            ),
            (
                "uv",
                vec!["--directory", "/x", "tool", "run", "--with", "dep", "thing"],
                "uv tool run",
                vec!["thing"],
            ),
            (
                "pipx",
                vec!["run", "thing==1.0.0"],
                "pipx run",
                vec!["thing==1.0.0"],
            ),
            (
                "pipx",
                vec!["run", "--spec", "thing==1.0.0", "thing-bin"],
                "pipx run",
                vec!["thing==1.0.0"],
            ),
            (
                "pipx",
                vec![
                    "run",
                    "--python",
                    "3.12",
                    "--index-url",
                    "https://i.invalid",
                    "thing",
                ],
                "pipx run",
                vec!["thing"],
            ),
            // Windows wrappers and suffixes.
            (
                "cmd",
                vec!["/c", "npx", "-y", "thing"],
                "npx",
                vec!["thing"],
            ),
            ("npx.cmd", vec!["-y", "thing"], "npx", vec!["thing"]),
        ] {
            let expected: Vec<String> = packages.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                specs(command, &list),
                Some((runner, expected)),
                "{command} {list:?}"
            );
        }
        // The same tools doing something else are not runners.
        for (command, list) in [
            ("npm", vec!["test"]),
            ("npm", vec!["run", "build"]),
            ("pnpm", vec!["install"]),
            ("pnpm", vec!["exec", "tsc"]),
            ("yarn", vec!["install"]),
            ("bun", vec!["run", "x.ts"]),
            ("uv", vec!["run", "script.py"]),
            ("uv", vec!["tool", "install", "thing"]),
            ("pipx", vec!["install", "thing"]),
            ("node", vec!["server.js"]),
        ] {
            assert_eq!(specs(command, &list), None, "{command} {list:?}");
        }
        // A local path given to pipx is not a registry package.
        assert_eq!(
            specs("pipx", &["run", "--path", "./tool.py"]),
            Some(("pipx run", vec![]))
        );
        // Options only: nothing to run, nothing to judge.
        assert_eq!(specs("npx", &["-y"]), Some(("npx", vec![])));
    }

    #[test]
    fn only_an_exact_version_is_a_pin() {
        let npm = |spec: &str| Package {
            spec: spec.to_string(),
            registry: Registry::Npm,
        };
        let pypi = |spec: &str| Package {
            spec: spec.to_string(),
            registry: Registry::PyPi,
        };
        for pinned in [
            "thing@1.2.3",
            "@acme/thing@1.2.3",
            "@modelcontextprotocol/server-filesystem@2025.8.21",
            "thing@1.2.3-beta.1",
            "thing@v1.2.3",
            "github:acme/thing#0123456789abcdef0123456789abcdef01234567",
            "./local-server",
            "/opt/servers/thing",
            "file:../thing",
        ] {
            assert!(npm(pinned).is_pinned(), "{pinned}");
        }
        for floating in [
            "thing",
            "@acme/thing",
            "thing@latest",
            "thing@next",
            "thing@^1",
            "thing@^1.2.3",
            "thing@~1.2.3",
            "thing@*",
            "thing@1",
            "thing@1.2",
            "thing@1.x",
            "thing@>=1.0.0",
            "acme/thing",
            "github:acme/thing",
            "github:acme/thing#main",
            "git+https://github.com/acme/thing.git",
        ] {
            assert!(!npm(floating).is_pinned(), "{floating}");
        }
        for pinned in [
            "thing==1.0.0",
            "thing==1.0",
            "thing[extra]==2.3.4",
            "thing===1.0.0",
            "thing@0.3.0",
            "git+https://github.com/acme/thing@v1.2.3",
            "git+https://github.com/acme/thing@0123abc",
            "https://files.example.invalid/thing-1.0-py3-none-any.whl",
            "./tool",
        ] {
            assert!(pypi(pinned).is_pinned(), "{pinned}");
        }
        for floating in [
            "thing",
            "thing@latest",
            "thing>=1.0",
            "thing~=1.0",
            "thing==1.*",
            "thing>=1.0,==1.*",
            "thing[extra]",
            "git+https://github.com/acme/thing",
            "git+https://github.com/acme/thing@main",
            "git+https://git@github.com/acme/thing",
        ] {
            assert!(!pypi(floating).is_pinned(), "{floating}");
        }
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(version_numbers("0.1.30") > version_numbers("0.1.15"));
        assert!(version_numbers("0.1.9") < version_numbers("0.1.16"));
        assert_eq!(version_numbers("^0.1.30"), Some((0, 1, 30)));
        assert_eq!(version_numbers(">=1"), Some((1, 0, 0)));
        assert_eq!(version_numbers("v2.0.1-rc.1"), Some((2, 0, 1)));
        assert_eq!(version_numbers("latest"), None);
        assert_eq!(version_numbers("next-1"), None);
        assert_eq!(
            npm_name_version("@scope/pkg@1.2.3"),
            ("@scope/pkg", Some("1.2.3"))
        );
        assert_eq!(npm_name_version("@scope/pkg"), ("@scope/pkg", None));
        assert_eq!(npm_name_version("pkg@latest"), ("pkg", Some("latest")));
    }

    #[test]
    fn a_container_reaching_the_host_is_recognised_in_every_spelling() {
        for (list, what) in [
            (vec!["run", "--privileged", "img"], "--privileged"),
            (vec!["run", "--privileged=true", "img"], "--privileged"),
            (
                vec![
                    "run",
                    "-v",
                    "/var/run/docker.sock:/var/run/docker.sock",
                    "img",
                ],
                "the Docker socket",
            ),
            (
                vec![
                    "run",
                    "--volume=/var/run/docker.sock:/var/run/docker.sock",
                    "img",
                ],
                "the Docker socket",
            ),
            (
                vec!["run", "-v=/run/docker.sock:/x", "img"],
                "the Docker socket",
            ),
            (
                vec![
                    "run",
                    "--mount",
                    "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
                    "img",
                ],
                "the Docker socket",
            ),
            (
                vec![
                    "run",
                    "--mount=type=bind,src=/run/user/1000/podman/podman.sock,dst=/x",
                    "img",
                ],
                "the Docker socket",
            ),
            (
                vec!["run", "-v", "/:/host", "img"],
                "a root-filesystem mount",
            ),
            (vec!["run", "-v/:/host", "img"], "a root-filesystem mount"),
            (
                vec!["run", "-v=/:/host:ro", "img"],
                "a root-filesystem mount",
            ),
            (
                vec!["run", "--volume", "/:/host", "img"],
                "a root-filesystem mount",
            ),
            (
                vec!["run", "--mount", "type=bind,src=/,dst=/host", "img"],
                "a root-filesystem mount",
            ),
            (
                vec!["run", "--mount", "source=/,target=/host,type=bind", "img"],
                "a root-filesystem mount",
            ),
        ] {
            assert_eq!(
                container_host_access(&run("docker", &list)),
                Some(what),
                "{list:?}"
            );
        }
        for list in [
            vec!["run", "-v", "/home/u/proj:/work", "img"],
            vec!["run", "-v", "/workspace:/w:ro", "img"],
            vec!["run", "--privileged=false", "img"],
            vec![
                "run",
                "--mount",
                "type=volume,source=data,target=/data",
                "img",
            ],
            vec![
                "run",
                "--mount",
                "type=bind,source=/srv/app,target=/app",
                "img",
            ],
            vec!["run", "-v", "cache:/cache", "img"],
            vec!["run", "-i", "--rm", "acme/thing:1.0"],
            vec!["run", "--verbose", "img"],
        ] {
            assert_eq!(
                container_host_access(&run("docker", &list)),
                None,
                "{list:?}"
            );
        }
        assert!(container_host_access(&run("podman", &["run", "--privileged", "img"])).is_some());
        // Another program's `--privileged` is not this finding.
        assert!(container_host_access(&run("mytool", &["--privileged"])).is_none());
    }

    #[test]
    fn a_whole_account_is_a_broad_root_and_a_folder_inside_one_is_not() {
        let home = Some("/data/people/dev");
        for broad in [
            "/",
            "//",
            "~",
            "~/",
            "$HOME",
            "${HOME}",
            "$HOME/",
            "%USERPROFILE%",
            "/home",
            "/home/",
            "/Users",
            "/root",
            "/root/",
            "/home/dev",
            "/home/dev/",
            "/Users/alice",
            r"C:\Users\alice",
            r"C:\Users\alice\",
            "C:/Users/alice",
            r"C:\",
            "D:",
            "/data/people/dev",
            "/data/people/dev/",
        ] {
            assert!(is_broad_root(broad, home), "{broad}");
        }
        for scoped in [
            "/home/dev/Projects/app",
            "/home/dev/Projects",
            "~/Projects",
            "$HOME/src",
            "/Users/alice/Documents",
            r"C:\Users\alice\src",
            "/srv/app/home",
            "/var/www",
            "/data/people/dev/work",
            "/data/people",
            ".",
            "./data",
            "",
            "/opt/homebrew",
            "/rooted",
        ] {
            assert!(!is_broad_root(scoped, home), "{scoped}");
        }
        assert!(!is_broad_root("/data/people/dev", None));
    }

    #[test]
    fn an_open_executor_admits_any_program_and_a_pinned_one_does_not() {
        for open in [
            vec![],
            vec!["curl"],
            vec!["curl", "-s"],
            vec!["wget"],
            vec!["sh", "-c"],
            vec!["bash", "-c"],
            vec!["bash", "-lc"],
            vec!["/bin/bash"],
            vec!["zsh"],
            vec!["python"],
            vec!["python3", "-c"],
            vec!["python3.12"],
            vec!["python", "-m"],
            vec!["node"],
            vec!["node", "-e"],
            vec!["deno"],
            vec!["deno", "run"],
            vec!["deno", "run", "-A"],
            vec!["deno", "eval"],
            vec!["bun"],
            vec!["bun", "run"],
            vec!["bun", "x"],
            vec!["rm"],
            vec!["rm", "-rf"],
            vec!["sudo"],
            vec!["sudo", "-n"],
            vec!["sudo", "bash", "-c"],
            vec!["env"],
            vec!["env", "FOO=1", "sh", "-c"],
            vec!["FOO=1", "bash"],
            vec!["xargs"],
            vec!["xargs", "sh", "-c"],
            vec!["eval"],
            vec!["npx"],
            vec!["npx", "-y"],
            vec!["npm", "exec"],
            vec!["npm", "exec", "--yes"],
            vec!["pnpm", "dlx"],
            vec!["uvx"],
            vec!["uv", "run"],
            vec!["uv", "tool", "run"],
            vec!["pipx", "run"],
            vec!["cmd", "/c"],
            vec!["powershell", "-Command"],
            // An option's value is not what runs.
            vec!["curl", "-H", "X-Token=abc"],
            vec!["curl", "-o", "out.txt"],
            vec!["bash", "-o", "pipefail", "-c"],
            vec!["python", "-W", "ignore", "-c"],
            vec!["node", "--require", "./hook.js", "-e"],
        ] {
            assert!(admits_any_program(&args(&open)), "{open:?}");
        }
        for scoped in [
            vec!["git"],
            vec!["git", "log"],
            vec!["npm", "test"],
            vec!["npm", "run", "test"],
            vec!["npm"],
            vec!["bulwarkctl", "ai", "scan"],
            vec!["bulwarkctl", "fix", "list"],
            vec!["ls"],
            vec!["cargo", "test"],
            vec!["python", "-m", "pytest"],
            vec!["python3", "manage.py", "test"],
            vec!["bash", "scripts/build.sh"],
            vec!["node", "server.js"],
            vec!["curl", "https://api.example.com/"],
            vec!["curl", "-s", "https://api.example.com/"],
            vec![
                "curl",
                "-H",
                "Accept: text/plain",
                "https://api.example.com/",
            ],
            vec!["nc", "localhost", "8080"],
            vec!["bash", "-o", "pipefail", "scripts/build.sh"],
            vec!["rm", "-rf", "node_modules"],
            vec!["npx", "prettier"],
            vec!["npx", "-y", "tsc"],
            vec!["npm", "exec", "eslint"],
            vec!["uvx", "ruff"],
            vec!["uv", "run", "pytest"],
            vec!["sudo", "apt-get", "update"],
            vec!["env", "CI=1", "cargo", "test"],
            vec!["bun", "test"],
            vec!["bun", "run", "test"],
            vec!["deno", "fmt"],
            vec!["deno", "run", "main.ts"],
            vec!["docker", "ps"],
        ] {
            assert!(!admits_any_program(&args(&scoped)), "{scoped:?}");
        }
    }
}
