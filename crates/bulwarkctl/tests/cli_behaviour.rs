//! How the CLI behaves at its edges, driven through the real binary: a reader that goes away, a
//! folder it was merely pointed at, input that holds nothing, a path that isn't there. Each of
//! these once ended in a panic, a changed folder, a check mark or "0 valid" with exit code 0.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The binary, with a private home so nothing reads or writes the developer's own state.
fn bulwarkctl(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bulwarkctl"));
    c.env("HOME", home)
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("BULWARK_DB_PATH")
        .env_remove("BULWARK_RULES_DIR")
        .env_remove("SUDO_USER")
        .env_remove("PKEXEC_UID")
        .env("LC_ALL", "C.UTF-8");
    c
}

fn text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

fn mode_of(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

/// `bulwarkctl rules list | head -1` printed `thread 'main' panicked … Broken pipe` and exited
/// 101. The reader here has already gone before the first byte is written, which is the same
/// thing without the race: every command must end by the pipe signal, quietly.
#[test]
fn a_closed_pipe_ends_the_command_quietly() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        &["rules", "list"][..],
        &["fix", "list"],
        &["fix", "all"],
        &["scan", "--json", "--no-persist"],
    ] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let out = bulwarkctl(home.path())
            .args(args)
            .stdout(Stdio::from(writer))
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stderr.contains("panicked"),
            "{args:?} panicked on a closed pipe:\n{stderr}"
        );
        assert_ne!(out.status.code(), Some(101), "{args:?}: {stderr}");
        assert_eq!(
            out.status.signal(),
            Some(13),
            "{args:?} should end the way any tool does when its reader leaves (SIGPIPE), \
             got {:?}\n{stderr}",
            out.status
        );
    }
}

/// The same through a real reader that takes one line and exits, as `| head -1` does. The exit
/// status depends on who is faster, so only the panic is asserted.
#[test]
fn piping_into_a_reader_that_exits_early_never_panics() {
    let home = tempfile::tempdir().unwrap();
    let mut child = bulwarkctl(home.path())
        .args(["rules", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::{BufRead, BufReader};
        let mut first = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut first)
            .unwrap();
        assert!(
            first.contains("BLWK-"),
            "expected a rule line, got {first:?}"
        );
        // The reader is dropped here, with most of the list unread.
    }
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert_ne!(out.status.code(), Some(101), "{stderr}");
}

/// `--db-path /tmp/scan.db` turned `/tmp` into 0700, and `--db-path ./scan.db` did it to the
/// project folder. A folder that was already there keeps its mode; the database is owner-only.
#[test]
fn db_path_does_not_change_the_folder_the_database_is_put_in() {
    let home = tempfile::tempdir().unwrap();
    let shared = home.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
    let project = home.path().join("project");
    fs::create_dir(&project).unwrap();
    fs::set_permissions(&project, fs::Permissions::from_mode(0o755)).unwrap();

    let out = bulwarkctl(home.path())
        .args(["history", "--db-path"])
        .arg(shared.join("scan.db"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    // `history` on a database that isn't there creates nothing; a command that writes does.
    let out = bulwarkctl(home.path())
        .args(["rules", "suppressions", "--db-path"])
        .arg(shared.join("scan.db"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let out = bulwarkctl(home.path())
        .args(["notify", "status", "--db-path"])
        .arg(shared.join("scan.db"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(shared.join("scan.db").exists(), "the database was created");
    assert_eq!(mode_of(&shared), 0o1777, "a shared folder keeps its mode");
    assert_eq!(mode_of(&shared.join("scan.db")), 0o600);

    // A relative path, from inside the folder.
    let out = bulwarkctl(home.path())
        .current_dir(&project)
        .args(["notify", "status", "--db-path", "./scan.db"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        mode_of(&project),
        0o755,
        "the project folder keeps its mode"
    );
    assert_eq!(mode_of(&project.join("scan.db")), 0o600);

    // The default location is Bulwark's own folder, and that one is still locked down.
    let out = bulwarkctl(home.path())
        .args(["notify", "status"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let own = home.path().join(".local/share/bulwark");
    assert_eq!(mode_of(&own), 0o700);
    assert_eq!(mode_of(&own.join("bulwark.db")), 0o600);
}

/// A database that can't be used is named in the error. SQLite's own message names no file.
#[test]
fn a_database_error_says_which_database() {
    let home = tempfile::tempdir().unwrap();
    let bad = home.path().join("bad.db");
    fs::write(&bad, "garbage, not sqlite\n".repeat(100)).unwrap();
    let out = bulwarkctl(home.path())
        .args(["history", "--db-path"])
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = text(&out);
    assert!(err.contains(&bad.display().to_string()), "{err}");
}

/// An empty log file printed "0 events read … ✓ Nothing suspicious" and exited 0; so did a log
/// in which Bulwark understood no line. Neither is a clean result: no check mark, exit code 2.
#[test]
fn a_log_scan_with_nothing_to_analyze_is_not_a_clean_result() {
    let home = tempfile::tempdir().unwrap();
    let empty = home.path().join("empty.log");
    fs::write(&empty, "").unwrap();
    let not_understood = home.path().join("kernel.log");
    fs::write(
        &not_understood,
        "Nov  1 10:00:00 host kernel: usb 1-1: new high-speed USB device number 2\n\
         Nov  1 10:00:01 host kernel: usb 1-1: New USB device found\n",
    )
    .unwrap();
    for file in [&empty, &not_understood] {
        let out = bulwarkctl(home.path())
            .args(["logs", "scan", "--no-persist", "--from-file"])
            .arg(file)
            .output()
            .unwrap();
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(2), "{}: {shown}", file.display());
        assert!(!shown.contains('✓'), "{}: {shown}", file.display());
        assert!(!shown.contains("Nothing suspicious"), "{shown}");

        // The same exit code for a script that reads the JSON, with the reason on stderr.
        let out = bulwarkctl(home.path())
            .args(["logs", "scan", "--no-persist", "--json", "--from-file"])
            .arg(file)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("error:"));
    }

    // A log with a line Bulwark does understand is analyzed, and may be clean.
    let real = home.path().join("auth.log");
    fs::write(
        &real,
        "Nov  1 10:00:00 host sshd[100]: Accepted publickey for alice from 192.0.2.10 port 50000 ssh2\n",
    )
    .unwrap();
    let out = bulwarkctl(home.path())
        .args(["logs", "scan", "--no-persist", "--from-file"])
        .arg(&real)
        .output()
        .unwrap();
    assert_ne!(out.status.code(), Some(2), "{}", text(&out));
}

/// `rules validate /nonexistent` printed "0 rule(s) valid" and exited 0, and a custom rule with a
/// reserved id was "valid" although a scan refuses to load it.
#[test]
fn rules_validate_fails_on_what_loading_would_refuse() {
    let home = tempfile::tempdir().unwrap();
    let validate = |path: &Path| {
        bulwarkctl(home.path())
            .args(["rules", "validate"])
            .arg(path)
            .output()
            .unwrap()
    };

    let out = validate(Path::new("/nonexistent/rules"));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("does not exist"), "{}", text(&out));
    assert!(!text(&out).contains("0 rule(s) valid"), "{}", text(&out));

    let empty = home.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let out = validate(&empty);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("no rule files"), "{}", text(&out));

    let rule = |id: &str| {
        format!(
            "id: {id}\ntitle: \"t\"\ncategory: ssh-remote-access\nseverity: info\n\
             collector: sshd_config\nos: [linux]\ncondition: strict_modes == \"never\"\n\
             explain: \"x\"\nfix: \"x\"\nreferences: []\n"
        )
    };
    // Your own rules folder: a good rule, one with the reserved prefix, one reusing a built-in id.
    let custom = home.path().join(".config/bulwark/rules");
    fs::create_dir_all(&custom).unwrap();
    fs::write(custom.join("mine.yaml"), rule("MY-001")).unwrap();
    let out = validate(&custom);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("1 rule(s) valid"), "{}", text(&out));

    fs::write(custom.join("reserved.yaml"), rule("BLWK-MINE-001")).unwrap();
    fs::write(custom.join("shadow.yaml"), rule("BLWK-SSH-001")).unwrap();
    let out = validate(&custom);
    let shown = text(&out);
    assert!(!out.status.success(), "{shown}");
    assert!(shown.contains("1 rule(s) valid"), "{shown}");
    assert!(
        shown.contains("BLWK-MINE-001") && shown.contains("BLWK-SSH-001"),
        "{shown}"
    );
    assert!(shown.contains("reserved"), "{shown}");
    // …and that is what a scan does with them, so the two agree.
    let list = bulwarkctl(home.path())
        .args(["rules", "list"])
        .output()
        .unwrap();
    assert!(!list.status.success(), "loading refuses them too");

    // The same folder anywhere else is still somebody's own rules.
    let elsewhere = home.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join("mine.yaml"), rule("MY-001")).unwrap();
    fs::write(elsewhere.join("reserved.yaml"), rule("BLWK-MINE-001")).unwrap();
    assert!(!validate(&elsewhere).status.success());

    // The built-in pack itself is all BLWK- ids, and it is valid: this is what CI runs.
    let pack = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let out = validate(&pack);
    assert!(out.status.success(), "{}", text(&out));
}

/// `--place /etc/issue` was accepted and ignored nothing (the place is `issue`). A place no
/// finding is at now gets a warning that says so.
#[test]
fn a_place_that_matches_nothing_is_said_to_match_nothing() {
    let home = tempfile::tempdir().unwrap();
    let db = home.path().join("b.db");
    // A saved scan, so there are real places to compare against.
    let scan = bulwarkctl(home.path())
        .args(["scan", "--no-notify", "--db-path"])
        .arg(&db)
        .output()
        .unwrap();
    assert!(db.exists(), "{}", text(&scan));

    let out = bulwarkctl(home.path())
        .args([
            "rules",
            "suppress",
            "BLWK-SSH-004",
            "--reason",
            "test",
            "--db-path",
        ])
        .arg(&db)
        .args(["--place", "/definitely/not/a/place"])
        .output()
        .unwrap();
    let shown = text(&out);
    assert!(out.status.success(), "{shown}");
    assert!(shown.contains("ignores nothing right now"), "{shown}");

    // History lists the run, not only a count.
    let out = bulwarkctl(home.path())
        .args(["history", "--db-path"])
        .arg(&db)
        .output()
        .unwrap();
    let shown = text(&out);
    assert!(shown.contains("1 scan run(s) recorded"), "{shown}");
    assert!(
        shown.contains("CHECKS RAN") && shown.contains(" of "),
        "{shown}"
    );
    assert!(
        shown
            .lines()
            .any(|l| l.trim_start().starts_with("20") && l.contains(" of ")),
        "a line per run, starting with its date: {shown}"
    );
}

/// Under `LC_ALL=C` the bullets and arrows were printed as UTF-8 anyway.
#[test]
fn a_locale_without_utf8_gets_no_utf8_symbols() {
    let home = tempfile::tempdir().unwrap();
    for args in [&["fix", "list"][..], &["scan", "--no-persist"]] {
        let out = bulwarkctl(home.path())
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        for symbol in ['●', '•', '→', '✓', '·', '×', '…', '—'] {
            assert!(
                !stdout.contains(symbol),
                "{args:?} printed {symbol} under LC_ALL=C:\n{stdout}"
            );
        }
        let utf8 = bulwarkctl(home.path()).args(args).output().unwrap();
        assert!(
            !String::from_utf8_lossy(&utf8.stdout).is_ascii(),
            "{args:?}: a UTF-8 locale keeps the symbols"
        );
    }
}

/// Help text that was missing, and help that said less than the command did.
#[test]
fn help_says_what_the_commands_do() {
    let home = tempfile::tempdir().unwrap();
    let help = |args: &[&str]| {
        let out = bulwarkctl(home.path())
            .args(args)
            .arg("--help")
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    for sub in ["sshd", "etc-perms", "all", "sysctl", "banner", "login-defs"] {
        let h = help(&["fix", sub]);
        let apply = h
            .lines()
            .skip_while(|l| !l.contains("--apply"))
            .nth(1)
            .unwrap_or("");
        assert!(
            h.contains("--apply") && !apply.trim().is_empty(),
            "fix {sub} --apply has no help text:\n{h}"
        );
    }
    let all = help(&["fix", "all"]);
    assert!(all.contains("kernel network settings"), "{all}");
    assert!(
        all.contains("fix banner") && all.contains("fix login-defs"),
        "{all}"
    );
    assert!(help(&["rules", "validate"]).contains("folder of YAML files"));
    let add = help(&["hosts", "add"]);
    assert!(add.contains("SSH port") && add.contains("JSON"), "{add}");
}
