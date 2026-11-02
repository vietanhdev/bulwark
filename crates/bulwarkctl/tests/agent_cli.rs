//! `bulwarkctl agent`: the real binary installing, listing and removing the agent skill, in a
//! throw-away home folder.

use std::path::Path;
use std::process::{Command, Output};

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bulwarkctl"))
        .env("HOME", home)
        .env("USERPROFILE", home)
        .args(["agent"])
        .args(args)
        .output()
        .expect("bulwarkctl runs")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(o)))
}

#[test]
fn with_no_agent_found_install_says_how_to_name_one() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["install"]);
    assert!(!o.status.success());
    assert!(text(&o).contains("--agent"), "{}", text(&o));
    assert!(!home.path().join(".agents").exists(), "nothing written");
}

#[test]
fn install_goes_where_each_found_agent_looks() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::create_dir_all(home.path().join(".gemini")).unwrap();

    // A dry run writes nothing.
    let o = run(home.path(), &["install", "--dry-run"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("would install"));
    assert!(!home.path().join(".claude/skills").exists());

    let o = run(home.path(), &["install", "--command", "bulwarkctl"]);
    assert!(o.status.success(), "{}", text(&o));
    let claude = home.path().join(".claude/skills/bulwark/SKILL.md");
    let shared = home.path().join(".agents/skills/bulwark/SKILL.md");
    for p in [&claude, &shared] {
        let s = std::fs::read_to_string(p).unwrap();
        assert!(s.starts_with("---\nname: bulwark\n"), "{}", p.display());
        assert!(s.contains("`bulwarkctl ai scan --target .`"));
    }

    // Twice is fine.
    let o = run(home.path(), &["install", "--command", "bulwarkctl"]);
    assert!(text(&o).contains("already installed"), "{}", text(&o));

    let rows = json(&run(
        home.path(),
        &["list", "--json", "--command", "bulwarkctl"],
    ));
    let row = |id: &str| {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(row("claude-code")["found"], true);
    assert_eq!(row("claude-code")["state"], "current");
    assert_eq!(row("gemini")["state"], "current");
    assert_eq!(row("codex")["found"], false);

    let o = run(home.path(), &["remove", "--json"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!claude.exists() && !shared.exists());
}

#[test]
fn a_named_agent_gets_only_its_folder() {
    let home = tempfile::tempdir().unwrap();
    let o = run(home.path(), &["install", "--agent", "codex"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(home.path().join(".agents/skills/bulwark/SKILL.md").exists());
    assert!(!home.path().join(".claude").exists());

    let o = run(home.path(), &["install", "--agent", "nope"]);
    assert!(!o.status.success());
}

#[test]
fn a_project_install_covers_every_agent() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().to_str().unwrap();
    let out = json(&run(home.path(), &["install", "--project", dir, "--json"]));
    let paths: Vec<String> = out
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["path"].as_str().unwrap().replace('\\', "/"))
        .collect();
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert!(paths[0].ends_with(".claude/skills/bulwark/SKILL.md"));
    assert!(paths[1].ends_with(".agents/skills/bulwark/SKILL.md"));
    assert!(project
        .path()
        .join(".claude/skills/bulwark/SKILL.md")
        .exists());
    assert!(!home.path().join(".claude").exists(), "home untouched");
}

#[test]
fn someone_elses_skill_is_left_alone_and_reported() {
    let home = tempfile::tempdir().unwrap();
    let mine = home.path().join(".agents/skills/bulwark/SKILL.md");
    std::fs::create_dir_all(mine.parent().unwrap()).unwrap();
    std::fs::write(&mine, "---\nname: bulwark\ndescription: mine\n---\n").unwrap();

    let o = run(home.path(), &["install", "--agent", "codex"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("left alone"), "{}", text(&o));
    let o = run(home.path(), &["remove", "--agent", "codex"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert_eq!(
        std::fs::read_to_string(&mine).unwrap(),
        "---\nname: bulwark\ndescription: mine\n---\n"
    );
}

#[test]
fn the_installed_skill_passes_bulwarks_own_agent_scan() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let dir = project.path().to_str().unwrap();
    assert!(run(home.path(), &["install", "--project", dir])
        .status
        .success());
    let o = Command::new(env!("CARGO_BIN_EXE_bulwarkctl"))
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .args(["ai", "scan", "--json", "--no-persist", "--target", dir])
        .output()
        .unwrap();
    let r = json(&o);
    assert!(r["artifacts_scanned"].as_u64().unwrap() >= 2, "{r}");
    assert_eq!(r["findings"].as_array().unwrap().len(), 0, "{r}");
}
