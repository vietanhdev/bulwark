//! User-triggered, metadata-only provider adapter. Never part of a background scan.
pub mod inventory;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_BYTES: usize = 1024 * 1024;
const INVALID: &str =
    "This aws-vault build did not return the expected metadata. It needs support for `list --json`.";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u32,
    pub observed_at: DateTime<Utc>,
    pub profiles: Vec<Profile>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub configured: bool,
    pub credential_reference: bool,
    pub oidc_cache_present: bool,
    pub sessions: Vec<Session>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    #[serde(rename = "type")]
    pub kind: String,
    pub expires_at: DateTime<Utc>,
    pub status: CacheStatus,
    pub selected_store: bool,
}
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CacheStatus {
    Cached,
    Expired,
}

fn label_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}

pub fn parse_snapshot(bytes: &[u8], now: DateTime<Utc>) -> Result<Snapshot, &'static str> {
    if bytes.len() > MAX_BYTES {
        return Err(INVALID);
    }
    // Do not surface serde errors: they can quote untrusted provider output.
    let mut result: Snapshot = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    if result.schema_version != 1 || result.profiles.len() > 4096 {
        return Err(INVALID);
    }
    let mut seen = std::collections::HashSet::new();
    for p in &mut result.profiles {
        if !label_ok(&p.name) || !seen.insert(p.name.clone()) || p.sessions.len() > 128 {
            return Err(INVALID);
        }
        for s in &mut p.sessions {
            if !label_ok(&s.kind) {
                return Err(INVALID);
            }
            // Expiry is evaluated here too: never trust a provider's stale "cached" label.
            s.status = if s.expires_at <= now {
                CacheStatus::Expired
            } else {
                CacheStatus::Cached
            };
        }
    }
    Ok(result)
}

/// Typed, static errors: provider paths/output and credential material are never serialized.
#[derive(Debug, Serialize)]
pub struct ReadError {
    pub code: &'static str,
    pub message: &'static str,
}
impl ReadError {
    pub fn failed(message: &'static str) -> Self {
        Self {
            code: "failed",
            message,
        }
    }
}
#[cfg(unix)]
fn path_error(error: std::io::Error) -> ReadError {
    if error.kind() == std::io::ErrorKind::NotFound {
        ReadError { code: "unavailable", message: "The local provider was not found at ~/.local/bin/aws-vault. Other locations were not searched." }
    } else {
        ReadError::failed("Could not inspect the local AWS Vault provider path.")
    }
}
/// Whether someone other than this user (or root) could replace an entry in a folder with this
/// owner, group and mode. Writable by everyone is fine only with the sticky bit (as on `/tmp`,
/// where others cannot rename your entries). Writable by a group is fine only when it is this
/// user's own group, which is how home folders are created on distributions with per-user groups.
#[cfg(unix)]
fn folder_exposed(uid: u32, gid: u32, mode: u32, me: u32, my_group: u32) -> bool {
    let sticky = mode & 0o1000 != 0;
    (uid != 0 && uid != me)
        || (mode & 0o002 != 0 && !sticky)
        || (mode & 0o020 != 0 && gid != my_group && !sticky)
}

pub fn read_aws_vault(home: &Path) -> Result<Snapshot, ReadError> {
    #[cfg(unix)]
    {
        let binary = home
            .join(".local/bin/aws-vault")
            .canonicalize()
            .map_err(path_error)?;
        use std::os::unix::fs::MetadataExt;
        let meta = binary
            .metadata()
            .map_err(|_| ReadError::failed("Could not inspect the local provider executable."))?;
        if !meta.is_file()
            || meta.mode() & 0o022 != 0
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
        {
            return Err(ReadError::failed(
                "AWS Vault must be owned by you or root and not writable by other users.",
            ));
        }
        // The file's own mode is not enough: whoever can write a folder above it can swap it.
        let me = unsafe { libc::geteuid() };
        let my_group = unsafe { libc::getegid() };
        let exposed = binary.ancestors().skip(1).any(|dir| match dir.metadata() {
            Ok(m) => folder_exposed(m.uid(), m.gid(), m.mode(), me, my_group),
            Err(_) => true,
        });
        if exposed {
            return Err(ReadError::failed(
                "A folder above AWS Vault can be changed by other users, so it was not run.",
            ));
        }
        run_provider(&binary, home, std::time::Duration::from_secs(8)).map_err(ReadError::failed)
    }
    #[cfg(not(unix))]
    {
        let _ = home;
        Err(ReadError {
            code: "unsupported",
            message: "AWS Vault session inspection is currently supported on Linux and macOS.",
        })
    }
}

#[cfg(unix)]
fn run_provider(
    binary: &Path,
    home: &Path,
    timeout: std::time::Duration,
) -> Result<Snapshot, &'static str> {
    run_provider_with_environment(binary, home, timeout, std::env::vars_os())
}

// Explicit environment input keeps synthetic contract tests independent of the
// developer's live vault routing, without changing production override behavior.
#[cfg(unix)]
fn run_provider_with_environment(
    binary: &Path,
    home: &Path,
    timeout: std::time::Duration,
    environment: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Result<Snapshot, &'static str> {
    use std::{
        io::Read,
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        sync::mpsc,
        time::Instant,
    };
    let mut cmd = Command::new(binary);
    cmd.args(["--prompt=terminal", "list", "--json"])
        .current_dir(home)
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    // Only configuration/session-bus routing. Never inherit AWS keys, vault session
    // keys, loader overrides, shell startup hooks, or project-supplied PATH entries.
    const ALLOWED: &[&str] = &[
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "AWS_CONFIG_FILE",
        "AWS_VAULT_BACKEND",
        "AWS_VAULT_SESSION_BACKEND",
        "AWS_VAULT_FILE_DIR",
        "AWS_VAULT_SESSION_FILE_DIR",
        "AWS_VAULT_KEYCHAIN_NAME",
        "AWS_VAULT_SESSION_KEYCHAIN_NAME",
        "AWS_VAULT_SECRET_SERVICE_COLLECTION_NAME",
        "AWS_VAULT_SESSION_SECRET_SERVICE_COLLECTION_NAME",
    ];
    // A backend's own config-file path (`AWS_VAULT_<BACKEND>_CONFIG`) is routing too. The suffix
    // keeps passphrase and token variables in the same namespace out.
    let backend_config = |name: &std::ffi::OsStr| {
        name.to_str().is_some_and(|n| {
            n.strip_prefix("AWS_VAULT_")
                .and_then(|rest| rest.strip_suffix("_CONFIG"))
                .is_some_and(|mid| {
                    !mid.is_empty()
                        && mid
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                })
        })
    };
    for (name, value) in environment {
        if ALLOWED.iter().any(|allowed| name == *allowed) || backend_config(&name) {
            cmd.env(name, value);
        }
    }
    let mut child = cmd.spawn().map_err(|_| "Could not start AWS Vault.")?;
    let group = child.id() as i32;
    let stdout = child
        .stdout
        .take()
        .ok_or("Could not read AWS Vault metadata.")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = tx.send(result);
    });
    let started = Instant::now();
    let outcome = loop {
        match rx.try_recv() {
            Ok(Ok(bytes)) if bytes.len() > MAX_BYTES => {
                break Err("AWS Vault metadata exceeded the size limit.")
            }
            Ok(Ok(bytes)) => {
                // Wait for the exit status with the same deadline; output alone is not success.
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) if status.success() => break,
                        Ok(Some(_)) | Err(_) => {
                            unsafe {
                                libc::kill(-group, libc::SIGKILL);
                            }
                            let _ = child.wait();
                            return Err("AWS Vault could not list metadata. Check its setup in your own terminal.");
                        }
                        Ok(None) if started.elapsed() < timeout => {
                            std::thread::sleep(std::time::Duration::from_millis(10))
                        }
                        _ => {
                            unsafe {
                                libc::kill(-group, libc::SIGKILL);
                            }
                            let _ = child.wait();
                            return Err("AWS Vault timed out. Unlock your local store in your own terminal, then retry.");
                        }
                    }
                }
                break parse_snapshot(&bytes, Utc::now());
            }
            Ok(Err(_)) | Err(mpsc::TryRecvError::Disconnected) => {
                break Err("Could not read AWS Vault metadata.")
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if started.elapsed() >= timeout {
            break Err(
                "AWS Vault timed out. Unlock your local store in your own terminal, then retry.",
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    // Kill the process group even after a successful parent exit: no inherited-pipe
    // descendants may outlive this bounded request. No provider output is logged.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    let _ = child.wait();
    outcome
}

#[cfg(all(test, unix))]
mod folder_tests {
    use super::folder_exposed;

    #[test]
    fn only_folders_others_can_change_are_exposed() {
        let (me, my_group) = (1000, 1000);
        // An ordinary home folder, one with a per-user group, root's folders, and /tmp.
        assert!(!folder_exposed(1000, 1000, 0o40755, me, my_group));
        assert!(!folder_exposed(1000, 1000, 0o40775, me, my_group));
        assert!(!folder_exposed(0, 0, 0o40755, me, my_group));
        assert!(!folder_exposed(0, 0, 0o41777, me, my_group));
        // Someone else's folder, world-writable without sticky, writable by another group.
        assert!(folder_exposed(1001, 1001, 0o40755, me, my_group));
        assert!(folder_exposed(1000, 1000, 0o40777, me, my_group));
        assert!(folder_exposed(1000, 50, 0o40775, me, my_group));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> serde_json::Value {
        serde_json::json!({"schema_version":1,"observed_at":"2030-01-01T00:00:00Z","profiles":[{
            "name":"synthetic","configured":true,"credential_reference":true,"oidc_cache_present":false,
            "sessions":[{"type":"sts.AssumeRole","expires_at":"2030-01-01T00:01:00Z","status":"cached","selected_store":true}]
        }]})
    }
    #[test]
    fn expiry_boundary_is_recomputed() {
        let bytes = serde_json::to_vec(&sample()).unwrap();
        let now = "2030-01-01T00:01:00Z".parse().unwrap();
        assert_eq!(
            parse_snapshot(&bytes, now).unwrap().profiles[0].sessions[0].status,
            CacheStatus::Expired
        );
    }
    #[test]
    fn reject_unknown_fields_versions_duplicates_and_controls() {
        let mut cases = Vec::new();
        let mut v = sample();
        v["secret_access_key"] = "synthetic-secret".into();
        cases.push(v);
        let mut v = sample();
        v["schema_version"] = 2.into();
        cases.push(v);
        let mut v = sample();
        v["profiles"][0]["name"] = "bad\nname".into();
        cases.push(v);
        let mut v = sample();
        let p = v["profiles"][0].clone();
        v["profiles"].as_array_mut().unwrap().push(p);
        cases.push(v);
        let mut v = sample();
        v["profiles"][0]["sessions"][0]["status"] = "verified".into();
        cases.push(v);
        for v in cases {
            assert_eq!(
                parse_snapshot(&serde_json::to_vec(&v).unwrap(), Utc::now()).unwrap_err(),
                INVALID
            );
        }
        assert_eq!(
            parse_snapshot(b"synthetic-secret", Utc::now()).unwrap_err(),
            INVALID
        );
        assert!(parse_snapshot(&vec![b' '; MAX_BYTES + 1], Utc::now()).is_err());
    }
    #[cfg(unix)]
    fn script(text: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("provider");
        std::fs::write(&p, format!("#!/bin/sh\n{text}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, p)
    }
    #[test]
    #[cfg(unix)]
    fn provider_failure_redacts_output_and_enforces_timeout() {
        let (dir, p) = script("echo synthetic-secret >&2; echo synthetic-secret; exit 1");
        let e = run_provider(&p, dir.path(), std::time::Duration::from_secs(1)).unwrap_err();
        assert!(!e.contains("synthetic-secret"));
        // A descendant retaining stdout must not defeat the timeout.
        let (dir, p) = script("sleep 30 & wait");
        let start = std::time::Instant::now();
        assert!(run_provider(&p, dir.path(), std::time::Duration::from_millis(100)).is_err());
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
    #[test]
    #[cfg(unix)]
    fn provider_environment_preserves_routing_but_drops_secrets_and_execution_hooks() {
        let (dir, p) = script(
            r#"
[ "$AWS_VAULT_BACKEND" = file ] || exit 1
[ "$AWS_VAULT_SESSION_BACKEND" = file ] || exit 2
[ "$AWS_CONFIG_FILE" = /synthetic/config ] || exit 3
[ "$AWS_VAULT_FILE_DIR" = /synthetic/keys ] || exit 4
[ "$AWS_VAULT_SESSION_FILE_DIR" = /synthetic/sessions ] || exit 5
[ "$AWS_VAULT_EXAMPLE_CONFIG" = /synthetic/mappings ] || exit 6
[ "$PATH" = /usr/bin:/bin ] || exit 7
[ -z "${AWS_SECRET_ACCESS_KEY+x}${AWS_SESSION_TOKEN+x}${AWS_VAULT_FILE_PASSPHRASE+x}${BASH_ENV+x}${LD_PRELOAD+x}" ] || exit 8
printf '%s' '{"schema_version":1,"observed_at":"2030-01-01T00:00:00Z","profiles":[]}'
"#,
        );
        let environment = [
            ("AWS_VAULT_BACKEND", "file"),
            ("AWS_VAULT_SESSION_BACKEND", "file"),
            ("AWS_CONFIG_FILE", "/synthetic/config"),
            ("AWS_VAULT_FILE_DIR", "/synthetic/keys"),
            ("AWS_VAULT_SESSION_FILE_DIR", "/synthetic/sessions"),
            ("AWS_VAULT_EXAMPLE_CONFIG", "/synthetic/mappings"),
            ("PATH", "/synthetic/bin"),
            ("AWS_SECRET_ACCESS_KEY", "synthetic"),
            ("AWS_SESSION_TOKEN", "synthetic"),
            ("AWS_VAULT_FILE_PASSPHRASE", "synthetic"),
            ("BASH_ENV", "/synthetic/hook"),
            ("LD_PRELOAD", "/synthetic/loader"),
        ]
        .map(|(key, value)| (key.into(), value.into()));
        assert!(run_provider_with_environment(
            &p,
            dir.path(),
            // Generous: this is the success path, and a loaded CI machine can be slow to start sh.
            std::time::Duration::from_secs(20),
            environment,
        )
        .unwrap()
        .profiles
        .is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn provider_arguments_and_empty_metadata() {
        let (dir,p)=script("[ \"$#\" = 3 ] && [ \"$1\" = '--prompt=terminal' ] && [ \"$2\" = list ] && [ \"$3\" = --json ] || exit 9\nprintf '%s' '{\"schema_version\":1,\"observed_at\":\"2030-01-01T00:00:00Z\",\"profiles\":[]}'");
        assert!(
            run_provider(&p, dir.path(), std::time::Duration::from_secs(20))
                .unwrap()
                .profiles
                .is_empty()
        );
    }
}

#[cfg(all(test, unix))]
mod integration_tests {
    use super::*;
    #[test]
    #[ignore = "requires the synthetic-test AWS Vault build; never point at a live vault"]
    fn real_aws_vault_contract() {
        let provider =
            std::env::var("BULWARK_TEST_PROVIDER").expect("synthetic test build required");
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".aws")).unwrap();
        std::fs::create_dir_all(dir.path().join(".local/bin")).unwrap();
        std::fs::write(
            dir.path().join(".aws/config"),
            "[profile synthetic-readonly]\nregion=us-east-1\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(provider, dir.path().join(".local/bin/aws-vault")).unwrap();
        // Never inherit AWS_CONFIG_FILE, a backend config, or OS keyring routing.
        // Both stores are empty directories inside this test's temporary home.
        let environment = [
            ("AWS_VAULT_BACKEND".into(), "file".into()),
            ("AWS_VAULT_SESSION_BACKEND".into(), "file".into()),
            (
                "AWS_CONFIG_FILE".into(),
                dir.path().join(".aws/config").into_os_string(),
            ),
            (
                "AWS_VAULT_FILE_DIR".into(),
                dir.path().join("keys").into_os_string(),
            ),
            (
                "AWS_VAULT_SESSION_FILE_DIR".into(),
                dir.path().join("sessions").into_os_string(),
            ),
        ];
        let result = run_provider_with_environment(
            &dir.path().join(".local/bin/aws-vault"),
            dir.path(),
            std::time::Duration::from_secs(8),
            environment,
        )
        .unwrap();
        assert_eq!(result.profiles.len(), 1);
        assert_eq!(result.profiles[0].name, "synthetic-readonly");
        assert!(result.profiles[0].configured);
        assert!(!result.profiles[0].credential_reference);
        assert!(result.profiles[0].sessions.is_empty());
    }
    #[test]
    fn excessive_output_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("provider");
        std::fs::write(&binary, "#!/bin/sh\nhead -c 2097152 /dev/zero\nsleep 30\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let start = std::time::Instant::now();
        let err = run_provider(&binary, dir.path(), std::time::Duration::from_secs(2)).unwrap_err();
        assert!(err.contains("size limit"));
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }
}

#[cfg(all(test, unix))]
mod availability_tests {
    use super::*;
    #[test]
    fn only_missing_path_is_unavailable_and_errors_never_serialize_sources() {
        let missing = path_error(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "CANARY-private-path-token",
        ));
        assert_eq!(missing.code, "unavailable");
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::Other,
        ] {
            let failure = path_error(std::io::Error::new(kind, "CANARY-private-path-token"));
            assert_eq!(failure.code, "failed");
            assert!(!serde_json::to_string(&failure).unwrap().contains("CANARY"));
        }
        assert!(!serde_json::to_string(&missing).unwrap().contains("CANARY"));
        let home = tempfile::tempdir().unwrap();
        assert_eq!(read_aws_vault(home.path()).unwrap_err().code, "unavailable");
    }
}
