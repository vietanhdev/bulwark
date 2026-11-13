use super::Collector;
use crate::models::Fact;
use serde_json::Value;

pub struct AuthorizedKeysCollector;

/// One row per key in an `authorized_keys`-format file. Doesn't attempt to parse the
/// `options` prefix some entries have (e.g. `command="...",no-pty ssh-ed25519 ...`) — v1
/// only reports key type, a short prefix of the key material, and the comment.
pub fn parse_authorized_keys(text: &str) -> Vec<Fact> {
    let mut rows = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(key_type_idx) = fields
            .iter()
            .position(|f| f.starts_with("ssh-") || f.starts_with("ecdsa-"))
        else {
            continue;
        };
        let key_type = fields[key_type_idx].to_string();
        let key_prefix: String = fields
            .get(key_type_idx + 1)
            .map(|k| k.chars().take(16).collect())
            .unwrap_or_default();
        // `get(range)` not `[range]`: this file is fully user-controlled, and a line whose
        // key-type token is the last field (e.g. a bare `ssh-rsa`, or `command="x" ssh-ed25519`)
        // makes `key_type_idx + 2 > fields.len()`, which panics with range indexing. A collector
        // panic unwinds through the whole scan (there is no catch_unwind at the call site), so a
        // single malformed authorized_keys line would abort an otherwise-good privileged scan.
        let comment = fields
            .get(key_type_idx + 2..)
            .map(|rest| rest.join(" "))
            .unwrap_or_default();

        let mut fact = Fact::new();
        fact.insert("line_number".to_string(), Value::from(line_no + 1));
        fact.insert("key_type".to_string(), Value::String(key_type));
        fact.insert("key_prefix".to_string(), Value::String(key_prefix));
        fact.insert("comment".to_string(), Value::String(comment));
        rows.push(fact);
    }
    rows
}

impl Collector for AuthorizedKeysCollector {
    fn name(&self) -> &'static str {
        "authorized_keys"
    }

    fn is_applicable(&self) -> bool {
        Self::path().is_some()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let Some(path) = Self::path() else {
            return Ok(vec![]);
        };
        let home = std::path::PathBuf::from(crate::paths::home_var_os().unwrap_or_default());
        Ok(rows_for(&home, &path))
    }
}

/// The rows for one `authorized_keys` file. It is a file its owner controls, so it is opened
/// through `homefs` (never a pipe, never a link out of the home folder) and size-capped; one that
/// cannot be read, or is larger than the cap, is reported as not fully checked.
fn rows_for(home: &std::path::Path, path: &std::path::Path) -> Vec<Fact> {
    use crate::homefs::HomeFile;
    match super::read_home(home, path) {
        HomeFile::Found(read) => {
            let mut rows = parse_authorized_keys(&read.text);
            if read.truncated {
                rows.push(super::unread_row(path, super::TOO_LARGE));
            }
            rows
        }
        HomeFile::Missing => Vec::new(),
        HomeFile::Refused => vec![super::unread_row(path, crate::homefs::REFUSED)],
    }
}

impl AuthorizedKeysCollector {
    fn path() -> Option<std::path::PathBuf> {
        let home = crate::paths::home_var_os()?;
        let path = std::path::Path::new(&home).join(".ssh/authorized_keys");
        path.exists().then_some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_key_type_and_comment() {
        let text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@laptop\n";
        let rows = parse_authorized_keys(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("key_type").unwrap(), "ssh-ed25519");
        assert_eq!(rows[0].get("comment").unwrap(), "user@laptop");
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let text = "# a comment\n\nssh-rsa AAAAB3NzaC1yc2EAAAExample\n";
        let rows = parse_authorized_keys(text);
        assert_eq!(rows.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_in_place_of_authorized_keys_is_reported_and_never_waited_on() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".ssh")).unwrap();
        let path = home.path().join(".ssh/authorized_keys");
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let (h, p) = (home.path().to_path_buf(), path.clone());
        std::thread::spawn(move || {
            let _ = tx.send(rows_for(&h, &p));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("must not block");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].contains_key(crate::homefs::COULD_NOT_READ));
        assert!(!rows[0].contains_key("key_type"));
    }
}
