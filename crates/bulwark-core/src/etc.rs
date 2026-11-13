//! Which configuration file a system program really reads.
//!
//! Most distributions keep a program's settings in `/etc`. openSUSE Tumbleweed and Leap 16 follow
//! the "hermetic /usr" layout instead: the package's defaults live under `/usr/etc` (PAM's under
//! `/usr/lib/pam.d`) and `/etc` holds only what the administrator changed. A collector that looks
//! for `/etc/ssh/sshd_config` there finds nothing and calls itself "not applicable", so every SSH
//! check silently did not run. How the two places combine differs from program to program, so the
//! rules live here, in one place, and no collector or fixer names a `/usr/etc` path itself.
//!
//! Each rule was measured with the program itself on Tumbleweed (OpenSSH 10.6, sudo 1.9.17,
//! shadow 4.20 with libeconf 0.8) and Leap 16.0, not taken from documentation:
//!
//! * **sshd** reads `/etc/ssh/sshd_config` when it exists, else `/usr/etc/ssh/sshd_config`. The
//!   `/etc` file replaces the vendor file whole: its `Include` lines go with it, and a setting only
//!   the vendor file made falls back to OpenSSH's default (`sshd -T`). The vendor file includes
//!   `/etc/ssh/sshd_config.d/*.conf` first and `/usr/etc/ssh/sshd_config.d/*.conf` after it, so a
//!   drop-in in `/etc` wins. A relative `Include` is relative to `/etc/ssh` either way.
//! * **sudo** reads `/etc/sudoers` when it exists, else `/usr/etc/sudoers`, again whole (`sudo -l`).
//!   The vendor file names both `/usr/etc/sudoers.d` and `/etc/sudoers.d`.
//! * **login.defs**, as read by shadow-utils built with libeconf (openSUSE, and Fedora too): the
//!   main file is `/etc/login.defs` when it exists, else `/usr/etc/login.defs`, whole. Then files
//!   named `*.defs` (not `*.conf`) in `/usr/etc/login.defs.d` and `/etc/login.defs.d` are applied
//!   over it key by key: the `/usr/etc` ones first, then the `/etc` ones, each folder in name order,
//!   a later file overriding an earlier one, and an `/etc` file hiding a `/usr/etc` file of the
//!   same name. Fedora's build has no `/usr/etc` and reads only the `/etc` folder. Measured with
//!   `useradd` and the fields it writes to `/etc/shadow`. shadow-utils without libeconf (Debian,
//!   Ubuntu) reads `/etc/login.defs` and nothing else.
//! * **PAM** looks for each service file in `/etc/pam.d`, then `/usr/lib/pam.d`, then
//!   `/usr/etc/pam.d`, and uses the first it finds, whole (a service set to deny in each place).
//!
//! On Debian, Ubuntu and Fedora none of the `/usr` places exist, so every answer here is the
//! `/etc` path it always was.

use std::io::Read;
use std::path::{Path, PathBuf};

/// A configuration file whose copy in `/etc`, when there is one, replaces the vendor's copy whole.
#[derive(Clone, Copy, Debug)]
pub struct Replaceable {
    /// The administrator's file.
    pub etc: &'static str,
    /// The package's default, read only when there is no `etc` file.
    pub vendor: &'static str,
}

/// sshd's main configuration file.
pub const SSHD_CONFIG: Replaceable = Replaceable {
    etc: "/etc/ssh/sshd_config",
    vendor: "/usr/etc/ssh/sshd_config",
};

/// What a relative sshd `Include` is relative to, whichever main file is in use.
pub const SSHD_CONFIG_DIR: &str = "/etc/ssh";

/// The folder of sshd drop-ins an administrator writes to. Every distribution checked (Debian,
/// Ubuntu, Fedora, openSUSE) includes it from the main file before any setting of its own.
pub const SSHD_DROP_IN_DIR: &str = "/etc/ssh/sshd_config.d";

/// The sudo policy.
pub const SUDOERS: Replaceable = Replaceable {
    etc: "/etc/sudoers",
    vendor: "/usr/etc/sudoers",
};

/// shadow-utils' settings.
pub const LOGIN_DEFS: Replaceable = Replaceable {
    etc: "/etc/login.defs",
    vendor: "/usr/etc/login.defs",
};

/// Drop-in folders for `login.defs`, in the order they are applied.
const LOGIN_DEFS_VENDOR_DROP_INS: &str = "/usr/etc/login.defs.d";
/// The drop-in folder an administrator writes to.
pub const LOGIN_DEFS_DROP_IN_DIR: &str = "/etc/login.defs.d";
/// libeconf takes drop-ins named after the main file's suffix: `login.defs.d/*.defs`.
pub const LOGIN_DEFS_DROP_IN_SUFFIX: &str = ".defs";

/// Where PAM looks for a service file, first match wins.
pub const PAM_DIRS: &[&str] = &["/etc/pam.d", "/usr/lib/pam.d", "/usr/etc/pam.d"];

/// The vendor's copies of the PAM files the file-integrity watch covers in `/etc/pam.d`.
pub const PAM_COMMON_AUTH_VENDOR: &str = "/usr/lib/pam.d/common-auth";
pub const PAM_SSHD_VENDOR: &str = "/usr/lib/pam.d/sshd";

/// `abs` (an absolute path) inside `root`. With `root` = `/` it is `abs` itself; tests pass a
/// temporary folder.
fn under(root: &Path, abs: &str) -> PathBuf {
    root.join(abs.trim_start_matches('/'))
}

impl Replaceable {
    /// The file the program reads: the `/etc` copy when it exists, else the vendor's, else `None`.
    /// "Exists" follows links, as sshd does: a link that leads nowhere counts as no file.
    pub fn in_use(&self) -> Option<PathBuf> {
        self.in_use_under(Path::new("/"))
    }

    pub(crate) fn in_use_under(&self, root: &Path) -> Option<PathBuf> {
        [self.etc, self.vendor]
            .into_iter()
            .map(|p| under(root, p))
            .find(|p| p.exists())
    }

    /// True when the vendor's copy is the one in use, so writing the `/etc` file would replace all
    /// of the vendor's settings rather than change one of them.
    pub fn vendor_in_use(&self) -> bool {
        self.in_use().is_some_and(|p| p == Path::new(self.vendor))
    }
}

/// The files that make up `login.defs` on this system, in the order they are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginDefsFiles {
    /// `/etc/login.defs`, or the vendor's copy when there is none.
    pub main: PathBuf,
    /// The drop-ins, in the order applied: a later one overrides an earlier one, key by key.
    pub drop_ins: Vec<PathBuf>,
    /// Whether the login tools read the files through libeconf. It changes more than the drop-ins:
    /// within one file the first value of a key wins, and a `#` anywhere starts a comment.
    pub econf: bool,
}

/// The `login.defs` files in use, or `None` when the system has none. A drop-in folder that exists
/// and cannot be listed is an error: a file in it may set the value that matters.
pub fn login_defs_files() -> anyhow::Result<Option<LoginDefsFiles>> {
    let root = Path::new("/");
    login_defs_files_under(root, shadow_uses_libeconf(root))
}

pub(crate) fn login_defs_files_under(
    root: &Path,
    econf_binary: bool,
) -> anyhow::Result<Option<LoginDefsFiles>> {
    let Some(main) = LOGIN_DEFS.in_use_under(root) else {
        return Ok(None);
    };
    // Only a build with libeconf has a vendor directory, so a system that ships one uses it, even
    // when an /etc/login.defs now replaces the vendor file.
    let vendor_layout = under(root, LOGIN_DEFS.vendor).exists();
    let econf = econf_binary || vendor_layout;
    let mut drop_ins = Vec::new();
    if econf {
        let mut dirs = Vec::new();
        if vendor_layout {
            dirs.push(under(root, LOGIN_DEFS_VENDOR_DROP_INS));
        }
        dirs.push(under(root, LOGIN_DEFS_DROP_IN_DIR));
        let mut listed: Vec<Vec<String>> = Vec::new();
        for dir in &dirs {
            let mut names: Vec<String> = list_dir(dir)?
                .into_iter()
                .filter(|name| {
                    name.len() > LOGIN_DEFS_DROP_IN_SUFFIX.len()
                        && name.ends_with(LOGIN_DEFS_DROP_IN_SUFFIX)
                        && !dir.join(name).is_dir()
                })
                .collect();
            names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            listed.push(names);
        }
        for (i, (dir, names)) in dirs.iter().zip(&listed).enumerate() {
            for name in names {
                // A file in a later folder hides one of the same name in an earlier folder, and a
                // link to /dev/null hides without adding anything.
                let hidden = listed[i + 1..].iter().any(|later| later.contains(name));
                let path = dir.join(name);
                let masked =
                    std::fs::canonicalize(&path).is_ok_and(|real| real == Path::new("/dev/null"));
                if !hidden && !masked {
                    drop_ins.push(path);
                }
            }
        }
    }
    Ok(Some(LoginDefsFiles {
        main,
        drop_ins,
        econf,
    }))
}

/// Whether shadow-utils on this system reads its settings through libeconf, judged by whether
/// `useradd` is linked against it. Reads the program; never starts it.
fn shadow_uses_libeconf(root: &Path) -> bool {
    const NEEDLE: &[u8] = b"libeconf.so";
    for candidate in ["/usr/sbin/useradd", "/sbin/useradd"] {
        let path = under(root, candidate);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        let mut bytes = Vec::new();
        if std::fs::File::open(&path)
            .and_then(|f| f.take(MAX_PROGRAM_BYTES).read_to_end(&mut bytes))
            .is_err()
        {
            continue;
        }
        return bytes.windows(NEEDLE.len()).any(|w| w == NEEDLE);
    }
    false
}

/// `useradd` is a few hundred kilobytes; the name of a library it links is near the start.
const MAX_PROGRAM_BYTES: u64 = 16 * 1024 * 1024;

/// The PAM service files in effect, one per service: for each name, the first of [`PAM_DIRS`] that
/// has it. Sorted by name. A folder that does not exist is skipped.
pub fn pam_service_files() -> Vec<PathBuf> {
    pam_service_files_under(Path::new("/"))
}

pub(crate) fn pam_service_files_under(root: &Path) -> Vec<PathBuf> {
    let mut chosen: std::collections::BTreeMap<String, PathBuf> = Default::default();
    for dir in PAM_DIRS.iter().map(|d| under(root, d)) {
        for name in list_dir(&dir).unwrap_or_default() {
            let path = dir.join(&name);
            if path.is_dir() {
                continue;
            }
            chosen.entry(name).or_insert(path);
        }
    }
    chosen.into_values().collect()
}

/// The names in `dir`. A folder that is not there has none; one that cannot be read is an error.
fn list_dir(dir: &Path) -> anyhow::Result<Vec<String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if is_absent(&e) => return Ok(Vec::new()),
        Err(e) => return Err(io_error("list", dir, e)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| io_error("list", dir, e))?;
        if let Ok(name) = entry.file_name().into_string() {
            names.push(name);
        }
    }
    Ok(names)
}

/// No real configuration file is anywhere near this size. A larger one is an error, never read in
/// part.
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

/// Keeps the cause in the error chain: the engine looks there for "permission denied" to tell a
/// scan that needs admin rights from one that failed.
pub(crate) fn io_error(what: &str, path: &Path, e: std::io::Error) -> anyhow::Error {
    let message = format!(
        "could not {what} {}: {e}",
        crate::engine::display_safe(&path.display().to_string())
    );
    anyhow::Error::new(e).context(message)
}

pub(crate) fn is_absent(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// Reads one configuration file as text. Bytes that are not UTF-8 are replaced, not refused: the
/// programs read bytes, and one Latin-1 character in a comment must not hide the lines around it.
/// A folder reads as empty (sshd opens one matched by `Include dir/*`, reads nothing and carries
/// on); a pipe or device is an error, since it would block or never end.
pub(crate) fn read_config_file(path: &Path) -> anyhow::Result<String> {
    let meta = std::fs::metadata(path).map_err(|e| io_error("read", path, e))?;
    if meta.is_dir() {
        return Ok(String::new());
    }
    if !meta.is_file() {
        anyhow::bail!(
            "could not read {}: it is not a regular file",
            crate::engine::display_safe(&path.display().to_string())
        );
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| io_error("read", path, e))?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        anyhow::bail!(
            "could not read {}: it is larger than {} MiB",
            crate::engine::display_safe(&path.display().to_string()),
            MAX_CONFIG_BYTES / (1024 * 1024)
        );
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;

    fn write(root: &Path, abs: &str, text: &str) {
        let path = under(root, abs);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn the_etc_file_wins_and_the_vendor_file_is_the_fallback() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        assert_eq!(SSHD_CONFIG.in_use_under(r), None);
        write(r, SSHD_CONFIG.vendor, "");
        assert_eq!(
            SSHD_CONFIG.in_use_under(r),
            Some(under(r, SSHD_CONFIG.vendor))
        );
        write(r, SSHD_CONFIG.etc, "");
        assert_eq!(SSHD_CONFIG.in_use_under(r), Some(under(r, SSHD_CONFIG.etc)));
    }

    #[test]
    fn a_link_that_leads_nowhere_is_no_file() {
        // sshd -T on Tumbleweed: a dangling /etc/ssh/sshd_config link leaves the vendor file in use.
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(r, SSHD_CONFIG.vendor, "");
        fs::create_dir_all(under(r, "/etc/ssh")).unwrap();
        std::os::unix::fs::symlink(r.join("gone"), under(r, SSHD_CONFIG.etc)).unwrap();
        assert_eq!(
            SSHD_CONFIG.in_use_under(r),
            Some(under(r, SSHD_CONFIG.vendor))
        );
    }

    /// The benign side: a Debian, Ubuntu or Fedora tree answers exactly as before.
    #[test]
    fn a_debian_layout_reads_only_etc() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(r, "/etc/login.defs", "PASS_MAX_DAYS 99999\n");
        write(r, "/etc/ssh/sshd_config", "");
        write(r, "/etc/sudoers", "");
        write(r, "/etc/pam.d/common-session", "");
        // Not read without libeconf, even if someone made the folder.
        write(r, "/etc/login.defs.d/50-x.defs", "PASS_MAX_DAYS 1\n");
        let files = login_defs_files_under(r, false).unwrap().unwrap();
        assert_eq!(
            files,
            LoginDefsFiles {
                main: under(r, "/etc/login.defs"),
                drop_ins: vec![],
                econf: false,
            }
        );
        assert_eq!(
            SSHD_CONFIG.in_use_under(r),
            Some(under(r, "/etc/ssh/sshd_config"))
        );
        assert_eq!(SUDOERS.in_use_under(r), Some(under(r, "/etc/sudoers")));
        assert_eq!(
            pam_service_files_under(r),
            [under(r, "/etc/pam.d/common-session")]
        );
    }

    #[test]
    fn login_defs_drop_ins_follow_libeconf() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(r, "/usr/etc/login.defs", "");
        write(r, "/usr/etc/login.defs.d/70-b.defs", "");
        write(r, "/usr/etc/login.defs.d/60-a.defs", "");
        write(r, "/usr/etc/login.defs.d/50-same.defs", "");
        write(r, "/etc/login.defs.d/50-same.defs", "");
        write(r, "/etc/login.defs.d/40-early.defs", "");
        write(r, "/etc/login.defs.d/10-notes.conf", ""); // not a .defs file: never read
        fs::create_dir_all(under(r, "/etc/login.defs.d/sub.defs")).unwrap();
        let files = login_defs_files_under(r, false).unwrap().unwrap();
        assert!(files.econf, "a vendor file implies libeconf");
        assert_eq!(files.main, under(r, "/usr/etc/login.defs"));
        assert_eq!(
            files.drop_ins,
            [
                under(r, "/usr/etc/login.defs.d/60-a.defs"),
                under(r, "/usr/etc/login.defs.d/70-b.defs"),
                under(r, "/etc/login.defs.d/40-early.defs"),
                under(r, "/etc/login.defs.d/50-same.defs"),
            ],
            "/usr/etc first, then /etc, each in name order; /etc hides a same-named vendor file"
        );

        // An /etc/login.defs replaces the vendor file; the drop-ins still apply over it.
        write(r, "/etc/login.defs", "");
        let files = login_defs_files_under(r, false).unwrap().unwrap();
        assert_eq!(files.main, under(r, "/etc/login.defs"));
        assert_eq!(files.drop_ins.len(), 4);

        // A link to /dev/null hides the vendor file of that name and adds nothing.
        std::os::unix::fs::symlink("/dev/null", under(r, "/etc/login.defs.d/60-a.defs")).unwrap();
        let files = login_defs_files_under(r, false).unwrap().unwrap();
        assert!(!files
            .drop_ins
            .iter()
            .any(|p| p.file_name().unwrap() == "60-a.defs"));
    }

    #[test]
    fn fedora_reads_the_etc_drop_ins_but_has_no_vendor_folder() {
        // Fedora's shadow-utils links libeconf but has no /usr/etc: a /usr/etc/login.defs.d made by
        // hand is not read (measured), and the /etc folder is.
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(r, "/etc/login.defs", "");
        write(r, "/etc/login.defs.d/50-x.defs", "");
        write(r, "/usr/etc/login.defs.d/50-y.defs", "");
        let files = login_defs_files_under(r, true).unwrap().unwrap();
        assert!(files.econf);
        assert_eq!(files.drop_ins, [under(r, "/etc/login.defs.d/50-x.defs")]);
    }

    #[test]
    fn libeconf_is_recognised_from_the_program_without_running_it() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(
            r,
            "/usr/sbin/useradd",
            "\x7fELF...libc.so.6\0libaudit.so.1\0",
        );
        assert!(!shadow_uses_libeconf(r));
        write(
            r,
            "/usr/sbin/useradd",
            "\x7fELF...libeconf.so.0\0libc.so.6\0",
        );
        assert!(shadow_uses_libeconf(r));
    }

    #[test]
    fn a_pam_service_in_etc_hides_the_vendor_one() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(r, "/usr/lib/pam.d/sshd", "");
        write(r, "/usr/lib/pam.d/common-session", "");
        write(r, "/usr/etc/pam.d/common-session", "");
        write(r, "/usr/etc/pam.d/only-here", "");
        write(r, "/etc/pam.d/sshd", "");
        assert_eq!(
            pam_service_files_under(r),
            [
                under(r, "/usr/lib/pam.d/common-session"),
                under(r, "/usr/etc/pam.d/only-here"),
                under(r, "/etc/pam.d/sshd"),
            ]
        );
    }
}
