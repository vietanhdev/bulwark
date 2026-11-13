//! Reading a file inside someone's home folder, safely enough to do as root.
//!
//! A privileged scan reads dotfiles in the invoking user's home. That user controls every name in
//! it, so a plain `read(path)` can be turned against the scan:
//!
//! - a symlink (the file itself, or any folder above it) points at a root-only file, whose
//!   contents or derived facts then appear in the user's findings;
//! - a named pipe in place of a file blocks the read forever;
//! - the path is swapped between a check and the read.
//!
//! [`open_in_home`] answers all three with one rule: open once, then decide from the open file
//! descriptor, never from the path again. Dotfile managers legitimately symlink these files (and
//! whole folders such as `~/.config`), so a link is followed when everything it resolves to stays
//! inside the home folder.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// The outcome of looking for a file in a home folder.
#[derive(Debug)]
pub enum HomeFile<T> {
    /// Nothing exists at that path.
    Missing,
    /// Something is there, but it is not a regular file inside the home folder that this scan may
    /// read: a pipe or device, a link leaving the home folder, a file the home's owner does not
    /// own (under a root scan), or an unreadable file. Callers report this as "could not check",
    /// never as "nothing found".
    Refused,
    Found(T),
}

/// Why a [`HomeFile::Refused`] file was not read, for the one line a scan shows about it.
pub const REFUSED: &str =
    "it is not a regular file inside this home folder (a link that leaves it, a pipe, or a file that could not be opened)";

/// The fact a collector sets on a row it could not fill in. The engine turns it into one plain
/// "could not check <path>" line per file, where a bare missing field would read as an engine fault
/// repeated once per rule.
pub const COULD_NOT_READ: &str = "could_not_read";

impl<T> HomeFile<T> {
    pub fn found(self) -> Option<T> {
        match self {
            HomeFile::Found(v) => Some(v),
            _ => None,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> HomeFile<U> {
        match self {
            HomeFile::Found(v) => HomeFile::Found(f(v)),
            HomeFile::Missing => HomeFile::Missing,
            HomeFile::Refused => HomeFile::Refused,
        }
    }
}

/// Opens `path` (somewhere under `home`) for reading, if it is or resolves to a regular file
/// inside `home`.
pub fn open_in_home(home: &Path, path: &Path) -> HomeFile<File> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HomeFile::Missing,
        Err(_) => return HomeFile::Refused,
        Ok(_) => {}
    }
    match Root::new(home) {
        Some(root) => root.open(path),
        None => HomeFile::Refused,
    }
}

/// A folder that everything read through it has to stay inside: a home folder, or a project
/// folder that is not in any home (`ai scan --target /srv/app`). The same rules as
/// [`open_in_home`], with the folder resolved once, so a scan can open thousands of files under it
/// without resolving it again each time.
#[derive(Debug, Clone)]
pub struct Root {
    real: PathBuf,
}

/// Why [`Root::try_open`] did not hand back a file that exists.
#[derive(Debug)]
pub enum Refusal {
    /// It resolves (through a link in its name or in a folder above it) to a place outside the
    /// folder, or to nothing.
    LeavesRoot,
    /// A pipe, socket, device or folder.
    NotRegular,
    /// It could not be opened or examined.
    Unreadable(std::io::Error),
    /// Under a root scan: it does not belong to the folder's owner, or where the open file really
    /// is could not be confirmed.
    NotOwners,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::LeavesRoot => {
                f.write_str("it is a link that leads outside the folder being checked, or nowhere")
            }
            Refusal::NotRegular => {
                f.write_str("it is not a regular file (a pipe, device or folder)")
            }
            Refusal::Unreadable(e) => write!(f, "it could not be opened ({e})"),
            Refusal::NotOwners => {
                f.write_str("it does not belong to the owner of the folder being checked")
            }
        }
    }
}

impl Root {
    /// `None` when the folder does not exist or cannot be resolved.
    pub fn new(dir: &Path) -> Option<Root> {
        std::fs::canonicalize(dir).ok().map(|real| Root { real })
    }

    /// Opens `path` for reading if it is, or resolves to, a regular file inside this folder.
    /// `Ok(None)` when nothing is there. Never blocks on a pipe, and decides from the open
    /// descriptor rather than from the path a second time.
    pub fn try_open(&self, path: &Path) -> Result<Option<File>, Refusal> {
        match std::fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Refusal::Unreadable(e)),
            Ok(_) => {}
        }
        // Resolve every link, in the file name and in the folders above it, then require the
        // result to be inside the folder. A dangling link resolves to nothing and is refused.
        let target = match std::fs::canonicalize(path) {
            Ok(target) => target,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(Refusal::Unreadable(e))
            }
            Err(_) => return Err(Refusal::LeavesRoot),
        };
        if !target.starts_with(&self.real) {
            return Err(Refusal::LeavesRoot);
        }
        let file = open_regular_nofollow(&target).map_err(|e| {
            // ELOOP: the resolved name became a link between the two calls.
            if e.raw_os_error() == Some(libc_eloop()) {
                Refusal::LeavesRoot
            } else {
                Refusal::Unreadable(e)
            }
        })?;
        let meta = file.metadata().map_err(Refusal::Unreadable)?;
        // Decided from the descriptor: a pipe, socket, device or folder is never read.
        if !meta.is_file() {
            return Err(Refusal::NotRegular);
        }
        if !descriptor_allowed(&file, &meta, &self.real) {
            return Err(Refusal::NotOwners);
        }
        Ok(Some(file))
    }

    /// [`Root::try_open`] in the shape collectors use.
    pub fn open(&self, path: &Path) -> HomeFile<File> {
        match self.try_open(path) {
            Ok(Some(file)) => HomeFile::Found(file),
            Ok(None) => HomeFile::Missing,
            Err(_) => HomeFile::Refused,
        }
    }
}

#[cfg(unix)]
fn libc_eloop() -> i32 {
    libc::ELOOP
}

#[cfg(not(unix))]
fn libc_eloop() -> i32 {
    -1
}

/// Opens a system file (one outside any home, such as `/etc/gitconfig`) if it is a regular file.
/// Links are followed, because those folders belong to root; the open never blocks on a pipe.
pub fn open_system_file(path: &Path) -> HomeFile<File> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HomeFile::Missing,
        Err(_) => return HomeFile::Refused,
        Ok(_) => {}
    }
    match open_nonblocking(path, false) {
        Ok(file) if file.metadata().is_ok_and(|m| m.is_file()) => HomeFile::Found(file),
        _ => HomeFile::Refused,
    }
}

/// At most `cap` bytes from the start of the file, as text (invalid UTF-8 is replaced).
pub fn read_start(mut file: File, cap: u64) -> Option<String> {
    let mut buf = Vec::new();
    (&mut file).take(cap).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// How much of a skipped prefix is worth reading just to keep line numbers exact.
const MAX_LINE_COUNT_PREFIX: u64 = 64 * 1024 * 1024;

/// At most `cap` bytes from the end of the file (where a growing file keeps its newest content),
/// as text, with the 1-based line number that text starts at. The line number is `None` when the
/// skipped part is too large to count: a sparse file can claim any size, and reading terabytes of
/// holes to number lines would stall the scan.
pub fn read_end(mut file: File, cap: u64) -> Option<(String, Option<usize>)> {
    let len = file.metadata().ok()?.len();
    let skip = len.saturating_sub(cap);
    let mut first_line = Some(1usize);
    if skip > MAX_LINE_COUNT_PREFIX {
        first_line = None;
    } else if skip > 0 {
        let mut chunk = vec![0u8; 64 * 1024];
        let mut left = skip;
        let mut lines = 1usize;
        while left > 0 {
            let want = chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX));
            let got = file.read(&mut chunk[..want]).ok()?;
            if got == 0 {
                break;
            }
            lines += chunk[..got].iter().filter(|b| **b == b'\n').count();
            left -= got as u64;
        }
        first_line = Some(lines);
    }
    file.seek(SeekFrom::Start(skip)).ok()?;
    let mut buf = Vec::new();
    (&mut file).take(cap).read_to_end(&mut buf).ok()?;
    Some((String::from_utf8_lossy(&buf).into_owned(), first_line))
}

/// Convenience: [`open_in_home`] then [`read_start`].
pub fn read_in_home(home: &Path, path: &Path, cap: u64) -> HomeFile<String> {
    match open_in_home(home, path) {
        HomeFile::Found(file) => match read_start(file, cap) {
            Some(text) => HomeFile::Found(text),
            None => HomeFile::Refused,
        },
        HomeFile::Missing => HomeFile::Missing,
        HomeFile::Refused => HomeFile::Refused,
    }
}

#[cfg(unix)]
fn open_nonblocking(path: &Path, nofollow: bool) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NONBLOCK: opening a FIFO with no writer returns at once, and the descriptor check then
    // rejects it. It has no effect on a regular file.
    let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
}

#[cfg(not(unix))]
fn open_nonblocking(path: &Path, _nofollow: bool) -> std::io::Result<File> {
    File::open(path)
}

/// The already-resolved path, so its last component must not be a link any more.
fn open_regular_nofollow(target: &Path) -> std::io::Result<File> {
    open_nonblocking(target, true)
}

/// Under a root scan, the path was resolved before the open, so it could have been swapped in
/// between. Ask the kernel where the open descriptor really is, and require the file to belong to
/// the home's owner (a hard link to someone else's file fails that). An unprivileged scan can only
/// open what its own user may read, so there is nothing to gain by racing it.
#[cfg(unix)]
fn descriptor_allowed(file: &File, meta: &std::fs::Metadata, home_real: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return true;
    }
    let Ok(home_meta) = std::fs::metadata(home_real) else {
        return false;
    };
    if meta.uid() != home_meta.uid() {
        return false;
    }
    match descriptor_path(file) {
        Some(real) => {
            real.starts_with(home_real)
                || std::fs::canonicalize(&real).is_ok_and(|r| r.starts_with(home_real))
        }
        // No way to ask on this system: as root, do not read what cannot be verified.
        None => false,
    }
}

#[cfg(not(unix))]
fn descriptor_allowed(_file: &File, _meta: &std::fs::Metadata, _home_real: &Path) -> bool {
    true
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn descriptor_path(file: &File) -> Option<PathBuf> {
    use std::os::unix::io::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()
}

#[cfg(target_os = "macos")]
fn descriptor_path(file: &File) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::io::AsRawFd;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes, NUL-terminated, into the buffer given.
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return None;
    }
    let len = buf.iter().position(|b| *b == 0)?;
    buf.truncate(len);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_os = "macos"))
))]
fn descriptor_path(_file: &File) -> Option<PathBuf> {
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    const CAP: u64 = 4 * 1024 * 1024;

    fn text(home: &Path, rel: &str) -> HomeFile<String> {
        read_in_home(home, &home.join(rel), CAP)
    }

    #[test]
    fn a_regular_file_and_links_that_stay_inside_home_are_read() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join("dotfiles/config/tool")).unwrap();
        std::fs::write(home.path().join("plain"), "one").unwrap();
        std::fs::write(home.path().join("dotfiles/npmrc"), "two").unwrap();
        std::fs::write(home.path().join("dotfiles/config/tool/conf"), "three").unwrap();
        // A linked file, and a linked folder above the file (how stow links ~/.config).
        symlink(
            home.path().join("dotfiles/npmrc"),
            home.path().join(".npmrc"),
        )
        .unwrap();
        symlink(
            home.path().join("dotfiles/config"),
            home.path().join(".config"),
        )
        .unwrap();
        assert_eq!(text(home.path(), "plain").found().as_deref(), Some("one"));
        assert_eq!(text(home.path(), ".npmrc").found().as_deref(), Some("two"));
        assert_eq!(
            text(home.path(), ".config/tool/conf").found().as_deref(),
            Some("three")
        );
        assert!(matches!(text(home.path(), "absent"), HomeFile::Missing));
    }

    #[test]
    fn links_that_leave_home_are_refused_at_any_depth() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join(".aws")).unwrap();
        std::fs::write(outside.path().join(".aws/credentials"), "secret").unwrap();
        std::fs::write(outside.path().join("file"), "secret").unwrap();
        // The file itself, a folder above it, and a dangling link.
        symlink(outside.path().join("file"), home.path().join(".netrc")).unwrap();
        symlink(outside.path().join(".aws"), home.path().join(".aws")).unwrap();
        symlink(home.path().join("nowhere"), home.path().join(".dangling")).unwrap();
        assert!(matches!(text(home.path(), ".netrc"), HomeFile::Refused));
        assert!(matches!(
            text(home.path(), ".aws/credentials"),
            HomeFile::Refused
        ));
        assert!(matches!(text(home.path(), ".dangling"), HomeFile::Refused));
    }

    #[test]
    fn a_pipe_or_a_folder_is_refused_without_blocking() {
        let home = tempfile::tempdir().unwrap();
        let fifo = home.path().join(".bunfig.toml");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        std::fs::create_dir(home.path().join(".npmrc")).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            text(home.path(), ".bunfig.toml"),
            HomeFile::Refused
        ));
        assert!(matches!(text(home.path(), ".npmrc"), HomeFile::Refused));
        assert!(matches!(open_system_file(&fifo), HomeFile::Refused));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "must not wait on a pipe"
        );
    }

    #[test]
    fn the_tail_is_read_with_true_line_numbers_and_huge_files_are_not_walked() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("history");
        std::fs::write(&path, "a\nb\nc\nd\ne\n").unwrap();
        let file = open_in_home(home.path(), &path).found().unwrap();
        // The last 4 bytes are "d\ne\n", which start on line 4.
        assert_eq!(read_end(file, 4), Some(("d\ne\n".to_string(), Some(4))));

        // A sparse file claiming far more than is worth counting: the tail is still read, at once.
        let big = home.path().join("sparse");
        let f = File::create(&big).unwrap();
        f.set_len(MAX_LINE_COUNT_PREFIX + 10 * 1024 * 1024).unwrap();
        drop(f);
        let started = std::time::Instant::now();
        let (tail, line) =
            read_end(open_in_home(home.path(), &big).found().unwrap(), 1024).unwrap();
        assert_eq!((tail.len(), line), (1024, None));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }
}
