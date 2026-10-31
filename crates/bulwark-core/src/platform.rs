//! The few host primitives that differ between Unix and Windows, in one place so the rest of the
//! core compiles everywhere. Unix permission bits have no Windows equivalent (NTFS uses ACLs), so
//! on Windows the mode is reported as unknown rather than guessed: callers omit the fact and the
//! rule reports it as undetermined, never as "fine".

use std::fs::Metadata;
use std::path::Path;

/// The Unix permission bits of `meta`, or `None` where the platform has no such concept.
pub fn file_mode(meta: &Metadata) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(meta.permissions().mode())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// Sets the Unix permission bits of `path`. On platforms without them this fails with
/// `Unsupported` instead of silently succeeding, so a remediation can never report a change it
/// did not make.
pub fn set_file_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Unix file modes are not supported on this platform",
        ))
    }
}

/// True when running with an effective UID of 0. Windows elevation is not detected yet, so there
/// this is always false and privileged collectors are reported as skipped, not run.
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}
