//! Which application sandbox, if any, this process is running inside.
//!
//! Several features depend on things a sandbox does not provide, and the honest response
//! differs per sandbox rather than being one generic "unavailable". Getting this wrong is
//! worse than saying nothing: the antivirus tab told Flatpak users to `sudo apt install
//! clamav`, which they can do, after which nothing changes — the sandbox still cannot see a
//! host binary. Advice that cannot work is worse than an admission that a feature is not
//! available here.
//!
//! Detection is by the markers each runtime documents for exactly this purpose:
//!   * Flatpak — `/.flatpak-info` exists inside every sandbox and nowhere else.
//!   * Snap    — `$SNAP` is set by snapd for every confinement level.

use std::path::Path;

/// The application sandbox this process is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    /// Ordinary install (.deb/.rpm/AppImage/AUR/COPR/cargo) — nothing between us and the host.
    None,
    Flatpak,
    /// A snap. Note this covers *classic* confinement too, which can see host paths; the
    /// distinction that matters here is that a snap's own `$PATH` and libraries come from
    /// the snap, so a host tool is not automatically usable.
    Snap,
}

impl Sandbox {
    /// Human-readable name, for messages the user reads.
    pub fn name(self) -> &'static str {
        match self {
            Sandbox::None => "native",
            Sandbox::Flatpak => "Flatpak",
            Sandbox::Snap => "Snap",
        }
    }

    pub fn is_sandboxed(self) -> bool {
        !matches!(self, Sandbox::None)
    }
}

/// Detect the current sandbox.
pub fn detect() -> Sandbox {
    if Path::new("/.flatpak-info").exists() {
        return Sandbox::Flatpak;
    }
    // SNAP is set to the snap's mount point for every confinement level. Checking a second
    // snapd-specific variable avoids a false positive from a stray SNAP in someone's shell.
    if std::env::var_os("SNAP").is_some() && std::env::var_os("SNAP_NAME").is_some() {
        return Sandbox::Snap;
    }
    Sandbox::None
}

/// What to tell the user when a host tool (ClamAV, `pkexec`) is unavailable.
///
/// Returns `None` when not sandboxed, meaning "the ordinary install instructions apply".
pub fn unavailable_reason(tool: &str) -> Option<String> {
    match detect() {
        Sandbox::None => None,
        Sandbox::Flatpak => Some(format!(
            "{tool} can't be reached from inside the Flatpak sandbox, and installing it on \
             the host won't change that — the sandbox has its own filesystem. Use the .deb, \
             .rpm or AppImage build, or the bulwarkctl command-line tool, for this feature."
        )),
        Sandbox::Snap => Some(format!(
            "{tool} isn't available to this snap. Use the .deb, .rpm or AppImage build, or \
             the bulwarkctl command-line tool, for this feature."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_gives_no_sandbox_excuse() {
        // The reason text exists only to explain a sandbox limitation. On a normal install
        // there is no limitation to explain, and returning one would send users chasing a
        // packaging problem they do not have.
        if detect() == Sandbox::None {
            assert!(unavailable_reason("ClamAV").is_none());
        }
    }

    #[test]
    fn sandbox_names_are_user_facing_words() {
        assert_eq!(Sandbox::Flatpak.name(), "Flatpak");
        assert_eq!(Sandbox::Snap.name(), "Snap");
        assert!(Sandbox::Flatpak.is_sandboxed());
        assert!(!Sandbox::None.is_sandboxed());
    }
}
