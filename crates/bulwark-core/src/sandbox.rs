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

/// Build a [`Command`] that runs `program` **on the host** when that is necessary.
///
/// Outside a sandbox this is just `Command::new(program)`. Inside a Flatpak it becomes
/// `flatpak-spawn --host program …`, which asks the Flatpak portal to run the program in the
/// user's normal session. That is how a sandboxed app reaches a tool the sandbox does not
/// contain — ClamAV being the case here: the engine and its ~250 MB signature database live
/// on the host, are updated there by the distribution, and bundling a second copy inside the
/// Flatpak would mean shipping and version-tracking an AV engine plus a database that is
/// stale the day it ships.
///
/// This requires `--talk-name=org.freedesktop.Flatpak` in the manifest. It is a real
/// widening of the sandbox and should stay limited to tools that genuinely cannot live
/// inside it. Precedent: flathub/io.github.linx_systems.ClamUI, a published ClamAV GUI,
/// ships exactly this permission (alongside a broader `--filesystem=host` than Bulwark's
/// read-only one) for the same reason.
///
/// Snap is deliberately NOT rewritten: a classic snap already runs with host filesystem
/// access, so a host binary resolves normally, and a strict snap has no equivalent escape.
pub fn host_command(program: &str) -> std::process::Command {
    if detect() == Sandbox::Flatpak {
        let mut cmd = std::process::Command::new("flatpak-spawn");
        cmd.arg("--host").arg(program);
        return cmd;
    }
    std::process::Command::new(program)
}

/// Whether reaching host tools is actually possible from here.
///
/// Inside a Flatpak this depends on a permission the manifest may not have been granted, so
/// it is probed rather than assumed: without `--talk-name=org.freedesktop.Flatpak` the
/// `flatpak-spawn` call fails, and the honest UI response ("this build cannot reach ClamAV")
/// differs from the one when the host simply has no ClamAV installed ("install it").
/// Confusing those two is what sent users to run an install command that changed nothing.
pub fn can_reach_host() -> bool {
    match detect() {
        Sandbox::None => true,
        Sandbox::Snap => true,
        Sandbox::Flatpak => std::process::Command::new("flatpak-spawn")
            .arg("--host")
            .arg("true")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false),
    }
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
