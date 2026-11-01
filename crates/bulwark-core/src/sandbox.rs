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
    let mut cmd = std::process::Command::new(program);
    no_console(&mut cmd);
    host_env(&mut cmd);
    cmd
}

/// A new [`Command`] for `program` that never opens a console window. On Windows a GUI process
/// that spawns a console program (PowerShell, `cmd`, `git`, the CLI sidecar) gets a terminal
/// window flashing up for each one — on every scan and every background tick — unless the child is
/// created with `CREATE_NO_WINDOW`. Elsewhere this is plain `Command::new`.
///
/// It also runs `program` with the host's environment, not an AppImage's — see [`host_env`]. Every
/// system tool Bulwark starts (`sha256sum`, `systemctl`, `git`, `ssh`, the CLI sidecar) should be
/// created through this or [`host_command`], never a bare `Command::new`.
pub fn quiet_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    no_console(&mut cmd);
    host_env(&mut cmd);
    cmd
}

/// Inside an AppImage, removes the AppImage's own paths from a child's environment, so a system
/// tool runs against the system's libraries and data.
///
/// An AppImage starts the app with `LD_LIBRARY_PATH` (and GTK/GIO/GDK/XDG variables) pointing into
/// its mount, so the bundled libraries win. Children inherit that. The app's bundled libraries come
/// from its build image (Ubuntu 22.04), and a newer system tool linked against a newer version of
/// one of them then fails to start: on a current Ubuntu, `sha256sum` died with
/// "libsystemd.so.0: version `LIBSYSTEMD_254' not found" and every file-integrity check reported
/// "could not verify". Any check that runs a system program was exposed the same way.
///
/// Every variable is filtered, not a fixed list: each `:`-separated entry inside `$APPDIR` is
/// dropped, and a variable left empty is removed. The AppImage's own markers (`APPDIR`,
/// `APPIMAGE`, `ARGV0`, `OWD`) are kept. Outside an AppImage this does nothing.
pub fn host_env(cmd: &mut std::process::Command) -> &mut std::process::Command {
    let Some(appdir) = std::env::var_os("APPDIR").filter(|d| !d.is_empty()) else {
        return cmd;
    };
    for (key, value) in bundle_env_fixes(&appdir.to_string_lossy(), std::env::vars_os()) {
        match value {
            Some(v) => cmd.env(key, v),
            None => cmd.env_remove(key),
        };
    }
    cmd
}

/// The environment changes [`host_env`] makes: `(variable, Some(new value) | None to remove)`.
/// Pure, so it is tested without being inside an AppImage.
fn bundle_env_fixes(
    appdir: &str,
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Vec<(std::ffi::OsString, Option<String>)> {
    const KEEP: &[&str] = &["APPDIR", "APPIMAGE", "ARGV0", "OWD"];
    let appdir = appdir.trim_end_matches('/');
    if appdir.is_empty() {
        return Vec::new();
    }
    let inside = |entry: &str| entry == appdir || entry.starts_with(&format!("{appdir}/"));
    let mut fixes = Vec::new();
    for (key, value) in vars {
        if KEEP.iter().any(|k| key == *k) {
            continue;
        }
        let Some(value) = value.to_str() else {
            continue;
        };
        if !value.contains(appdir) {
            continue;
        }
        let kept: Vec<&str> = value
            .split(':')
            .filter(|e| !e.is_empty() && !inside(e))
            .collect();
        if kept.len() == value.split(':').filter(|e| !e.is_empty()).count() {
            continue; // mentions the path only in passing, not as an entry — leave it alone
        }
        fixes.push((
            key,
            if kept.is_empty() {
                None
            } else {
                Some(kept.join(":"))
            },
        ));
    }
    fixes
}

/// Applies `CREATE_NO_WINDOW` on Windows; a no-op on every other OS.
pub fn no_console(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
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
    use std::ffi::OsString;

    fn fixes(vars: &[(&str, &str)]) -> Vec<(String, Option<String>)> {
        super::bundle_env_fixes(
            "/tmp/.mount_bulwarkX",
            vars.iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        )
        .into_iter()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v))
        .collect()
    }

    #[test]
    fn appimage_paths_are_removed_from_a_childs_environment() {
        let got = fixes(&[
            (
                "LD_LIBRARY_PATH",
                "/tmp/.mount_bulwarkX/usr/lib:/tmp/.mount_bulwarkX/usr/lib/x86_64-linux-gnu",
            ),
            (
                "XDG_DATA_DIRS",
                "/tmp/.mount_bulwarkX/usr/share:/usr/local/share:/usr/share",
            ),
            ("PATH", "/tmp/.mount_bulwarkX/usr/bin:/usr/bin:/bin"),
            (
                "GDK_PIXBUF_MODULE_FILE",
                "/tmp/.mount_bulwarkX/usr/lib/gdk-pixbuf/loaders.cache",
            ),
            ("HOME", "/home/u"),
            ("APPDIR", "/tmp/.mount_bulwarkX"),
            ("APPIMAGE", "/home/u/Bulwark.AppImage"),
            // A look-alike prefix is not inside the mount.
            ("SOMETHING", "/tmp/.mount_bulwarkXYZ/lib"),
        ]);
        assert_eq!(
            got,
            vec![
                ("LD_LIBRARY_PATH".into(), None),
                (
                    "XDG_DATA_DIRS".into(),
                    Some("/usr/local/share:/usr/share".into())
                ),
                ("PATH".into(), Some("/usr/bin:/bin".into())),
                ("GDK_PIXBUF_MODULE_FILE".into(), None),
            ]
        );
    }

    #[test]
    fn outside_an_appimage_nothing_changes() {
        assert!(super::bundle_env_fixes(
            "",
            [(
                OsString::from("LD_LIBRARY_PATH"),
                OsString::from("/opt/x/lib")
            )]
        )
        .is_empty());
    }

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
