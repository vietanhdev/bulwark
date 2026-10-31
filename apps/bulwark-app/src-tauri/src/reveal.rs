//! Let the user jump from a finding to the file it flagged.
//!
//! When the AI scan reports something like "an instruction file contains prompt-injection style
//! directives — confirm by reading line 80", the natural next step is to *go read line 80*. These
//! commands open that file (in the OS default app) or reveal it in the file manager, so the user can
//! verify a heuristic finding themselves rather than take it on faith. Copying the path is done
//! entirely in the webview (`navigator.clipboard`) and needs no backend.
//!
//! This uses the already-linked opener plugin's Rust API directly, which performs the open without
//! the JS-side scope gate — appropriate here because the path always comes from a finding Bulwark
//! itself produced by scanning the user's own files, never from arbitrary web content.

use std::path::Path;
use tauri_plugin_opener::OpenerExt;

/// Whether this process is running inside a Flatpak sandbox.
///
/// `/.flatpak-info` is present in every Flatpak sandbox and nowhere else, which is the check
/// Flatpak itself documents for this purpose.
fn in_flatpak_sandbox() -> bool {
    Path::new("/.flatpak-info").exists()
}

/// Hand `path` to the sandbox's `xdg-open`, which is Flatpak's portal shim.
///
/// Inside a sandbox the opener plugin's normal route fails. It asks the OpenURI portal to open a
/// `file://` URI, and xdg-desktop-portal refuses that from a sandboxed caller — sandboxed apps
/// must use `OpenFile` and pass a *file descriptor*, so the app cannot name a host path it has no
/// right to. The refusal surfaces as:
///
///   GDBus.Error:org.freedesktop.portal.Error.NotAllowed: This call is not available inside the sandbox
///
/// Flatpak's `/usr/bin/xdg-open` is exactly the shim for this: it opens the file itself and passes
/// the descriptor, so it works for both files and directories with no extra permission. Note this
/// applies to plain *opening* too, not only revealing — an earlier fix that redirected "reveal" to
/// open the parent directory did not help, because it went through the same rejected call.
fn open_via_portal_shim(path: &str) -> Result<(), String> {
    let status = std::process::Command::new("xdg-open")
        .arg(path)
        .status()
        .map_err(|e| format!("couldn't launch xdg-open for {path}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "couldn't open {path} (xdg-open exited with {status})"
        ))
    }
}

/// Open `path` in the system default application (`reveal = false`), or highlight it in the file
/// manager (`reveal = true`). Returns a readable error string on failure so the UI can surface it
/// instead of failing silently.
///
/// Revealing also has no sandbox route of its own: `reveal_item_in_dir` calls
/// `org.freedesktop.FileManager1.ShowItems` on the session bus, which the sandbox answers with
/// `ServiceUnknown` because the app may not talk to that name. Granting
/// `--talk-name=org.freedesktop.FileManager1` would fix it, but that is a broad permission to ask
/// Flathub reviewers for so one button can highlight a file. Opening the containing *directory*
/// instead lands the user in the same folder, which is what "show in folder" means anyway.
#[tauri::command]
pub fn open_flagged_file(app: tauri::AppHandle, path: String, reveal: bool) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("no file path on this finding".into());
    }
    if in_flatpak_sandbox() {
        let target = if reveal {
            Path::new(&path)
                .parent()
                .ok_or_else(|| format!("{path} has no containing folder"))?
                .to_string_lossy()
                .to_string()
        } else {
            path.clone()
        };
        return open_via_portal_shim(&target);
    }
    if reveal {
        app.opener()
            .reveal_item_in_dir(&path)
            .map_err(|e| format!("couldn't reveal {path}: {e}"))
    } else {
        app.opener()
            .open_path(path.clone(), None::<&str>)
            .map_err(|e| format!("couldn't open {path}: {e}"))
    }
}

/// The website page for a check, built from the rule ID alone so this command can never be used
/// to open an arbitrary URL: anything that isn't shaped like `BLWK-<AREA>-<NNN>` is refused.
fn check_page_url(rule_id: &str) -> Option<String> {
    let mut parts = rule_id.split('-');
    let (prefix, area, num) = (parts.next()?, parts.next()?, parts.next()?);
    let valid = prefix == "BLWK"
        && parts.next().is_none()
        && !area.is_empty()
        && area.len() <= 12
        && area.chars().all(|c| c.is_ascii_uppercase())
        && num.len() == 3
        && num.chars().all(|c| c.is_ascii_digit());
    valid.then(|| {
        format!(
            "https://bulwark.nrl.ai/checks/{}",
            rule_id.to_ascii_lowercase()
        )
    })
}

/// Opens a check's explanation page on the Bulwark website in the default browser. Inside Flatpak
/// an https URL goes through the OpenURI portal, which (unlike `file://`) sandboxed apps may use.
#[tauri::command]
pub fn open_check_page(app: tauri::AppHandle, rule_id: String) -> Result<(), String> {
    let url =
        check_page_url(&rule_id).ok_or_else(|| format!("{rule_id} is not a Bulwark rule ID"))?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| format!("couldn't open the check page: {e}"))
}

#[cfg(test)]
mod tests {
    use super::check_page_url;

    #[test]
    fn check_page_url_accepts_rule_ids_only() {
        assert_eq!(
            check_page_url("BLWK-SSH-012").as_deref(),
            Some("https://bulwark.nrl.ai/checks/blwk-ssh-012")
        );
        assert_eq!(
            check_page_url("BLWK-ROOTKIT-002").as_deref(),
            Some("https://bulwark.nrl.ai/checks/blwk-rootkit-002")
        );
        for bad in [
            "",
            "BLWK-SSH-12",
            "BLWK-ssh-012",
            "BLWK-SSH-012-x",
            "BLWK-SSH-012/../../evil",
            "https://evil.example",
            "BLWK--012",
            "XBLWK-SSH-012",
        ] {
            assert_eq!(check_page_url(bad), None, "{bad:?} must be refused");
        }
    }
}
