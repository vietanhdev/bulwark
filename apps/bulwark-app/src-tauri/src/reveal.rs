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

use tauri_plugin_opener::OpenerExt;

/// Open `path` in the system default application (`reveal = false`), or highlight it in the file
/// manager (`reveal = true`). Returns a readable error string on failure so the UI can surface it
/// instead of failing silently.
#[tauri::command]
pub fn open_flagged_file(app: tauri::AppHandle, path: String, reveal: bool) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("no file path on this finding".into());
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
