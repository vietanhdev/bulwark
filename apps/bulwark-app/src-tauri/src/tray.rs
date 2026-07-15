//! System tray integration — what actually makes "continuous monitoring" continuous in
//! practice. Without this, closing the window quits the whole process, including the
//! background monitoring loop and file watcher (`monitoring.rs`), which would make every
//! claim about periodic re-scanning dishonest the moment a user closes the window like any
//! other app. Closing the window now hides it instead; the process (and monitoring) keeps
//! running, with the tray icon as the one visible sign that it's still there. Quitting is a
//! deliberate, explicit action (tray menu → Quit), not an accidental side effect of an
//! ordinary window-manager close click.

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};

pub fn spawn(app: &AppHandle) -> tauri::Result<()> {
    // No separator between the items on purpose: a `PredefinedMenuItem::separator` is a common
    // trouble spot for the GNOME/ayatana AppIndicator dbusmenu, where it can render the whole menu
    // empty or truncated. Two plain, always-enabled items are the most portable shape, and both are
    // load-bearing on Linux — the tray icon emits no click event there (Tauri's docs), so this menu
    // (right-click on GNOME) is the only in-tray way to reopen the window or quit.
    let show = MenuItem::with_id(app, "show", "Show Bulwark", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Bulwark", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or_else(|| tauri::Error::AssetNotFound("default window icon".into()))?;

    TrayIconBuilder::with_id("main")
        .icon(icon)
        .tooltip("Bulwark — continuous monitoring active")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            // A plain left-click (not the menu, which is a separate right-click/long-press
            // gesture handled by on_menu_event) is the conventional "bring the app back"
            // action for a tray icon — matches how most tray-resident apps behave.
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

pub fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
}
