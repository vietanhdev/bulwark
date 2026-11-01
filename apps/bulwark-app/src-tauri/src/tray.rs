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

    // A symbolic white glyph, not the full-colour app icon: the GNOME/Ubuntu top bar draws status
    // icons as white symbols, and the app icon squeezed to panel size read as a dark blob there.
    // Raw RGBA (rendered by scripts/render-app-icons.py from icons/tray-icon.svg) so no image
    // decoder crate is needed.
    const TRAY_SIZE: u32 = 64;
    const TRAY_RGBA: &[u8] = include_bytes!("../icons/tray-icon.rgba");
    let icon = tauri::image::Image::new_owned(TRAY_RGBA.to_vec(), TRAY_SIZE, TRAY_SIZE);

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
