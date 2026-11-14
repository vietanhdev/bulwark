// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Answered before GTK or WebKit start, so a package test (or a user over SSH, with no
    // display) can ask an installed build which version it is without opening a window.
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("bulwark-app {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    bulwark_app_lib::run();
}
