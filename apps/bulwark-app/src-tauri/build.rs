use std::path::PathBuf;

fn main() {
    stage_cli_sidecar();
    tauri_build::build()
}

/// Stages the `bulwarkctl` CLI as a Tauri `externalBin` sidecar.
///
/// Tauri expects the sidecar at `binaries/bulwarkctl-<target-triple>`, and its own build step
/// hard-errors if that file is missing — which would break a plain `cargo build`/`cargo test` of
/// this crate (and CI) even when nobody is bundling. So on every build we copy the
/// already-built `bulwarkctl` from the workspace target dir into place; if it hasn't been built
/// yet we drop a zero-byte placeholder so compilation still succeeds, and warn.
///
/// This is why the release build order matters: `cargo build -p bulwarkctl --release` **before**
/// bundling the app, so a real binary — not the placeholder — ends up in the `.deb`/`.rpm`/AppImage.
/// Bundling the CLI beside the GUI is what lets "Run privileged checks" work from a GUI-only
/// install (the desktop package and the single-file AppImage both lack a `bulwarkctl` on PATH);
/// `resolve_cli_binary` finds this sidecar next to the running executable.
fn stage_cli_sidecar() {
    let triple = std::env::var("TARGET").unwrap_or_default();
    if triple.is_empty() {
        return;
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let binaries_dir = manifest_dir.join("binaries");
    let dest = binaries_dir.join(format!("bulwarkctl-{triple}"));
    let _ = std::fs::create_dir_all(&binaries_dir);

    // The workspace target dir is `<workspace>/target`; from `apps/bulwark-app/src-tauri` that's
    // three levels up. Prefer a release build, fall back to debug.
    let workspace_target = manifest_dir.join("..").join("..").join("..").join("target");
    let source = ["release", "debug"]
        .iter()
        .map(|p| workspace_target.join(p).join("bulwarkctl"))
        .find(|p| p.is_file());

    if let Some(src) = source {
        if std::fs::copy(&src, &dest).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
            }
            println!("cargo:rerun-if-changed={}", src.display());
            return;
        }
    }

    // No built CLI to stage. Keep an existing real sidecar if one is already there; otherwise
    // write a placeholder so this crate still compiles, and warn that a bundle built now would
    // ship a non-functional CLI.
    if !dest.exists() {
        let _ = std::fs::write(&dest, b"");
        println!(
            "cargo:warning=bulwarkctl sidecar not found — staged an empty placeholder at {}. \
             Run `cargo build -p bulwarkctl --release` before bundling so a real CLI ships.",
            dest.display()
        );
    }
}
