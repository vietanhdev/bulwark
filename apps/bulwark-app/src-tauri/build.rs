use std::path::PathBuf;

fn main() {
    stage_cli_sidecar();
    tauri_build::build()
}

/// Stages the `bulwarkctl` CLI as a Tauri `externalBin` sidecar, under the name `bulwark-cli`.
///
/// The rename is load-bearing, not cosmetic. Tauri copies a staged sidecar back out next to the
/// app binary — i.e. into `target/<profile>/`. When the sidecar was called `bulwarkctl` that
/// landed *exactly on top of* the CLI crate's own build output, `target/debug/bulwarkctl`. Since
/// nothing orders this build script against the `bulwarkctl` crate's build, which file won the
/// race varied between runs, and `cargo test --workspace` intermittently executed a stale binary
/// (the failure that `crates/bulwarkctl/tests/ai_cli.rs` kept tripping over). A sidecar that
/// doesn't share a filename with a workspace binary cannot clobber one.
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
    let dest = binaries_dir.join(format!("bulwark-cli-{triple}"));
    let _ = std::fs::create_dir_all(&binaries_dir);

    // The workspace target dir is `<workspace>/target`; from `apps/bulwark-app/src-tauri` that's
    // three levels up.
    //
    // Stage the CLI from **the profile currently being built**, falling back to the other only if
    // that one doesn't exist yet. This used to unconditionally prefer `release`, which was a real
    // bug rather than a preference: Tauri copies the staged `externalBin` back out next to the app
    // binary (`target/debug/bulwarkctl`), so a debug build would take a stale, possibly
    // months-old `target/release/bulwarkctl` and *overwrite the freshly-compiled debug CLI with
    // it*. Every `cargo test --workspace` then ran the old binary — which is exactly how
    // `tests/ai_cli.rs` caught this, failing with "unrecognized subcommand 'ai'" against a CLI
    // that demonstrably had the subcommand.
    let workspace_target = manifest_dir.join("..").join("..").join("..").join("target");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let preferred: [&str; 2] = if profile == "release" {
        ["release", "debug"]
    } else {
        ["debug", "release"]
    };
    let source = preferred
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
            "cargo:warning=bulwark-cli sidecar not found — staged an empty placeholder at {}. \
             Run `cargo build -p bulwarkctl --release` before bundling so a real CLI ships.",
            dest.display()
        );
    }
}
