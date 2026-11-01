//! Compiles the shipped content packs — `rules/`, `log-rules/`, `decoders/` — into the binary, so
//! `bulwarkctl` is a single file that works wherever it is copied: no install step, no rules
//! folder to keep beside it, and no chance of a binary running against an older pack left behind
//! by a previous install. The packs stay plain YAML in the repository and on disk in the packages;
//! this only adds a copy the binary carries with it.
//!
//! The generated file is a list of `(path relative to the pack, include_str!(absolute path))`, so
//! Cargo tracks every rule file as a dependency of the build and a rule edit rebuilds the binary.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

const PACKS: &[(&str, &str)] = &[
    ("EMBEDDED_RULES", "rules"),
    ("EMBEDDED_LOG_RULES", "log-rules"),
    ("EMBEDDED_DECODERS", "decoders"),
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../..");
    let mut out = String::new();

    for (name, dir) in PACKS {
        let pack = root.join(dir);
        println!("cargo:rerun-if-changed={}", pack.display());
        let mut files = Vec::new();
        if pack.is_dir() {
            collect(&pack, &pack, &mut files);
        } else {
            // Not fatal — the CLI still finds a pack on disk (`--rules-dir`, the env var) — but a
            // binary built this way is not self-contained, which must not go unnoticed.
            println!(
                "cargo:warning={} not found: this bulwarkctl has no built-in {dir} pack",
                pack.display()
            );
        }
        files.sort();
        let _ = writeln!(out, "pub static {name}: &[(&str, &str)] = &[");
        for (rel, abs) in &files {
            let _ = writeln!(out, "    ({rel:?}, include_str!({abs:?})),");
        }
        let _ = writeln!(out, "];");
    }

    let dest = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("embedded_packs.rs");
    std::fs::write(dest, out).expect("write embedded_packs.rs");
}

/// Every `.yaml`/`.yml` under `dir`, as `(path relative to the pack with '/' separators, absolute
/// path)`. Symlinks are not followed: the pack is the repository's own files.
fn collect(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect(base, &path, out);
        } else if kind.is_file()
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yaml") | Some("yml")
            )
        {
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let abs = path.to_string_lossy().into_owned();
            out.push((rel, abs));
        }
    }
}
