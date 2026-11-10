//! Root, reached through `sudo` or `pkexec`, only uses a database no other account can write to.
//!
//! A root process that opens a SQLite file from a folder its owner controls is parsing input that
//! account chose: the database, its `-wal` and `-shm` side files, and whatever a swapped folder
//! puts in their place. With a preserved `HOME` (`sudo -E`, or macOS, where `sudo` keeps it) the
//! default database is exactly such a file. This module answers one question, without opening
//! anything: could an account other than `trusted_uid` (or root) change what would be read?

use std::path::{Path, PathBuf};

/// SQLite's own files for a database at `db`.
fn sqlite_files(db: &Path) -> Vec<PathBuf> {
    let mut files = vec![db.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = db.as_os_str().to_os_string();
        name.push(suffix);
        files.push(PathBuf::from(name));
    }
    files
}

/// Why the database at `db` could be changed by an account other than `trusted_uid` or root, or
/// `None` when it cannot. The file does not have to exist yet.
///
/// Three things are checked. The database and its side files, when present, must be regular files
/// owned by a trusted account and writable by nobody else. The nearest existing folder above the
/// database must be owned by a trusted account and writable by nobody else, sticky or not: files
/// SQLite creates later (`-wal`) land there, and a shared folder lets anyone create them first.
/// Every folder above that must be owned by a trusted account, and may be writable by others only
/// with the sticky bit (`/tmp`), where the entry on our path cannot be replaced.
///
/// Anything that cannot be examined counts as exposed.
pub fn exposure(db: &Path, trusted_uid: u32) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let trusted = |uid: u32| uid == trusted_uid || uid == 0;
    let abs = match std::path::absolute(db) {
        Ok(p) => p,
        Err(_) => return Some(format!("{} could not be resolved", db.display())),
    };

    for file in sqlite_files(&abs) {
        match std::fs::symlink_metadata(&file) {
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    return Some(format!("{} is not a regular file", file.display()));
                }
                if !trusted(meta.uid()) || meta.mode() & 0o022 != 0 {
                    return Some(format!(
                        "{} can be written by another account",
                        file.display()
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Some(format!("{} could not be checked", file.display())),
        }
    }

    // The nearest folder that exists; the ones below it are created by this process.
    let mut nearest = abs.parent()?;
    while std::fs::symlink_metadata(nearest).is_err() {
        nearest = nearest.parent()?;
    }
    // Resolved first, so a link is judged by the folders it really leads through.
    let Ok(real) = nearest.canonicalize() else {
        return Some(format!("{} could not be checked", nearest.display()));
    };
    for (depth, folder) in real.ancestors().enumerate() {
        let Ok(meta) = std::fs::metadata(folder) else {
            return Some(format!("{} could not be checked", folder.display()));
        };
        let shared = meta.mode() & 0o022 != 0;
        let sticky = meta.mode() & 0o1000 != 0;
        let exposed = !meta.is_dir() || !trusted(meta.uid()) || (shared && (depth == 0 || !sticky));
        if exposed {
            return Some(format!(
                "the folder {} can be changed by another account",
                folder.display()
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// A private folder and the account that owns it (the tests' stand-in for root).
    fn private_dir() -> (tempfile::TempDir, u32) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let me = std::fs::metadata(dir.path()).unwrap().uid();
        (dir, me)
    }

    #[test]
    fn a_private_folder_is_safe_whether_or_not_the_database_exists_yet() {
        let (dir, me) = private_dir();
        let db = dir.path().join("bulwark.db");
        assert_eq!(exposure(&db, me), None);
        // Folders this process would create below a private one are safe too.
        assert_eq!(exposure(&dir.path().join("a/b/bulwark.db"), me), None);
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(exposure(&db, me), None);
    }

    #[test]
    fn a_folder_or_file_others_can_write_is_exposed() {
        let (dir, me) = private_dir();
        let db = dir.path().join("bulwark.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(exposure(&db, me).unwrap().contains("bulwark.db"));

        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(exposure(&db, me).unwrap().contains("folder"));
        // The sticky bit protects existing entries, not the side files SQLite has yet to create.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(exposure(&db, me).unwrap().contains("folder"));
    }

    #[test]
    fn a_side_file_that_is_a_link_is_exposed() {
        let (dir, me) = private_dir();
        let db = dir.path().join("bulwark.db");
        std::fs::write(dir.path().join("elsewhere"), b"").unwrap();
        std::os::unix::fs::symlink(
            dir.path().join("elsewhere"),
            dir.path().join("bulwark.db-wal"),
        )
        .unwrap();
        assert!(exposure(&db, me).unwrap().contains("bulwark.db-wal"));
    }

    #[test]
    fn a_database_in_another_accounts_folder_is_exposed() {
        let (dir, me) = private_dir();
        // Root owns everything it looks at, so this case cannot be staged while running as root.
        if me == 0 {
            return;
        }
        // Trusting only root, the way a `sudo` scan does: the folder belongs to someone else.
        let why = exposure(&dir.path().join("bulwark.db"), 0).unwrap();
        assert!(why.contains("folder"), "{why}");
    }

    #[test]
    fn a_link_to_a_shared_folder_is_judged_by_where_it_leads() {
        let (dir, me) = private_dir();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::os::unix::fs::symlink(&shared, dir.path().join("data")).unwrap();
        let why = exposure(&dir.path().join("data/bulwark.db"), me).unwrap();
        assert!(why.contains("shared"), "{why}");
    }
}
