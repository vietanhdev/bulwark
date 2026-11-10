use std::sync::atomic::{AtomicBool, Ordering};
static BUSY: AtomicBool = AtomicBool::new(false);

struct RequestGuard;
impl Drop for RequestGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

/// The AWS Vault tab needs an aws-vault build with `list --json`, which upstream aws-vault does not
/// have. Until it does, the tab is a preview that exists only when this switch is set, so a normal
/// install never offers a manager that cannot work.
fn aws_vault_preview() -> bool {
    std::env::var_os("BULWARK_AWS_VAULT_PREVIEW").is_some_and(|v| v == "1")
}

#[tauri::command]
pub async fn access_aws_snapshot() -> Result<bulwark_access::Snapshot, bulwark_access::ReadError> {
    if !aws_vault_preview() {
        return Err(bulwark_access::ReadError::failed(
            "The AWS Vault preview is not turned on.",
        ));
    }
    if BUSY.swap(true, Ordering::Acquire) {
        return Err(bulwark_access::ReadError::failed(
            "A session refresh is already running.",
        ));
    }
    tauri::async_runtime::spawn_blocking(|| {
        let _guard = RequestGuard;
        let home = bulwark_core::paths::home_var_os().ok_or_else(|| {
            bulwark_access::ReadError::failed("Your home directory is unavailable.")
        })?;
        bulwark_access::read_aws_vault(std::path::Path::new(&home))
    })
    .await
    .map_err(|_| bulwark_access::ReadError::failed("Session refresh failed."))?
}

#[derive(serde::Serialize)]
pub struct Detected {
    id: &'static str,
    present: bool,
}

/// The managers `secrets_inventory` can read from files, in the order the app lists them.
const FILE_MANAGERS: &[&str] = &[
    "aws-cli",
    "docker",
    "git",
    "github-cli",
    "npm",
    "pypi",
    "kubernetes",
];

/// The managers this build offers, and whether each has files on this machine: existence checks
/// only, nothing is read. The app lists exactly these, so a manager missing here is not offered.
#[tauri::command]
pub fn secrets_detect() -> Vec<Detected> {
    let Some(home) = bulwark_core::paths::home_var_os() else {
        return Vec::new();
    };
    detect_in(std::path::Path::new(&home), aws_vault_preview())
}

fn detect_in(home: &std::path::Path, aws_vault: bool) -> Vec<Detected> {
    let mut found = Vec::new();
    if aws_vault {
        found.push(Detected {
            id: "aws-vault",
            present: bulwark_access::inventory::present(home, "aws-vault"),
        });
    }
    found.extend(FILE_MANAGERS.iter().map(|id| Detected {
        id,
        present: bulwark_access::inventory::present(home, id),
    }));
    found.push(Detected {
        id: "tool-tokens",
        present: !bulwark_core::collectors::token_files(home).is_empty(),
    });
    found
}

/// One manager's metadata inventory, read only when the user asks (never on load or in a scan).
#[tauri::command]
pub async fn secrets_inventory(
    provider: String,
) -> Result<bulwark_access::inventory::Inventory, bulwark_access::inventory::InventoryError> {
    tauri::async_runtime::spawn_blocking(move || {
        let home = bulwark_core::paths::home_var_os().ok_or(
            bulwark_access::inventory::InventoryError {
                code: "failed",
                message: "Your home directory is unavailable.",
            },
        )?;
        let home = std::path::Path::new(&home);
        if provider == "tool-tokens" {
            return tool_tokens(home);
        }
        bulwark_access::inventory::read(home, &provider, chrono::Utc::now())
    })
    .await
    .map_err(|_| bulwark_access::inventory::InventoryError {
        code: "failed",
        message: "Reading the inventory failed.",
    })?
}

/// The token files Scan's CRED-009 checks (GitHub CLI, Cargo, Terraform, RubyGems, Composer,
/// netrc), as an inventory. Same parser and symlink rule as the scan, so the two agree; counts
/// only, never a value.
fn tool_tokens(
    home: &std::path::Path,
) -> Result<bulwark_access::inventory::Inventory, bulwark_access::inventory::InventoryError> {
    use bulwark_access::inventory::{Inventory, InventoryError, Item, Storage};
    let files = bulwark_core::collectors::token_files(home);
    if files.is_empty() {
        return Err(InventoryError {
            code: "unavailable",
            message: "No token files from GitHub CLI, Cargo, Terraform, RubyGems, Composer or netrc were found.",
        });
    }
    Ok(Inventory {
        provider: "tool-tokens",
        observed_at: chrono::Utc::now(),
        sources: files.iter().map(|f| f.path.clone()).collect(),
        items: files
            .into_iter()
            .map(|f| {
                let (storage, detail) = match f.tokens {
                    Some(0) => (Storage::Config, format!("No token written in {}", f.path)),
                    Some(n) => (
                        Storage::Plaintext,
                        format!(
                            "{n} token{} written in {}",
                            if n == 1 { "" } else { "s" },
                            f.path
                        ),
                    ),
                    None => (Storage::Config, format!("Could not read {}", f.path)),
                };
                Item {
                    name: f.tool.to_string(),
                    kind: "tool",
                    storage,
                    detail,
                    expires_at: None,
                }
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every manager the frontend catalog lists must be offered here, or it can never be detected
    /// or auto-added in the real app (the browser mock would still show it).
    #[test]
    fn detection_offers_every_catalog_manager_and_gates_aws_vault() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".cargo")).unwrap();
        std::fs::write(home.path().join(".cargo/credentials.toml"), "[registry]\n").unwrap();
        std::fs::write(home.path().join(".npmrc"), "save-exact=true\n").unwrap();

        let public: Vec<_> = detect_in(home.path(), false);
        let ids: Vec<_> = public.iter().map(|d| d.id).collect();
        assert_eq!(
            ids,
            [
                "aws-cli",
                "docker",
                "git",
                "github-cli",
                "npm",
                "pypi",
                "kubernetes",
                "tool-tokens"
            ]
        );
        let present: Vec<_> = public.iter().filter(|d| d.present).map(|d| d.id).collect();
        assert!(
            present.contains(&"npm") && present.contains(&"tool-tokens"),
            "{present:?}"
        );
        assert!(!present.contains(&"docker"));

        // The catalog file is the frontend's list; keep the two in step.
        let catalog = include_str!("../../src/lib/secret-managers.ts");
        for id in ids.iter().chain(["aws-vault"].iter()) {
            assert!(
                catalog.contains(&format!("id: \"{id}\"")),
                "{id} missing from the catalog"
            );
        }
        assert_eq!(
            catalog.matches("    id: \"").count(),
            ids.len() + 1,
            "catalog has a manager detection does not offer"
        );

        assert_eq!(detect_in(home.path(), true)[0].id, "aws-vault");
    }
}
