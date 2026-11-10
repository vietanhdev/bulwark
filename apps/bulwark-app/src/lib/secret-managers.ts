/**
 * The secrets managers Secrets can show. Adding one here makes it appear in the market; each
 * entry is backed by a real reader (`bulwark_access::inventory`, or the AWS Vault adapter), so the
 * market never offers a control that does nothing. "Add" only adds a tab: Bulwark never
 * downloads or installs third-party software — `install` is a command for the user's own terminal.
 * AWS Vault is a preview: the backend offers it only when BULWARK_AWS_VAULT_PREVIEW=1 is set,
 * because it needs an aws-vault build with `list --json`, and the page hides it otherwise.
 */
export interface SecretManager {
  id: string;
  name: string;
  /** What the tab shows, in one line. */
  shows: string;
  install: { text: string; command: string };
}

export const SECRET_MANAGERS: SecretManager[] = [
  {
    id: "aws-vault",
    name: "AWS Vault",
    shows: "AWS profiles held in your keychain, with cached-session expiry.",
    install: {
      text: "Needs an aws-vault build that supports `list --json`, at ~/.local/bin/aws-vault.",
      command: "install -m 0755 ./aws-vault ~/.local/bin/aws-vault",
    },
  },
  {
    id: "aws-cli",
    name: "AWS CLI",
    shows: "Each profile's credential type, and IAM Identity Center sign-in expiry.",
    install: { text: "Set up the AWS CLI with short-lived sign-in:", command: "aws configure sso" },
  },
  {
    id: "docker",
    name: "Docker",
    shows: "Registry logins, and whether each sits in a credential helper or in config.json.",
    install: { text: "Log in to a registry to create Docker's config:", command: "docker login" },
  },
  {
    id: "git",
    name: "Git",
    shows: "Credential helpers in use, and hosts with passwords saved in plain text.",
    install: {
      text: "Store Git credentials in your system keychain:",
      command: "git config --global credential.helper libsecret",
    },
  },
  {
    id: "github-cli",
    name: "GitHub CLI",
    shows: "Signed-in GitHub hosts and accounts, and where each token is kept.",
    install: { text: "Sign in with the GitHub CLI:", command: "gh auth login" },
  },
  {
    id: "npm",
    name: "npm",
    shows: "Registry logins in .npmrc, and whether each token is written down or taken from the environment.",
    install: { text: "Log in to a registry (prefer a granular, expiring token):", command: "npm login" },
  },
  {
    id: "pypi",
    name: "PyPI",
    shows: "Package indexes in .pypirc, and whether a password is stored there or left to your keyring.",
    install: {
      text: "Keep the upload token in your keyring instead of .pypirc:",
      command: "keyring set https://upload.pypi.org/legacy/ __token__",
    },
  },
  {
    id: "kubernetes",
    name: "Kubernetes",
    shows: "Users in your kubeconfig, and whether each uses an exec plugin or embeds a credential.",
    install: {
      text: "Add a cluster with short-lived cloud credentials, for example:",
      command: "aws eks update-kubeconfig --name <cluster>",
    },
  },
  {
    id: "tool-tokens",
    name: "Tool tokens",
    shows: "Login tokens that GitHub CLI, Cargo, Terraform, RubyGems, Composer or netrc keep in a file.",
    install: {
      text: "Nothing to set up: this lists token files only when a tool has created one, for example:",
      command: "cargo login",
    },
  },
];

export function managerById(id: string): SecretManager | undefined {
  return SECRET_MANAGERS.find((m) => m.id === id);
}

const KEY = "bulwark.secrets.managers";

/** The tabs the user has added. A per-viewer convenience: unreadable storage means "none yet". */
export function loadAdded(): string[] {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) ?? "[]");
    return Array.isArray(raw) ? raw.filter((id) => typeof id === "string" && managerById(id)) : [];
  } catch {
    return [];
  }
}

/** Whether the user has ever had a saved set of tabs. "Never chosen" (first run: add what is found
 *  on this computer) is different from "chose none" (removed every tab: respect that). */
export function hasSavedChoice(): boolean {
  try {
    return localStorage.getItem(KEY) !== null;
  } catch {
    return false;
  }
}

export function saveAdded(ids: string[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(ids));
  } catch {
    // Storage blocked: the tabs still work for this session.
  }
}
