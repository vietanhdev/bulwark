import { invoke } from "@tauri-apps/api/core";

export type Storage = "plaintext" | "keychain" | "helper" | "session" | "memory" | "config" | "environment";

export interface InventoryItem {
  name: string;
  kind: string;
  storage: Storage;
  detail: string;
  expires_at: string | null;
}

export interface Inventory {
  provider: string;
  observed_at: string;
  sources: string[];
  items: InventoryItem[];
}

export type InventoryState =
  | { status: "loading" }
  | { status: "ok"; inventory: Inventory }
  | { status: "unavailable" | "error"; message: string };

/** Managers whose inventory comes from reading their own files (nothing executed), so it is safe
 *  to read automatically. AWS Vault runs a program and is read when its tab is opened. */
export const PASSIVE = new Set([
  "aws-cli",
  "docker",
  "git",
  "github-cli",
  "npm",
  "pypi",
  "kubernetes",
  "tool-tokens",
]);

export async function readInventory(provider: string): Promise<InventoryState> {
  try {
    return { status: "ok", inventory: await invoke<Inventory>("secrets_inventory", { provider }) };
  } catch (e) {
    const failure = e as { code?: string; message?: string };
    return {
      status: failure?.code === "unavailable" ? "unavailable" : "error",
      message: typeof failure?.message === "string" ? failure.message : "Could not read this tool's files.",
    };
  }
}

export const STORAGE: Record<Storage, { label: string; tone: string }> = {
  plaintext: { label: "Plain text", tone: "bg-[var(--sev-medium-tint)] text-[var(--sev-medium-fg)]" },
  keychain: { label: "Keychain", tone: "bg-primary/12 text-primary" },
  session: { label: "Session", tone: "bg-primary/12 text-primary" },
  helper: { label: "Helper", tone: "bg-muted text-foreground" },
  memory: { label: "In memory", tone: "bg-muted text-foreground" },
  config: { label: "No secret", tone: "bg-muted text-muted-foreground" },
  environment: { label: "From environment", tone: "bg-muted text-foreground" },
};
