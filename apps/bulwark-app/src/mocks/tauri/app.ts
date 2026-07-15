// Mock of @tauri-apps/api/app — see README.md.
export async function getVersion(): Promise<string> {
  return "0.6.8";
}

export async function getTauriVersion(): Promise<string> {
  return "2.11.5";
}
