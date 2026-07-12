// Mock of @tauri-apps/plugin-dialog — see README.md. `open()` always resolves as if the user
// cancelled, so the "Browse…" button is clickable without crashing during screenshot capture,
// even though it can't actually exercise a real native file/folder picker here.
export async function open(_options?: unknown): Promise<string | string[] | null> {
  return null;
}
