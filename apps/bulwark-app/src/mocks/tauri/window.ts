// Mock of @tauri-apps/api/window — see README.md. TitleBar.tsx calls getCurrentWindow() at
// module scope (not inside a component), so this has to be safely callable synchronously
// with no Tauri context present at all.
interface MockWindow {
  onFocusChanged(handler: (event: { payload: boolean }) => void): Promise<() => void>;
  minimize(): Promise<void>;
  toggleMaximize(): Promise<void>;
  close(): Promise<void>;
}

export function getCurrentWindow(): MockWindow {
  return {
    async onFocusChanged() {
      return () => {};
    },
    async minimize() {},
    async toggleMaximize() {},
    async close() {},
  };
}
