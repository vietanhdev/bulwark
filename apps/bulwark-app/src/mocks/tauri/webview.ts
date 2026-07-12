// Mock of @tauri-apps/api/webview — see README.md. `onDragDropEvent` never fires here; OS-level
// drag-and-drop can't be simulated in a plain browser, so this mock only exists to keep the
// Antivirus tab's drop zones from crashing (no `__TAURI_INTERNALS__`) during screenshot capture.
export function getCurrentWebview() {
  return {
    onDragDropEvent: async (_handler: (event: unknown) => void) => {
      return () => {};
    },
  };
}
