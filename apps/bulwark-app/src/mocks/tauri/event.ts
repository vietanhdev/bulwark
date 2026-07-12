// Mock of @tauri-apps/api/event — see README.md. The real app only listens for
// "monitoring:tick", which never needs to fire for a static screenshot capture.
export async function listen<T>(_event: string, _handler: (event: { payload: T }) => void) {
  return () => {};
}
