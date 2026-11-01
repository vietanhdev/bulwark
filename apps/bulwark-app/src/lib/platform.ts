import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export type Platform = "linux" | "macos" | "windows";

let cached: Promise<Platform> | null = null;

/** The OS the app runs on, asked once and shared. Defaults to Linux until the answer arrives,
 *  which is what every page was written for. */
export function usePlatform(): Platform {
  const [platform, setPlatform] = useState<Platform>("linux");
  useEffect(() => {
    cached ??= invoke<string>("host_platform")
      .then((p) => (p === "macos" || p === "windows" ? p : "linux") as Platform)
      .catch(() => "linux" as Platform);
    let live = true;
    cached.then((p) => live && setPlatform(p));
    return () => {
      live = false;
    };
  }, []);
  return platform;
}
