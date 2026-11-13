export interface SessionMetadata {
  type: string;
  expires_at: string;
  status: "cached" | "expired";
  selected_store: boolean;
}
export interface ProfileMetadata {
  name: string;
  configured: boolean;
  credential_reference: boolean;
  oidc_cache_present: boolean;
  sessions: SessionMetadata[];
}
export type CacheStatus = "cached" | "expired" | "no-cache";
/** Aggregate STS metadata only: an SSO cache has no known expiry and is reported separately. */
export function cacheStatus(profile: ProfileMetadata, now: number): CacheStatus {
  if (profile.sessions.some((s) => Date.parse(s.expires_at) > now)) return "cached";
  return profile.sessions.length ? "expired" : "no-cache";
}
/** A profile name that is one plain argument in every shell: POSIX shells, fish, PowerShell and
 *  cmd all read it the same way, and it holds nothing invisible. */
const PLAIN_NAME = /^[A-Za-z0-9][A-Za-z0-9_.@:+=,/-]*$/;

/**
 * The command to start a shell for `profile`, or null when the name is not plain. Quoting a hostile
 * name correctly for POSIX is not enough: the user may paste into fish or PowerShell, where the same
 * quoted text parses differently, and a name can carry invisible characters. So only names that need
 * no quoting get a copyable command. Kingpin's `--` still precedes the profile.
 */
export function terminalCommand(profile: string): string | null {
  return PLAIN_NAME.test(profile) ? `aws-vault exec -- ${profile}` : null;
}
export function expiryText(timestamp: string, now: number): string {
  const delta = Date.parse(timestamp) - now;
  const minutes = Math.max(1, Math.ceil(Math.abs(delta) / 60000));
  const duration =
    minutes < 60
      ? `${minutes} min`
      : minutes < 1440
        ? `${Math.ceil(minutes / 60)} hr`
        : `${Math.ceil(minutes / 1440)} ${minutes === 1440 ? "day" : "days"}`;
  return delta > 0 ? `Expires in ${duration}` : `Expired ${duration} ago`;
}
