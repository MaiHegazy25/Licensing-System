/**
 * Offline activation file formats, shared by the SDK (which produces requests
 * and consumes responses) and the server (which consumes requests and produces
 * responses). Air-gapped flow:
 *
 *   SDK.generateOfflineRequest()  -> [request file] --(sneakernet/portal)-->
 *   server.generateOfflineResponse() -> [signed response file] -->
 *   SDK.importOfflineResponse()   -> activated offline
 *
 * The response's trust anchor is the embedded signed license `token` (device-
 * bound via `deviceBinding` and long-lived via `offlineUntil`), so the client
 * verifies it locally with no server contact.
 */
export const OFFLINE_SCHEMA_VERSION = 1;

export interface OfflineRequestFile {
  schemaVersion: number;
  kind: "offline-request";
  /** Client-generated unique id; the server uses it for idempotency/replay. */
  requestId: string;
  deviceId: string;
  deviceLabel?: string | null;
  /** The activation code (bearer secret) — never log this. */
  activationCode: string;
  createdAt: number;
}

export interface OfflineResponseFile {
  schemaVersion: number;
  kind: "offline-response";
  requestId: string;
  licenseId: string;
  deviceId: string;
  /** Signed, device-bound license token — the offline trust anchor. */
  token: string;
  issuedAt: number;
}
