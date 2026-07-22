/** Port: turns a License (server state) into a signed, verifiable token. */
import type { License } from "../domain/license.js";

export interface IssuedToken {
  token: string;
  tokenId: string;
  keyId: string;
  expiresAt: number | null;
}

export interface IssueOptions {
  /** Bind the token to a device (hashed). null/omitted = not device-bound. */
  deviceBinding?: string | null;
  /** Override the token's own expiry (e.g. long-lived offline tokens). */
  expiresAtOverride?: number | null;
  /** Override the offline window. */
  offlineUntilOverride?: number | null;
}

export interface TokenIssuer {
  issue(license: License, opts?: IssueOptions): Promise<IssuedToken>;
}
