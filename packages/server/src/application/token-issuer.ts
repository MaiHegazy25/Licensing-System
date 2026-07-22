/** Port: turns a License (server state) into a signed, verifiable token. */
import type { License } from "../domain/license.js";

export interface IssuedToken {
  token: string;
  tokenId: string;
  keyId: string;
  expiresAt: number | null;
}

export interface TokenIssuer {
  issue(license: License): Promise<IssuedToken>;
}
