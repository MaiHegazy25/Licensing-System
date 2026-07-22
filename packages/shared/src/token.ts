/**
 * Signed license token format.
 *
 * Envelope: a JWS-like compact string  `<b64url(header)>.<b64url(payload)>.<b64url(sig)>`.
 *   - `header`  is canonical JSON: { alg: "EdDSA", typ: "license+jws", kid }
 *   - `payload` is canonical JSON of `LicenseClaims`
 *   - `sig`     is Ed25519 over the ASCII bytes of `b64url(header) + "." + b64url(payload)`
 *
 * This is deliberately a thin layer over well-established primitives (EdDSA /
 * Ed25519, base64url, JWS structure). We do NOT invent cryptography. Canonical
 * JSON is used for the payload so re-serialization on the client is stable.
 *
 * The SIGNED payload is immutable proof of entitlement. Anything mutable at
 * runtime (revocation, current seat leases, suspension) lives in server state
 * and is NOT part of the token — the SDK must confirm liveness online for those.
 */

export const LICENSE_TOKEN_TYP = "license+jws";
export const LICENSE_TOKEN_ALG = "EdDSA";

export type LicenseType =
  | "named_user"
  | "device"
  | "floating"
  | "subscription"
  | "perpetual"
  | "trial";

/** The signed payload. Fields refined from the brief's suggested model. */
export interface LicenseClaims {
  /** Explicit versioning of the claim schema for forward compatibility. */
  schemaVersion: number;
  /** Unique token identifier (jti) — for replay/audit tracking. */
  tokenId: string;
  licenseId: string;
  customerId: string;
  organizationId: string | null;
  productId: string;
  /** e.g. "standard" | "pro" | "enterprise". */
  edition: string;
  /** Feature codes enabled by this license/edition. */
  enabledFeatures: string[];
  licenseType: LicenseType;
  /** Epoch seconds. */
  issuedAt: number;
  notBefore: number;
  /** null = never expires (perpetual). */
  expiresAt: number | null;
  /** Perpetual licenses: maintenance/updates cutoff. null = n/a. */
  maintenanceExpiresAt: number | null;
  maximumSeats: number;
  /** Node-locked binding: a salted, derived device id. null = not device-bound. */
  deviceBinding: string | null;
  /** Client may run offline (no server contact) until this epoch second. */
  offlineUntil: number | null;
  /** Extra grace seconds after expiry/offlineUntil before hard-fail. */
  gracePeriodSeconds: number;
  /** iss */
  issuer: string;
  /** aud */
  audience: string;
}

export interface LicenseTokenHeader {
  alg: typeof LICENSE_TOKEN_ALG;
  typ: typeof LICENSE_TOKEN_TYP;
  /** Key id — selects the public key for verification; enables rotation. */
  kid: string;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function base64UrlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/** The exact ASCII bytes that get signed / verified. */
export function signingInput(headerB64: string, payloadB64: string): Uint8Array {
  return new TextEncoder().encode(`${headerB64}.${payloadB64}`);
}

export interface ParsedToken {
  header: LicenseTokenHeader;
  claims: LicenseClaims;
  headerB64: string;
  payloadB64: string;
  signature: Uint8Array;
}

export class TokenFormatError extends Error {}

/** Structural parse only — does NOT verify the signature. */
export function parseToken(token: string): ParsedToken {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new TokenFormatError("token must have three dot-separated segments");
  }
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];
  let header: LicenseTokenHeader;
  let claims: LicenseClaims;
  try {
    header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    throw new TokenFormatError("token header/payload is not valid JSON");
  }
  if (header.alg !== LICENSE_TOKEN_ALG || header.typ !== LICENSE_TOKEN_TYP) {
    throw new TokenFormatError("unexpected token header alg/typ");
  }
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    throw new TokenFormatError("token header missing kid");
  }
  return {
    header,
    claims,
    headerB64,
    payloadB64,
    signature: base64UrlDecode(sigB64),
  };
}
