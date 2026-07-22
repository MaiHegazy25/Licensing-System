/**
 * Local (offline-capable) verification of a signed license token.
 *
 * This is the trust anchor used by the SDK. It proves the token was signed by a
 * key we trust and that its time-bound claims are currently satisfied. It does
 * NOT prove the license is un-revoked or un-suspended — those are mutable
 * server-side facts the SDK confirms via online validation.
 */
import type { KeyObject } from "node:crypto";
import { verifyEd25519 } from "./crypto.js";
import {
  parseToken,
  signingInput,
  TokenFormatError,
  type LicenseClaims,
} from "./token.js";

/** Epoch-seconds clock. Injectable so tests are deterministic. */
export interface Clock {
  now(): number;
}

export const systemClock: Clock = {
  now: () => Math.floor(Date.now() / 1000),
};

/** Resolves a public key by its key id (kid). Enables rotation. */
export interface PublicKeyStore {
  get(kid: string): KeyObject | undefined;
}

export type VerifyStatus =
  | "valid"
  | "grace" // expired/offline but within grace window
  | "malformed"
  | "unknown_key"
  | "bad_signature"
  | "not_yet_valid"
  | "expired"
  | "wrong_audience"
  | "wrong_issuer";

export interface VerifyOptions {
  expectedAudience: string;
  expectedIssuer: string;
  clock?: Clock;
}

export interface VerifyResult {
  status: VerifyStatus;
  ok: boolean; // true for "valid" or "grace"
  claims?: LicenseClaims;
  /** Seconds until hard expiry (incl. grace). null = perpetual. undefined when not applicable. */
  secondsRemaining?: number | null;
}

export function verifyLicenseToken(
  token: string,
  keyStore: PublicKeyStore,
  opts: VerifyOptions,
): VerifyResult {
  const clock = opts.clock ?? systemClock;
  const now = clock.now();

  let parsed;
  try {
    parsed = parseToken(token);
  } catch (e) {
    if (e instanceof TokenFormatError) return { status: "malformed", ok: false };
    throw e;
  }

  const key = keyStore.get(parsed.header.kid);
  if (!key) return { status: "unknown_key", ok: false };

  const input = signingInput(parsed.headerB64, parsed.payloadB64);
  if (!verifyEd25519(input, parsed.signature, key)) {
    return { status: "bad_signature", ok: false };
  }

  const c = parsed.claims;

  if (c.audience !== opts.expectedAudience) {
    return { status: "wrong_audience", ok: false, claims: c };
  }
  if (c.issuer !== opts.expectedIssuer) {
    return { status: "wrong_issuer", ok: false, claims: c };
  }

  if (now < c.notBefore) {
    return { status: "not_yet_valid", ok: false, claims: c };
  }

  // Perpetual: never time-expires (maintenance is a separate, non-blocking flag).
  if (c.expiresAt === null) {
    return { status: "valid", ok: true, claims: c, secondsRemaining: null };
  }

  if (now <= c.expiresAt) {
    return {
      status: "valid",
      ok: true,
      claims: c,
      secondsRemaining: c.expiresAt - now,
    };
  }

  const graceEnd = c.expiresAt + Math.max(0, c.gracePeriodSeconds);
  if (now <= graceEnd) {
    return {
      status: "grace",
      ok: true,
      claims: c,
      secondsRemaining: graceEnd - now,
    };
  }

  return { status: "expired", ok: false, claims: c, secondsRemaining: 0 };
}
