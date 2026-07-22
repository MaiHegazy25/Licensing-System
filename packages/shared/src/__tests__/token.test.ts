import { describe, it, expect, beforeAll } from "vitest";
import { canonicalize } from "../canonical.js";
import {
  generateEd25519KeyPair,
  publicKeyFromPem,
  privateKeyFromPem,
} from "../crypto.js";
import { localSigner, signLicenseToken } from "../sign.js";
import type { LicenseClaims } from "../token.js";
import { verifyLicenseToken, type Clock, type PublicKeyStore } from "../verify.js";

const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";
const KID = "key-2026-01";

function fixedClock(t: number): Clock {
  return { now: () => t };
}

function baseClaims(overrides: Partial<LicenseClaims> = {}): LicenseClaims {
  return {
    schemaVersion: 1,
    tokenId: "tok_1",
    licenseId: "lic_1",
    customerId: "cust_1",
    organizationId: null,
    productId: "prod_1",
    edition: "pro",
    enabledFeatures: ["export_pdf", "batch_mode"],
    licenseType: "subscription",
    issuedAt: 1000,
    notBefore: 1000,
    expiresAt: 2000,
    maintenanceExpiresAt: null,
    maximumSeats: 5,
    deviceBinding: null,
    offlineUntil: null,
    gracePeriodSeconds: 100,
    issuer: ISSUER,
    audience: AUDIENCE,
    ...overrides,
  };
}

describe("canonicalize", () => {
  it("is stable regardless of key insertion order", () => {
    const a = canonicalize({ b: 1, a: 2, c: [3, { z: 1, y: 2 }] });
    const b = canonicalize({ c: [3, { y: 2, z: 1 }], a: 2, b: 1 });
    expect(a).toBe(b);
  });

  it("rejects non-finite numbers", () => {
    expect(() => canonicalize({ x: NaN })).toThrow();
  });
});

describe("license token sign + verify", () => {
  let keyStore: PublicKeyStore;
  let token: string;

  beforeAll(async () => {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const pub = publicKeyFromPem(publicKeyPem);
    keyStore = { get: (kid) => (kid === KID ? pub : undefined) };
    token = await signLicenseToken(
      baseClaims(),
      localSigner(KID, privateKeyFromPem(privateKeyPem)),
    );
  });

  it("verifies a well-formed, in-window token", () => {
    const r = verifyLicenseToken(token, keyStore, {
      expectedAudience: AUDIENCE,
      expectedIssuer: ISSUER,
      clock: fixedClock(1500),
    });
    expect(r.status).toBe("valid");
    expect(r.ok).toBe(true);
    expect(r.claims?.enabledFeatures).toContain("export_pdf");
  });

  it("detects a tampered payload (feature injection)", async () => {
    // Flip an entitlement in the payload segment; signature must fail.
    const [h, p, s] = token.split(".") as [string, string, string];
    const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    claims.enabledFeatures.push("enterprise_only");
    const forgedPayload = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const forged = `${h}.${forgedPayload}.${s}`;
    const r = verifyLicenseToken(forged, keyStore, {
      expectedAudience: AUDIENCE,
      expectedIssuer: ISSUER,
      clock: fixedClock(1500),
    });
    expect(r.status).toBe("bad_signature");
    expect(r.ok).toBe(false);
  });

  it("rejects an unknown signing key id", () => {
    const emptyStore: PublicKeyStore = { get: () => undefined };
    const r = verifyLicenseToken(token, emptyStore, {
      expectedAudience: AUDIENCE,
      expectedIssuer: ISSUER,
      clock: fixedClock(1500),
    });
    expect(r.status).toBe("unknown_key");
  });

  it("rejects wrong audience", () => {
    const r = verifyLicenseToken(token, keyStore, {
      expectedAudience: "someone-else",
      expectedIssuer: ISSUER,
      clock: fixedClock(1500),
    });
    expect(r.status).toBe("wrong_audience");
  });

  it("is not_yet_valid before notBefore", () => {
    const r = verifyLicenseToken(token, keyStore, {
      expectedAudience: AUDIENCE,
      expectedIssuer: ISSUER,
      clock: fixedClock(500),
    });
    expect(r.status).toBe("not_yet_valid");
  });

  it("enters grace after expiry then hard-expires", () => {
    const opts = { expectedAudience: AUDIENCE, expectedIssuer: ISSUER };
    expect(
      verifyLicenseToken(token, keyStore, { ...opts, clock: fixedClock(2050) }).status,
    ).toBe("grace"); // within 100s grace
    expect(
      verifyLicenseToken(token, keyStore, { ...opts, clock: fixedClock(2200) }).status,
    ).toBe("expired"); // past grace
  });

  it("treats a null expiresAt (perpetual) as never-expiring", async () => {
    const { publicKeyPem, privateKeyPem } = generateEd25519KeyPair();
    const store: PublicKeyStore = {
      get: (kid) => (kid === KID ? publicKeyFromPem(publicKeyPem) : undefined),
    };
    const perp = await signLicenseToken(
      baseClaims({ licenseType: "perpetual", expiresAt: null }),
      localSigner(KID, privateKeyFromPem(privateKeyPem)),
    );
    const r = verifyLicenseToken(perp, store, {
      expectedAudience: AUDIENCE,
      expectedIssuer: ISSUER,
      clock: fixedClock(9_999_999),
    });
    expect(r.status).toBe("valid");
    expect(r.secondsRemaining).toBeNull();
  });

  it("rejects a malformed token", () => {
    const r = verifyLicenseToken("not-a-token", keyStore, {
      expectedAudience: AUDIENCE,
      expectedIssuer: ISSUER,
      clock: fixedClock(1500),
    });
    expect(r.status).toBe("malformed");
  });
});
