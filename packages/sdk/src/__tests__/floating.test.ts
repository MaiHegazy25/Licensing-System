/**
 * SDK floating-seat client: checkout / heartbeat / return against a scriptable
 * mock transport (DI), including seat-unavailable and lease-expired paths.
 */
import { describe, it, expect } from "vitest";
import {
  generateEd25519KeyPair,
  privateKeyFromPem,
  localSigner,
  signLicenseToken,
  type LicenseClaims,
} from "@vehiclevo/licensing-shared";
import {
  LicensingClient,
  InMemoryTokenStore,
  LicensingErrorCode,
  type Clock,
  type HttpClient,
  type HttpResponse,
} from "@vehiclevo/licensing-sdk";

const KID = "k1";
const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";
const NOW = 1_700_000_000;

const clock: Clock = { now: () => NOW };

async function token(kp: { privateKeyPem: string }): Promise<string> {
  const claims: LicenseClaims = {
    schemaVersion: 1, tokenId: "t", licenseId: "lic_1", customerId: "c1",
    organizationId: null, productId: "p1", edition: "pro", enabledFeatures: ["f1"],
    licenseType: "floating", issuedAt: NOW, notBefore: NOW, expiresAt: NOW + 3600,
    maintenanceExpiresAt: null, maximumSeats: 5, deviceBinding: null, offlineUntil: null,
    gracePeriodSeconds: 0, issuer: ISSUER, audience: AUDIENCE,
  };
  return signLicenseToken(claims, localSigner(KID, privateKeyFromPem(kp.privateKeyPem)));
}

/** Scriptable floating backend. */
function backend(tok: string) {
  const state = { checkout: "ok" as "ok" | "full", heartbeat: "ok" as "ok" | "expired" };
  const http: HttpClient = {
    async post(path: string): Promise<HttpResponse> {
      if (path.endsWith("/activate")) return { status: 200, body: { token: tok, licenseId: "lic_1", status: "active" } };
      if (path.endsWith("/floating/checkout")) {
        return state.checkout === "full"
          ? { status: 409, body: { error: { code: "SEAT_LIMIT_REACHED" } } }
          : { status: 200, body: { leaseId: "lease_1", expiresAt: NOW + 900, seatsUsed: 1, maximumSeats: 5, token: tok } };
      }
      if (path.endsWith("/floating/heartbeat")) {
        return state.heartbeat === "expired"
          ? { status: 409, body: { error: { code: "LEASE_NOT_FOUND" } } }
          : { status: 200, body: { expiresAt: NOW + 1800 } };
      }
      if (path.endsWith("/floating/return")) return { status: 204, body: null };
      throw new Error(`unexpected ${path}`);
    },
  };
  return { http, state };
}

async function activatedClient(kp: { publicKeyPem: string }, http: HttpClient) {
  const c = await LicensingClient.initialize({
    expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId: "dev-1",
    publicKeys: [{ kid: KID, pem: kp.publicKeyPem }], http, store: new InMemoryTokenStore(), clock,
  });
  await c.activate("CODE");
  return c;
}

describe("SDK floating seats", () => {
  it("checks out a seat and tracks the lease", async () => {
    const kp = generateEd25519KeyPair();
    const tok = await token(kp);
    const { http } = backend(tok);
    const c = await activatedClient(kp, http);

    const seat = await c.checkoutSeat();
    expect(seat.leaseId).toBe("lease_1");
    expect(seat.maximumSeats).toBe(5);
    expect(c.getSeat()?.leaseId).toBe("lease_1");
    expect(c.hasFeature("f1")).toBe(true);
  });

  it("throws SeatUnavailable when all seats are taken", async () => {
    const kp = generateEd25519KeyPair();
    const tok = await token(kp);
    const { http, state } = backend(tok);
    const c = await activatedClient(kp, http);
    state.checkout = "full";
    await expect(c.checkoutSeat()).rejects.toMatchObject({ code: LicensingErrorCode.SeatUnavailable });
  });

  it("extends the lease via heartbeat and releases via return", async () => {
    const kp = generateEd25519KeyPair();
    const tok = await token(kp);
    const { http } = backend(tok);
    const c = await activatedClient(kp, http);
    await c.checkoutSeat();

    const hb = await c.heartbeatSeat();
    expect(hb.expiresAt).toBe(NOW + 1800);

    await c.returnSeat();
    expect(c.getSeat()).toBeNull();
  });

  it("surfaces LeaseExpired and drops the seat when the lease was reclaimed", async () => {
    const kp = generateEd25519KeyPair();
    const tok = await token(kp);
    const { http, state } = backend(tok);
    const c = await activatedClient(kp, http);
    await c.checkoutSeat();
    state.heartbeat = "expired";
    await expect(c.heartbeatSeat()).rejects.toMatchObject({ code: LicensingErrorCode.LeaseExpired });
    expect(c.getSeat()).toBeNull();
  });

  it("requires activation before checkout", async () => {
    const kp = generateEd25519KeyPair();
    const tok = await token(kp);
    const { http } = backend(tok);
    const c = await LicensingClient.initialize({
      expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId: "dev-x",
      publicKeys: [{ kid: KID, pem: kp.publicKeyPem }], http, store: new InMemoryTokenStore(), clock,
    });
    await expect(c.checkoutSeat()).rejects.toMatchObject({ code: LicensingErrorCode.NotActivated });
  });
});
