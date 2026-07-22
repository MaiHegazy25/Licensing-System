/**
 * SDK offline behaviour + security edges, isolated from the server via a
 * scriptable mock HttpClient (demonstrating DI/mockability).
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

class MutableClock implements Clock {
  constructor(private t: number) {}
  now() {
    return this.t;
  }
  set(t: number) {
    this.t = t;
  }
}

/** HttpClient that always fails the network (simulates outage). */
const offlineHttp: HttpClient = {
  async post(): Promise<HttpResponse> {
    throw new Error("network down");
  },
};

/** HttpClient that returns a scripted activation token, then goes offline. */
function scriptedHttp(token: string, licenseId: string): { http: HttpClient; goOffline(): void } {
  let offline = false;
  return {
    goOffline() {
      offline = true;
    },
    http: {
      async post(path: string): Promise<HttpResponse> {
        if (offline) throw new Error("network down");
        if (path.endsWith("/activate")) {
          return { status: 200, body: { token, licenseId, status: "active" } };
        }
        throw new Error("unexpected");
      },
    },
  };
}

async function makeToken(overrides: Partial<LicenseClaims>, kp: { privateKeyPem: string }) {
  const now = 1_700_000_000;
  const claims: LicenseClaims = {
    schemaVersion: 1,
    tokenId: "tok",
    licenseId: "lic_1",
    customerId: "c1",
    organizationId: null,
    productId: "p1",
    edition: "pro",
    enabledFeatures: ["export_pdf"],
    licenseType: "subscription",
    issuedAt: now,
    notBefore: now,
    expiresAt: now + 3600,
    maintenanceExpiresAt: null,
    maximumSeats: 1,
    deviceBinding: null,
    offlineUntil: now + 10 * 86400,
    gracePeriodSeconds: 0,
    issuer: ISSUER,
    audience: AUDIENCE,
    ...overrides,
  };
  return signLicenseToken(claims, localSigner(KID, privateKeyFromPem(kp.privateKeyPem)));
}

function baseCfg(kp: { publicKeyPem: string }, http: HttpClient, clock: Clock, store = new InMemoryTokenStore()) {
  return {
    expectedIssuer: ISSUER,
    expectedAudience: AUDIENCE,
    deviceId: "dev-1",
    publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
    http,
    store,
    clock,
  };
}

describe("SDK offline + security edges", () => {
  it("keeps working offline within the offline window after a successful activation", async () => {
    const kp = generateEd25519KeyPair();
    const clock = new MutableClock(1_700_000_000);
    const token = await makeToken({}, kp);
    const net = scriptedHttp(token, "lic_1");
    const client = await LicensingClient.initialize(baseCfg(kp, net.http, clock));

    expect((await client.activate("CODE")).ok).toBe(true);

    // Server goes down; move 5 days ahead (< 10d offline window).
    net.goOffline();
    clock.set(1_700_000_000 + 5 * 86400);
    const snap = await client.validateLicense();
    // Signed token stays valid offline (falls into grace/valid via offline cache).
    expect(snap.source).toBe("offline_cache");
    expect(["offline_exceeded", "revoked"]).not.toContain(snap.status);
  });

  it("stops after the offline window is exceeded", async () => {
    const kp = generateEd25519KeyPair();
    const clock = new MutableClock(1_700_000_000);
    const token = await makeToken({ offlineUntil: 1_700_000_000 + 2 * 86400 }, kp);
    const net = scriptedHttp(token, "lic_1");
    const client = await LicensingClient.initialize(baseCfg(kp, net.http, clock));
    await client.activate("CODE");

    net.goOffline();
    clock.set(1_700_000_000 + 3 * 86400); // past offlineUntil
    const snap = await client.validateLicense();
    expect(snap.ok).toBe(false);
    expect(snap.status).toBe("offline_exceeded");
    expect(client.hasFeature("export_pdf")).toBe(false);
  });

  it("detects clock rollback and refuses to extend trust", async () => {
    const kp = generateEd25519KeyPair();
    const clock = new MutableClock(1_700_000_000);
    const token = await makeToken({}, kp);
    const net = scriptedHttp(token, "lic_1");
    const client = await LicensingClient.initialize(baseCfg(kp, net.http, clock));
    await client.activate("CODE");

    net.goOffline();
    clock.set(1_700_000_000 - 100_000); // rewound well beyond skew tolerance
    const snap = await client.validateLicense();
    expect(snap.status).toBe("clock_tampered");
    expect(snap.reason).toBe(LicensingErrorCode.ClockTampered);
    expect(client.hasFeature("export_pdf")).toBe(false);
  });

  it("fails safe (features disabled) when not activated", async () => {
    const kp = generateEd25519KeyPair();
    const clock = new MutableClock(1_700_000_000);
    const client = await LicensingClient.initialize(baseCfg(kp, offlineHttp, clock));
    const snap = await client.validateLicense();
    expect(snap.ok).toBe(false);
    expect(snap.status).toBe("not_activated");
    expect(client.hasFeature("export_pdf")).toBe(false);
  });
});
