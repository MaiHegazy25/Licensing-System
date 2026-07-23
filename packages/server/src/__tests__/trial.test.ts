/**
 * Self-service trial licenses: start via SDK, feature gating, one-trial-per-
 * device guard, resume-while-running, deny-after-expiry, device binding,
 * revocation, and products without a trial policy.
 */
import { describe, it, expect, beforeAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { generateEd25519KeyPair, parseToken, type GeneratedKeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  buildHttpServer,
  LocalKeyProvider,
  FakeClock,
  type AppConfig,
} from "@vehiclevo/licensing-server";
import {
  LicensingClient,
  InMemoryTokenStore,
  LicensingErrorCode,
  type HttpClient,
  type HttpResponse,
} from "@vehiclevo/licensing-sdk";

const KID = "key-trial-test";
const ADMIN = "admin-trial-key-1234567890";
const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";
const NOW = 1_700_000_000;
const adminH = { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };

function sdkHttp(app: FastifyInstance): HttpClient {
  return {
    async post(path: string, body: unknown): Promise<HttpResponse> {
      const res = await app.inject({
        method: "POST", url: path, payload: body as object,
        headers: { "content-type": "application/json" },
      });
      return { status: res.statusCode, body: res.json() };
    },
  };
}

describe("trial licenses", () => {
  let app: FastifyInstance;
  let clock: FakeClock;
  let kp: GeneratedKeyPair;

  beforeAll(async () => {
    process.env.ADMIN_API_KEY = ADMIN;
    delete process.env.ADMIN_API_KEYS;
    delete process.env.AUTH_MODE;
    delete process.env.RATE_LIMIT_MAX;
    kp = generateEd25519KeyPair();
    clock = new FakeClock(NOW);
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    const cfg: AppConfig = {
      env: "development", httpPort: 0, signingProvider: "local", localKeysDir: "",
      activeSigningKeyId: KID, tokenIssuer: ISSUER, tokenAudience: AUDIENCE,
      tokenTtlSeconds: 3600, activationCodePepper: "pepper-trial-tests-1234567", databaseUrl: null,
    };
    app = buildHttpServer(buildContainer(cfg, clock, keyProvider));
    await app.ready();

    // Product WITH a 14-day trial and one WITHOUT.
    await app.inject({
      method: "POST", url: "/api/v1/admin/products", headers: adminH,
      payload: {
        key: "vv-trial", name: "Trial Product",
        trial: { enabled: true, days: 14, features: ["basic_mode"] },
      },
    });
    await app.inject({
      method: "POST", url: "/api/v1/admin/products", headers: adminH,
      payload: { key: "vv-notrial", name: "No Trial" },
    });
  });

  function sdk(deviceId: string) {
    return LicensingClient.initialize({
      expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId,
      publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
      http: sdkHttp(app), store: new InMemoryTokenStore(), clock,
    });
  }

  it("starts a trial, gates features, and reports days remaining", async () => {
    const client = await sdk("trial-dev-1");
    const snap = await client.startTrial("vv-trial");
    expect(snap.ok).toBe(true);
    expect(snap.licenseType).toBe("trial");
    expect(snap.edition).toBe("trial");
    expect(client.hasFeature("basic_mode")).toBe(true);
    expect(client.hasFeature("pro_only")).toBe(false);
    // The snapshot's expiresAt is the short-lived TOKEN expiry (ADR-0003); the
    // trial LICENSE expiry is reported by the endpoint itself.
    const res = await app.inject({
      method: "POST", url: "/api/v1/trial/start", headers: { "content-type": "application/json" },
      payload: { productKey: "vv-trial", deviceId: "trial-dev-1" },
    });
    expect(res.json().expiresAt).toBe(NOW + 14 * 86400);
    // /validate works for the trial device (it holds a real activation).
    expect((await client.validateLicense()).ok).toBe(true);
  });

  it("issues a device-bound token (cannot be copied to another machine)", async () => {
    const client = await sdk("trial-dev-bind");
    const snap = await client.startTrial("vv-trial");
    expect(snap.ok).toBe(true);
    // Read the raw stored token and check the binding claim is set.
    const res = await app.inject({
      method: "POST", url: "/api/v1/trial/start", headers: { "content-type": "application/json" },
      payload: { productKey: "vv-trial", deviceId: "trial-dev-bind" },
    });
    const { claims } = parseToken(res.json().token);
    expect(claims.deviceBinding).not.toBeNull();
  });

  it("resumes the SAME trial on repeat requests while it is running", async () => {
    const raw = async () =>
      (
        await app.inject({
          method: "POST", url: "/api/v1/trial/start", headers: { "content-type": "application/json" },
          payload: { productKey: "vv-trial", deviceId: "trial-dev-resume" },
        })
      ).json() as { licenseId: string; expiresAt: number };

    const client = await sdk("trial-dev-resume");
    expect((await client.startTrial("vv-trial")).ok).toBe(true);
    const first = await raw();
    clock.advance(5 * 86400); // 5 days in
    const again = await raw();
    // Same underlying license, unchanged expiry (remaining days keep ticking).
    expect(again.licenseId).toBe(first.licenseId);
    expect(again.expiresAt).toBe(first.expiresAt);
    expect((await client.startTrial("vv-trial")).ok).toBe(true); // SDK resume works too
    clock.advance(-5 * 86400);
  });

  it("denies a second trial after the first has expired", async () => {
    const client = await sdk("trial-dev-expire");
    const snap = await client.startTrial("vv-trial");
    expect(snap.ok).toBe(true);
    clock.advance(15 * 86400); // past the 14-day trial
    await expect(client.startTrial("vv-trial")).rejects.toMatchObject({
      code: LicensingErrorCode.TrialAlreadyUsed,
    });
    clock.advance(-15 * 86400);
  });

  it("each device gets its own independent trial", async () => {
    const a = await sdk("trial-dev-A");
    const b = await sdk("trial-dev-B");
    const snapA = await a.startTrial("vv-trial");
    const snapB = await b.startTrial("vv-trial");
    expect(snapA.ok).toBe(true);
    expect(snapB.ok).toBe(true);
    // Distinct licenses (each customer id is trial:<device>).
    const resA = await app.inject({
      method: "POST", url: "/api/v1/trial/start", headers: { "content-type": "application/json" },
      payload: { productKey: "vv-trial", deviceId: "trial-dev-A" },
    });
    const resB = await app.inject({
      method: "POST", url: "/api/v1/trial/start", headers: { "content-type": "application/json" },
      payload: { productKey: "vv-trial", deviceId: "trial-dev-B" },
    });
    expect(resA.json().licenseId).not.toBe(resB.json().licenseId);
  });

  it("rejects products without a trial (and unknown products) uniformly", async () => {
    const client = await sdk("trial-dev-none");
    await expect(client.startTrial("vv-notrial")).rejects.toMatchObject({
      code: LicensingErrorCode.TrialNotAvailable,
    });
    await expect(client.startTrial("vv-does-not-exist")).rejects.toMatchObject({
      code: LicensingErrorCode.TrialNotAvailable,
    });
  });

  it("a revoked trial cannot be resumed and fails validation", async () => {
    const client = await sdk("trial-dev-revoke");
    await client.startTrial("vv-trial");
    const licenseId = (
      await app.inject({
        method: "POST", url: "/api/v1/trial/start", headers: { "content-type": "application/json" },
        payload: { productKey: "vv-trial", deviceId: "trial-dev-revoke" },
      })
    ).json().licenseId as string;

    await app.inject({
      method: "POST", url: `/api/v1/admin/licenses/${licenseId}/revoke`,
      headers: adminH, payload: { reason: "abuse" },
    });

    const after = await client.validateLicense();
    expect(after.ok).toBe(false);
    expect(after.status).toBe("revoked");
    await expect(client.startTrial("vv-trial")).rejects.toMatchObject({
      code: LicensingErrorCode.TrialAlreadyUsed,
    });
  });

  it("trial expiry is enforced end-to-end (features go dark)", async () => {
    const client = await sdk("trial-dev-e2e-exp");
    await client.startTrial("vv-trial");
    expect(client.hasFeature("basic_mode")).toBe(true);
    clock.advance(15 * 86400);
    const snap = await client.validateLicense();
    expect(snap.ok).toBe(false);
    expect(snap.status).toBe("expired");
    expect(client.hasFeature("basic_mode")).toBe(false);
    clock.advance(-15 * 86400);
  });
});
