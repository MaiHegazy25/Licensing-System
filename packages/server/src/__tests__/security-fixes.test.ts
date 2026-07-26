/**
 * Regression tests for the repo-review fixes:
 *  1. a deactivated device can no longer obtain fresh tokens via /validate,
 *     and the SDK clears its cached token when told so
 *  2. SDK deactivate() releases the seat server-side (proof-of-possession)
 *  3. /deactivate rejects tampered tokens
 *  4. public endpoints are rate limited + security events are recorded
 *  5. failed admin auth is recorded as a security event
 *  6. /api/v1/keys serves real public-key PEMs for trust-store bootstrap
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { generateEd25519KeyPair, type GeneratedKeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  buildHttpServer,
  LocalKeyProvider,
  FakeClock,
  InMemorySecurityEventRepository,
  type AppConfig,
  type Container,
} from "@vehiclevo/licensing-server";
import {
  LicensingClient,
  InMemoryTokenStore,
  type HttpClient,
  type HttpResponse,
} from "@vehiclevo/licensing-sdk";

const KID = "key-secfix";
const ADMIN = "admin-secfix-key-1234567890";
const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";
const adminH = { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };

function sdkHttp(app: FastifyInstance): HttpClient {
  return {
    async post(path: string, body: unknown): Promise<HttpResponse> {
      const res = await app.inject({
        method: "POST",
        url: path,
        payload: body as object,
        headers: { "content-type": "application/json" },
      });
      return { status: res.statusCode, body: res.json() };
    },
  };
}

describe("security fixes", () => {
  let app: FastifyInstance;
  let container: Container;
  let clock: FakeClock;
  let kp: GeneratedKeyPair;
  let productId: string;

  beforeAll(async () => {
    process.env.ADMIN_API_KEY = ADMIN;
    delete process.env.ADMIN_API_KEYS;
    delete process.env.AUTH_MODE;
    process.env.RATE_LIMIT_MAX = "8"; // small limit so the test can trip it
    kp = generateEd25519KeyPair();
    clock = new FakeClock(1_700_000_000);
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    const cfg: AppConfig = {
      env: "development", httpPort: 0, signingProvider: "local", localKeysDir: "",
      activeSigningKeyId: KID, tokenIssuer: ISSUER, tokenAudience: AUDIENCE,
      tokenTtlSeconds: 3600, activationCodePepper: "pepper-secfix-tests-123456", databaseUrl: null,
    };
    container = buildContainer(cfg, clock, keyProvider);
    app = buildHttpServer(container);
    await app.ready();
    productId = (
      await app.inject({ method: "POST", url: "/api/v1/admin/products", headers: adminH, payload: { key: "vv-sec", name: "Sec" } })
    ).json().id;
  });

  afterAll(() => {
    delete process.env.RATE_LIMIT_MAX;
  });

  async function makeLicenseAndCode(maxSeats = 1, maxActivations = 5) {
    const licenseId = (
      await app.inject({
        method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
        payload: {
          customerId: "c", productId, edition: "pro", enabledFeatures: ["f1"],
          licenseType: "subscription", maximumSeats: maxSeats,
        },
      })
    ).json().id as string;
    const code = (
      await app.inject({
        method: "POST", url: `/api/v1/admin/licenses/${licenseId}/activation-codes`,
        headers: adminH, payload: { maxActivations },
      })
    ).json().activationCode as string;
    return { licenseId, code };
  }

  function sdk(deviceId: string) {
    return LicensingClient.initialize({
      expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId,
      publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
      http: sdkHttp(app), store: new InMemoryTokenStore(), clock,
    });
  }

  /** Client + its store, so a test can present the stored token as PoP. */
  async function sdkWithStore(deviceId: string) {
    const store = new InMemoryTokenStore();
    const client = await LicensingClient.initialize({
      expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId,
      publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
      http: sdkHttp(app), store, clock,
    });
    return { client, store };
  }

  const postValidate = (payload: object) =>
    app.inject({
      method: "POST", url: "/api/v1/validate",
      headers: { "content-type": "application/json" }, payload,
    });

  it("denies /validate to a device without an active activation (and SDK clears its cache)", async () => {
    const { licenseId, code } = await makeLicenseAndCode();
    const { client, store } = await sdkWithStore("dev-val-1");
    await client.activate(code);
    const token = (await store.load())!.token;

    // Sanity: validates fine while activated.
    expect((await client.validateLicense()).ok).toBe(true);

    // Admin-side data: find and deactivate the device (as the customer portal does).
    const detail = (
      await app.inject({ method: "GET", url: `/api/v1/admin/licenses/${licenseId}`, headers: adminH })
    ).json();
    const activationId = detail.activations[0].id;
    await container.service.deactivateDevice("c", licenseId, activationId);

    // Even holding a VALID, correctly-bound token, the deactivated device gets
    // no fresh token any more.
    const res = await postValidate({ token, deviceId: "dev-val-1" });
    expect(res.statusCode).toBe(403);
    expect(res.json().status).toBe("device_not_activated");
    expect(res.json().token).toBeUndefined();

    // And the SDK drops its cached entitlement instead of falling back offline.
    const snap = await client.validateLicense();
    expect(snap.ok).toBe(false);
    expect(snap.status).toBe("not_activated");
    expect(client.hasFeature("f1")).toBe(false);
  });

  it("/validate requires proof-of-possession: ids alone mint nothing", async () => {
    const { licenseId } = await makeLicenseAndCode();
    // The pre-fix attack: licenseId + deviceId in a plain body.
    const res = await postValidate({ licenseId, deviceId: "attacker" });
    expect(res.statusCode).toBe(400); // schema rejects it outright
    expect(res.json().error.code).toBe("VALIDATION");

    // A syntactically valid but unsigned token is refused too.
    const forged = await postValidate({ token: "aaaa.bbbb.cccc", deviceId: "attacker" });
    expect(forged.statusCode).toBe(401);
  });

  it("a token bound to one device cannot validate as another (copied state file)", async () => {
    const { code } = await makeLicenseAndCode(2);
    const { client, store } = await sdkWithStore("dev-owner");
    await client.activate(code);
    const token = (await store.load())!.token;

    // Copying license.json to another machine no longer works: online tokens
    // are device-bound, so the binding check refuses the impostor.
    const res = await postValidate({ token, deviceId: "dev-impostor" });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("FORBIDDEN");

    // ...and the SDK on that machine denies locally as well.
    const impostor = await LicensingClient.initialize({
      expectedIssuer: ISSUER, expectedAudience: AUDIENCE, deviceId: "dev-impostor",
      publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
      http: sdkHttp(app), store: new InMemoryTokenStore(), clock,
    });
    await impostor["cfg"].store.save({
      licenseId: "lic", deviceId: "dev-impostor", token, lastServerTime: clock.now(),
    });
    const snap = await impostor.validateLicense();
    expect(snap.ok).toBe(false);
    expect(impostor.hasFeature("f1")).toBe(false);
  });

  it("an unbound token cannot deactivate an arbitrary device (seat-denial DoS)", async () => {
    const { licenseId, code } = await makeLicenseAndCode(2);
    const { client } = await sdkWithStore("victim-device");
    await client.activate(code);

    // A customer-portal license file is deliberately NOT device-bound; it must
    // not act as a wildcard over other devices' seats.
    const unbound = (
      await container.service.downloadLicenseFile("c", licenseId)
    ).token;
    const res = await app.inject({
      method: "POST", url: "/api/v1/deactivate",
      headers: { "content-type": "application/json" },
      payload: { token: unbound, deviceId: "victim-device" },
    });
    expect(res.statusCode).toBe(403);

    // The victim's seat is untouched.
    const detail = (
      await app.inject({ method: "GET", url: `/api/v1/admin/licenses/${licenseId}`, headers: adminH })
    ).json();
    expect(detail.activations.filter((a: { status: string }) => a.status === "active")).toHaveLength(1);
  });

  it("SDK deactivate() releases the seat server-side so another device can activate", async () => {
    const { code } = await makeLicenseAndCode(1); // single seat
    const c1 = await sdk("dev-seat-a");
    await c1.activate(code);

    const c2 = await sdk("dev-seat-b");
    await expect(c2.activate(code)).rejects.toBeTruthy(); // seat taken

    await c1.deactivate(); // proof-of-possession release
    expect((await c2.activate(code)).ok).toBe(true); // seat is free again
  });

  it("rejects /deactivate with a tampered token and records auth_failed", async () => {
    const { code } = await makeLicenseAndCode();
    const c = await sdk("dev-tamper");
    const snap = await c.activate(code);
    expect(snap.ok).toBe(true);

    // Forge the stored token's payload.
    const state = (await app.inject({
      method: "POST", url: "/api/v1/deactivate", headers: { "content-type": "application/json" },
      payload: { token: "aaaa.bbbb.cccc", deviceId: "dev-tamper" },
    }));
    expect(state.statusCode).toBe(401);
    const events = (container.securityEvents as InMemorySecurityEventRepository).events;
    expect(events.some((e) => e.type === "auth_failed" && e.metadata.surface === "deactivate")).toBe(true);
  });

  it("floating checkout requires proof-of-possession (seat-exhaustion DoS)", async () => {
    const licenseId = (
      await app.inject({
        method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
        payload: {
          customerId: "c", productId, edition: "pro", enabledFeatures: ["f1"],
          licenseType: "floating", maximumSeats: 2,
        },
      })
    ).json().id as string;
    const code = (
      await app.inject({
        method: "POST", url: `/api/v1/admin/licenses/${licenseId}/activation-codes`,
        headers: adminH, payload: { maxActivations: 5 },
      })
    ).json().activationCode as string;

    const { client, store } = await sdkWithStore("float-owner");
    await client.activate(code);
    const token = (await store.load())!.token;

    const checkout = (payload: object) =>
      app.inject({
        method: "POST", url: "/api/v1/floating/checkout",
        headers: { "content-type": "application/json" }, payload,
      });

    // Knowing the licenseId is no longer enough to burn concurrent seats.
    expect((await checkout({ licenseId, deviceId: "leech" })).statusCode).toBe(400);
    // Nor is holding someone else's token.
    expect((await checkout({ token, deviceId: "leech" })).statusCode).toBe(403);
    // The legitimate holder still checks out normally.
    const ok = await checkout({ token, deviceId: "float-owner" });
    expect(ok.statusCode).toBe(200);
    expect(ok.json().seatsUsed).toBe(1);
  });

  it("records auth_failed on a bad admin key", async () => {
    await app.inject({ method: "GET", url: "/api/v1/admin/licenses", headers: { authorization: "Bearer wrong" } });
    const events = (container.securityEvents as InMemorySecurityEventRepository).events;
    expect(events.some((e) => e.type === "auth_failed" && e.metadata.surface === "admin")).toBe(true);
  });

  it("serves public-key PEMs from /api/v1/keys", async () => {
    const res = await app.inject({ method: "GET", url: "/api/v1/keys" });
    const body = res.json();
    expect(body.activeKeyId).toBe(KID);
    expect(body.keys[0].publicKeyPem).toContain("BEGIN PUBLIC KEY");
    // Never leak private material.
    expect(JSON.stringify(body)).not.toContain("PRIVATE");
  });

  it("rate limits a hammered public endpoint with 429 and a security event", async () => {
    // RATE_LIMIT_MAX=8 for group "validate" per ip; burn through it.
    let limited = 0;
    for (let i = 0; i < 15; i++) {
      // Schema-valid so the request reaches the rate limiter (schema rejection
      // would 400 before the handler runs); PoP then fails with 401.
      const res = await postValidate({ token: "aaaa.bbbb.cccc", deviceId: "d" });
      if (res.statusCode === 429) {
        limited++;
        expect(res.json().error.code).toBe("RATE_LIMITED");
      }
    }
    expect(limited).toBeGreaterThan(0);
    const events = (container.securityEvents as InMemorySecurityEventRepository).events;
    expect(events.some((e) => e.type === "rate_limit_exceeded")).toBe(true);
  });
});
