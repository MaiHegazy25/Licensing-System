/**
 * Transport-layer hardening: CORS for BOTH portals, request-body validation,
 * and rate-limit keying behind a proxy.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { generateEd25519KeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  buildHttpServer,
  LocalKeyProvider,
  FakeClock,
  type AppConfig,
} from "@vehiclevo/licensing-server";

const KID = "key-harden";
const ADMIN = "admin-harden-key-1234567890";
const ADMIN_ORIGIN = "https://admin.example";
const CUSTOMER_ORIGIN = "https://portal.example";
const adminH = { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };

describe("HTTP hardening", () => {
  let app: FastifyInstance;
  let productId: string;

  beforeAll(async () => {
    process.env.ADMIN_API_KEY = ADMIN;
    delete process.env.ADMIN_API_KEYS;
    delete process.env.AUTH_MODE;
    process.env.RATE_LIMIT_MAX = "3";
    const kp = generateEd25519KeyPair();
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    const cfg: AppConfig = {
      env: "development", httpPort: 0, signingProvider: "local", localKeysDir: "",
      activeSigningKeyId: KID, tokenIssuer: "https://licensing.test",
      tokenAudience: "vehiclevo-products", tokenTtlSeconds: 3600,
      activationCodePepper: "pepper-harden-tests-1234567", databaseUrl: null,
      adminWebOrigin: ADMIN_ORIGIN,
      customerWebOrigin: CUSTOMER_ORIGIN,
      trustProxy: true,
    };
    app = buildHttpServer(buildContainer(cfg, new FakeClock(1_700_000_000), keyProvider));
    await app.ready();
    productId = (
      await app.inject({
        method: "POST", url: "/api/v1/admin/products", headers: adminH,
        payload: { key: "vv-harden", name: "Harden" },
      })
    ).json().id;
  });

  afterAll(() => {
    delete process.env.RATE_LIMIT_MAX;
  });

  it("allows BOTH portal origins (the customer SPA runs on its own origin)", async () => {
    for (const origin of [ADMIN_ORIGIN, CUSTOMER_ORIGIN]) {
      const res = await app.inject({
        method: "OPTIONS", url: "/api/v1/admin/licenses", headers: { origin },
      });
      expect(res.statusCode).toBe(204);
      expect(res.headers["access-control-allow-origin"]).toBe(origin);
      expect(res.headers["vary"]).toBe("Origin");
    }
  });

  it("does not echo an origin outside the allow-list", async () => {
    const res = await app.inject({
      method: "OPTIONS", url: "/api/v1/admin/licenses",
      headers: { origin: "https://evil.example" },
    });
    expect(res.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("rejects a malformed request body before it reaches the domain", async () => {
    // Wrong type: `as CreateLicenseInput` would have waved this straight through.
    const badType = await app.inject({
      method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
      payload: {
        customerId: "c", productId, edition: "pro", enabledFeatures: [],
        licenseType: "subscription", maximumSeats: "many",
      },
    });
    expect(badType.statusCode).toBe(400);
    expect(badType.json().error.code).toBe("VALIDATION");

    // Unknown enum value.
    const badEnum = await app.inject({
      method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
      payload: {
        customerId: "c", productId, edition: "pro", enabledFeatures: [],
        licenseType: "unlimited_forever", maximumSeats: 1,
      },
    });
    expect(badEnum.statusCode).toBe(400);

    // Missing required field.
    const missing = await app.inject({
      method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
      payload: { customerId: "c", productId },
    });
    expect(missing.statusCode).toBe(400);
  });

  it("rate limits per forwarded client IP, not per load balancer", async () => {
    const hit = (ip: string) =>
      app.inject({
        method: "POST", url: "/api/v1/validate",
        headers: { "content-type": "application/json", "x-forwarded-for": ip },
        payload: { token: "aaaa.bbbb.cccc", deviceId: "d" },
      });

    // Burn through one client's bucket (RATE_LIMIT_MAX=3).
    const noisy = [];
    for (let i = 0; i < 6; i++) noisy.push((await hit("203.0.113.9")).statusCode);
    expect(noisy).toContain(429);

    // A DIFFERENT client behind the same balancer must still be served. Without
    // trustProxy both would share the balancer's single bucket.
    const other = await hit("198.51.100.7");
    expect(other.statusCode).not.toBe(429);
  });
});
