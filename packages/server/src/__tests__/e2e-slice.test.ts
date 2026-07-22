/**
 * Stage 3 vertical slice, end to end, exercising the REAL HTTP API + the REAL
 * SDK against a shared deterministic clock:
 *
 *   admin creates product + license -> generates activation code ->
 *   SDK activates -> SDK verifies the signed token LOCALLY -> app gates a
 *   feature -> admin revokes -> SDK detects revocation on next online validate.
 */
import { describe, it, expect, beforeAll } from "vitest";
import type { FastifyInstance } from "fastify";
import {
  generateEd25519KeyPair,
  type GeneratedKeyPair,
} from "@vehiclevo/licensing-shared";
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

const KID = "key-test-1";
const ADMIN_KEY = "test-admin-key-abcdefghijklmnop";
const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";

/** Bridges the SDK's HttpClient to the Fastify app via light-weight injection. */
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

async function adminPost(app: FastifyInstance, url: string, body: unknown) {
  const res = await app.inject({
    method: "POST",
    url,
    payload: body as object,
    headers: { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/json" },
  });
  return { status: res.statusCode, body: res.statusCode === 204 ? null : res.json() };
}

describe("vertical slice (HTTP API + SDK)", () => {
  let app: FastifyInstance;
  let clock: FakeClock;
  let kp: GeneratedKeyPair;

  beforeAll(async () => {
    process.env.ADMIN_API_KEY = ADMIN_KEY;
    kp = generateEd25519KeyPair();
    clock = new FakeClock(1_700_000_000);

    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    const cfg: AppConfig = {
      env: "development",
      httpPort: 0,
      signingProvider: "local",
      localKeysDir: "",
      activeSigningKeyId: KID,
      tokenIssuer: ISSUER,
      tokenAudience: AUDIENCE,
      tokenTtlSeconds: 3600,
      activationCodePepper: "pepper-for-tests-1234567890",
      databaseUrl: null,
    };
    const container = buildContainer(cfg, clock, keyProvider);
    app = buildHttpServer(container);
    await app.ready();
  });

  it("runs create -> activate -> gate -> revoke -> detect", async () => {
    // 1. Admin creates a product.
    const product = await adminPost(app, "/api/v1/admin/products", {
      key: "vv-analyzer",
      name: "Vehiclevo Analyzer",
    });
    expect(product.status).toBe(201);
    const productId = product.body.id as string;

    // 2. Admin creates a subscription license with a feature + offline window.
    const license = await adminPost(app, "/api/v1/admin/licenses", {
      customerId: "cust_acme",
      productId,
      edition: "pro",
      enabledFeatures: ["export_pdf", "batch_mode"],
      licenseType: "subscription",
      maximumSeats: 3,
      expiresAt: clock.now() + 30 * 86400,
      gracePeriodSeconds: 7 * 86400,
      offlineUntil: clock.now() + 14 * 86400,
    });
    expect(license.status).toBe(201);
    const licenseId = license.body.id as string;

    // 3. Admin generates an activation code (plaintext returned once).
    const codeRes = await adminPost(
      app,
      `/api/v1/admin/licenses/${licenseId}/activation-codes`,
      { maxActivations: 1 },
    );
    expect(codeRes.status).toBe(201);
    const activationCode = codeRes.body.activationCode as string;
    expect(activationCode).toMatch(/[0-9A-Z-]{10,}/);

    // 4. SDK initializes with ONLY the embedded public key, then activates.
    const store = new InMemoryTokenStore();
    const client = await LicensingClient.initialize({
      expectedIssuer: ISSUER,
      expectedAudience: AUDIENCE,
      deviceId: "device-derived-abc123",
      publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
      http: sdkHttp(app),
      store,
      clock,
    });
    const activated = await client.activate(activationCode);
    expect(activated.ok).toBe(true);
    expect(activated.status).toBe("valid");
    expect(activated.source).toBe("online");

    // 5. Feature gating uses locally-verified claims.
    expect(client.hasFeature("export_pdf")).toBe(true);
    expect(client.hasFeature("enterprise_only")).toBe(false);
    expect(client.getOfflineDaysRemaining()).toBeGreaterThan(0);

    // 6. Admin revokes the license.
    const revoke = await adminPost(
      app,
      `/api/v1/admin/licenses/${licenseId}/revoke`,
      { reason: "chargeback" },
    );
    expect(revoke.status).toBe(204);

    // 7. Next online validation detects revocation; features go dark.
    const afterRevoke = await client.validateLicense();
    expect(afterRevoke.ok).toBe(false);
    expect(afterRevoke.status).toBe("revoked");
    expect(afterRevoke.reason).toBe(LicensingErrorCode.Revoked);
    expect(client.hasFeature("export_pdf")).toBe(false);
  });

  it("enforces seat limits and rejects a bad activation code", async () => {
    const productId = (
      await adminPost(app, "/api/v1/admin/products", {
        key: "vv-seats",
        name: "Seats Product",
      })
    ).body.id as string;
    const licenseId = (
      await adminPost(app, "/api/v1/admin/licenses", {
        customerId: "c1",
        productId,
        edition: "std",
        enabledFeatures: ["f1"],
        licenseType: "device",
        maximumSeats: 1,
      })
    ).body.id as string;
    const code = (
      await adminPost(app, `/api/v1/admin/licenses/${licenseId}/activation-codes`, {
        maxActivations: 5,
      })
    ).body.activationCode as string;

    const mk = async (deviceId: string) => {
      const c = await LicensingClient.initialize({
        expectedIssuer: ISSUER,
        expectedAudience: AUDIENCE,
        deviceId,
        publicKeys: [{ kid: KID, pem: kp.publicKeyPem }],
        http: sdkHttp(app),
        store: new InMemoryTokenStore(),
        clock,
      });
      return c;
    };

    const c1 = await mk("dev-1");
    expect((await c1.activate(code)).ok).toBe(true);

    // Second distinct device exceeds maximumSeats=1.
    const c2 = await mk("dev-2");
    await expect(c2.activate(code)).rejects.toMatchObject({
      code: LicensingErrorCode.ActivationFailed,
    });

    // Wrong code fails cleanly.
    const c3 = await mk("dev-3");
    await expect(c3.activate("00000-00000-00000-00000")).rejects.toMatchObject({
      code: LicensingErrorCode.ActivationFailed,
    });
  });
});
