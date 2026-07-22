/**
 * Customer portal API — scoped strictly to the authenticated customer. The
 * central security property under test: a customer can NEVER see or act on
 * another customer's licenses/devices (returns 404, never leaks existence).
 */
import { describe, it, expect, beforeAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { generateEd25519KeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  buildHttpServer,
  LocalKeyProvider,
  FakeClock,
  type AppConfig,
} from "@vehiclevo/licensing-server";

const KID = "key-cust-test";
const ADMIN = "admin-cust-key-1234567890";
const K_ACME = "cust-acme-key-111111";
const K_GLOBEX = "cust-globex-key-222222";

const adminH = { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" };
const acmeH = { authorization: `Bearer ${K_ACME}`, "content-type": "application/json" };
const globexH = { authorization: `Bearer ${K_GLOBEX}`, "content-type": "application/json" };

describe("customer portal API", () => {
  let app: FastifyInstance;
  let acmeLicenseId: string;
  let globexLicenseId: string;
  let acmeActivationId: string;

  beforeAll(async () => {
    process.env.ADMIN_API_KEY = ADMIN;
    delete process.env.ADMIN_API_KEYS;
    delete process.env.AUTH_MODE;
    process.env.CUSTOMER_API_KEYS = JSON.stringify([
      { customerId: "acme", subject: "acme-admin", key: K_ACME },
      { customerId: "globex", key: K_GLOBEX },
    ]);
    const kp = generateEd25519KeyPair();
    const keyProvider = LocalKeyProvider.fromPems(
      [{ kid: KID, publicKeyPem: kp.publicKeyPem, privateKeyPem: kp.privateKeyPem }],
      KID,
    );
    const cfg: AppConfig = {
      env: "development", httpPort: 0, signingProvider: "local", localKeysDir: "",
      activeSigningKeyId: KID, tokenIssuer: "https://licensing.test",
      tokenAudience: "vehiclevo-products", tokenTtlSeconds: 3600,
      activationCodePepper: "pepper-customer-tests-123456", databaseUrl: null,
    };
    app = buildHttpServer(buildContainer(cfg, new FakeClock(1_700_000_000), keyProvider));
    await app.ready();

    const productId = (
      await app.inject({ method: "POST", url: "/api/v1/admin/products", headers: adminH, payload: { key: "vv-c", name: "C" } })
    ).json().id;
    const mkLicense = async (customerId: string) =>
      (
        await app.inject({
          method: "POST", url: "/api/v1/admin/licenses", headers: adminH,
          payload: {
            customerId, productId, edition: "pro", enabledFeatures: ["export_pdf"],
            licenseType: "subscription", maximumSeats: 3, expiresAt: 1_700_000_000 + 86400,
          },
        })
      ).json().id;
    acmeLicenseId = await mkLicense("acme");
    globexLicenseId = await mkLicense("globex");

    // Activate a device on acme's license.
    const code = (
      await app.inject({
        method: "POST", url: `/api/v1/admin/licenses/${acmeLicenseId}/activation-codes`,
        headers: adminH, payload: { maxActivations: 1 },
      })
    ).json().activationCode;
    await app.inject({
      method: "POST", url: "/api/v1/activate", headers: { "content-type": "application/json" },
      payload: { activationCode: code, deviceId: "acme-device-1", deviceLabel: "Laptop" },
    });
    acmeActivationId = (
      await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${acmeLicenseId}`, headers: acmeH })
    ).json().devices[0].id;
  });

  it("rejects unauthenticated access", async () => {
    expect((await app.inject({ method: "GET", url: "/api/v1/customer/licenses" })).statusCode).toBe(401);
  });

  it("returns the caller's identity", async () => {
    const me = (await app.inject({ method: "GET", url: "/api/v1/customer/me", headers: acmeH })).json();
    expect(me.customerId).toBe("acme");
  });

  it("lists ONLY the caller's own licenses", async () => {
    const acme = (await app.inject({ method: "GET", url: "/api/v1/customer/licenses", headers: acmeH })).json();
    const ids = acme.items.map((l: { id: string }) => l.id);
    expect(ids).toContain(acmeLicenseId);
    expect(ids).not.toContain(globexLicenseId);
    acme.items.forEach((l: { customerId: string }) => expect(l.customerId).toBe("acme"));
  });

  it("shows detail with features, seat usage, and own devices", async () => {
    const d = (await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${acmeLicenseId}`, headers: acmeH })).json();
    expect(d.license.enabledFeatures).toContain("export_pdf");
    expect(d.seatsUsed).toBe(1);
    expect(d.devices[0].deviceLabel).toBe("Laptop");
    // Customer view must NOT include internal audit.
    expect(d.audit).toBeUndefined();
  });

  it("ISOLATION: a customer cannot read another customer's license (404, no leak)", async () => {
    const res = await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${globexLicenseId}`, headers: acmeH });
    expect(res.statusCode).toBe(404);
  });

  it("ISOLATION: a customer cannot deactivate a device on another's license", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/customer/licenses/${globexLicenseId}/devices/${acmeActivationId}/deactivate`,
      headers: acmeH,
    });
    expect(res.statusCode).toBe(404);
  });

  it("lets a customer deactivate their own device (frees a seat)", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/customer/licenses/${acmeLicenseId}/devices/${acmeActivationId}/deactivate`,
      headers: acmeH,
    });
    expect(res.statusCode).toBe(204);
    const d = (await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${acmeLicenseId}`, headers: acmeH })).json();
    expect(d.seatsUsed).toBe(0);
  });

  it("accepts an activation-reset request and records it in the audit trail", async () => {
    const res = await app.inject({
      method: "POST", url: `/api/v1/customer/licenses/${acmeLicenseId}/activation-reset`,
      headers: acmeH, payload: { note: "lost my laptop" },
    });
    expect(res.statusCode).toBe(202);
    const audit = (
      await app.inject({ method: "GET", url: `/api/v1/admin/audit?licenseId=${acmeLicenseId}`, headers: adminH })
    ).json();
    expect(audit.items.map((e: { type: string }) => e.type)).toContain("activation_reset.requested");
  });

  it("downloads a signed license file for an owned license; 404 for others", async () => {
    const res = await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${acmeLicenseId}/license-file`, headers: acmeH });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-disposition"]).toContain("attachment");
    expect(res.json().token.split(".")).toHaveLength(3);

    const denied = await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${globexLicenseId}/license-file`, headers: globexH });
    // globex CAN download its own — sanity that the scoping is per-owner, not global deny.
    expect(denied.statusCode).toBe(200);
    const cross = await app.inject({ method: "GET", url: `/api/v1/customer/licenses/${globexLicenseId}/license-file`, headers: acmeH });
    expect(cross.statusCode).toBe(404);
  });
});
