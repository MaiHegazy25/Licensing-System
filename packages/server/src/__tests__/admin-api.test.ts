/**
 * Admin read + management API (the surface the portal consumes):
 * list products/licenses, license detail, suspend/resume/renew, audit,
 * plus auth enforcement and that activation-code plaintext/hash never leaks.
 */
import { describe, it, expect, beforeAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { generateEd25519KeyPair, type GeneratedKeyPair } from "@vehiclevo/licensing-shared";
import {
  buildContainer,
  buildHttpServer,
  LocalKeyProvider,
  FakeClock,
  type AppConfig,
} from "@vehiclevo/licensing-server";

const KID = "key-admin-test";
const ADMIN_KEY = "admin-key-abcdefghijklmnopqrstuvwx";
const ISSUER = "https://licensing.test";
const AUDIENCE = "vehiclevo-products";

function adminHeaders() {
  return { authorization: `Bearer ${ADMIN_KEY}`, "content-type": "application/json" };
}

describe("admin portal API", () => {
  let app: FastifyInstance;
  let clock: FakeClock;
  let kp: GeneratedKeyPair;
  let licenseId: string;
  let productId: string;

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
      activationCodePepper: "pepper-for-admin-tests-123456",
      databaseUrl: null,
    };
    app = buildHttpServer(buildContainer(cfg, clock, keyProvider));
    await app.ready();

    productId = (
      await app.inject({
        method: "POST",
        url: "/api/v1/admin/products",
        headers: adminHeaders(),
        payload: { key: "vv-tool", name: "VV Tool" },
      })
    ).json().id;

    licenseId = (
      await app.inject({
        method: "POST",
        url: "/api/v1/admin/licenses",
        headers: adminHeaders(),
        payload: {
          customerId: "cust_1",
          productId,
          edition: "pro",
          enabledFeatures: ["f1"],
          licenseType: "subscription",
          maximumSeats: 2,
          expiresAt: clock.now() + 86400,
        },
      })
    ).json().id;
  });

  it("rejects unauthenticated and mis-authenticated reads", async () => {
    expect((await app.inject({ method: "GET", url: "/api/v1/admin/licenses" })).statusCode).toBe(401);
    expect(
      (
        await app.inject({
          method: "GET",
          url: "/api/v1/admin/licenses",
          headers: { authorization: "Bearer wrong" },
        })
      ).statusCode,
    ).toBe(401);
  });

  it("lists products and licenses with filters", async () => {
    const products = (
      await app.inject({ method: "GET", url: "/api/v1/admin/products", headers: adminHeaders() })
    ).json();
    expect(products.items.map((p: { id: string }) => p.id)).toContain(productId);

    const filtered = (
      await app.inject({
        method: "GET",
        url: `/api/v1/admin/licenses?productId=${productId}&status=active`,
        headers: adminHeaders(),
      })
    ).json();
    expect(filtered.total).toBeGreaterThanOrEqual(1);
    expect(filtered.items[0].productId).toBe(productId);

    const none = (
      await app.inject({
        method: "GET",
        url: "/api/v1/admin/licenses?status=revoked",
        headers: adminHeaders(),
      })
    ).json();
    expect(none.items).toHaveLength(0);
  });

  it("returns license detail WITHOUT activation-code hashes/plaintext", async () => {
    const codeRes = await app.inject({
      method: "POST",
      url: `/api/v1/admin/licenses/${licenseId}/activation-codes`,
      headers: adminHeaders(),
      payload: { maxActivations: 1 },
    });
    expect(codeRes.statusCode).toBe(201);

    const detail = (
      await app.inject({
        method: "GET",
        url: `/api/v1/admin/licenses/${licenseId}`,
        headers: adminHeaders(),
      })
    ).json();
    expect(detail.license.id).toBe(licenseId);
    expect(detail.activationCodes).toHaveLength(1);
    // Neither the plaintext nor the stored hash may be exposed to the portal.
    const serialized = JSON.stringify(detail);
    expect(serialized).not.toContain("codeHash");
    expect(detail.activationCodes[0].codeHash).toBeUndefined();
    expect(detail.audit.length).toBeGreaterThan(0);
  });

  it("suspends, resumes, and renews a license with audit trail", async () => {
    const suspended = await app.inject({
      method: "POST",
      url: `/api/v1/admin/licenses/${licenseId}/suspend`,
      headers: adminHeaders(),
      payload: { reason: "billing" },
    });
    expect(suspended.json().status).toBe("suspended");

    const resumed = await app.inject({
      method: "POST",
      url: `/api/v1/admin/licenses/${licenseId}/resume`,
      headers: adminHeaders(),
    });
    expect(resumed.json().status).toBe("active");

    const renewed = await app.inject({
      method: "POST",
      url: `/api/v1/admin/licenses/${licenseId}/renew`,
      headers: adminHeaders(),
      payload: { expiresAt: clock.now() + 365 * 86400 },
    });
    expect(renewed.json().expiresAt).toBe(clock.now() + 365 * 86400);

    const audit = (
      await app.inject({
        method: "GET",
        url: `/api/v1/admin/audit?licenseId=${licenseId}`,
        headers: adminHeaders(),
      })
    ).json();
    const types = audit.items.map((e: { type: string }) => e.type);
    expect(types).toEqual(expect.arrayContaining(["license.suspended", "license.resumed", "license.renewed"]));
  });

  it("blocks invalid transitions (resume when active) with 409", async () => {
    const res = await app.inject({
      method: "POST",
      url: `/api/v1/admin/licenses/${licenseId}/resume`,
      headers: adminHeaders(),
    });
    expect(res.statusCode).toBe(409);
  });
});
