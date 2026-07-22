/**
 * Per-role authorization enforced at the HTTP boundary. Each role gets its own
 * API key; we assert the permission matrix is actually applied to endpoints
 * (403 for missing permission, 401 for unknown key) and that /admin/me reports
 * the caller's role + permissions.
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

const KID = "key-rbac-test";
const KEYS = {
  system_admin: "key-sysadmin-000000",
  license_admin: "key-licadmin-111111",
  sales_ops: "key-sales-222222",
  support: "key-support-333333",
  auditor: "key-auditor-444444",
};

function h(role: keyof typeof KEYS) {
  return { authorization: `Bearer ${KEYS[role]}`, "content-type": "application/json" };
}

describe("RBAC at the API boundary", () => {
  let app: FastifyInstance;
  let productId: string;
  let licenseId: string;

  beforeAll(async () => {
    delete process.env.ADMIN_API_KEY;
    process.env.ADMIN_API_KEYS = JSON.stringify(
      Object.entries(KEYS).map(([role, key]) => ({ subject: `${role}-user`, role, key })),
    );
    const kp: GeneratedKeyPair = generateEd25519KeyPair();
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
      tokenIssuer: "i",
      tokenAudience: "a",
      tokenTtlSeconds: 3600,
      activationCodePepper: "pepper-for-rbac-tests-123456",
      databaseUrl: null,
    };
    app = buildHttpServer(buildContainer(cfg, new FakeClock(1_700_000_000), keyProvider));
    await app.ready();

    // Seed a product + license as system_admin.
    productId = (
      await app.inject({
        method: "POST",
        url: "/api/v1/admin/products",
        headers: h("system_admin"),
        payload: { key: "vv-rbac", name: "RBAC Tool" },
      })
    ).json().id;
    licenseId = (
      await app.inject({
        method: "POST",
        url: "/api/v1/admin/licenses",
        headers: h("system_admin"),
        payload: {
          customerId: "c1",
          productId,
          edition: "pro",
          enabledFeatures: ["f1"],
          licenseType: "subscription",
          maximumSeats: 2,
        },
      })
    ).json().id;
  });

  const createLicensePayload = () => ({
    customerId: "c2",
    productId,
    edition: "std",
    enabledFeatures: [],
    licenseType: "subscription" as const,
    maximumSeats: 1,
  });

  it("rejects unknown credentials with 401", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/api/v1/admin/licenses",
      headers: { authorization: "Bearer nope" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("/admin/me reports role + permissions", async () => {
    const me = (
      await app.inject({ method: "GET", url: "/api/v1/admin/me", headers: h("sales_ops") })
    ).json();
    expect(me.role).toBe("sales_ops");
    expect(me.permissions).toContain("license:create");
    expect(me.permissions).not.toContain("license:revoke");
  });

  it("auditor: can read, cannot write", async () => {
    expect(
      (await app.inject({ method: "GET", url: "/api/v1/admin/licenses", headers: h("auditor") }))
        .statusCode,
    ).toBe(200);
    expect(
      (await app.inject({ method: "GET", url: "/api/v1/admin/audit", headers: h("auditor") }))
        .statusCode,
    ).toBe(200);
    expect(
      (
        await app.inject({
          method: "POST",
          url: "/api/v1/admin/products",
          headers: h("auditor"),
          payload: { key: "x", name: "x" },
        })
      ).statusCode,
    ).toBe(403);
    expect(
      (
        await app.inject({
          method: "POST",
          url: "/api/v1/admin/licenses",
          headers: h("auditor"),
          payload: createLicensePayload(),
        })
      ).statusCode,
    ).toBe(403);
  });

  it("sales_ops: can create licenses + issue codes, cannot revoke or read audit", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/admin/licenses",
      headers: h("sales_ops"),
      payload: createLicensePayload(),
    });
    expect(created.statusCode).toBe(201);

    expect(
      (
        await app.inject({
          method: "POST",
          url: `/api/v1/admin/licenses/${licenseId}/activation-codes`,
          headers: h("sales_ops"),
          payload: { maxActivations: 1 },
        })
      ).statusCode,
    ).toBe(201);

    expect(
      (
        await app.inject({
          method: "POST",
          url: `/api/v1/admin/licenses/${licenseId}/revoke`,
          headers: h("sales_ops"),
          payload: { reason: "x" },
        })
      ).statusCode,
    ).toBe(403);

    expect(
      (await app.inject({ method: "GET", url: "/api/v1/admin/audit", headers: h("sales_ops") }))
        .statusCode,
    ).toBe(403);
  });

  it("support: can issue codes (reset) but not create licenses or suspend", async () => {
    expect(
      (
        await app.inject({
          method: "POST",
          url: `/api/v1/admin/licenses/${licenseId}/activation-codes`,
          headers: h("support"),
          payload: { maxActivations: 1 },
        })
      ).statusCode,
    ).toBe(201);
    expect(
      (
        await app.inject({
          method: "POST",
          url: "/api/v1/admin/licenses",
          headers: h("support"),
          payload: createLicensePayload(),
        })
      ).statusCode,
    ).toBe(403);
    expect(
      (
        await app.inject({
          method: "POST",
          url: `/api/v1/admin/licenses/${licenseId}/suspend`,
          headers: h("support"),
          payload: { reason: "x" },
        })
      ).statusCode,
    ).toBe(403);
  });

  it("license_admin: can run the full lifecycle including revoke", async () => {
    const lid = (
      await app.inject({
        method: "POST",
        url: "/api/v1/admin/licenses",
        headers: h("license_admin"),
        payload: createLicensePayload(),
      })
    ).json().id;
    expect(
      (
        await app.inject({
          method: "POST",
          url: `/api/v1/admin/licenses/${lid}/suspend`,
          headers: h("license_admin"),
          payload: { reason: "x" },
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await app.inject({
          method: "POST",
          url: `/api/v1/admin/licenses/${lid}/revoke`,
          headers: h("license_admin"),
          payload: { reason: "x" },
        })
      ).statusCode,
    ).toBe(204);
  });

  it("records the acting principal (not a generic 'admin') in the audit trail", async () => {
    const audit = (
      await app.inject({
        method: "GET",
        url: `/api/v1/admin/audit?licenseId=${licenseId}`,
        headers: h("system_admin"),
      })
    ).json();
    const actors = audit.items.map((e: { actor: string }) => e.actor);
    // Codes were issued by sales_ops and support above.
    expect(actors).toContain("sales_ops-user");
    expect(actors).toContain("support-user");
  });
});
