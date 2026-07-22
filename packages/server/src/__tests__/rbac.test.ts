import { describe, it, expect } from "vitest";
import {
  ROLES,
  PERMISSIONS,
  roleHasPermission,
  permissionsForRole,
  isRole,
  type Permission,
} from "@vehiclevo/licensing-server";
import { ApiKeyPrincipalResolver } from "@vehiclevo/licensing-server";

describe("RBAC matrix", () => {
  it("system_admin has every permission", () => {
    for (const p of PERMISSIONS) expect(roleHasPermission("system_admin", p)).toBe(true);
  });

  it("auditor is read-only (no writes)", () => {
    const writes: Permission[] = [
      "product:write",
      "license:create",
      "license:manage",
      "license:revoke",
      "activation:issue",
      "system:admin",
    ];
    for (const w of writes) expect(roleHasPermission("auditor", w)).toBe(false);
    expect(roleHasPermission("auditor", "license:read")).toBe(true);
    expect(roleHasPermission("auditor", "audit:read")).toBe(true);
  });

  it("sales_ops can create licenses + issue codes but not revoke/suspend", () => {
    expect(roleHasPermission("sales_ops", "license:create")).toBe(true);
    expect(roleHasPermission("sales_ops", "activation:issue")).toBe(true);
    expect(roleHasPermission("sales_ops", "license:revoke")).toBe(false);
    expect(roleHasPermission("sales_ops", "license:manage")).toBe(false);
  });

  it("support can issue codes (reset) + read, but not create licenses", () => {
    expect(roleHasPermission("support", "activation:issue")).toBe(true);
    expect(roleHasPermission("support", "license:read")).toBe(true);
    expect(roleHasPermission("support", "license:create")).toBe(false);
    expect(roleHasPermission("support", "license:revoke")).toBe(false);
  });

  it("license_admin manages full lifecycle but lacks system:admin", () => {
    expect(roleHasPermission("license_admin", "license:revoke")).toBe(true);
    expect(roleHasPermission("license_admin", "license:manage")).toBe(true);
    expect(roleHasPermission("license_admin", "product:write")).toBe(true);
    expect(roleHasPermission("license_admin", "system:admin")).toBe(false);
  });

  it("exposes exactly the five roles and validates role strings", () => {
    expect([...ROLES]).toEqual([
      "system_admin",
      "license_admin",
      "sales_ops",
      "support",
      "auditor",
    ]);
    expect(isRole("auditor")).toBe(true);
    expect(isRole("root")).toBe(false);
    expect(permissionsForRole("auditor").length).toBeGreaterThan(0);
  });
});

describe("ApiKeyPrincipalResolver", () => {
  it("maps legacy ADMIN_API_KEY to system_admin", async () => {
    const r = ApiKeyPrincipalResolver.fromEnv({ ADMIN_API_KEY: "legacy-key-123456" });
    expect(r.isConfigured()).toBe(true);
    expect(await r.resolve("legacy-key-123456")).toEqual({ subject: "admin", role: "system_admin" });
    expect(await r.resolve("wrong")).toBeNull();
    expect(await r.resolve(null)).toBeNull();
  });

  it("maps JSON ADMIN_API_KEYS to their roles", async () => {
    const r = ApiKeyPrincipalResolver.fromEnv({
      ADMIN_API_KEYS: JSON.stringify([
        { subject: "alice", role: "auditor", key: "auditor-key-1" },
        { subject: "bob", role: "sales_ops", key: "sales-key-2" },
      ]),
    });
    expect((await r.resolve("auditor-key-1"))?.role).toBe("auditor");
    expect(await r.resolve("sales-key-2")).toEqual({ subject: "bob", role: "sales_ops" });
  });

  it("rejects unknown roles and malformed JSON", () => {
    expect(() =>
      ApiKeyPrincipalResolver.fromEnv({
        ADMIN_API_KEYS: JSON.stringify([{ subject: "x", role: "wizard", key: "k" }]),
      }),
    ).toThrow(/unknown role/);
    expect(() => ApiKeyPrincipalResolver.fromEnv({ ADMIN_API_KEYS: "{not json" })).toThrow();
  });

  it("reports unconfigured when no keys are set", () => {
    expect(ApiKeyPrincipalResolver.fromEnv({}).isConfigured()).toBe(false);
  });
});
