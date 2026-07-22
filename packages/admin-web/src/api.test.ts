import { describe, it, expect, vi } from "vitest";
import { AdminApi, ApiError } from "./api";

function mockFetch(status: number, body: unknown) {
  return vi.fn(async () =>
    new Response(status === 204 ? null : JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );
}

describe("AdminApi", () => {
  it("sends the bearer token and parses JSON", async () => {
    const fetchImpl = mockFetch(200, { items: [{ id: "prod_1", key: "k", name: "n", createdAt: 1 }] });
    const api = new AdminApi({ getToken: () => "secret-key", fetchImpl, baseUrl: "http://x" });
    const res = await api.listProducts();
    expect(res.items[0].id).toBe("prod_1");
    const [, init] = fetchImpl.mock.calls[0]!;
    expect((init!.headers as Record<string, string>).authorization).toBe("Bearer secret-key");
  });

  it("builds query strings for license listing", async () => {
    const fetchImpl = mockFetch(200, { items: [], total: 0 });
    const api = new AdminApi({ getToken: () => "k", fetchImpl });
    await api.listLicenses({ status: "active", productId: "prod_1" });
    const [url] = fetchImpl.mock.calls[0]!;
    expect(url).toContain("status=active");
    expect(url).toContain("productId=prod_1");
  });

  it("throws a typed ApiError with the server code on failure", async () => {
    const fetchImpl = mockFetch(409, { error: { code: "INVALID_STATE_TRANSITION", message: "nope" } });
    const api = new AdminApi({ getToken: () => "k", fetchImpl });
    await expect(api.resume("lic_1")).rejects.toBeInstanceOf(ApiError);
    await expect(api.resume("lic_1")).rejects.toMatchObject({
      status: 409,
      code: "INVALID_STATE_TRANSITION",
    });
  });

  it("fetches identity (role + permissions) via me()", async () => {
    const fetchImpl = mockFetch(200, {
      subject: "alice",
      role: "auditor",
      permissions: ["license:read", "audit:read"],
    });
    const api = new AdminApi({ getToken: () => "k", fetchImpl });
    const id = await api.me();
    expect(id.role).toBe("auditor");
    expect(id.permissions).toContain("audit:read");
    const [url] = fetchImpl.mock.calls[0]!;
    expect(url).toContain("/api/v1/admin/me");
  });

  it("handles 204 No Content (revoke)", async () => {
    const fetchImpl = mockFetch(204, null);
    const api = new AdminApi({ getToken: () => "k", fetchImpl });
    await expect(api.revoke("lic_1", "reason")).resolves.toBeUndefined();
  });

  it("omits the auth header when no token is set", async () => {
    const fetchImpl = mockFetch(200, { items: [] });
    const api = new AdminApi({ getToken: () => null, fetchImpl });
    await api.listProducts();
    const [, init] = fetchImpl.mock.calls[0]!;
    expect((init!.headers as Record<string, string>).authorization).toBeUndefined();
  });
});
